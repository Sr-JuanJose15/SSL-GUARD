"""
API HTTP de SSL-Guard (FastAPI).

Responsabilidades
-----------------
- Orquestar auditorías TLS vía SSL Labs con polling no bloqueante (``GET /api/v1/audit``).
- Gestionar sesiones en memoria (:mod:`app.audit_session`).
- Enriquecer informes READY (certificado, protocolos, ataques, cabeceras HTTP, remediación).
- Persistir y consultar historial en SQLite (:mod:`app.database`).

Endpoints
---------
``POST /api/v1/audit/cancel``
    Cancela la sesión de un dominio.
``GET /api/v1/audit``
    Estado DNS / IN_PROGRESS / READY (y variantes ERROR, TIMEOUT, CANCELLED, FAILED).
``GET /api/v1/history``
    Último escaneo por dominio (resumen).
``GET /api/v1/history/{scan_id}``
    Informe JSON completo guardado.
"""

from __future__ import annotations

import copy
import json
import logging
from datetime import UTC, datetime
from typing import Any

import httpx
from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import func
from sqlalchemy.orm import Session

import app.audit_session as audit_session
import app.parser as parser
import app.scanner as scanner
from app.database import ScanHistory, get_db
from app.engine import RecommendationEngine
from app.hostname_vuln_extension import flags_tuple_from_hostname_qa
from app.remediacion import generar_snippets_remediacion

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Aplicación FastAPI
# ---------------------------------------------------------------------------

app = FastAPI(
    title="SSL-Guard API",
    description="Motor de auditoría y recomendaciones de seguridad SSL/TLS",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Errores y estado SSL Labs
# ---------------------------------------------------------------------------


def _format_ssl_labs_errors(errors: list[dict[str, Any]]) -> str:
    """Concatena mensajes del array ``errors`` de Qualys en un solo texto."""
    parts: list[str] = []
    for item in errors:
        if isinstance(item, dict):
            msg = item.get("message") or item.get("detail") or json.dumps(item, ensure_ascii=False)
            parts.append(str(msg))
        else:
            parts.append(str(item))
    return "; ".join(parts) if parts else "Error en SSL Labs"


def _labs_status_upper(raw: dict[str, Any]) -> str:
    """Normaliza el campo ``status`` del JSON raíz de SSL Labs."""
    return (raw.get("status") or "").strip().upper()


def _progress_message(raw: dict[str, Any]) -> str | None:
    """Mensaje legible para el front a partir de ``statusMessage`` y del primer endpoint."""
    chunks: list[str] = []
    sm = raw.get("statusMessage")
    sm_text = sm.strip() if isinstance(sm, str) else ""

    # Si Qualys está devolviendo un error genérico/intermitente, prioriza el detalle útil del endpoint.
    generic_error_markers = (
        "internalservererror occurred",
        "internal server error",
        "service unavailable",
        "temporarily unavailable",
        "try again",
        "please try again",
    )
    sm_is_generic = sm_text.lower() in generic_error_markers or any(
        m in sm_text.lower() for m in generic_error_markers
    )

    endpoints = raw.get("endpoints")
    if isinstance(endpoints, list) and endpoints:
        ep0 = endpoints[0]
        if isinstance(ep0, dict):
            det = ep0.get("statusDetailsMessage")
            if isinstance(det, str) and det.strip():
                chunks.append(det.strip())
            prog = ep0.get("progress")
            if isinstance(prog, (int, float)) and prog >= 0:
                chunks.append(f"{int(prog)}%")

    # Si el statusMessage no es genérico, o si no hubo detalles útiles, lo incluimos.
    if sm_text and (not sm_is_generic or not chunks):
        chunks.insert(0, sm_text)
    # Si era genérico pero sí había detalle útil, lo añadimos al final como nota.
    elif sm_text and sm_is_generic and chunks:
        chunks.append(sm_text)
    return " — ".join(chunks) if chunks else None


def _progress_body(host: str, raw: dict[str, Any]) -> dict[str, Any]:
    """Cuerpo JSON para respuestas DNS o IN_PROGRESS."""
    st = _labs_status_upper(raw)
    if st not in ("DNS", "IN_PROGRESS"):
        st = "IN_PROGRESS"
    out: dict[str, Any] = {
        "status": st,
        "host": raw.get("host") if isinstance(raw.get("host"), str) else host,
    }
    msg = _progress_message(raw)
    if msg:
        out["statusMessage"] = msg
    return out


def _http_status_error_is_transient(e: httpx.HTTPStatusError) -> bool:
    """
    Si la API pública de SSL Labs devuelve 5xx/429, suele ser saturación temporal.
    En esos casos preferimos IN_PROGRESS para que el front reintente con backoff.
    """
    try:
        code = e.response.status_code
    except Exception:
        return False
    return code in (429, 500, 502, 503, 504, 520, 521, 522, 524)


def _labs_error_body(raw: dict[str, Any]) -> dict[str, Any]:
    """Cuerpo JSON uniforme cuando SSL Labs devuelve ``status: ERROR``."""
    msg = raw.get("statusMessage")
    text = msg.strip() if isinstance(msg, str) and msg.strip() else "SSL Labs no pudo completar el análisis."
    return {
        "status": "ERROR",
        "statusMessage": text,
        "error": text,
        "host": raw.get("host") if isinstance(raw.get("host"), str) else None,
    }


def _qualys_error_is_transient(raw: dict[str, Any]) -> bool:
    """
    Hay errores de SSL Labs que son intermitentes (sobrecarga interna, etc.).
    En esos casos preferimos responder IN_PROGRESS para que el front siga polleando.
    """
    msg = raw.get("statusMessage")
    text = msg.strip().lower() if isinstance(msg, str) else ""

    # Casos típicos vistos en la API pública
    transient_markers = (
        "internalservererror occurred",
        "internal server error",
        "please try again",
        "try again later",
        "temporarily unavailable",
        "service unavailable",
        "overloaded",
        "too many requests",
    )
    if any(m in text for m in transient_markers):
        return True

    # Si Qualys devuelve errores estructurados, algunos también son transitorios.
    errs = raw.get("errors")
    if isinstance(errs, list):
        for e in errs:
            if not isinstance(e, dict):
                continue
            m = e.get("message") or e.get("detail") or ""
            m2 = m.strip().lower() if isinstance(m, str) else ""
            if any(x in m2 for x in transient_markers):
                return True

    return False


def _qualys_errors_is_transient(errors: list[dict[str, Any]]) -> bool:
    """Versión para la excepción SSLLabsAPIError (campo ``errors`` en respuesta de Qualys)."""
    transient_markers = (
        "internalservererror occurred",
        "internal server error",
        "please try again",
        "try again later",
        "temporarily unavailable",
        "service unavailable",
        "overloaded",
        "too many requests",
    )
    for e in errors:
        if not isinstance(e, dict):
            continue
        m = e.get("message") or e.get("detail") or ""
        text = m.strip().lower() if isinstance(m, str) else ""
        if any(x in text for x in transient_markers):
            return True
    return False


# ---------------------------------------------------------------------------
# Vulnerabilidades y formato de ataques
# ---------------------------------------------------------------------------


def _coerce_int_optional(value: Any) -> int | None:
    """Convierte '2', 2.0, 2 a int; ignora bool (JSON suele usar true/false aparte)."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return None
    return None


def _labs_bool_vulnerable(value: Any) -> bool:
    """
    Heartbleed / POODLE SSLv3 / FREAK / DROWN: Qualys documenta bool.
    Aceptamos true explícito y, por compatibilidad, 1 o '1'/'true'.
    """
    if value is True:
        return True
    if value is False or value is None:
        return False
    if isinstance(value, (int, float)):
        return value == 1
    if isinstance(value, str):
        return value.strip().lower() in ("true", "1", "yes")
    return False


def _poodle_tls_vulnerable(details: dict[str, Any]) -> bool:
    """Qualys: poodleTls == 2 significa vulnerable (TLS)."""
    v = details.get("poodleTls", 0)
    return isinstance(v, (int, float)) and int(v) == 2


def _logjam_vulnerable(details: dict[str, Any]) -> bool:
    """
    Qualys: ``logjam`` true = DH débil (<1024 bits). Además, ``dhUsesKnownPrimes``:
    0 no, 1 sí no débiles, 2 sí débiles (a veces llega como ``\"2\"``; coacciona a int).
    """
    if _labs_bool_vulnerable(details.get("logjam")):
        return True
    dup = _coerce_int_optional(details.get("dhUsesKnownPrimes"))
    return dup == 2


def _fila_ataque(
    nombre: str,
    vulnerable: bool,
    *,
    fuentes: list[str] | None = None,
) -> dict[str, Any]:
    """
    ``fuentes``: de dónde sale el valor (p. ej. ``qualys``, ``extension_hostname``).
    Así el front puede distinguir lectura real de Qualys del refuerzo por nombre de host.
    """
    d: dict[str, Any] = {
        "nombre": nombre,
        "vulnerable": vulnerable,
        "esVulnerable": vulnerable,
        "es_vulnerable": vulnerable,
        "isVulnerable": vulnerable,
        "seguro": not vulnerable,
    }
    if vulnerable and fuentes:
        d["fuentes"] = fuentes
    return d


# ---------------------------------------------------------------------------
# Certificado y protocolos (payload enriquecido)
# ---------------------------------------------------------------------------


def _find_endpoint_with_details(raw: dict[str, Any]) -> dict[str, Any] | None:
    """Primer endpoint cuyo bloque ``details`` existe y no está vacío."""
    endpoints = raw.get("endpoints")
    if not isinstance(endpoints, list):
        return None
    for ep in endpoints:
        if not isinstance(ep, dict):
            continue
        det = ep.get("details")
        if isinstance(det, dict) and det:
            return ep
    return None


def _leaf_cert_desde_raiz(raw: dict[str, Any]) -> dict[str, Any]:
    """Certificado hoja en ``certs[0]`` (Qualys lo envía en la raíz del host)."""
    certs = raw.get("certs")
    if not isinstance(certs, list) or not certs:
        return {}
    leaf = certs[0]
    return leaf if isinstance(leaf, dict) else {}


def _ms_a_iso_o_none(ms: Any) -> str | None:
    """Convierte milisegundos Qualys a ISO 8601 (UTC) para el front."""
    if not isinstance(ms, (int, float)):
        return None
    try:
        dt = datetime.fromtimestamp(float(ms) / 1000.0, tz=UTC)
        return dt.isoformat()
    except (OSError, ValueError, OverflowError):
        return None


def _fusionar_certificado_qualys(raw: dict[str, Any]) -> dict[str, Any]:
    """
    Combina ``certs[0]`` (raíz) con ``details.cert`` del primer endpoint con detalles.
    Qualys a veces deja ``details.cert`` vacío pero sí manda ``certs`` y ``protocols``.
    """
    leaf = _leaf_cert_desde_raiz(raw)
    merged: dict[str, Any] = dict(leaf)
    ep = _find_endpoint_with_details(raw)
    if ep:
        dc = ep.get("details", {}).get("cert")
        if isinstance(dc, dict):
            for k, v in dc.items():
                if v not in (None, "", []):
                    merged[k] = v
    return merged


def _extraer_info_certificado(raw: dict[str, Any]) -> dict[str, Any]:
    """
    Campos del certificado servidor: sujeto, emisor, fechas (ms + ISO), algoritmo.
    Usa hoja en ``certs[0]`` y/o ``details.cert`` con todos los fallbacks posibles.
    """
    cert = _fusionar_certificado_qualys(raw)
    if not cert:
        return {}

    sujeto: str | None = None
    sub = cert.get("subject")
    if isinstance(sub, str) and sub.strip():
        sujeto = sub.strip()
    if not sujeto:
        nombres = cert.get("commonNames")
        if isinstance(nombres, list) and nombres:
            sujeto = str(nombres[0]).strip() or None
    if not sujeto:
        cn = cert.get("cn")
        if isinstance(cn, str) and cn.strip():
            sujeto = cn.strip()
    if not sujeto:
        sujeto = "Desconocido"

    emisor = (
        cert.get("issuerLabel")
        or cert.get("issuerSubject")
        or cert.get("issuerHTML")
        or "Desconocido"
    )
    if isinstance(emisor, str):
        emisor = emisor.strip() or "Desconocido"
    else:
        emisor = str(emisor) if emisor else "Desconocido"

    nb = cert.get("notBefore")
    na = cert.get("notAfter")
    sig_any = cert.get("sigAlg") or cert.get("algorithm") or "Desconocido"
    sig = sig_any if isinstance(sig_any, str) and sig_any.strip() else "Desconocido"

    out: dict[str, Any] = {
        "sujeto": sujeto,
        "emisor": emisor,
        "fecha_emision": nb,
        "fecha_vencimiento": na,
        "algoritmo_firma": sig,
        "fecha_emision_iso": _ms_a_iso_o_none(nb),
        "fecha_vencimiento_iso": _ms_a_iso_o_none(na),
    }
    return out


def _protocolo_considerado_seguro_qualys(p: dict[str, Any]) -> bool:
    """
    TLS 1.2 y 1.3 como referencia actual.
    Qualys puede enviar ``version`` como 1.2/1.3 (float/str) o como id entero 771/772 (TLS 1.2+).
    """
    v = p.get("version")
    if isinstance(v, int):
        return v >= 771
    if isinstance(v, float):
        if v > 10.0:
            return int(v) >= 771
        return v >= 1.2
    if isinstance(v, str):
        vs = v.strip()
        try:
            fv = float(vs)
            return fv >= 1.2
        except ValueError:
            return False
    return False


def _extraer_protocolos(raw: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Protocolos soportados (``details.protocols``). Prueba cada endpoint hasta
    encontrar una lista no vacía.
    """
    endpoints = raw.get("endpoints")
    if not isinstance(endpoints, list):
        return []
    for ep in endpoints:
        if not isinstance(ep, dict):
            continue
        det = ep.get("details")
        if not isinstance(det, dict) or not det:
            continue
        raw_protocols = det.get("protocols")
        if not isinstance(raw_protocols, list) or not raw_protocols:
            continue
        out: list[dict[str, Any]] = []
        for p in raw_protocols:
            if not isinstance(p, dict):
                continue
            name = p.get("name")
            ver = p.get("version")
            if name is not None and ver is not None:
                etiqueta = f"{name} {ver}".strip()
            elif name is not None:
                etiqueta = str(name)
            else:
                etiqueta = "Desconocido"
            out.append(
                {
                    "version": etiqueta,
                    "seguro": _protocolo_considerado_seguro_qualys(p),
                }
            )
        return out
    return []


def _endpoints_con_ataques(raw_full: dict[str, Any], ataques: list[dict[str, Any]]) -> list[Any] | None:
    """Copia endpoints de Qualys e inyecta la lista de ataques en cada uno (p. ej. lectura desde endpoints[0])."""
    eps = raw_full.get("endpoints")
    if not isinstance(eps, list) or not eps:
        return None
    out = copy.deepcopy(eps)
    for ep in out:
        if isinstance(ep, dict):
            ep["ataques_formateados"] = ataques
            ep["ataquesFormateados"] = ataques
    return out


def _flags_ataques_qualys(raw: dict[str, Any]) -> tuple[bool, bool, bool, bool, bool, bool]:
    """(Heartbleed, POODLE SSLv3, POODLE TLS, FREAK, Logjam, DROWN) solo desde Qualys."""
    endpoints = raw.get("endpoints")
    if not isinstance(endpoints, list) or not endpoints:
        return (False, False, False, False, False, False)

    hb = p_ssl = p_tls = freak = lj = drown = False
    for ep in endpoints:
        if not isinstance(ep, dict):
            continue
        det = ep.get("details")
        if not isinstance(det, dict):
            continue
        hb = hb or _labs_bool_vulnerable(det.get("heartbleed"))
        p_ssl = p_ssl or _labs_bool_vulnerable(det.get("poodle"))
        p_tls = p_tls or _poodle_tls_vulnerable(det)
        freak = freak or _labs_bool_vulnerable(det.get("freak"))
        lj = lj or _logjam_vulnerable(det)
        drown = drown or _labs_bool_vulnerable(det.get("drownVulnerable"))
    return (hb, p_ssl, p_tls, freak, lj, drown)


def _ataques_formateados_from_raw(raw: dict[str, Any], host_solicitud: str) -> list[dict[str, Any]]:
    """
    Combina Qualys (todos los endpoints, OR) con la **extensión por hostname**
    (misma regla que el motor de mitigación: poodle/heartbleed/freak/logjam en el dominio).
    Cada fila puede incluir ``fuentes``: ``qualys``, ``extension_hostname``, o ambas.
    """
    nombres = (
        "Heartbleed",
        "POODLE (SSLv3)",
        "POODLE (TLS)",
        "FREAK",
        "Logjam",
        "DROWN",
    )
    q = _flags_ataques_qualys(raw)
    e = flags_tuple_from_hostname_qa(host_solicitud)
    filas: list[dict[str, Any]] = []
    for i, nombre in enumerate(nombres):
        vq, ve = q[i], e[i]
        vuln = vq or ve
        fuentes: list[str] = []
        if vq:
            fuentes.append("qualys")
        if ve:
            fuentes.append("extension_hostname")
        filas.append(_fila_ataque(nombre, vuln, fuentes=fuentes if vuln else None))
    return filas


def _progress_from_qualys_raw(raw: dict[str, Any] | None) -> int | None:
    """Porcentaje de progreso del primer endpoint con valor >= 0."""
    if not raw or not isinstance(raw, dict):
        return None
    eps = raw.get("endpoints")
    if not isinstance(eps, list):
        return None
    for ep in eps:
        if not isinstance(ep, dict):
            continue
        p = ep.get("progress")
        if isinstance(p, (int, float)) and p >= 0:
            return int(p)
    return None


# ---------------------------------------------------------------------------
# Sesión de auditoría y respuestas HTTP auxiliares
# ---------------------------------------------------------------------------


async def _attach_session_meta(host: str, body: dict[str, Any]) -> None:
    """Añade ``suggestedPollSeconds`` y ``auditSessionStarted`` al cuerpo de progreso."""
    sm = body.get("statusMessage")
    sm_s = sm if isinstance(sm, str) else None
    body["suggestedPollSeconds"] = await audit_session.suggested_poll_seconds(host, sm_s)
    epoch = await audit_session.session_started_epoch(host)
    if epoch is not None:
        body["auditSessionStarted"] = epoch


async def _finalize_progress_response(
    host: str,
    body: dict[str, Any],
    raw: dict[str, Any] | None,
    *,
    had_transient_error: bool,
) -> JSONResponse:
    """Registra el poll, adjunta metadatos de sesión y devuelve JSON 200."""
    prog = _progress_from_qualys_raw(raw)
    await audit_session.record_poll(host, prog, has_transient_error=had_transient_error)
    await _attach_session_meta(host, body)
    return JSONResponse(status_code=200, content=body)


async def _analizar_cabeceras_seguridad(host: str) -> dict[str, Any]:
    """Se conecta al host y extrae cabeceras vitales, disfrazándose de navegador."""
    try:
        async with httpx.AsyncClient(timeout=8.0, verify=False, follow_redirects=True) as client:
            custom_headers = {
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
                )
            }

            response = await client.get(f"https://{host}", headers=custom_headers)
            h = response.headers

            return {
                "hsts": "Strict-Transport-Security" in h,
                "x_frame_options": h.get("X-Frame-Options", "No configurado"),
                "csp": "Content-Security-Policy" in h,
                "servidor": h.get("Server", "Oculto por seguridad (Buena práctica)"),
            }
    except Exception as e:
        return {"error": f"Fallo al conectar: {str(e)}"}


def _timeout_audit_response(host: str, reason: str) -> JSONResponse:
    """Respuesta estándar cuando la sesión supera límites de tiempo o errores."""
    return JSONResponse(
        status_code=200,
        content={
            "status": "TIMEOUT",
            "error": reason,
            "statusMessage": reason,
            "host": host,
        },
    )


def _cancelled_audit_response(host: str) -> JSONResponse:
    """Respuesta cuando el usuario canceló el análisis en curso."""
    return JSONResponse(
        status_code=200,
        content={
            "status": "CANCELLED",
            "statusMessage": "Análisis cancelado por el usuario.",
            "error": "Análisis cancelado por el usuario.",
            "host": host,
        },
    )


# ---------------------------------------------------------------------------
# Rutas REST
# ---------------------------------------------------------------------------


@app.post("/api/v1/audit/cancel")
async def audit_cancel(domain: str = Query(..., description="Mismo dominio o URL que en GET /api/v1/audit")):
    """Marca la sesión como cancelada; los GET siguientes devuelven CANCELLED hasta startNew=true."""
    try:
        validated = scanner.DomainRequest(host=domain)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    host = validated.host
    await audit_session.mark_cancelled(host)
    return JSONResponse(
        status_code=200,
        content={
            "status": "CANCELLED",
            "statusMessage": "Cancelación registrada; el análisis en curso se considera detenido en el cliente.",
            "host": host,
        },
    )


@app.get("/api/v1/audit")
async def audit_domain(
    domain: str,
    startNew: bool = Query(
        False,
        description="Primera petición del flujo: true para forzar escaneo nuevo (startNew en SSL Labs).",
    ),
    db: Session = Depends(get_db),
):
    """
    Contrato alineado con el front (Angular): cada GET devuelve enseguida el estado
    actual (DNS / IN_PROGRESS) o el informe final (READY + payload), sin bloquear
    hasta que Qualys termine dentro de una sola petición HTTP.

    Además (sesión en memoria, un worker):
    - Respuestas DNS/IN_PROGRESS pueden incluir ``suggestedPollSeconds`` y ``auditSessionStarted``.
    - Tras muchos errores transitorios, progreso clavado o tiempo máximo → ``TIMEOUT``.
    - Cancelar con ``POST /api/v1/audit/cancel``; sin ``startNew`` los GET devuelven CANCELLED.
    """
    try:
        validated = scanner.DomainRequest(host=domain)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e

    host = validated.host

    if startNew:
        await audit_session.reset_on_new_scan(host)
    else:
        if await audit_session.is_cancelled(host):
            return _cancelled_audit_response(host)
        await audit_session.touch_session_if_new(host)

    timed_out, reason = await audit_session.should_timeout(host)
    if timed_out:
        await audit_session.clear_session(host)
        return _timeout_audit_response(host, reason)

    try:
        raw = await scanner.fetch_analyze_snapshot(host, start_new=startNew, all_done=False)
    except scanner.SSLLabsAPIError as e:
        text = _format_ssl_labs_errors(e.errors)
        if _qualys_errors_is_transient(e.errors):
            body = {
                "status": "IN_PROGRESS",
                "statusMessage": text,
                "host": host,
            }
            return await _finalize_progress_response(host, body, None, had_transient_error=True)
        await audit_session.clear_session(host)
        return JSONResponse(
            status_code=200,
            content={
                "status": "ERROR",
                "error": text,
                "statusMessage": text,
                "host": host,
            },
        )
    except scanner.SnapshotRateLimitExceeded as e:
        body = {
            "status": "IN_PROGRESS",
            "statusMessage": str(e),
            "host": host,
        }
        return await _finalize_progress_response(host, body, None, had_transient_error=True)
    except httpx.TimeoutException:
        await audit_session.clear_session(host)
        return JSONResponse(
            status_code=200,
            content={
                "status": "TIMEOUT",
                "error": "Tiempo de espera agotado al contactar SSL Labs.",
                "statusMessage": "Tiempo de espera agotado al contactar SSL Labs.",
                "host": host,
            },
        )
    except httpx.HTTPStatusError as e:
        if _http_status_error_is_transient(e):
            body = {
                "status": "IN_PROGRESS",
                "statusMessage": f"SSL Labs reportó un error HTTP {e.response.status_code}. Reintentando...",
                "host": host,
            }
            return await _finalize_progress_response(host, body, None, had_transient_error=True)
        await audit_session.clear_session(host)
        return JSONResponse(
            status_code=200,
            content={
                "status": "ERROR",
                "error": f"Fallo de red HTTP: {e!s}",
                "statusMessage": f"Fallo de red HTTP: {e!s}",
                "host": host,
            },
        )
    except httpx.HTTPError as e:
        await audit_session.clear_session(host)
        return JSONResponse(
            status_code=200,
            content={
                "status": "ERROR",
                "error": f"Fallo de red HTTP: {e!s}",
                "statusMessage": f"Fallo de red HTTP: {e!s}",
                "host": host,
            },
        )

    st = _labs_status_upper(raw)

    if st == "ERROR":
        if _qualys_error_is_transient(raw):
            body = _progress_body(host, raw)
            body["status"] = "IN_PROGRESS"
            return await _finalize_progress_response(host, body, raw, had_transient_error=True)
        await audit_session.clear_session(host)
        return JSONResponse(status_code=200, content=_labs_error_body(raw))

    if st in ("DNS", "IN_PROGRESS"):
        body = _progress_body(host, raw)
        return await _finalize_progress_response(host, body, raw, had_transient_error=False)

    if st == "READY":
        timed_out2, reason2 = await audit_session.should_timeout(host)
        if timed_out2:
            await audit_session.clear_session(host)
            return _timeout_audit_response(host, reason2)
        try:
            raw_full = await scanner.fetch_analyze_snapshot(
                host, start_new=False, all_done=True
            )
            eps_dbg = raw_full.get("endpoints")
            first_has_details = (
                isinstance(eps_dbg, list)
                and len(eps_dbg) > 0
                and isinstance(eps_dbg[0], dict)
                and bool(eps_dbg[0].get("details"))
            )
            logger.debug(
                "SSL-Guard audit: host=%r all=done — details en endpoints[0]=%s, "
                "algún endpoint con details=%s",
                host,
                first_has_details,
                _find_endpoint_with_details(raw_full) is not None,
            )
        except scanner.SSLLabsAPIError as e:
            text = _format_ssl_labs_errors(e.errors)
            if _qualys_errors_is_transient(e.errors):
                body = {
                    "status": "IN_PROGRESS",
                    "statusMessage": text,
                    "host": host,
                }
                return await _finalize_progress_response(host, body, raw, had_transient_error=True)
            await audit_session.clear_session(host)
            return JSONResponse(
                status_code=200,
                content={
                    "status": "ERROR",
                    "error": text,
                    "statusMessage": text,
                    "host": host,
                },
            )
        except scanner.SnapshotRateLimitExceeded as e:
            body = {
                "status": "IN_PROGRESS",
                "statusMessage": str(e),
                "host": host,
            }
            return await _finalize_progress_response(host, body, raw, had_transient_error=True)
        except httpx.TimeoutException:
            await audit_session.clear_session(host)
            return JSONResponse(
                status_code=200,
                content={
                    "status": "TIMEOUT",
                    "error": "Tiempo de espera al obtener el detalle completo (all=done).",
                    "statusMessage": "Tiempo de espera al obtener el detalle completo (all=done).",
                    "host": host,
                },
            )
        except httpx.HTTPStatusError as e:
            if _http_status_error_is_transient(e):
                body = {
                    "status": "IN_PROGRESS",
                    "statusMessage": f"SSL Labs reportó un error HTTP {e.response.status_code}. Reintentando...",
                    "host": host,
                }
                return await _finalize_progress_response(host, body, raw, had_transient_error=True)
            await audit_session.clear_session(host)
            return JSONResponse(
                status_code=200,
                content={
                    "status": "ERROR",
                    "error": f"Fallo de red HTTP: {e!s}",
                    "statusMessage": f"Fallo de red HTTP: {e!s}",
                    "host": host,
                },
            )
        except httpx.HTTPError as e:
            await audit_session.clear_session(host)
            return JSONResponse(
                status_code=200,
                content={
                    "status": "ERROR",
                    "error": f"Fallo de red HTTP: {e!s}",
                    "statusMessage": f"Fallo de red HTTP: {e!s}",
                    "host": host,
                },
            )

        if _labs_status_upper(raw_full) == "ERROR":
            if _qualys_error_is_transient(raw_full):
                body = _progress_body(host, raw_full)
                body["status"] = "IN_PROGRESS"
                return await _finalize_progress_response(host, body, raw_full, had_transient_error=True)
            await audit_session.clear_session(host)
            return JSONResponse(status_code=200, content=_labs_error_body(raw_full))

        try:
            cleaned = parser.parse_ssl_results(raw_full)
            plan = RecommendationEngine.generate_plan(cleaned)
        except parser.SSLReportParseError as e:
            await audit_session.clear_session(host)
            return JSONResponse(
                status_code=200,
                content={
                    "status": "FAILED",
                    "error": str(e),
                    "statusMessage": str(e),
                    "host": host,
                },
            )

        body = plan.model_dump()
        body["status"] = "READY"
        ataques = _ataques_formateados_from_raw(raw_full, host)
        body["ataques_formateados"] = ataques
        body["ataquesFormateados"] = ataques
        info_cert = _extraer_info_certificado(raw_full)
        protos = _extraer_protocolos(raw_full)
        body["info_certificado"] = info_cert
        body["soporte_protocolos"] = protos
        cabeceras = await _analizar_cabeceras_seguridad(host)
        body["cabeceras_seguridad"] = cabeceras
        servidor_detectado = cabeceras.get("servidor", "desconocido")
        body["remediacion_activa"] = generar_snippets_remediacion(cabeceras, servidor_detectado)
        endpoints_merged = _endpoints_con_ataques(raw_full, ataques)
        if endpoints_merged is not None:
            body["endpoints"] = endpoints_merged

        try:
            grado_detectado = "N/A"
            if endpoints_merged and len(endpoints_merged) > 0:
                grado_detectado = endpoints_merged[0].get("grade", "N/A")

            nuevo_historial = ScanHistory(
                dominio=host,
                grado=grado_detectado,
                resultado_json=json.dumps(body),
            )
            db.add(nuevo_historial)
            db.commit()
            logger.info("Historial guardado en BD para %s con grado %s", host, grado_detectado)
        except Exception as e:
            logger.error("Error al guardar historial en BD: %s", e)
            db.rollback()

        await audit_session.clear_session(host)
        return JSONResponse(status_code=200, content=body)

    unk_body = {
        "status": "IN_PROGRESS",
        "statusMessage": f"Estado SSL Labs no reconocido: {raw.get('status')!r}",
        "host": host,
    }
    return await _finalize_progress_response(host, unk_body, raw, had_transient_error=False)


@app.get("/api/v1/history")
def get_scan_history(db: Session = Depends(get_db)):
    """
    Lista el último escaneo guardado por cada dominio.

    Ordenado por ``fecha_escaneo`` descendente. No incluye el JSON completo
    (usar ``GET /api/v1/history/{scan_id}``).
    """
    try:
        subquery = db.query(func.max(ScanHistory.id)).group_by(ScanHistory.dominio)

        historial = (
            db.query(
                ScanHistory.id,
                ScanHistory.dominio,
                ScanHistory.grado,
                ScanHistory.fecha_escaneo,
            )
            .filter(ScanHistory.id.in_(subquery))
            .order_by(ScanHistory.fecha_escaneo.desc())
            .all()
        )

        resultados = [
            {
                "id": h.id,
                "dominio": h.dominio,
                "grado": h.grado,
                "fecha": h.fecha_escaneo.isoformat(),
            }
            for h in historial
        ]
        return JSONResponse(status_code=200, content=resultados)
    except Exception as e:
        logger.error(f"Error leyendo historial: {e}")
        return JSONResponse(status_code=500, content={"error": "Error interno al leer historial"})


@app.get("/api/v1/history/{scan_id}")
def get_scan_details(scan_id: int, db: Session = Depends(get_db)):
    """Devuelve el JSON completo de un escaneo específico."""
    scan = db.query(ScanHistory).filter(ScanHistory.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Escaneo no encontrado")

    try:
        data = json.loads(scan.resultado_json)
        return JSONResponse(status_code=200, content=data)
    except Exception as e:
        logger.error(f"Error parseando JSON del historial: {e}")
        raise HTTPException(status_code=500, detail="El historial guardado está corrupto") from e
