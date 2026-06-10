"""
Normalización de respuestas crudas de SSL Labs API v3 a un esquema estable.

SSL Labs documenta tiempos (``startTime``, ``testTime``, ``notBefore``, ``notAfter``)
en milisegundos Unix UTC. Las vulnerabilidades booleanas en ``details`` reflejan
resultados de probes concretos (p. ej. ``poodle`` = SSLv3 POODLE, distinto de
``poodleTls`` que codifica variantes TLS en entero).

Punto de entrada: :func:`parse_ssl_results`.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Excepciones y modelos
# ---------------------------------------------------------------------------


class SSLReportParseError(ValueError):
    """Payload incompleto: sin endpoints, sin ``details``, certificado o campos mínimos."""


class CleanedReport(BaseModel):
    """Vista reducida y tipada de un análisis READY (primer endpoint + certificado hoja)."""

    host: str = Field(..., description="Hostname analizado (campo raíz del JSON).")
    grade: str = Field(..., description="Nota del primer endpoint; vacío si la API no la envía.")
    ip: str | None = Field(
        default=None,
        description="IP del primer endpoint (ipAddress en SSL Labs).",
    )
    issuer: str | None = Field(
        default=None,
        description="Emisor del certificado (p. ej. issuerLabel o issuerSubject).",
    )
    not_after: int | float | None = Field(
        default=None,
        description="notAfter del certificado hoja en milisegundos Unix UTC (SSL Labs).",
    )
    protocols: list[str] = Field(
        ...,
        description="Protocolos negociados reportados, p. ej. 'TLS 1.2'.",
    )
    vulnerabilities: dict[str, bool] = Field(
        ...,
        description="heartbleed, poodle, freak, logjam — True si el servidor es vulnerable.",
    )
    cert_expiration: datetime = Field(
        ...,
        description="notAfter del certificado de servidor (hoja), en UTC.",
    )
    suites: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Suites de cifrado negociadas (entradas de details.suites[*].list).",
    )
    details: dict[str, Any] = Field(
        default_factory=dict,
        description="Bloque details completo del primer endpoint de SSL Labs.",
    )

    @field_validator("cert_expiration")
    @classmethod
    def _normalize_cert_expiration_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)


# ---------------------------------------------------------------------------
# Mapeo de campos Qualys
# ---------------------------------------------------------------------------


def _ms_epoch_to_utc_datetime(ms: int | float) -> datetime:
    """Convierte milisegundos desde epoch (SSL Labs) a datetime consciente de zona UTC."""
    return datetime.fromtimestamp(ms / 1000.0, tz=UTC)


def _map_protocols(details: dict[str, Any]) -> list[str]:
    raw = details.get("protocols")
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise SSLReportParseError("El campo details.protocols no es una lista.")
    out: list[str] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        version = item.get("version")
        if name is not None and version is not None:
            out.append(f"{name} {version}".strip())
        elif name is not None:
            out.append(str(name))
    return out


def _map_vulnerabilities(details: dict[str, Any]) -> dict[str, bool]:
    """
    Expone solo las cuatro pruebas pedidas. Valores ausentes se interpretan como False
    (no vulnerable / no reportado como tal por la API en este payload).
    """
    keys = ("heartbleed", "poodle", "freak", "logjam")
    result: dict[str, bool] = {}
    for key in keys:
        value = details.get(key)
        if value is None:
            result[key] = False
        elif isinstance(value, bool):
            result[key] = value
        else:
            raise SSLReportParseError(
                f"Tipo inválido para details.{key!r}: se esperaba bool, se obtuvo {type(value).__name__}."
            )
    return result


def _map_cipher_suites(details: dict[str, Any]) -> list[dict[str, Any]]:
    """
    SSL Labs expone ``details.suites`` como lista de bloques por protocolo, cada uno con
    ``list`` de suites; en otros casos puede ser un objeto con clave ``list``.
    """
    raw = details.get("suites")
    if raw is None:
        return []
    out: list[dict[str, Any]] = []
    if isinstance(raw, list):
        for block in raw:
            if not isinstance(block, dict):
                continue
            inner = block.get("list")
            if isinstance(inner, list):
                for item in inner:
                    if isinstance(item, dict):
                        out.append(item)
    elif isinstance(raw, dict):
        inner = raw.get("list")
        if isinstance(inner, list):
            for item in inner:
                if isinstance(item, dict):
                    out.append(item)
    return out


def _leaf_issuer_and_not_after_ms(
    raw_data: dict[str, Any],
) -> tuple[str | None, int | float | None]:
    """Emisor y notAfter (ms) del certificado hoja desde ``certs`` en la raíz."""
    certs = raw_data.get("certs")
    if not isinstance(certs, list) or not certs:
        return None, None
    leaf = certs[0]
    if not isinstance(leaf, dict):
        return None, None
    issuer = leaf.get("issuerLabel")
    if not isinstance(issuer, str) or not issuer.strip():
        subj = leaf.get("issuerSubject")
        issuer = subj.strip() if isinstance(subj, str) and subj.strip() else None
    not_after = leaf.get("notAfter")
    if not isinstance(not_after, (int, float)):
        not_after = None
    return issuer, not_after


def _leaf_cert_not_after(raw_data: dict[str, Any]) -> datetime:
    certs = raw_data.get("certs")
    if not isinstance(certs, list) or not certs:
        raise SSLReportParseError("No hay entradas en certs para obtener notAfter.")
    leaf = certs[0]
    if not isinstance(leaf, dict):
        raise SSLReportParseError("El primer certificado no es un objeto JSON.")
    not_after = leaf.get("notAfter")
    if not_after is None:
        raise SSLReportParseError("El certificado hoja no incluye notAfter.")
    if not isinstance(not_after, (int, float)):
        raise SSLReportParseError("notAfter debe ser un número (ms desde epoch).")
    return _ms_epoch_to_utc_datetime(not_after)


# ---------------------------------------------------------------------------
# API pública
# ---------------------------------------------------------------------------


def parse_ssl_results(raw_data: dict[str, Any]) -> CleanedReport:
    """
    Transforma el dict devuelto por ``/api/v3/analyze`` (idealmente status READY con all=done)
    en :class:`CleanedReport` usando el **primer endpoint** y el **primer certificado** en
    ``certs`` (certificado del servidor en respuestas típicas de SSL Labs).
    """
    if not isinstance(raw_data, dict):
        raise TypeError("raw_data debe ser un dict.")

    host = raw_data.get("host")
    if not host or not isinstance(host, str):
        raise SSLReportParseError("Falta host válido en la raíz del JSON.")

    endpoints = raw_data.get("endpoints")
    if not isinstance(endpoints, list) or len(endpoints) == 0:
        raise SSLReportParseError("No hay endpoints: el análisis puede estar en curso o el JSON es incompleto.")

    first = endpoints[0]
    if not isinstance(first, dict):
        raise SSLReportParseError("El primer endpoint no es un objeto JSON.")

    details = first.get("details")
    if not isinstance(details, dict):
        raise SSLReportParseError(
            "El primer endpoint no contiene details (se requiere all=done / análisis completado)."
        )

    grade_val = first.get("grade")
    grade = grade_val if isinstance(grade_val, str) else ""

    ip_val = first.get("ipAddress")
    ip = ip_val.strip() if isinstance(ip_val, str) and ip_val.strip() else None

    cert_raw = details.get("cert")
    cert = cert_raw if isinstance(cert_raw, dict) else {}

    leaf_issuer, leaf_not_after_ms = _leaf_issuer_and_not_after_ms(raw_data)

    not_after_ms = cert.get("notAfter")
    if not isinstance(not_after_ms, (int, float)):
        not_after_ms = leaf_not_after_ms

    issuer_val = cert.get("issuerLabel") or cert.get("issuerSubject")
    if isinstance(issuer_val, str) and issuer_val.strip():
        issuer: str | None = issuer_val.strip()
    else:
        issuer = leaf_issuer

    if isinstance(not_after_ms, (int, float)):
        cert_expiration = _ms_epoch_to_utc_datetime(not_after_ms)
    else:
        cert_expiration = _leaf_cert_not_after(raw_data)
        _, resolved_ms = _leaf_issuer_and_not_after_ms(raw_data)
        if isinstance(resolved_ms, (int, float)):
            not_after_ms = resolved_ms

    protocols = _map_protocols(details)
    vulnerabilities = _map_vulnerabilities(details)
    suites = _map_cipher_suites(details)

    return CleanedReport(
        host=host.strip(),
        grade=grade,
        ip=ip,
        issuer=issuer,
        not_after=not_after_ms,
        protocols=protocols,
        vulnerabilities=vulnerabilities,
        cert_expiration=cert_expiration,
        suites=suites,
        details=details,
    )
