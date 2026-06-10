"""
Cliente asíncrono para la API pública SSL Labs v3 (Qualys).

Expone validación de dominio, consultas puntuales (``fetch_analyze_snapshot``) y
utilidades de consola (``analyze_domain``, ``poll_status``) con manejo de
rate limits según la documentación oficial.
"""

from __future__ import annotations

import asyncio
import random
from typing import Any
from urllib.parse import urlparse

import httpx
from pydantic import BaseModel, Field, field_validator

# ---------------------------------------------------------------------------
# Constantes y endpoints
# ---------------------------------------------------------------------------

SSL_LABS_BASE = "https://api.ssllabs.com/api/v3/"
ANALYZE_ENDPOINT = f"{SSL_LABS_BASE}analyze"

POLL_INTERVAL_DNS = 5.0
POLL_INTERVAL_IN_PROGRESS = 10.0

_MAX_SNAPSHOT_TRANSPORT_ROUNDS = 8
"""Reintentos máximos por petición HTTP del endpoint de auditoría (Angular hace polling)."""


# ---------------------------------------------------------------------------
# Modelos y excepciones
# ---------------------------------------------------------------------------


class DomainRequest(BaseModel):
    """Entrada validada: hostname normalizado (sin esquema, ruta ni puerto)."""

    host: str = Field(..., min_length=1, max_length=253)

    @field_validator("host")
    @classmethod
    def strip_and_nonempty(cls, value: str) -> str:
        raw = value.strip()
        if not raw:
            raise ValueError("El host no puede estar vacío.")
        normalized = _normalize_host_input(raw)
        if not normalized:
            raise ValueError("Host inválido. Use solo dominio o una URL válida.")
        return normalized


class SSLLabsAPIError(RuntimeError):
    """La API devolvió el campo ``errors`` en el JSON de respuesta."""

    def __init__(self, errors: list[dict[str, Any]]) -> None:
        self.errors = errors
        super().__init__(errors)


class SnapshotRateLimitExceeded(RuntimeError):
    """
    Demasiados 429/503/529 en una sola petición snapshot.

    El API de SSL-Guard debe responder ``IN_PROGRESS`` para que el front reintente.
    """

    def __init__(
        self,
        message: str = "Cuota temporal de SSL Labs agotada en esta petición.",
    ) -> None:
        super().__init__(message)


# ---------------------------------------------------------------------------
# Normalización de host
# ---------------------------------------------------------------------------


def _normalize_host_input(raw: str) -> str:
    """
    Acepta host o URL pegada por el usuario y devuelve solo el hostname.

    - Quita esquema (http/https), ruta, query y fragmento.
    - Quita puerto (ej. ``example.com:443``).
    - Quita corchetes IPv6 (``[::1]``) si aparecen.
    """
    s = raw.strip()
    if not s:
        return ""

    parsed = urlparse(s)
    host = parsed.hostname

    if host is None and ("/" in s or "?" in s or "#" in s):
        parsed2 = urlparse("//" + s)
        host = parsed2.hostname

    if host is None:
        candidate = s
        if candidate.startswith("[") and "]" in candidate:
            candidate = candidate[1 : candidate.index("]")]
        if ":" in candidate:
            left, right = candidate.rsplit(":", 1)
            if right.isdigit():
                candidate = left
        host = candidate

    host = (host or "").strip().lower().rstrip(".")
    if not host:
        return ""
    if any(ch.isspace() for ch in host) or "/" in host:
        return ""
    return host


# ---------------------------------------------------------------------------
# Cliente HTTP interno
# ---------------------------------------------------------------------------


async def _sleep_jitter(low: float, high: float) -> None:
    """Pausa aleatoria entre ``low`` y ``high`` segundos (evitar thundering herd)."""
    await asyncio.sleep(random.uniform(low, high))


async def _get_analyze(
    client: httpx.AsyncClient,
    host: str,
    start_new: bool,
    all_done: bool = False,
) -> dict[str, Any]:
    """
    GET ``/analyze`` con reintentos indefinidos ante rate limits (modo consola).

    Parameters
    ----------
    all_done
        Si es ``True``, añade ``all=done`` para obtener ``details`` al estar READY.
    """
    params: dict[str, str] = {"host": host, "publish": "off"}

    if start_new:
        params["startNew"] = "on"
        params["ignoreMismatch"] = "on"
    if all_done:
        params["all"] = "done"

    while True:
        response = await client.get(ANALYZE_ENDPOINT, params=params)

        if response.status_code == 429:
            await _sleep_jitter(15.0, 45.0)
            continue
        if response.status_code == 503:
            await _sleep_jitter(14 * 60.0, 16 * 60.0)
            continue
        if response.status_code == 529:
            await _sleep_jitter(28 * 60.0, 32 * 60.0)
            continue

        response.raise_for_status()
        data = response.json()

        errors = data.get("errors")
        if errors:
            raise SSLLabsAPIError(errors if isinstance(errors, list) else [errors])

        return data


# ---------------------------------------------------------------------------
# API pública
# ---------------------------------------------------------------------------


async def fetch_analyze_snapshot(
    host: str,
    *,
    start_new: bool = False,
    all_done: bool = False,
) -> dict[str, Any]:
    """
    Una consulta coherente a ``/analyze`` (sin bucle hasta READY).

    Reintenta ante 429/503/529 un número acotado de veces; si se agota, lanza
    :class:`SnapshotRateLimitExceeded` para que el API devuelva ``IN_PROGRESS``.
    """
    validated = DomainRequest(host=host)
    params: dict[str, str] = {"host": validated.host, "publish": "off"}
    if start_new:
        params["startNew"] = "on"
        params["ignoreMismatch"] = "on"
    if all_done:
        params["all"] = "done"

    timeout = httpx.Timeout(90.0, connect=25.0)
    transport_rounds = 0
    async with httpx.AsyncClient(timeout=timeout) as client:
        while True:
            response = await client.get(ANALYZE_ENDPOINT, params=params)

            if response.status_code == 429:
                transport_rounds += 1
                if transport_rounds > _MAX_SNAPSHOT_TRANSPORT_ROUNDS:
                    raise SnapshotRateLimitExceeded()
                await _sleep_jitter(3.0, 10.0)
                continue
            if response.status_code in (503, 529):
                transport_rounds += 1
                if transport_rounds > _MAX_SNAPSHOT_TRANSPORT_ROUNDS:
                    raise SnapshotRateLimitExceeded(
                        "SSL Labs devolvió 503/529 repetidamente; reintente en unos minutos."
                    )
                await _sleep_jitter(5.0, 15.0)
                continue

            response.raise_for_status()
            data = response.json()
            errors = data.get("errors")
            if errors:
                raise SSLLabsAPIError(errors if isinstance(errors, list) else [errors])
            return data


async def analyze_domain(host: str, start_new: bool = False) -> dict[str, Any]:
    """
    Inicia o consulta un análisis (una petición; puede devolver estado intermedio).

    Con ``start_new=False`` aprovecha la caché de SSL Labs cuando existe.
    """
    validated = DomainRequest(host=host)
    timeout = httpx.Timeout(120.0, connect=30.0)
    async with httpx.AsyncClient(timeout=timeout) as client:
        return await _get_analyze(client, validated.host, start_new=start_new)


async def poll_status(host: str, verbose: bool = True) -> dict[str, Any]:
    """
    Bucle de espera hasta ``status == READY`` (uso en consola o tests).

    Respeta intervalos recomendados por SSL Labs (DNS vs IN_PROGRESS).
    """
    validated = DomainRequest(host=host)
    timeout = httpx.Timeout(120.0, connect=30.0)

    async with httpx.AsyncClient(timeout=timeout) as client:
        while True:
            payload = await _get_analyze(
                client, validated.host, start_new=False, all_done=True
            )
            status = payload.get("status", "").upper()

            if status == "READY":
                if verbose:
                    print(f"\n[+] Análisis completado para {host}")
                return payload

            if status == "ERROR":
                message = payload.get("statusMessage", "Error desconocido")
                raise RuntimeError(f"API Error: {message}")

            if verbose and status in ("DNS", "IN_PROGRESS"):
                endpoints = payload.get("endpoints", [])
                if endpoints:
                    ep = endpoints[0]
                    progress = ep.get("progress", 0)
                    msg = ep.get("statusDetailsMessage", "Procesando...")
                    if progress >= 0:
                        print(
                            f"[*] Analizando {host}... [{progress}%] - {msg}",
                            end="\r",
                        )
                else:
                    print(f"[*] Resolviendo DNS para {host}...", end="\r")

            delay = POLL_INTERVAL_DNS if status == "DNS" else POLL_INTERVAL_IN_PROGRESS
            await asyncio.sleep(delay)
