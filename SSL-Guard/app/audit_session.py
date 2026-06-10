"""
Estado de sesión de auditoría por host (memoria, un solo worker).

Contrato con el frontend (Angular)
------------------------------------
- ``GET /api/v1/audit`` puede incluir ``suggestedPollSeconds`` (5 por defecto si
  el back no lo envía) y ``auditSessionStarted`` (epoch Unix).
- ``POST /api/v1/audit/cancel?domain=...`` marca la sesión cancelada; los GET
  siguientes devuelven ``CANCELLED`` hasta un nuevo análisis con ``startNew=true``.

Limitaciones
------------
No comparte estado entre workers de Uvicorn ni sobrevive al reinicio del proceso.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Umbrales de timeout y backoff
# ---------------------------------------------------------------------------

STALL_SECONDS = 900
"""Sin avance de progreso Qualys durante 15 minutos → TIMEOUT."""

MAX_TOTAL_SECONDS = 1800
"""Duración máxima de una sesión (30 minutos) → TIMEOUT."""

MAX_CONSECUTIVE_TRANSIENT = 20
"""Errores transitorios seguidos antes de abandonar la sesión."""

_LOCK = asyncio.Lock()
_sessions: dict[str, "_Session"] = {}


# ---------------------------------------------------------------------------
# Modelo interno
# ---------------------------------------------------------------------------


@dataclass
class _Session:
    """Estado mutable asociado a un hostname en curso de auditoría."""

    started_mono: float
    started_epoch: float
    last_progress: int | None = None
    last_progress_mono: float | None = None
    consecutive_transient_errors: int = 0
    cancelled: bool = False


def _get_or_create_unlocked(host: str) -> _Session:
    """Crea o devuelve la sesión del host. Debe llamarse bajo ``_LOCK``."""
    now_m = time.monotonic()
    now_e = time.time()
    if host not in _sessions:
        _sessions[host] = _Session(started_mono=now_m, started_epoch=now_e)
    return _sessions[host]


# ---------------------------------------------------------------------------
# API pública (async)
# ---------------------------------------------------------------------------


async def reset_on_new_scan(host: str) -> None:
    """Reinicia la sesión (p. ej. ``startNew=true``): limpia cancelación y contadores."""
    async with _LOCK:
        now_m = time.monotonic()
        now_e = time.time()
        _sessions[host] = _Session(started_mono=now_m, started_epoch=now_e)


async def touch_session_if_new(host: str) -> None:
    """Primera petición sin ``startNew``: crea sesión si aún no existe."""
    async with _LOCK:
        _get_or_create_unlocked(host)


async def mark_cancelled(host: str) -> None:
    """Marca el host como cancelado por el usuario."""
    async with _LOCK:
        s = _get_or_create_unlocked(host)
        s.cancelled = True


async def is_cancelled(host: str) -> bool:
    """Indica si el análisis de este host fue cancelado."""
    async with _LOCK:
        s = _sessions.get(host)
        return bool(s and s.cancelled)


async def clear_session(host: str) -> None:
    """Elimina la sesión en memoria (fin de auditoría, error fatal o timeout)."""
    async with _LOCK:
        _sessions.pop(host, None)


async def should_timeout(host: str) -> tuple[bool, str]:
    """
    Evalúa si la sesión debe cerrarse por tiempo o errores repetidos.

    Returns
    -------
    tuple[bool, str]
        ``(True, mensaje)`` si debe responder TIMEOUT; ``(False, "")`` en caso contrario.
    """
    async with _LOCK:
        s = _sessions.get(host)
        if not s or s.cancelled:
            return False, ""
        now = time.monotonic()
        if s.consecutive_transient_errors >= MAX_CONSECUTIVE_TRANSIENT:
            return (
                True,
                "Demasiados errores transitorios de SSL Labs; intente más tarde o sin modo forzado.",
            )
        if now - s.started_mono > MAX_TOTAL_SECONDS:
            return (
                True,
                "Tiempo máximo de análisis excedido (30 min); intente de nuevo más tarde.",
            )
        if (
            s.last_progress is not None
            and s.last_progress >= 0
            and s.last_progress_mono is not None
        ):
            if now - s.last_progress_mono > STALL_SECONDS:
                return (
                    True,
                    "SSL Labs no avanzó el progreso en 15 min; intente más tarde o sin modo forzado.",
                )
        return False, ""


async def record_poll(
    host: str,
    progress: int | None,
    *,
    has_transient_error: bool,
) -> None:
    """
    Actualiza contadores tras cada respuesta de progreso del cliente.

    Parameters
    ----------
    progress
        Porcentaje Qualys del primer endpoint, o ``None`` si no está disponible.
    has_transient_error
        Si hubo error transitorio (rate limit, 5xx, etc.) en esta ronda.
    """
    async with _LOCK:
        s = _get_or_create_unlocked(host)
        if has_transient_error:
            s.consecutive_transient_errors += 1
        else:
            s.consecutive_transient_errors = 0
        if progress is not None and isinstance(progress, (int, float)) and progress >= 0:
            pi = int(progress)
            if s.last_progress != pi:
                s.last_progress = pi
                s.last_progress_mono = time.monotonic()
            elif s.last_progress is None:
                s.last_progress = pi
                s.last_progress_mono = time.monotonic()


async def session_started_epoch(host: str) -> float | None:
    """Epoch Unix de inicio de sesión, o ``None`` si no hay sesión activa."""
    async with _LOCK:
        s = _sessions.get(host)
        return s.started_epoch if s else None


async def suggested_poll_seconds(host: str, status_message: str | None) -> int:
    """
    Intervalo sugerido (segundos) para el siguiente poll del frontend.

    Devuelve 60 si hay muchos errores transitorios o mensajes de saturación;
    5 en el caso habitual.
    """
    async with _LOCK:
        s = _sessions.get(host)
        consecutive = s.consecutive_transient_errors if s else 0
    msg = (status_message or "").lower()
    if consecutive >= 3:
        return 60
    if any(
        x in msg
        for x in (
            "internalservererror",
            "internal server error",
            "service unavailable",
            "temporarily unavailable",
            "try again",
            "503",
            "529",
            "429",
        )
    ):
        return 60
    return 5
