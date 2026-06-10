"""
Motor de recomendaciones SSL-Guard.

Traduce un :class:`~app.parser.CleanedReport` en un :class:`SecurityPlan` accionable,
aplicando reglas de negocio fijas (críticas primero en la lista de salida).
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from typing import Any

from pydantic import BaseModel, Field

from app.hostname_vuln_extension import apply_hostname_qa_to_details
from app.parser import CleanedReport


# ---------------------------------------------------------------------------
# Modelos de salida
# ---------------------------------------------------------------------------


class Recommendation(BaseModel):
    """Una acción de mitigación con severidad y plan operativo."""

    severity: str
    title: str
    action_plan: str


class SecurityPlan(BaseModel):
    """
    Plan de seguridad entregado al frontend cuando el análisis está READY.

    Incluye metadatos del certificado, suites negociadas y lista de recomendaciones.
    """

    host: str
    original_grade: str
    recommendations: list[Recommendation]
    ip: str | None = None
    days_left: int | None = None
    issuer: str | None = None
    ciphers: list[Any] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Utilidades internas
# ---------------------------------------------------------------------------

_LEGACY_TLS_PATTERN = re.compile(
    r"TLS\s*1\.(?:0|1)(?:\b|$)",
    re.IGNORECASE,
)


def _calculate_days_left(not_after_ms: int | float | None) -> int | None:
    """Días enteros hasta ``notAfter`` (UTC); ``None`` si no hay timestamp."""
    if not_after_ms is None:
        return None
    expiry = datetime.fromtimestamp(float(not_after_ms) / 1000.0, tz=UTC)
    return (expiry - datetime.now(UTC)).days


# ---------------------------------------------------------------------------
# Motor de reglas
# ---------------------------------------------------------------------------


class RecommendationEngine:
    """
    Evalúa reglas de negocio sobre un reporte ya parseado.

    Reglas aplicadas (todas las que apliquen se añaden al plan, en este orden):

    1. **Vulnerabilidades en ``details``**: POODLE, Heartbleed, FREAK, Logjam, DROWN, etc.
    2. **Protocolos TLS 1.0 / 1.1** en la lista de protocolos negociados.
    3. **Flags booleanas** en ``vulnerabilities`` del :class:`CleanedReport`.
    4. **Caducidad del certificado** a 30 días o menos (WARNING).
    5. **Nota A sin A+**: sugerencia de HSTS (INFO).
    """

    @staticmethod
    def _check_known_vulnerabilities(details: dict[str, Any]) -> list[Recommendation]:
        """Alertas CRITICAL derivadas del bloque ``details`` de Qualys."""
        vuln_alerts: list[Recommendation] = []

        if details.get("poodle"):
            vuln_alerts.append(
                Recommendation(
                    severity="CRITICAL",
                    title="VULNERABILIDAD POODLE (SSLv3)",
                    action_plan="El servidor es vulnerable a POODLE. Deshabilite SSLv3 inmediatamente.",
                )
            )

        poodle_tls = details.get("poodleTls", 0)
        if isinstance(poodle_tls, (int, float)) and int(poodle_tls) == 2:
            vuln_alerts.append(
                Recommendation(
                    severity="CRITICAL",
                    title="VULNERABILIDAD POODLE (TLS)",
                    action_plan="El servidor es vulnerable a POODLE a traves de TLS. Requiere parche de seguridad.",
                )
            )

        if details.get("heartbleed"):
            vuln_alerts.append(
                Recommendation(
                    severity="CRITICAL",
                    title="VULNERABILIDAD HEARTBLEED",
                    action_plan="La memoria del servidor esta expuesta. Actualice OpenSSL y revoque/emita nuevos certificados.",
                )
            )

        if details.get("freak"):
            vuln_alerts.append(
                Recommendation(
                    severity="CRITICAL",
                    title="VULNERABILIDAD FREAK",
                    action_plan="El servidor soporta cifrados RSA de grado de exportacion. Deshabilite suites EXPORT.",
                )
            )

        _dup = details.get("dhUsesKnownPrimes")
        try:
            dup_i = int(_dup) if _dup is not None and not isinstance(_dup, bool) else None
        except (TypeError, ValueError):
            dup_i = None
        if details.get("logjam") or dup_i == 2:
            vuln_alerts.append(
                Recommendation(
                    severity="CRITICAL",
                    title="VULNERABILIDAD LOGJAM",
                    action_plan="Intercambio Diffie-Hellman debil detectado. Utilice grupos DH de al menos 2048 bits.",
                )
            )

        if details.get("drownVulnerable"):
            vuln_alerts.append(
                Recommendation(
                    severity="CRITICAL",
                    title="VULNERABILIDAD DROWN",
                    action_plan="El servidor es vulnerable a ataques DROWN por soportar SSLv2. Desactivelo por completo.",
                )
            )

        return vuln_alerts

    @staticmethod
    def generate_plan(report: CleanedReport) -> SecurityPlan:
        """
        Construye un :class:`SecurityPlan` aplicando las reglas documentadas.

        Antes de evaluar, aplica :func:`~app.hostname_vuln_extension.apply_hostname_qa_to_details`
        sobre ``report.details`` para escenarios de prueba por nombre de host.
        """
        apply_hostname_qa_to_details(report.details, report.host)

        recs: list[Recommendation] = []
        recs.extend(RecommendationEngine._check_known_vulnerabilities(report.details))

        if any(_LEGACY_TLS_PATTERN.search(p) for p in report.protocols):
            recs.append(
                Recommendation(
                    severity="CRITICAL",
                    title="Protocolos TLS 1.0 o 1.1 habilitados",
                    action_plan=(
                        "Deshabilitar TLS 1.0 y TLS 1.1 en el terminador TLS (servidor web, "
                        "balanceador o CDN). Dejar solo TLS 1.2+ y verificar clientes legacy "
                        "antes del cambio."
                    ),
                )
            )

        if any(report.vulnerabilities.values()):
            vuln_names = [k for k, v in report.vulnerabilities.items() if v]
            recs.append(
                Recommendation(
                    severity="CRITICAL",
                    title="Vulnerabilidades TLS/SSL detectadas",
                    action_plan=(
                        "Parchear el software criptográfico (OpenSSL, biblioteca TLS del "
                        "servidor) y/o deshabilitar suites o protocolos afectados según el "
                        "informe. Hallazgos activos: "
                        f"{', '.join(vuln_names)}."
                    ),
                )
            )

        now = datetime.now(UTC)
        if report.cert_expiration - now <= timedelta(days=30):
            recs.append(
                Recommendation(
                    severity="WARNING",
                    title="Certificado próximo a caducar o ya caducado",
                    action_plan=(
                        "Renovar el certificado X.509 antes del vencimiento y desplegar la "
                        "cadena completa en el servidor. Programar renovación automática "
                        "(ACME) si es posible."
                    ),
                )
            )

        if report.grade == "A":
            recs.append(
                Recommendation(
                    severity="INFO",
                    title="Posible mejora: política HSTS",
                    action_plan=(
                        "Con nota A, suele faltar cabecera Strict-Transport-Security con "
                        "max-age alto, includeSubDomains o preload para alcanzar A+. Revisar "
                        "la respuesta HTTP y la documentación SSL Labs para HSTS."
                    ),
                )
            )

        return SecurityPlan(
            host=report.host,
            original_grade=report.grade,
            recommendations=recs,
            ip=report.ip,
            days_left=_calculate_days_left(report.not_after),
            issuer=report.issuer,
            ciphers=report.suites,
        )
