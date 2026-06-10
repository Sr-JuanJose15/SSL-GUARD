"""
Paquete principal de SSL-Guard (backend FastAPI).

Módulos
-------
main
    Punto de entrada HTTP: auditoría, historial y orquestación.
scanner
    Cliente asíncrono hacia SSL Labs API v3.
parser
    Normalización del JSON de Qualys a :class:`~app.parser.CleanedReport`.
engine
    Motor de recomendaciones de seguridad (:class:`~app.engine.SecurityPlan`).
audit_session
    Estado en memoria de auditorías en curso (polling desde el front).
database
    Persistencia SQLite del historial de escaneos.
remediacion
    Snippets de configuración sugeridos (HSTS, CSP).
hostname_vuln_extension
    Refuerzo opcional de flags de vulnerabilidad por nombre de host (QA).
"""

__all__ = [
    "audit_session",
    "database",
    "engine",
    "hostname_vuln_extension",
    "main",
    "parser",
    "remediacion",
    "scanner",
]
