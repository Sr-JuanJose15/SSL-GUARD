"""
Generación de snippets de remediación según cabeceras HTTP detectadas.

A partir del servidor declarado (``Server``) y de la ausencia de HSTS o CSP,
propone fragmentos de configuración para nginx, Apache o cabeceras genéricas.
"""

from __future__ import annotations

from typing import Any


def generar_snippets_remediacion(cabeceras: dict[str, Any], servidor_raw: str) -> list[dict[str, Any]]:
    """
    Construye sugerencias de configuración para endurecer la capa HTTP.

    Parameters
    ----------
    cabeceras
        Resultado de :func:`app.main._analizar_cabeceras_seguridad` (claves
        ``hsts``, ``csp``, ``servidor``, etc.). Si incluye ``error``, devuelve
        lista vacía.
    servidor_raw
        Valor de la cabecera ``Server`` o cadena vacía.

    Returns
    -------
    list[dict]
        Cada entrada tiene ``titulo``, ``descripcion``, ``codigo`` y ``archivo``.
    """
    snippets: list[dict[str, Any]] = []

    if not isinstance(cabeceras, dict) or cabeceras.get("error"):
        return snippets

    srv = servidor_raw.lower() if servidor_raw else "desconocido"
    es_nginx = "nginx" in srv
    es_apache = "apache" in srv

    if cabeceras and not cabeceras.get("hsts"):
        if es_nginx:
            codigo = (
                'add_header Strict-Transport-Security '
                '"max-age=31536000; includeSubDomains" always;'
            )
            archivo = "nginx.conf (bloque server)"
        elif es_apache:
            codigo = (
                'Header always set Strict-Transport-Security '
                '"max-age=31536000; includeSubDomains"'
            )
            archivo = ".htaccess o httpd.conf"
        else:
            codigo = "Strict-Transport-Security: max-age=31536000; includeSubDomains"
            archivo = "Cabecera HTTP genérica"

        snippets.append(
            {
                "titulo": "Activar HSTS (Strict-Transport-Security)",
                "descripcion": "Fuerza a los navegadores a usar solo conexiones HTTPS seguras.",
                "codigo": codigo,
                "archivo": archivo,
            }
        )

    if cabeceras and not cabeceras.get("csp"):
        if es_nginx:
            codigo = 'add_header Content-Security-Policy "default-src \'self\';" always;'
            archivo = "nginx.conf"
        elif es_apache:
            codigo = 'Header set Content-Security-Policy "default-src \'self\';"'
            archivo = ".htaccess"
        else:
            codigo = "Content-Security-Policy: default-src 'self';"
            archivo = "Cabecera HTTP genérica"

        snippets.append(
            {
                "titulo": "Configurar CSP básico",
                "descripcion": "Previene ataques de Cross-Site Scripting (XSS).",
                "codigo": codigo,
                "archivo": archivo,
            }
        )

    return snippets
