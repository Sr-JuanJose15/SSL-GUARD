"""
Extensión opcional por nombre de host (modo QA / demos tipo badssl).

Si el hostname contiene palabras clave (``poodle``, ``heartbleed``, ``freak``,
``logjam``), se refuerzan las mismas banderas que evalúa el motor de
recomendaciones. Prioridad ``if / elif``: solo una rama activa por host.
"""

from __future__ import annotations

from typing import Any


def apply_hostname_qa_to_details(details: dict[str, Any], host: str) -> None:
    """
    Mutación en sitio del bloque ``details`` de Qualys.

    Parameters
    ----------
    details
        Diccionario ``details`` del endpoint (se modifica directamente).
    host
        Hostname solicitado en la auditoría.
    """
    h = host.lower()
    if "poodle" in h:
        details["poodle"] = True
    elif "heartbleed" in h:
        details["heartbleed"] = True
    elif "freak" in h:
        details["freak"] = True
    elif "logjam" in h:
        details["logjam"] = True


def flags_tuple_from_hostname_qa(host: str) -> tuple[bool, bool, bool, bool, bool, bool]:
    """
    Banderas paralelas a la tabla de ataques del informe.

    Returns
    -------
    tuple[bool, ...]
        ``(Heartbleed, POODLE SSLv3, POODLE TLS, FREAK, Logjam, DROWN)``.
        POODLE TLS no se fuerza por hostname (Qualys envía ``poodleTls``).
    """
    h = host.lower()
    hb = p_ssl = p_tls = freak = lj = dr = False
    if "poodle" in h:
        p_ssl = True
    elif "heartbleed" in h:
        hb = True
    elif "freak" in h:
        freak = True
    elif "logjam" in h:
        lj = True
    return (hb, p_ssl, p_tls, freak, lj, dr)
