"""
Capa de persistencia: SQLite + SQLAlchemy.

Archivo generado en la raíz del proyecto: ``ssl_guard_history.db``.
Una fila en ``scan_history`` guarda el informe completo serializado en JSON.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Integer, String, Text, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

# ---------------------------------------------------------------------------
# Configuración del motor
# ---------------------------------------------------------------------------

SQLALCHEMY_DATABASE_URL = "sqlite:///./ssl_guard_history.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


# ---------------------------------------------------------------------------
# Modelos ORM
# ---------------------------------------------------------------------------


class ScanHistory(Base):
    """
    Historial de auditorías completadas (estado READY).

    Attributes
    ----------
    id
        Clave primaria autoincremental.
    dominio
        Host analizado (indexado; puede repetirse en varios escaneos).
    grado
        Nota SSL Labs del primer endpoint (p. ej. ``A+``, ``T``).
    fecha_escaneo
        Marca temporal UTC del guardado.
    resultado_json
        Informe completo serializado (plan, cabeceras, remediación, etc.).
    """

    __tablename__ = "scan_history"

    id = Column(Integer, primary_key=True, index=True)
    dominio = Column(String, index=True)
    grado = Column(String)
    fecha_escaneo = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    resultado_json = Column(Text)


Base.metadata.create_all(bind=engine)


# ---------------------------------------------------------------------------
# Dependencias FastAPI
# ---------------------------------------------------------------------------


def get_db():
    """
    Generador de sesión SQLAlchemy para inyección con ``Depends(get_db)``.

    Yields
    ------
    sqlalchemy.orm.Session
        Sesión abierta; se cierra al finalizar la petición.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
