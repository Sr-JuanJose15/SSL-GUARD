# SSL-Guard 🛡️
### Plataforma de Auditoría SSL/TLS y Motor de Remediación Activa

**SSL-Guard** es una herramienta full-stack de ciberseguridad diseñada para la auditoría avanzada de la capa de transporte (SSL/TLS) y la evaluación de políticas de seguridad perimetral en la capa de aplicación (cabeceras HTTP). 

A diferencia de los escáneres convencionales que solo diagnostican, **SSL-Guard** procesa datos criptográficos complejos para actuar como un motor de remediación activa, identificando la infraestructura del servidor (Nginx/Apache) e inyectando dinámicamente bloques de código listos para su mitigación directa, facilitando el camino hacia la máxima calificación de seguridad (**A+**).

---

## 🚀 Características Principales

* **Auditoría Integral SSL/TLS:** Análisis profundo de suites de cifrado (*Cipher Suites*), protocolos soportados (TLS 1.0 a 1.3), vulnerabilidades históricas (Heartbleed, POODLE, DROWN, etc.) y validación estricta de cadenas de certificados digitales.
* **Seguridad Perimetral HTTP:** Inspección automática de cabeceras esenciales de protección contra ataques *Man-in-the-Middle* (MitM), Clickjacking y XSS (`Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`).
* **Motor de Remediación Inteligente:** Generación automática y contextualizada de *snippets* de configuración para servidores web basados en **Nginx** y **Apache** según las brechas detectadas.
* **Arquitectura Resiliente (Amortiguador API):** Backend asíncrono con tolerancia a fallos que gestiona colas de peticiones mediante un flujo de *polling* inteligente, mitigando errores de red (500) y bloqueos por límite de tasa (*Rate Limiting* / Error 429) de la API pública de Qualys SSL Labs.
* **Persistencia y Caché Híbrida:** Almacenamiento local estructurado en base de datos que evita peticiones redundantes a la red, optimiza los tiempos de respuesta y consolida un historial depurado (filtrado inteligente por el escaneo más reciente por dominio).
* **Dashboard Analítico e Informes:** Panel interactivo visual (gráfico de dona con Chart.js) para la distribución de estados de seguridad y un módulo configurador para la exportación de reportes ejecutivos y técnicos auditable en formato **PDF**.

---

## 📐 Arquitectura del Sistema

El siguiente diagrama describe el flujo de comunicación desacoplado entre el cliente, los módulos lógicos del backend, la persistencia y los servicios externos (se renderiza automáticamente en GitHub):

```mermaid
flowchart TB
  subgraph Cliente
    FE[Frontend Angular / Ionic]
  end

  subgraph API["FastAPI app/main.py"]
    CORS[CORSMiddleware]
    R1["GET /api/v1/audit"]
    R2["POST /api/v1/audit/cancel"]
    R3["GET /api/v1/history"]
    R4["GET /api/v1/history/{scan_id}"]
  end

  subgraph Dominio["Lógica de aplicación"]
    AS[audit_session.py - Sesión en memoria]
    SC[scanner.py - Cliente httpx API]
    PR[parser.py - Limpieza JSON Qualys]
    EN[engine.py - RecommendationEngine]
    HV[hostname_vuln_extension.py - QA Host]
    RM[remediacion.py - Snippets HSTS/CSP]
    HELP[Helpers - Gestión de Progreso y Errores]
  end

  subgraph Externo
    SSL[api.ssllabs.com v3]
    SITE["https://{host} - Cabeceras HTTP"]
  end

  subgraph Datos
    DB[(SQLite ssl_guard_history.db)]
    ORM[database.py - SQLAlchemy ORM]
  end

  FE --> CORS
  CORS --> R1 & R2 & R3 & R4
  R1 --> AS
  R1 --> SC
  R2 --> AS
  SC --> SSL
  R1 --> PR
  PR --> EN
  EN --> HV
  R1 --> HELP
  HELP --> SITE
  R1 --> RM
  R3 & R4 --> ORM
  R1 --> ORM
  ORM --> DB
