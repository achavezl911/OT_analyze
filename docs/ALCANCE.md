# Alcance del proyecto

Qué es OT_analisis, para quién, qué entra, qué sale y qué no hace. Es la referencia para decidir si una función
nueva pertenece al proyecto. Lo que está marcado **por confirmar** lo dijo o lo dedujo una sesión, no está validado
por el propietario; no lo trates como decisión (se resuelve en `docs/ESTADO.md`, "Preguntas abiertas").

## 1. Propósito

Sustituto de bajo costo de las plataformas OT comerciales (Nozomi, Claroty, Dragos) **para los proyectos donde el
analista no tiene acceso a ellas**. Con una captura de red (pcap) o con lo que exporta una plataforma, produce el
análisis y los entregables que se presentan a un cliente: inventario de activos, matriz de comunicaciones,
hallazgos con referencia a marcos de seguridad, diagramas, plan de remediación y, con la configuración de los
firewalls, una política nueva propuesta con su Solicitud de Cambio. Resumen en una página: `docs/CAPACIDADES.md`.

No compite con esas plataformas en detección continua ni en cobertura de vulnerabilidades: cubre el assessment
puntual hecho por una persona (D19).

## 2. Usuario y contexto

- Un analista OT que entrega proyectos comerciales a terceros. Cada proyecto es un cliente distinto, con su
  marco, su país y su sector.
- Sectores: energía (generación, transmisión y distribución; gas y ductos), minería, alimentos, construcción y
  ferrocarril (hay clientes con equipos de fabricantes ferroviarios; **por confirmar** qué sistemas y qué protocolos).
- Países: México, EE. UU. y Chile.
- El resultado lo lee un cliente: el texto debe sostenerse ante una auditoría (ver `docs/AUDITORIA.md`).

## 3. Modos de uso

| Modo | Entrada | Estado |
|---|---|---|
| Captura propia | pcap/pcapng de un SPAN o TAP, analizada con `tshark` | Hecho |
| Exportación de plataforma | CSV/JSON/XLSX de inventario y enlaces de Nozomi, Claroty o Dragos | Los mismos entregables que con capturas: diagramas, reportes, hallazgos y plan (D53) |
| Mixto | Captura más exportación del mismo sitio | No existe |

## 4. Entradas

| Entrada | Estado |
|---|---|
| pcap/pcapng | Hecho |
| Inventario y enlaces de plataformas | Hecho, con formatos **no validados** contra exportaciones reales (D4, P1) |
| Vulnerabilidades por activo, alertas y eventos de plataformas | Pedido por el propietario; no existe |
| Reglas de firewall o ACL del cliente | Pedido por el propietario; no existe |
| Perfil del proyecto (cliente, país, sector, idioma, marcos) | No existe; hoy son opciones sueltas de la línea de comandos |

## 5. Salidas

| Salida | Estado |
|---|---|
| HTML, Markdown, CSV y JSON; diagramas SVG y Mermaid | Hecho |
| Informe en Word o PDF | Pedido por el propietario; no existe |
| Excel de inventario y matriz de comunicaciones | Pedido por el propietario; hoy solo CSV |
| Diagramas editables (Visio o draw.io) | Pedido por el propietario; hoy solo SVG y Mermaid |
| Plan de remediación priorizado | Pedido por el propietario; no existe |
| Idioma español e inglés elegible por proyecto | Pedido por el propietario; hoy solo español sin acentos (D12) |

## 6. Marcos y regulación

Cada cliente puede exigir un marco distinto. La herramienta **no decide** cuál aplica: lo decide el propietario
por proyecto. Hoy ofrece MITRE ATT&CK for ICS (siempre), IEC 62443, NERC CIP y NIST SP 800-82, más marcos propios
por JSON. Los mapeos son orientativos y sin revisión de un especialista (DIS-01). Lo investigado y sus fuentes
están en `docs/ESTADO.md`, "Hechos ya investigados".

| Contexto | Qué se sabe | Qué falta |
|---|---|---|
| EE. UU., entidades del sistema eléctrico (BES) | NERC CIP; CIP-015-1 aprobado por FERC | Qué clientes son BES |
| EE. UU., ductos | TSA Pipeline Security Directive: texto no público, no mapeable | Decidir cómo tratarlo |
| EE. UU., ferrocarril | Sin investigar | Qué marco rige y qué sistemas ferroviarios hay |
| Chile | Ley 21.663 aplica a organizaciones; no define requisitos técnicos mapeables | Si el cliente es OIV |
| México | No se halló norma de ciberseguridad OT para energía | Lo que imponga el contrato |
| Cualquiera | IEC 62443 y NIST suelen ser el marco que impone el cliente | El texto de la norma (el propietario lo aportará) |

Las normas con derechos de autor (IEC, ISA) **no se guardan en el repositorio**, que puede ser público; se trabaja
sobre una copia local en `normas/` (ignorada por git) y solo se versionan los identificadores de requisito y
paráfrasis breves.

## 7. Principios

1. **Honestidad.** No se afirma normativa, requisito ni formato de fabricante sin fuente. Lo no validado se rotula.
2. **Solo evidencia técnica.** Un análisis pasivo de tráfico no demuestra cumplimiento de un marco: muestra
   evidencia técnica relacionada. El reporte nunca dice "cumple" ni "no cumple".
3. **Pasivo.** No se genera tráfico hacia la red del cliente.
4. **Datos de cliente fuera del repositorio** (D9). Las pruebas usan datos sintéticos.
5. **Sin dependencias en ejecución** (D11) y salida determinista (D10).
6. **Trazable.** Un entregable se relaciona con la versión de la herramienta que lo produjo; lo que no se pueda
   reproducir no se entrega.

## 8. Fuera de alcance

Escaneo activo; detección en tiempo real o IDS; certificar cumplimiento; guardar datos de cliente; sustituir el
juicio del analista (las zonas, los roles y los niveles Purdue son inferencias que alguien debe validar en planta).

## 9. Modularidad y escalabilidad

Objetivo de diseño: cualquier pieza se puede auditar, sustituir o ampliar sin tocar las demás.

| Capa | Hoy | Contrato |
|---|---|---|
| Ingesta | `flows.py`, `detail/`, `importers/` | Produce el modelo (`Capture` o activos y enlaces importados) |
| Modelo | `model.py`, `consolidate.py` | Estructuras sin lógica de marcos ni de formato |
| Reglas | `rules/` | Una función por detección que llama a `finding()`; no conoce marcos ni formatos |
| Marcos | `standards.py` (tablas en Python) | Objetivo: archivos de datos con fuente, versión y estado de validación |
| Salidas | `report/`, `diagram/` | Una función por formato sobre el modelo ya calculado |

Cada pieza nueva entra con su prueba, su fila en el catálogo generado (`docs/CATALOGO.md`) y, si cambia una
garantía, su fila en el registro de auditoría. La tabla "Cómo extender" del README dice dónde tocar para cada caso.
Brechas de esta arquitectura frente al objetivo: `docs/PROPUESTAS.md`, grupo B.
