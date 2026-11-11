# Banco de propuestas

Funciones candidatas, con su valor y su costo, para decidir qué se construye. **Nada de aquí está aprobado salvo
lo que `docs/ESTADO.md` ponga en "Pendiente".** Cuando el propietario aprueba una propuesta, pasa a ESTADO y aquí
queda su ID con el estado actualizado. Alcance y límites: [ALCANCE.md](ALCANCE.md).

Esfuerzo: **S** menos de una sesión · **M** una o dos · **L** más de dos o con riesgo de rediseño. Es una
estimación de quien redactó la propuesta, no una medición.

## Cómo se usa (para cualquier sesión)

- Si el usuario pide ideas o falta información para decidir: entrevistar con preguntas de opciones cerradas
  (`AskUserQuestion`), tres o cuatro por ronda, y registrar las respuestas aquí o en ESTADO en la misma sesión.
- Una propuesta nueva lleva: qué, valor para el entregable, esfuerzo, de qué depende y qué necesita del usuario.
- Nunca se propone normativa sin fuente: se anota "por investigar" y se busca una vez (regla de tokens).

## B · Base multi-marco y trazabilidad (prioridad definida por el propietario)

| ID | Propuesta | Valor | Esf. | Depende de |
|---|---|---|---|---|
| B1 | **Perfil de proyecto**: un JSON por cliente con cliente, sitio, país, sector, idioma, marcos elegidos y regulación aplicable que declara el analista. Opción `--perfil`. Reemplaza `--titulo`, `--cliente` y `--estandar` sueltos | Un proyecto = un archivo reproducible; el reporte imprime el perfil | M | Nada |
| B2 | **Marcos como datos**: pasar las tablas de `standards.py` a archivos JSON con versión de la fuente, fuente, estado de validación (sin revisar, revisado por quién y cuándo) y mapeo hallazgo a requisito | Agregar un marco es agregar un archivo; el auditor revisa datos, no código | M | B1 |
| B3 | **Matriz de cobertura por marco** (generada): qué requisitos pueden tener evidencia en tráfico y cuáles no pueden evidenciarse con esta herramienta | Evita afirmar de más; sirve de anexo al cliente | M | B2 |
| B4 | **Entorno de análisis en el reporte** (cierra COR-03): versión y commit de la herramienta, versión de `tshark`, perfil, campos ignorados, muestreo y SHA-256 de cada captura | Cadena de custodia y reproducibilidad | S | Nada |
| B5 | **Idioma por proyecto** (es/en): textos de reglas y marcos en catálogos por idioma. Obliga a revisar D12 (hoy ASCII sin acentos) | Entregables para clientes de EE. UU. | L | B1 |
| B6 | **Paquete de entrega** con manifiesto: carpeta con reporte, perfil y `manifiesto.json` con hash de entradas y salidas | Auditoría externa de un entregable concreto | S | B1, B4 |

## E · Entradas

| ID | Propuesta | Valor | Esf. | Depende de |
|---|---|---|---|---|
| E0 | **Análisis desde exportaciones**: hoy el subcomando `diagrama` solo dibuja. Que la misma lista de reglas corra sobre inventario y enlaces importados (puertos y servicios inseguros, cruce de zonas, exposición a Internet, firmware obsoleto) y genere hallazgos e informe | Cubre el caso "no tengo la plataforma, solo su exportación". Es la brecha mayor frente al propósito | L | P1 (formatos reales) para validar; se puede construir sobre los perfiles actuales |
| E1 | **Importar vulnerabilidades por activo** (CVE, severidad, estado) y cruzarlas con el inventario | Hallazgos de vulnerabilidad sin la plataforma | M | P1; E0 |
| E2 | **Importar alertas y eventos** como evidencia de hallazgos | Complementa la captura | M | P1; E0 |
| E3 | **Importar reglas de firewall o ACL** (CSV genérico: origen, destino, puerto, acción) y contrastarlas con la matriz observada: tráfico sin regla y reglas sin tráfico | Política contra realidad, muy vendible en un assessment | M | Formato genérico; no depende de un fabricante |
| E4 | **Comparación entre dos corridas** (activos, conductos y escritores nuevos) (P5) | Línea base y control de cambios | M | B1 |
| E5 | **Anonimizador** de capturas y exportaciones (IP, MAC, nombres con mapeo estable) | Permite compartir muestras reales sin datos de cliente: desbloquea P1 y P6 | M | Nada |
| E6 | **Regenerar el informe desde `resultado.json`** sin releer capturas de GB | Rapidez en iteraciones de formato; separa análisis de salida | M | Nada |

## S · Salidas

La restricción de cero dependencias en ejecución (D11) se mantiene: Word y Excel son archivos OOXML, es decir ZIP
con XML, que se pueden escribir con la biblioteca estándar (el lector de XLSX ya trabaja en ese formato).

| ID | Propuesta | Valor | Esf. | Depende de |
|---|---|---|---|---|
| S1 | **Excel (.xlsx)** de inventario, matriz de comunicaciones y hallazgos, con filtros y formato | Es lo que el cliente suele pedir para trabajar el inventario | M | Nada |
| S2 | **Informe Word (.docx)** con portada, resumen, hallazgos y diagramas incrustados; PDF por impresión del HTML | Entregable editable | L | S3 para diagramas |
| S3 | **Diagramas editables**: draw.io (XML abierto) primero; Visio (.vsdx) solo si un cliente lo exige. Que draw.io exporte o importe Visio sin pérdidas: por verificar | Diagramas que el cliente pueda retocar | M | Nada |
| S4 | **Plan de remediación priorizado**: severidad por criticidad del activo por esfuerzo, en fases (inmediato, corto, mediano). El método de priorización lo define el propietario; se documenta, no se atribuye a un estándar | Entregable que cierra el assessment | M | B2 si se mapea a controles |
| S5 | **Resumen ejecutivo de una página** con los cinco riesgos principales | Lectura de directivos | S | S4 |

## T · Detección y protocolos

| ID | Propuesta | Valor | Esf. | Depende de |
|---|---|---|---|---|
| T1 | **Ferroviario**: investigar qué protocolos y qué marco aplican, con una sola búsqueda y muestras del propietario | Abre un sector con clientes reales | M | Información del propietario: qué sistemas ferroviarios y si hay pcaps |
| T2 | **Protocolos de los sectores** (P3): MQTT, KNXnet/IP, HART-IP, CODESYS, Beckhoff ADS, DLMS/COSEM; cada puerto se verifica en fuente oficial | Cobertura de construcción, alimentos y energía | M | Fuentes |
| T3 | **NIST CSF 2.0** como marco (P2): lenguaje común para informe directivo | Sirve a los tres países | M | B2; IDs verificados contra el texto oficial |
| T4 | **Seguridad de protocolos**: OPC UA con SecurityPolicy None, versiones de TLS, Modbus FC8, reinicio DNP3 (P7) | Hallazgos de mayor valor en un assessment | M | Escenarios sintéticos |
| T5 | **Periodicidad**: detectar polling irregular, pérdida de comunicación y escritores nuevos con series de tiempo | Anomalías sin plataforma | L | Nada |
| T6 | **Cruce opcional con avisos CISA** (D1) | Contexto de vulnerabilidad sin base de CVE propia | M | Decidir fuente y actualización |
| T7 | **IEC 62351, dictamen de aplicabilidad por protocolo**: para cada protocolo observado, qué parte aplica (-3 perfiles TCP/IP, -5 serie IEC 60870-5 y derivados, -6 IEC 61850, -8 control de acceso por roles), si hay evidencia de la protección (por ejemplo TLS o autenticación segura) y "no aplica" donde la norma no cubre el protocolo | Lo exige un cliente de alimentos | M | B2; texto de la norma en `normas/` (D3). **Hecha la parte observable (D117, `iec62351_evidencia.csv`):** sin texto de la norma; el dictamen de aplicabilidad con catálogo propio queda al propietario |

## A · Auditoría y calidad

| ID | Propuesta | Valor | Esf. | Depende de |
|---|---|---|---|---|
| A1 | Cerrar los hallazgos abiertos de `docs/AUDITORIA.md` §4 (SEG-01, SEG-02, COR-02 y demás) | Reducir lo que ve un auditor | S cada uno | Nada |
| A2 | **Revisión de mapeos por un especialista** (DIS-01) con el estado guardado en los datos de B2 | Pasar de orientativo a revisado | Externo | B2 |
| A3 | **Pruebas con datos reales anonimizados** (PRU-02) | Validar formatos y reglas fuera de lo sintético | Externo | E5 |
