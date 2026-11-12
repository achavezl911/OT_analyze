# ot_analisis

**Evaluación de ciberseguridad OT sin plataforma comercial.** Toma lo que el analista ya tiene (capturas de red,
exportaciones de Claroty xDome, Nozomi o Dragos, configuraciones de firewalls y switches) y, en el equipo del analista y
sin salir a Internet, produce los entregables de un assessment: inventario de activos, matriz de comunicaciones,
hallazgos priorizados con referencia a IEC 62443, NIST y MITRE ATT&CK for ICS, diagramas editables, plan de remediación
y una política de firewall nueva, construida solo con el tráfico observado, lista para revisión y carga.

> **Para entender el proyecto en una página** (capacidades, entregables, límites, calidad y manejo de datos):
> [docs/CAPACIDADES.md](docs/CAPACIDADES.md). Alcance y arquitectura: [docs/ALCANCE.md](docs/ALCANCE.md),
> [docs/ARQUITECTURA.md](docs/ARQUITECTURA.md). Cada opción, regla, puerto y salida, generado del código:
> [docs/CATALOGO.md](docs/CATALOGO.md).

## Qué hace

| Área | Comando u opción | Qué resuelve | Qué entrega |
|---|---|---|---|
| Análisis de capturas | `python ot_pcap_assess.py CAPTURAS -o SALIDA` | Inventario pasivo (fabricante, modelo, firmware, rol, nivel Purdue), comunicaciones, operaciones de escritura y control, DNS, periodicidad del sondeo OT y hallazgos | Reporte HTML, informe Word, Excel, Markdown, CSV, JSON, diagramas SVG/draw.io/Mermaid, resumen ejecutivo y plan de remediación |
| Sin capturas | `diagrama --activos ... --enlaces ...` | Lo mismo desde exportaciones de xDome, Claroty, Nozomi, Dragos o CSV genérico; varias fuentes a la vez | Los mismos entregables |
| Claroty xDome | `xdome-descargar` | Descarga por API, solo lectura: inventario, comunicaciones, vulnerabilidades y alertas | CSV listos para `diagrama` |
| Firewalls | `--firewall` (Cisco FTD/ASA con su NAT estático, FortiGate, Palo Alto, Check Point), `--rutas-firewall`, `--zonas-fw`, `--firewall-contadores` | Qué cruza cada firewall y por qué regla, qué se deniega, reglas sin uso, rutas, varios firewalls en cadena, higiene de la configuración | `firewall_*.csv`, sección en los reportes, hallazgos |
| Switches | `--switch` (CLI de Cisco IOS/IOS-XE, CLI de Aruba AOS-CX o recorrido SNMP de cualquier fabricante) | VLAN, puertos, espejo (SPAN) y su cobertura, higiene; las credenciales se cuentan, nunca se copian | Tablas y hallazgos |
| Inventario normalizado | `--inventario-manual ARCHIVO` (en ambos CLI; `--mapeo` con la clave `manual`), `equipos_propios` en el perfil | Un inventario único con fuente, última observación y estado por campo; declarados no observados y observados no declarados; sin los equipos del analista | `inventario_normalizado.csv`, `inventario_procedencia.csv` |
| Obsolescencia | `--fin-de-soporte ARCHIVO` (CSV o XLSX, en ambos CLI) | Fin de soporte por activo (fabricante, modelo, firmware, SO) con fecha, días, estado y fuente; tabla integrada de SO Microsoft; hallazgos de vencidos y de los próximos 12 meses | `obsolescencia.csv` |
| Ubicación de sensores (S1, D96) | Análisis completo con capturas | Cuántos puntos de captura conviene dejar como sensor permanente (cobertura voraz de conductos OT), cuáles sobran o hay que corregir, y qué zonas, VLAN sin espejo y segmentos no ve ningún punto | `sensores_puntos.csv`, `sensores_brechas.csv` |
| Salud de la red y línea base de tráfico | Análisis completo y `diagrama` (con `--switch` agrega las interfaces) | Top equipos y conductos por bytes y paquetes, mezcla de protocolos, difusión, ARP, retransmisiones TCP, cuellos de botella del switch y línea base de tráfico por conducto | `salud_red.csv`, `top_equipos.csv`, `top_conductos.csv`, `mezcla_protocolos.csv`, `interfaces_switch.csv`, `linea_base_trafico.json` |
| Validación de la captura | `validar-captura CAPTURAS` (una pasada, primer día en sitio); también automática en el análisis completo | Veredicto por punto de captura (apta, apta con limitaciones, no apta) con motivos: pérdida TCP del espejo, sesiones de un solo sentido, huecos, truncamiento, VLAN y zonas sin tráfico, protocolos industriales vistos | `cobertura_captura.csv`, `cobertura_zonas.csv`, `validacion_captura.html` |
| Zonas y conductos | `--perfil` (zonas del cliente, ejemplo en `docs/ejemplos/perfil_zonas.json`), `--origen-ataque`, `--objetivo-ataque` | Zonas y conductos al estilo IEC 62443, rutas de ataque entre zonas, segmentación propuesta (TO-BE: permitir, por DMZ, revisar, bloquear) | `zonas.csv`, `conductos_zcr.csv`, `rutas_ataque.csv`, `allowlist_tobe.csv`, `matriz_tobe.csv`, `hardening_baseline.csv`, `hardening_activos.csv`, diagramas de zonas y TO-BE |
| Rediseño de la política | automático con `--firewall` | Política "desde cero" solo con lo observado: cada fila `permitir`, `revisar` o `bloquear`, con objetos y justificación, y su comparación con la política actual | `politica_propuesta.csv`, `politica_objetos.csv`, `politica_comparacion.csv`, `politica_bloqueados.csv` |
| Validar antes del corte | `politica-validar --propuesta ... --cruces OTRA_CORRIDA` | Qué rompería la propuesta con el tráfico de otra ventana, qué casi coincide con una regla y qué agregar, qué reglas no se usaron | `validacion_cruces.csv`, `validacion_reglas.csv`, `validacion.md` |
| Preguntas antes del corte | automático con `--firewall` | Servicios de infraestructura que cabría esperar por zona (AD, DNS, NTP, WSUS, syslog, SNMP, respaldo...) y no se vieron cruzar, y cuántos días cubre la evidencia | `preguntas_cliente.csv` (hoja «Preguntas al cliente»): una pregunta por servicio con todas las zonas, lista para enviar; `esperados_no_observados.csv`: el detalle por zona con la regla sugerida |
| Carga al firewall | `politica-fmc` (Cisco FMC 7.6; `--formato fortios\|checkpoint\|panos`) | Objetos y reglas para la API del FMC; el script simula por defecto y solo crea con confirmación | JSON y `aplicar_fmc.py`, o archivos de comandos |
| Control de cambios | `solicitud-cambio` | Solicitud de Cambio para el comité, con la plantilla del cliente si la hay | `solicitud_cambio.docx` y `.md`, lista de cambios en CSV |
| Línea base aprobada | `linea-base aprobar` / `verificar`; `--linea-base CARPETA` al analizar | Qué se desvió de la corrida que el equipo aprobó para el sitio (activos, conductos, escritores, firmware, volumen) | `desviaciones_linea_base.csv`, hoja, sección y hallazgos con playbook |
| Madurez por dominio | `madurez cuestionario -o ARCHIVO.csv`; `--madurez ARCHIVO` al analizar (capturas y `diagrama`) | Madurez de ciberseguridad OT en 8 dominios (activos, segmentación, acceso, parches, monitoreo, incidentes, suministro, riesgo): cuestionario de entrevista de 32 preguntas, nivel actual, objetivo y brecha (escala 0 a 4) y dónde la evidencia de red no respalda lo declarado | `madurez.csv`, `cuestionario_madurez.csv`, hojas, sección con radar y `resultado.json` |
| Comparar corridas | `comparar --antes A --despues B` | Qué cambió: activos, conductos, escritores, hallazgos y firewall (se cortó, se abrió) | `comparacion.html`, `.md`, `.json` y un CSV por sección, con prioridad |
| Acceso remoto de terceros | automático (capturas y exportaciones) | TeamViewer, AnyDesk, RustDesk, ScreenConnect y otras herramientas por nombre (DNS, SNI, HTTP, dominio exportado) y por puerto; descarta los destinos que "sirven" miles de puertos | `acceso_remoto.csv` y hallazgo |
| Canales que evaden la inspección | automático; `--tor-relays` con una lista local | DNS cifrado hacia resolvedores externos (DoH, DoQ), Tor, VPN y túneles hacia Internet, proxies abiertos | `evasion.csv` y hallazgos |
| Capa 2 y bucles | automático en capturas; `--switch` con `show spanning-tree detail` y `show logging` | Servidor DHCP no autorizado, cambio de raíz STP, BPDU desde equipos finales, salto de VLAN, HSRP/VRRP sin autenticación, anuncios de router IPv6, inundación de MAC, bucles; controles de capa 2 ausentes en el switch (BPDU guard, storm-control, DHCP snooping, DTP) | Hallazgos con playbook |
| Vulnerabilidades y alertas | `--vulnerabilidades`, `--kev`, `--avisos-ics`, `--alertas` | Cruce con el inventario y con el catálogo KEV y los avisos ICS de CISA desde archivos locales | Tablas, hallazgos y prioridad |
| Custodia | `custodia registrar/verificar/exportar` | Registro de cadena de custodia encadenado por hash, con CSV y HTML imprimible con firmas | `custodia.csv`, `custodia.html` |
| Entrega y auditoría | `empaquetar` / `empaquetar --verificar` | Paquete para el cliente con manifiesto y SHA-256 de entradas y salidas | Carpeta o ZIP verificable |
| Avisos sin red | `paquete-avisos` / `--paquete-avisos` | Paquete de avisos ICS y KEV de CISA con SHA-256, verificado antes de usarlo en plantas aisladas | Carpeta o ZIP verificable |
| Datos del cliente | `anonimizar` | Compartir muestras sin datos del cliente (IP, MAC, nombres con mapeo estable) | Copia anonimizada |
| Proyecto | `--perfil`, `--estandar`, `--idioma es\|en`, `--cache` | Cliente, sitio, marcos exigidos, idioma del entregable; no releer capturas grandes | |

**Lo que no hace:** no captura tráfico ni toca la red (solo lee archivos), no se conecta a firewalls ni plataformas
salvo la descarga de xDome que el analista lanza, no trae una base de CVE propia y **nunca dictamina "cumple / no
cumple"**: entrega evidencia técnica relacionada con cada marco.

## Inicio rápido

```bash
scripts/setup.sh                                   # una vez: tshark y lo que usan las pruebas
python ot_pcap_assess.py capturas/ --perfil perfil.json -o salida/
python ot_pcap_assess.py diagrama --activos inventario.csv --enlaces comunicaciones.csv \
    --firewall fw_show_running.txt -o salida_fw/   # sin capturas, con el firewall
```

Abra `salida/reporte_ot.html` o `salida/informe_ot.docx`. Python 3.9 o superior, sin dependencias en ejecución, más
Wireshark (tshark) para las capturas. Probado de forma automática en Linux (Python 3.9 y 3.13); en Windows y macOS
está diseñado para correr igual, sin prueba automática.

Origen: un cliente reportó que, sobre las mismas capturas, una plataforma encontraba vulnerabilidades y otra no. El
reporte conserva una sección con las causas técnicas de esa brecha que se pueden confirmar desde la captura.

## Requisitos

Python 3.9 o superior y Wireshark (se usan `tshark`, `capinfos` y `editcap`).

```bash
# Debian / Ubuntu
sudo apt install tshark

# RHEL / Rocky / Alma
sudo dnf install wireshark-cli

# macOS
brew install --cask wireshark
```

En Windows basta instalar Wireshark; el script lo localiza solo en
`C:\Program Files\Wireshark`. En cualquier sistema se puede forzar la ruta con
`--tshark`.

No hace falta `sudo` para ejecutarlo: solo lee archivos, nunca captura tráfico.

## Uso

```bash
python ot_pcap_assess.py capturas/ -o reporte/
```

Es equivalente a `python -m ot_assess capturas/ -o reporte/`.

```bash
python ot_pcap_assess.py planta.pcapng -o reporte/ \
  --titulo "Assessment de ciberseguridad OT" \
  --cliente "Central de generación X"
```

Acepta archivos sueltos, varias rutas o un directorio (que recorre de forma
recursiva).

### Opciones

| Opción | Para qué sirve |
|---|---|
| `-o, --out` | Carpeta de salida. Por defecto `reporte_ot`. |
| `--perfil` | Perfil del proyecto en JSON. Reemplaza a `--titulo`, `--cliente` y `--estandar`. Ver [Perfil de proyecto](#perfil-de-proyecto). |
| `--tor-relays ARCHIVO` | Lista de relays Tor que usted descargó (la herramienta no descarga nada): texto con una IP por línea (como la lista de salidas de check.torproject.org) o JSON de Onionoo (documento `summary`: `relays[].a`; `details`: `relays[].or_addresses`); se detecta por contenido. Un conducto hacia una IP de la lista se reporta como Tor. Avisa si la lista no trae fecha o tiene más de 7 días. Sin lista, solo los puertos TCP 9001 y 9030 hacia Internet cuentan, como indicio sin verificar. Límites: 50 MB y 500 000 direcciones. Se registra en el entorno con su SHA-256. |
| `--vulnerabilidades` | CSV de vulnerabilidades por activo de un escáner o plataforma (columnas `cve`; `severidad` o `cvss`; `activo`, `ip` o `mac`; `estado`, `producto`, `version`, `fuente` opcionales; `cvss_v4`/`cvss4` y `vector_cvss_v4`/`vector_v4` opcionales: con vector se puntúa CVSS v4.0 y `vulnerabilidades.csv` agrega `cvss_v4` y `vector_cvss_v4` junto a `cvss`, sin cambiar severidad ni orden, D113; ejemplo ficticio en [`docs/ejemplos/vulnerabilidades.csv`](docs/ejemplos/vulnerabilidades.csv)). Cruza cada fila con el inventario observado (IP, MAC, nombre) y, si trae CPE (`matching_cpes` de Nozomi), infiere fabricante, modelo, firmware y sistema operativo del activo como valores inferidos (D101). Genera un hallazgo mapeado a los marcos, `vulnerabilidades.csv` (también hoja del libro) y una sección en el reporte. No consulta bases de CVE ni verifica la versión instalada. |
| `--cis ARCHIVO` | CIS Controls v8.1 (XLSX oficial de CIS o CSV con sus columnas) que usted descargó: agrega a `matriz_controles.csv` una fila por salvaguarda del grupo `cis_ig` del perfil (IG1, IG2 o IG3; por defecto IG2). Títulos leídos del archivo; el repo no distribuye texto de CIS (CC BY-NC-ND 4.0). Ver «Matriz de controles». |
| `--kev ARCHIVO` | Catálogo KEV de CISA (`known_exploited_vulnerabilities.json` o su CSV) que usted descargó; la herramienta no descarga nada. Requiere `--vulnerabilidades` (si no, se ignora con un aviso). Agrega a `vulnerabilidades.csv` las columnas `kev`, `kev_fecha_agregada`, `kev_fecha_limite` (la fija CISA para agencias federales de EE. UU., BOD 22-01: referencia, no obligación del cliente) y `kev_ransomware`, y el hallazgo «Vulnerabilidades explotadas activamente» (Alta) si hay abiertas asociadas a un activo. Avisa si el catálogo tiene más de 30 días. Ejemplo ficticio: [`docs/ejemplos/kev_ejemplo.json`](docs/ejemplos/kev_ejemplo.json). |
| `--avisos-ics RUTA` | Un aviso ICS de CISA en CSAF 2.0 (JSON, de github.com/cisagov/CSAF) o una carpeta con muchos (recursiva, sin seguir enlaces simbólicos; tope de 20 MB por archivo y 20000 archivos). Cruce solo por CVE exacto con `--vulnerabilidades`; no compara fabricante, modelo ni firmware. Agrega `avisos_ics` y `remediacion_fabricante` a `vulnerabilidades.csv` y genera `avisos_ics.csv` (un aviso por fila, por CVSS máximo). Ejemplo ficticio: [`docs/ejemplos/avisos_ics/`](docs/ejemplos/avisos_ics/). Ambos archivos son candidatos: verifique con el aviso del fabricante (D1, D66). |
| `--catalogo-vulnerabilidades ARCHIVO` | Catálogo del analista (CSV o XLSX; columnas `fabricante`, `producto`, `version_afectada`, `cve`; `cvss`, `aviso`, `remediacion` y `fuente` opcionales; alias de encabezado en inglés). Con él o con `--avisos-ics` corre V1a (D89): compara fabricante, modelo y firmware del inventario normalizado con el `product_tree` de los avisos y con el catálogo, sin red, y genera `vulnerabilidades_firmware.csv`, la sección «Vulnerabilidades candidatas por fabricante, modelo y firmware» y un hallazgo. Son candidatos a confirmar con el aviso o el fabricante, no un dictamen. Los alias de fabricante están en `ot_assess/data/fabricantes_alias.json` (ampliable). Si un aviso de Siemens pone el número de pedido (MLFB) donde va la versión, se trata como restricción de modelo (D119): exacto solo con un modelo del inventario en forma de MLFB que case; un modelo por nombre queda como familia. |
| `--alertas` | CSV de alertas de un IDS o plataforma OT (columnas `firma`; `origen` y/o `destino`; `severidad` o `prioridad`; `puerto`, `protocolo`, `fecha`, `categoria`, `conteo` opcionales; ejemplo ficticio en [`docs/ejemplos/alertas.csv`](docs/ejemplos/alertas.csv)). Asocia cada alerta a un conducto observado (par origen/destino y puerto) y a los activos por IP; genera un hallazgo mapeado a los marcos, `alertas.csv` (también hoja del libro) y la sección «Alertas importadas». No valida las firmas ni descarta falsos positivos. |
| `--idioma` | Idioma de los reportes: `es` (por defecto) o `en`. Manda sobre la clave `idioma` del perfil. En inglés salen los textos del reporte (HTML, Markdown, Word, Excel y cabeceras de CSV, hallazgos, diagramas y notas). No se traducen los datos de entrada (nombres de archivo, hostnames, valores del perfil, firmas de una plataforma), el JSON de salida ni los mensajes de consola. Los nombres de controles de los marcos van en inglés. |
| `--titulo` | Título de la portada del HTML. |
| `--cliente` | Subtítulo de la portada: cliente o sitio. |
| `--max-packets` | Tope de paquetes para el mapa de flujos. `0` procesa todo. Por defecto 1 000 000. |
| `--max-rows` | Filas máximas por tabla en los reportes. Por defecto 120. |
| `--cache CARPETA` | Guarda la lectura de cada captura (gzip, permisos 600) y la reutiliza en la corrida siguiente: permite cambiar perfil, firewall, switches, zonas, idioma, límites de tabla o formato sin que tshark relea capturas de GB. La clave incluye el contenido del pcap, la versión de ot_assess, la de tshark, `--max-packets` y `--no-detail`. Contiene datos del cliente: guárdela junto a sus salidas, nunca en el repositorio. No aplica a `diagrama`. |
| `--cache-renovar` | Ignora lo guardado en `--cache` y lo reescribe. |
| `--no-detail` | Omite el pase de detalle. Mucho más rápido, pero sin identidad ni operaciones de control. |
| `--tshark` | Carpeta donde está Wireshark, si no se encuentra en el `PATH`. |
| `--reglas-firewall` | CSV de reglas de firewall/ACL (columnas `origen`, `destino`, `puerto`, `protocolo`, `accion`; `id` opcional; ejemplo en [`docs/ejemplos/reglas_firewall.csv`](docs/ejemplos/reglas_firewall.csv)). Contrasta la política con los conductos observados: tráfico sin regla, tráfico denegado que se observó y reglas de permitir sin tráfico. |
| `--firewall` | Salida de la CLI de un Cisco FTD/ASA ([detalle](#firewall-cisco-ftdasa---firewall)): rutas reales, contraste de reglas por interfaz y `firewall_reglas.csv`. No se combina con `--reglas-firewall`. |
| `--zonas-fw` | CSV `firewall,interfaz,zona` con la zona de seguridad de cada interfaz para la política propuesta (requiere `--firewall`; [detalle](#firewall-cisco-ftdasa---firewall)). |
| `--switch` | Salida de la CLI de un switch Cisco IOS/IOS-XE o Aruba AOS-CX, o recorrido SNMP (`snmpwalk -On`) de cualquier fabricante, repetible; el formato se detecta solo ([detalle](#switches-cisco-iosios-xe---switch), [AOS-CX](#switches-aruba-aos-cx), [SNMP](#switches-por-recorrido-snmp)): puerto y VLAN de cada activo por MAC y, con la CLI de Cisco, cobertura de las sesiones SPAN. No guarda contraseñas ni comunidades. |
| `--rutas-firewall` | Tabla de rutas de un firewall (formatos en [Rutas del firewall](#rutas-del-firewall)). Asigna a cada IP la interfaz por la que el firewall la alcanza, marca los conductos que cruzan el firewall y agrupa los diagramas por interfaz. |
| `--no-diagrams` | No genera los diagramas de red. |
| `--estandar` | Marco(s) de referencia de los hallazgos, separados por coma: `iec62443` (por defecto), `nerc-cip`, `nist-800-82`, `nist-csf`, `tsa-sd-1580-82` (derivado, ver TSA2). El primero rige el texto del reporte. Ver [Estándares](#estándares-de-referencia). |
| `--estandar-archivo` | Marco propio en JSON. Se puede repetir. |
| `--diagram-max-nodes` | Equipos máximos en el diagrama por activo. Entran primero los que reciben escrituras o participan en conductos críticos. Por defecto 40. |
| `--diagram-max-edges` | Trazos máximos en el diagrama por activo; se conservan los de mayor criticidad y volumen. Por defecto 60. |

### Firewall Cisco FTD/ASA (`--firewall`)

`--firewall ARCHIVO` (también en `diagrama`; archivo con la sesión pegada o carpeta con un archivo por
comando; se puede repetir, esta versión usa el primero y avisa) lee la salida de la CLI de un FTD/ASA y
hace dos cosas: da a cada activo y conducto su interfaz/zona con las rutas reales (incluidas las
conectadas; reemplaza a `--rutas-firewall`, que se ignora con aviso) y contrasta las reglas con los
conductos observados respetando las interfaces (`ifc`) de cada regla; la primera que casa decide, `trust`
cuenta como permitido y la regla por defecto del final atrapa el resto. No se combina con
`--reglas-firewall` (código 2). Salidas nuevas: `firewall_reglas.csv` (hoja «Reglas del firewall»: reglas
con aciertos del firewall y `conductos_observados`) y un resumen en las secciones de firewall del reporte.
Solo se leen las secciones listadas abajo; usuarios, comunidades SNMP y claves se descartan.

Los conductos con las dos puntas detrás de la misma interfaz (o con una sin interfaz conocida) no atraviesan ese
firewall: resultado `no_cruza` («No cruza este firewall»), sin regla y sin contar como tráfico de ninguna.
La columna `marcas` de `firewall_reglas.csv` señala por regla: `any-any` (permite o confía de cualquier origen a
cualquier destino sin puerto), `confia sin inspeccion` (trust), `sombreada por <id>` (todas sus líneas cubiertas
por reglas anteriores; `(accion distinta)` si la cubridora hace lo contrario), `sin aciertos` y `sin conductos
observados` y `espejo de <id> (retorno)` (regla que invierte origen, destino e interfaces de otra y repite su
puerto de destino: en un firewall con estado solo agrega conexiones entrantes; un nombre como «Regreso» sin
cumplir el criterio solo avisa en la columna `avisos`). De ellas salen cinco hallazgos «(segun la configuracion
del firewall)»: cualquier origen a cualquier destino, tráfico confiado sin inspección, reglas sombreadas o sin
uso, reglas de retorno que abren conexiones entrantes y tráfico observado que el firewall denegaría; entran al plan de remediación y al resumen ejecutivo. Son evidencia técnica relacionada con
SC-7, CIP-005 y SR 5.x, no un dictamen de cumplimiento; las referencias no están cotejadas con la norma.

Con `show arp` (también dentro de una sesión pegada) sale `firewall_rutas.csv` (hoja «Rutas del firewall»): por ruta,
`salto_en_arp` (si/no/sin dato), `conductos` (observados cuyo destino tiene esa ruta como la más específica; sin los
`no_cruza`) y `marcas`: `salto sin ARP`, `sin trafico observado` (estática sin conductos), `cubierta por <red>`
(estática contenida en otra con el mismo salto e interfaz) y `mismo prefijo en dos saltos` (estáticas solapadas con
saltos distintos: puede ser intencional). Sin `show arp` el aviso es «sin show arp: no se valida el salto». Hallazgo
«Rutas estaticas hacia saltos que no responden o sin trafico observado»: Baja, Media si una ruta con salto sin ARP
tiene conductos. El ARP envejece: una ruta poco usada puede no tener entrada en ese momento; confirmar con el dueño
de la red antes de retirarla.

**NAT de Cisco FTD/ASA (D70).** Las reglas de acceso se evalúan con las IP reales; si la configuración trae `nat`
estático (twice NAT u object NAT), el contraste invierte la traducción de lo observado (captura del lado mapeado o del
real) y evalúa, propone (`politica_propuesta.csv`) y valida (`politica-validar`) con la IP real. En
`firewall_cruces_detalle.csv` aparecen al final `ip_origen_real`, `ip_destino_real`, `nat_regla` y `nat_sentido` (solo si
hubo NAT; `ip_origen`/`ip_destino` siguen siendo las observadas), y `firewall_nat.csv` lista cada regla con su estado
(usada, sin uso en la ventana, inactiva o no modelable con el motivo) y, al final, las redes ya resueltas
(`origen_real_red`, `origen_mapeado_red`, `destino_mapeado_red`, `destino_real_red`). Si la sesión trae
`show nat detail` (F6b) se agregan `translate_hits` y `untranslate_hits` (desde el último clear, cubren más tiempo que la
captura) y el estado distingue «sin trafico en la ventana, con aciertos en el contador» (se usa fuera de la ventana: no
proponer quitarla) de «sin aciertos en el contador» (candidata a revisar con el cliente); las reglas que no emparejan
con la configuración se cuentan en la nota y los avisos, y no se les inventan contadores. NAT dinámico/PAT no se puede invertir: se marca y
la IP no cambia. No se modela la traducción de puertos (`service`) ni el NAT de otros fabricantes ni entre firewalls en
cadena. Un activo cuya IP es un mapeado lleva la columna `nota_nat` en el inventario (no se fusiona con el real).

Varias tomas de `show nat detail` (F6c): pegue cada toma con su prompt en la sesión, en orden cronológico, o ponga un archivo por toma en la carpeta (`show_nat_detail_20261106.txt`, `show_nat_detail_20261110.txt`; se leen por nombre, por eso la fecha AAAAMMDD). Cada regla usa el máximo de sus contadores y, si algún contador baja entre dos tomas (clear, despliegue o reinicio), `firewall_nat.csv` lo marca en `reinicio_contadores` y la nota lo dice; agrega `tomas_nat`, `translate_hits_por_toma` y `untranslate_hits_por_toma`.

Con `--firewall` también sale el inventario de lo que cruza el firewall (los conductos que no son `no_cruza`):
`firewall_cruces.csv` (hoja «Cruces del firewall»), agregado por par de interfaces, protocolo, puerto y protocolo de
aplicación (orígenes, destinos, ejemplos, conductos, bytes, permitidos, denegados, reglas actuales y destinos en
Internet), y `firewall_cruces_detalle.csv` (hoja «Cruces del firewall (detalle)»), una fila por par de IP y servicio.
La columna `etiquetas` (acceso remoto, administracion, compartir archivos, texto claro, protocolo OT, hacia/desde
Internet, DNS externo, muchos origenes/destinos, denegado observado, puerto alto) son marcas para la revisión, no
juicios. Los reportes traen la sección «Trafico que cruza el firewall» con los 15 pares con más conductos. Es la
entrada de la política propuesta (F5b).

**Varios firewalls en cadena (`--firewall` repetido, D45).** Cada archivo es un firewall (identificador = hostname; si
falta o se repite, el nombre del archivo). Se descubre cómo se unen: una ruta de A cuyo salto es una IP de B, o
interfaces de A y B en la misma red. Para cada conducto se calcula el camino (los firewalls donde su interfaz de
entrada y de salida difieren, en el orden de los enlaces) con la decisión de cada uno. Salidas nuevas:
`firewall_topologia.csv` (hoja «Topologia de firewalls»), `firewall_coherencia.csv` (hoja «Coherencia entre
firewalls»: `permitido en X, denegado en Y`, `salto hacia X sin cruce en X`, `sin firewall en el camino`), columna
`camino` en `firewall_cruces_detalle.csv`, columna `firewall` en `firewall_cruces.csv`, y por firewall
`<id>_firewall_reglas.csv`, `<id>_firewall_rutas.csv`, `<id>_firewall_interfaces.csv` y `<id>_firewall_matriz.csv`.
Los hallazgos de reglas y rutas se juntan (uno por tipo, evidencia con el prefijo `<id>:`). Supone red en cadena o
árbol, sin caminos alternos; las marcas indican dónde revisar, no un error confirmado. Con un solo `--firewall` todo
sale como antes.

**Política propuesta por firewall (M3a, D47).** Con `--firewall` (uno o varios) sale, para cada firewall,
`politica_propuesta.csv` (reglas puntuales: equipo o grupo + servicio exacto + interfaces y zonas, clasificadas en
permitir / revisar con sus razones y su justificación), `politica_objetos.csv` (hosts `H_`, redes `N_`, grupos `G_`,
servicios `S_`, grupos de servicio `SG_`; nombres válidos para FMC), `politica_comparacion.csv` (cada regla actual:
`reemplazada`, `acotar`, `eliminar candidata`, `validar antes de eliminar`, `bloqueo`, `mantener bloqueo explicito`) y
`politica_bloqueados.csv` (lo que se propone bloquear o ya se niega: no genera regla; la acción por defecto propuesta
es bloquear con registro) y `esperados_no_observados.csv` (detalle por zona; `preguntas_cliente.csv` lo agrupa en una pregunta por servicio
con todas las zonas y firewalls. Por zona: servicios de infraestructura que cabría esperar
—DNS, NTP, Active Directory, WSUS, syslog, SNMP, respaldo— y no se vieron cruzar, con la pregunta para el cliente y la
regla a agregar si la respuesta es sí; más preguntas generales si la evidencia cubre menos de 31 días; no es un
hallazgo). La cobertura temporal (días calendario de las fuentes) va en `resultado.json`, en la consola y en el
encabezado de la propuesta. Con varios firewalls los archivos llevan el prefijo `<id>_`. `--zonas-fw ARCHIVO` (CSV
`firewall,interfaz,zona`) da el nombre de la zona de seguridad de cada interfaz; sin él se usa la zona de `show zone`
o `SZ_<nameif>`, con aviso. La clasificación es fija y el analista la ajusta en el Excel; la propuesta solo cubre lo
observado en la ventana de las fuentes: desplegar primero con registro y revisar antes de bloquear.

**Rutas propuestas por firewall (F5c, D49).** Con `--firewall` sale además `rutas_propuestas.csv` (cada ruta con
`accion` = mantener / eliminar / revisar / `resumir en <red>` y su `razon`; las conectadas y locales no se tocan) y
`rutas_destinos_sin_ruta.csv` (destinos observados, por /24, cuya ruta más específica es la de defecto o un salto que no
responde en el ARP; el salto correcto lo define el analista). Con varios firewalls llevan el prefijo `<id>_`. El ARP
envejece: una ruta de uso poco frecuente puede no tener ARP; confirmar con el dueño de la red antes de eliminar.

Comandos a guardar (desde el prompt `>` de FTD: `show zone` y `show access-control-config`; el resto,
desde `system support diagnostic-cli`):

```text
show route
show nameif
show interface ip brief
show running-config access-list
show running-config object
show running-config object-group
show running-config nat
show nat detail
show rule hits
show zone
```

Sin `show zone` las zonas son los `nameif`. Es evidencia pasiva: las reglas se aproximan (ver D43), no
es un motor de decisión del firewall, y el reporte no dice «cumple» ni «no cumple».

### Firewall FortiGate (`--firewall`, D57)

El mismo `--firewall` acepta una FortiGate (FortiOS 6.x/7.x): el fabricante se detecta por el contenido
(`config firewall policy` o `config system interface`) y todo lo anterior (contraste, higiene, rutas, cruces,
política propuesta, varios firewalls en cadena, también mezclando Cisco y FortiGate) funciona igual. Cada VDOM
es un firewall (`<hostname>:<vdom>`). Qué pedir al cliente, una salida por archivo o todas en uno (nunca un
respaldo completo: trae contraseñas y llaves):

- `show full-configuration system interface`, `... system zone`, `... router static`
- `show full-configuration firewall address`, `... firewall addrgrp`, `... firewall service custom`,
  `... firewall service group`, `... firewall policy`
- `get router info routing-table all`
- Opcional: el CSV de la tabla de políticas de la GUI con las columnas `ID` o `Name` y `Hit Count`, que se
  da con `--firewall-contadores CSV` (FortiOS no pone los aciertos en la configuración; sin él no se evalúa
  «sin aciertos»).

Se agrega una regla `Implicit deny` al final de cada firewall. NAT/VIP, FQDN, geografía y servicios no
predefinidos conocidos quedan como aviso. Sintaxis pública de FortiOS, **sin validar todavía con una muestra
real**.

### Firewall Palo Alto PAN-OS (`--firewall`, D59)

El mismo `--firewall` acepta un Palo Alto (PAN-OS 9.x-11.x), en formato `set` o XML; se detecta por el contenido
(`set ... rulebase security`, `set network virtual-router` o `<rulebase>`). Cada vsys es un firewall
(`<hostname>:<vsys>`; con un solo vsys, sin sufijo). Qué pedir al cliente, todo en un archivo o en varios
(nunca un respaldo con usuarios: trae `phash`, llaves y certificados):

- La configuración: `set cli config-output-format set` y luego `configure` + `show` (o `show config running`),
  o el XML exportado de la GUI (se rechaza si trae `DOCTYPE` o `ENTITY`; máximo 100 MB).
- `show routing route` (rutas activas, banderas `A S`, `A C`, `A O`...).
- Opcional: `show rule-hit-count vsys vsys-name vsys1 rule-base security rules all`, en el mismo archivo o en
  otro con `--firewall-contadores ARCHIVO` (se asocia por nombre de regla; sin él no se evalúa «sin aciertos»).

Se modelan las reglas por defecto `intrazone-default` (permite dentro de la zona) e `interzone-default` (deniega
entre zonas). `application-default`, App-ID, NAT, FQDN, grupos dinámicos, `negate-*` y `source-user` quedan como
aviso: el contraste puede ser más amplio que la realidad. Sintaxis pública de PAN-OS, **sin validar todavía con
una muestra real**.

### Firewall Check Point (`--firewall`, D60)

El mismo `--firewall` acepta la política de un Check Point (R80.x/R81.x) exportada en JSON con `mgmt_cli`, en un
archivo o en una carpeta con todas las páginas (se detecta por el contenido: JSON con `rulebase` y
`objects-dictionary`). Qué pedir al cliente, **con la sesión del propio analista o de un usuario de solo lectura
y sin exportar usuarios, administradores ni llaves** (la salida de reglas y objetos de red no los trae; el
adaptador además solo lee los campos de reglas, direcciones y servicios):

- La política, una página por archivo hasta cubrir `total` (`offset` 0, 500, 1000...):
  `mgmt_cli show access-rulebase name "Network" details-level full use-object-dictionary true show-hits true limit 500 offset 0 --format json > rulebase_0.json`
  (repetir por cada capa de acceso que se quiera analizar; `show-hits true` da los aciertos y sus fechas).
- Opcional, del gateway en clish: `show interfaces all` y `show route` (o `netstat -rn` en modo expert), en un
  `.txt` dentro de la misma carpeta. Sin ellos el contraste no conoce interfaces y no puede decir qué conductos
  cruzan el firewall.

Se modelan reglas por sección en orden de `rule-number`, objetos `host`, `network`, `address-range`, `group`
(anidados, con ciclos cortados) y `Any`; servicios TCP/UDP (`443`, `8080-8090`, `>1023`, `<1024`), ICMP y grupos de
servicio; `enabled`, aciertos y la regla final implícita *Cleanup rule* si la política no la trae. Quedan como aviso:
`negate`, capas `inline-layer` (la regla se trata como bloquear y se marca no confiable), `service-other`, FQDN,
`updatable-object`, `access-role`, IPv6 y NAT. Las `security-zone` de las reglas se usan como interfaz de la
regla y no casan con las interfaces del gateway (el mapeo está en el objeto gateway, que no se tiene);
`--zonas-fw` solo afecta la política propuesta. Formato público de la Management API y de Gaia, **sin validar
todavía con una muestra real**.

### Switches Cisco IOS/IOS-XE (`--switch`)

`--switch ARCHIVO` (repetible; también en `diagrama`) lee la sesión de terminal pegada de un switch
(MobaXterm, PuTTY, etc.; prompts `host#` y comandos abreviados como `sh mac add` incluidos) y entiende solo:
`show running-config` (hostname, VLAN y nombres, interfaces con descripción, modo, VLAN de acceso, trunk
permitido y nativo, channel-group, shutdown, SVI, `monitor session`, `ip http`, `line vty`),
`show ip interface brief`, `show mac address-table`, `show interfaces description`,
`show cdp neighbors detail`, `show inventory` y `show version` (modelo y versión; no se guarda el número de
serie). Para el estado de capa 2 (opcionales): `show spanning-tree detail` (cambios de topología por VLAN, hace
cuánto y desde qué puerto), `show logging` (solo MAC flapping y err-disable) y `show interfaces` /
`show interfaces counters errors` (paquetes, broadcast y errores de entrada por puerto). Lo demás se descarta. **No se guarda ninguna credencial**: usuarios, contraseñas (tipo 0/7), secretos
(5/8/9), `enable`, comunidades SNMP, llaves TACACS/RADIUS y certificados solo se cuentan por tipo (el
conteo se ve en `resultado.json`, `switches.switches[].credenciales`).

Con él, cada activo con MAC del inventario queda ubicado por la tabla MAC (`switch_puerto` y `vlan` en
`inventario.csv`/`inventario_importado.csv`; si la MAC aparece en varios puertos gana el de acceso sobre el
trunk, el Port-channel o el puerto con vecino CDP). Salidas: `switch_puertos.csv`, `switch_vlans.csv` y
`switch_span.csv` (hojas «Switch puertos», «Switch VLAN», «Switch SPAN») y la sección «Switches» del reporte. En
`switch_vlans.csv`, `espejada_span` es `si` (la VLAN es origen de una sesión SPAN), `parcial` (solo una interfaz
de origen de esa VLAN: cubre el tráfico de ese puerto) o `no`; una VLAN con MAC aprendidas y `no` lleva la marca
«VLAN sin espejo». Con `--fuente-flujos`, `fuentes_cobertura.csv` suma la columna `espejo_switch` por segmento
(vacía si no se conoce la VLAN de sus equipos). Los fabricantes por puerto salen del inventario, no de una tabla OUI.
El formato de cada comando viene de una sesión real de un C9200L (IOS-XE 17.15): otros modelos o versiones
pueden variar.

Con la running-config, el análisis suma seis hallazgos de higiene del switch («segun la configuracion del switch»),
cada uno con sus referencias en los cinco marcos y su playbook: VLAN que el SPAN no espeja, gestión por HTTP o
Telnet, credenciales con cifrado reversible o en texto, autenticación local sin AAA, puertos de acceso sin uso y sin
`shutdown`, y VLAN 1 en uso o como nativa. La evidencia nombra el switch y los elementos; de las credenciales solo se
cuentan por tipo. Es evidencia de la configuración, no una evaluación de cumplimiento.

Tres hallazgos más completan los de capa 2 (D73): **controles de capa 2 ausentes en puertos de acceso** (BPDU guard,
storm-control de broadcast, port-security por puerto; DHCP snooping e inspección ARP globales; el BPDU guard global
cuenta en los puertos portfast), **troncales que negocian con DTP** (sin `switchport nonegotiate`, o puertos en
`dynamic auto|desirable`; un puerto sin `switchport mode` se lista como «no se pudo determinar», no se supone) e
**inestabilidad de STP o MAC flapping** (Alta con cambios de topología recientes —últimas 24 h y al menos 3 en la
instancia— o MAC flapping en el log; Media con muchos cambios antiguos, err-disable o contadores altos). Cada uno
dice qué se evaluó y qué no (sin running-config, sin interfaces en ella, o sin las salidas de estado). El root guard
y el modo STP solo se muestran como contexto.

Cuatro hallazgos más salen del estado del switch (T10c, ajusta D73): **bucle físico entre puertos del switch contenido
por STP** (de `show spanning-tree detail`: un puerto en rol `backup`, o bloqueado cuyo puente designado es el propio
switch, recibe BPDU propias; se nombra el puerto par de la misma VLAN, las BPDU recibidas y los cambios de topología;
Alta si alguno de los dos es de acceso con portfast y sin BPDU guard, Media si no), **el puerto destino del espejo
(SPAN) descarta paquetes** (OutDiscards de `show interfaces counters errors` o `Total output drops` de
`show interfaces` en el destino de `monitor session`; con paquetes de salida da el porcentaje sobre lo que le tocaba
enviar; la captura de ese puerto está incompleta; va en la categoría Visibilidad junto a la cobertura del espejo),
**hora del switch sin sincronizar** (la mayoría de las líneas fechadas de `show logging` empieza con `*`, o con `.`
si se perdió la sincronía; con `ntp server` en la configuración dice «NTP configurado pero el reloj no está
sincronizado», sin él «sin NTP») y **puente raíz de STP sin prioridad fijada** (el switch es raíz de VLAN con la
prioridad de fábrica 32768). Del registro solo se cuentan líneas: no se guardan usuarios, IP de sesiones ni otros
mensajes. Los contadores son acumulados desde el arranque o el último `clear`. Formato de las salidas tomado de la
documentación de IOS; sin validar con una muestra real.

### Switches Aruba AOS-CX

`--switch` lee la sesión de terminal guardada de un Aruba AOS-CX (6000/6100/6200/6300/6400/8xxx; se detecta por
`show version`/`show system` de AOS-CX o por `show mac-address-table`). Si la sesión trae `show running-config`
(AR2, D99) se leen puertos, VLAN, espejo, gestión, AAA, NTP y STP, y la higiene evalúa solo BPDU guard en capa 2
(sin DTP; storm-control, port-security, DHCP snooping e inspección ARP quedan «no evaluados»); sin ella la higiene
dice «No evaluado». Ninguna línea con `password ciphertext`, `key ciphertext` o comunidades SNMP se guarda ni se
cita: solo se cuentan. Comandos a recolectar (acepta abreviaturas; `no page` evita el paginador):

```
no page
show system
show version
show interface
show vlan
show mac-address-table
show lldp neighbor-info detail
show mirror
show mirror 1          (uno por cada sesión habilitada del resumen)
show spanning-tree
```

`show interface` da puertos, modo (`VLAN Mode`, VLAN de acceso, nativa y permitidas), LAG con sus miembros, SVI y
contadores (use la salida sin `human-readable`; con ella el puerto se ignora y se avisa). `show interface brief`
solo completa puertos que `show interface` no trajo. `show cdp neighbor-info` suma vecinos. Sin `show mirror` (o con
una sesión habilitada sin su detalle) el espejo de las VLAN queda desconocido, como con SNMP, y no entra en «VLAN sin
espejo». Una sesión con `Admin Status: disable` o sin operación `enabled` no cuenta y se avisa.

### Switches por recorrido SNMP

`--switch` también acepta un recorrido de `snmpwalk`/`snmpbulkwalk` (un archivo por switch; se detecta por las
líneas `OID = valor`). La herramienta no consulta SNMP: lee un archivo de texto que el analista ya generó, de
cualquier fabricante que exponga MIB estándar (Aruba, Hirschmann, SCALANCE, Moxa, Cisco...). Comandos de referencia
(SNMPv3 recomendado; la comunidad o la clave quedan en la terminal, nunca en el archivo):

```
for ARBOL in 1.3.6.1.2.1.1 1.3.6.1.2.1.2 1.3.6.1.2.1.31 1.3.6.1.2.1.17 1.3.6.1.2.1.47.1.1.1.1 \
              1.3.6.1.2.1.10.7.2 1.0.8802.1.1.2; do
  snmpbulkwalk -v3 -l authPriv -u USUARIO -a SHA -A ... -x AES -X ... -On IP_SWITCH $ARBOL >> sw1.walk
done
```

Se lee: `sysName`, ENTITY-MIB (modelo y versión del chasis), IF-MIB (nombre, alias, estado y contadores: errores,
descartes, paquetes, difusión, velocidad), EtherLike-MIB (CRC), tabla MAC (Q-BRIDGE; sin ella BRIDGE-MIB con VLAN
desconocida), VLAN, PVID y pertenencia por puerto (etiquetado = `trunk`, solo sin etiquetar = `access`), vecinos
LLDP y STP (raíz, prioridad, cambios de topología). Se admite `-On` (recomendado) y la salida simbólica con índice
numérico; los índices entre corchetes (`-OX`) no se leen. Una línea que no es `OID = valor` (por ejemplo el
comando con la comunidad) se descarta sin guardarla ni citarla; el aviso solo da el conteo. Sin running-config ni
sesiones SPAN: la higiene de configuración dice «No evaluado» y el espejo de las VLAN queda desconocido
(`espejada_span` vacío; no entra en «VLAN sin espejo»).

### Rutas del firewall

`--rutas-firewall` (también en `diagrama`) acepta tres formatos, detectados por contenido:

```text
# 1. Tabla CSV/XLSX: columna de interfaz (interfaz, interface, nameif) y de red (red_cidr, cidr, red +
#    mascara o prefijo); zona, siguiente_salto y tipo son opcionales. Ejemplo: docs/ejemplos/rutas_firewall.csv
Interfaz,Zona,CIDR
OT-NET,Planta,10.0.0.0/8

# 2. Comandos route de Cisco ASA
route OT-NET 10.0.0.0 255.0.0.0 10.10.15.1 1

# 3. Salida de show route (recomendada: trae las rutas conectadas, C y L)
C        10.10.15.0 255.255.255.0 is directly connected, OT-NET
S        10.130.0.0 255.255.0.0 [1/0] via 10.130.0.254, PROCESO
```

Cada IP toma la interfaz de la ruta de prefijo más largo (empate entre interfaces: la primera del archivo,
con aviso); `sin ruta` si ninguna la contiene; `el firewall (<interfaz>)` si es una IP local (tipo `L`).
Una IP que solo casa con la ruta por defecto (`0.0.0.0/0`) cae en `<interfaz> (ruta por defecto)`, fila
propia: así Internet no se mezcla con la red interna de esa interfaz. Es inferencia desde la tabla de
rutas, no desde la política: no dice que el tráfico esté permitido. Sin rutas conectadas, las redes de
tránsito pueden quedar en la interfaz equivocada.

Salidas: `firewall_interfaces.csv` (interfaz, zona, redes, rutas, activos, siguientes saltos) y
`firewall_matriz.csv` (pares de interfaces con conductos, servicios, bytes, orígenes y destinos), hojas
`FW interfaces` y `FW matriz` del libro, columnas `interfaz_firewall` (inventario) y `if_origen`,
`if_destino`, `cruza_firewall` (comunicaciones), y la sección «Flujos entre interfaces del firewall» en
HTML, Markdown y Word (los 20 pares con más conductos; el resto, en el CSV). Con esta opción los
diagramas se agrupan por interfaz (nombre de la interfaz y, si la tabla trae zona, la zona entre
paréntesis) salvo que se pida otra agrupación con `--agrupar` en `diagrama`.

## Qué genera

| Archivo | Contenido |
|---|---|
| `reporte_ot.html` | Reporte presentable a cliente. Autocontenido, imprimible a PDF en horizontal. |
| `reporte_ot.md` | El mismo contenido en Markdown, para anexo técnico. |
| `diagrama_zonas.svg` | Zonas y conductos: una caja por nivel Purdue y los conductos que las cruzan. Incrustado en el HTML. |
| `diagrama_red.svg` | Comunicaciones por activo, por banda de nivel Purdue, con la criticidad de cada conducto. Incrustado en el HTML. |
| `diagrama_*.mmd` | Los mismos diagramas en Mermaid, editables (GitHub, GitLab, Notion, draw.io). |
| `diagrama_*.drawio` | Los mismos diagramas como archivo de draw.io (diagrams.net), con las mismas bandas, equipos y conductos y la misma disposición, para que el cliente los retoque. XML sin comprimir. |
| `informe_ot.docx` | Informe editable en Word con el mismo contenido sustantivo que el HTML (perfil, resumen, hallazgos con referencias, inventario y comunicaciones recortados a `--max-rows`, firewall, cobertura, preguntas y entorno). Incluye los diagramas de red y de zonas incrustados como SVG (Word 2016 o posterior; en otros editores, abra el `.svg` o el `.drawio`). |
| `resumen_ejecutivo.html` | Resumen ejecutivo de una página impresa (tamaño carta) para directivos: alcance, hallazgos por severidad y por fase, y los cinco riesgos principales en el orden del registro de riesgos (probabilidad x impacto, mismo orden que `riesgos.csv`) con su recomendación recortada. Autónomo, sin diagramas. No es una evaluación de cumplimiento. El subcomando `diagrama` también lo genera (sin la línea de capturas). |
| `resumen_ejecutivo.docx` | El mismo resumen ejecutivo en Word. |
| `reporte_ot.xlsx` | Libro de Excel con las hojas Inventario, Comunicaciones, Hallazgos, Plan de remediacion, DNS registros, DNS resoluciones, DNS servidores, Control, Identidad y Cobertura de cada marco; mismo contenido que los CSV, sin `activos.csv` ni `flujos.csv`. |
| `inventario.csv` | Un renglón por activo: nombre, IP, MAC, fabricante, modelo, firmware, rol y zona. La última columna, `nombre_dns`, trae el nombre DNS de la primera IP del activo que tenga uno. Si la captura se tomó detrás de un enrutador, la MAC que junta muchas IP (o varias con alguna pública) se presenta como una fila por IP: la MAC queda solo en la IP que responde ARP con ella y las demás llevan la columna `mac_salto` (D105); `activos.csv` sigue por MAC. Con filas partidas, la columna `activos` de `zonas.csv` (y la sección Zonas de los reportes) cuenta esas mismas filas (D107); la línea base y los conductos usan la zona de cada activo. |
| `comunicaciones.csv` | Matriz de comunicaciones completa, un renglón por conducto. La última columna, `nombre_dns`, trae el nombre DNS de la IP de destino (hasta 2, de DNS A/AAAA, PTR, TLS SNI o HTTP Host, en ese orden); en el HTML va bajo la IP de destino. |
| `dns_registros.csv` | Un renglón por nombre y tipo consultado: consultas, respuestas, consultas sin respuesta, rcodes, TTL mínimo, registros devueltos, clientes, servidores, ámbito (interno o externo) y capturas. También hoja `DNS registros`. |
| `dns_resoluciones.csv` | Relación IP-nombre observada y su fuente (DNS A, AAAA, PTR, TLS SNI, HTTP Host). También hoja `DNS resoluciones`. |
| `dns_servidores.csv` | Un renglón por servidor DNS: ámbito, consultas, respuestas, rcodes y clientes. También hoja `DNS servidores`. La sección «Resolucion de nombres (DNS)» del HTML, Markdown y Word (tras los hallazgos) resume estas tres tablas; sin tráfico DNS dice «No se observo trafico DNS.». |
| `identidad.csv` | Cada dato de identidad observado y de qué paquete salió. |
| `control.csv` | Cada operación de escritura o comando, con número de trama. La última columna, `clase`, es la clase de ingeniería (D92): `descarga`, `carga`, `modo`, `reinicio`, `firmware`, `forzado`, `configuracion`, `escritura` o vacía. |
| `eventos_ingenieria.csv` | Una fila por sesión de ingeniería (D92): operaciones de clase descarga, carga, modo, reinicio, firmware, forzado o configuración con la misma captura, origen, destino, protocolo y clase, sin huecos de más de 300 s: `captura`, `inicio`, `fin` (UTC, `AAAA-MM-DDTHH:MM:SSZ`, como `periodicidad.csv`), `origen`, `destino`, `protocolo`, `clase`, `operaciones` (las 5 más frecuentes), `tramas`, `primera_trama` y `tecnica_mitre`. Responde «quién descargó lógica o paró un PLC, cuándo y desde dónde». PROFINET DCP Set (cambio de IP o de nombre de estación, restablecer a fábrica; D102) entra con la MAC en `origen` y `destino`, porque DCP no usa IP. Sin eventos, solo la cabecera. Sin hoja en el Excel. |
| `periodicidad.csv` | Un renglón por conducto de sondeo o de eventos con carga útil: peticiones, periodo medio, CV, hueco máximo y cuándo, primera y última carga (UTC), patrón y marcas (`hueco`, `termina_antes`, `aparece_tarde`). Sin hoja en el Excel. |
| `acceso_remoto.csv` | Un renglón por indicador (activo cliente, herramienta, método, indicador) de acceso remoto de terceros: `activo`, `ip`, `herramienta`, `estado_indicador` (`verificado`, `sin verificar` o `descartado`: puerto hacia un destino con más de 100 puertos distintos, explicado en `nota`, última columna), `metodo` (puerto, DNS, SNI, HTTP, dominio exportado), `indicador`, `destino` (Internet, interno o sin determinar), `destino_ip`, `ambito` (OT o IT), `conductos`, `bytes`, `primera`, `ultima`, `fuente` y `nota` (por qué se descartó: destino con más de 100 puertos distintos). En `diagrama` solo se escribe si hay indicadores. Sin hoja en el Excel. |
| `hallazgos.csv` | Hallazgos con evidencia y recomendación. La primera columna, `id`, es el ID estable del hallazgo: `H-` y los seis primeros hexadecimales del SHA-256 del título en español, igual en cualquier corrida, idioma y sitio. El mismo ID sale junto al título en HTML, Markdown y Word y en la columna `id_hallazgo` (primera) de `plan_remediacion.csv`. |
| `attack_ics_cobertura.csv` | Matriz de ATT&CK for ICS v20.1 (AT2, D115): una fila por par táctica-técnica vigente, con `con_regla` (la herramienta puede citarla con su mapeo propio sin revisar; no implica detección ni protección), referencias que la citan, hallazgos de esta corrida y sus títulos. Hoja `ATT&CK ICS cobertura`. Ver «Tácticas y matriz de cobertura». |
| `iec62351_evidencia.csv` | Evidencia observable de IEC 62351 por protocolo (E62351, D117): una fila por IEC 60870-5-104, DNP3, MMS, GOOSE, SV y control de acceso por roles (-8), más una por cada protocolo OT que la tabla no cubre y que se vio (`no aplica`). Columnas `partes_62351`, `observado`, `conductos_en_claro`, `conductos_puerto_seguro`, `tls_confirmado`, `autenticacion_segura` (solo DNP3), `evidencia` y `nota`. Toda corrida con capturas. Hoja `IEC 62351 evidencia`. Ver «Evidencia observable de IEC 62351». |
| `csf_transicion.csv` | Transición oficial de NIST CSF 1.1 a 2.0 (CSFT, D116): una fila por fila de la hoja oficial de NIST (211), con `csf11` (vacío en los 12 elementos nuevos), `reubicacion`, `modificaciones`, `csf20`, `nueva_en_csf20`, `hallazgos_en_esta_corrida` y `titulos`. Solo si la corrida incluye `nist-csf` en `--estandar`. Hoja `CSF 1.1 a 2.0`. Ver «Transición de NIST CSF 1.1 a 2.0». |
| `riesgos.csv`, `mapa_calor_riesgo.csv` | Registro de riesgos (R1, D83): un renglón por hallazgo (mismo título; la Informativa queda fuera) con probabilidad (1-5), impacto (1-5) en una dimensión, puntuación P × I, nivel (1-4 Bajo, 5-9 Medio, 10-16 Alto, 20-25 Muy alto), técnicas MITRE ATT&CK for ICS, esfuerzo estimado, `quick_win` (nivel Alto o Muy alto con esfuerzo bajo) y `origen` (`inferido` o `analista`). La probabilidad parte de la severidad (Alta 4, Media 3, Baja 2) y sube 1 si algún activo es objetivo o paso de un camino de rutas de ataque desde Internet o IT, o el hallazgo involucra una CVE en KEV. El impacto sale de `zonas[].impacto` del perfil (seguridad, ambiente, produccion, financiero, reputacion, regulatorio; enteros 1-5; manda el máximo de las zonas de los activos) o, sin él, se infiere de la criticidad del activo («produccion (inferida)»; requiere validación con el cliente). **Método propio con heurísticas sin calibrar; el esfuerzo de cada playbook es una estimación propia sin revisar.** No cambia el plan de remediación. `mapa_calor_riesgo.csv` es la matriz 5×5 (cuadrícula con color en la hoja `Mapa de calor de riesgo` del libro, y en HTML, Word y Markdown). `ajustes_riesgo` del perfil permite corregir: `{"H-xxxxxx": {"probabilidad": 2, "impacto": 4, "justificacion": "texto"}}` (justificación obligatoria; un ID que no aparece en la corrida solo avisa). Sección «Registro de riesgos y mapa de calor» (nota del método, mapa, 10 riesgos principales y quick wins), hojas `Registro de riesgos` y `Mapa de calor de riesgo` y clave `riesgos` de `resultado.json`. El subcomando `diagrama` también lo genera. |
| `plan_remediacion.csv` | Plan de remediación (también hoja `Plan de remediacion` del libro y sección «Plan de remediacion» del HTML, Markdown y Word, tras los hallazgos). Prioriza los hallazgos de severidad Alta, Media y Baja en fases Inmediato, Corto plazo y Mediano plazo con un método propio (severidad × criticidad del activo), no de un estándar. La columna `playbook` trae el id del playbook del hallazgo (vacía si no tiene) y las secciones «Playbooks de remediacion» del HTML, Markdown y Word traen, en el orden del plan, solo los de los hallazgos presentes: qué hacer, en qué orden, por plataforma, cómo verificar y revertir y qué precauciones tomar en OT. Son guía genérica y no sustituyen el procedimiento de cambios del cliente ni la documentación del fabricante. La columna `esfuerzo` queda vacía: la anota el analista en el CSV o en el Excel. El subcomando `diagrama` también lo genera. |
| `flujos.csv`, `activos.csv` | Detalle por captura, sin consolidar. |
| `firewall_contraste.csv`, `firewall_reglas_sin_trafico.csv` | Solo con `--reglas-firewall` (también hojas `Firewall` y `Reglas sin trafico` del libro, y sección en el reporte). Resultado por conducto (`sin_regla`, `denegado_observado`, `permitido`) y reglas de permitir que no casaron con tráfico. |
| `evasion.csv` | Un renglón por indicador de canal que evade la inspección (T9): `activo`, `ip`, `tipo` (`doh`, `doq`, `tor`, `vpn`, `tunel`, `proxy`, `canario_doh`), `herramienta_o_servicio`, `estado_indicador` (`verificado`, `sin verificar` o `descartado`), `metodo` (puerto, DNS, SNI, HTTP, dominio exportado, IP y puerto, lista de relays Tor, protocolo), `indicador`, `destino`, `destino_ip`, `ambito`, `conductos`, `bytes`, `primera`, `ultima`, `fuente` y `nota` (por qué se descartó: destino con más de 100 puertos distintos). En `diagrama` solo se escribe si hay indicadores. Sin hoja en el Excel. |
| `vulnerabilidades.csv` | Solo con `--vulnerabilidades` (también hoja `Vulnerabilidades` del libro). Una fila por vulnerabilidad importada con su activo y cómo se asoció (`asociado_por`); las no asociadas, al final con `activo` vacío. Con `--kev` y `--avisos-ics` suma al final seis columnas (`kev`, `kev_fecha_agregada`, `kev_fecha_limite`, `kev_ransomware`, `avisos_ics`, `remediacion_fabricante`); vacías si no se dio la opción. |
| `avisos_ics.csv` | Solo con `--avisos-ics` y al menos un cruce por CVE. Una fila por aviso (`aviso`, `titulo`, `publicado`, `actualizado`, `url`, `cves`, `activos`, `abiertas`, `cvss_max`, `cvss_v4_max`, `remediaciones`), por CVSS v3 máximo descendente. `cvss_v4_max` es informativa: la calcula la herramienta (D113). |
| `vulnerabilidades_firmware.csv` | Solo con `--avisos-ics` o `--catalogo-vulnerabilidades` y al menos un candidato (también hoja `Vulnerabilidades por firmware`). Una fila por activo y CVE: `activo`, `ip`, `fabricante`, `modelo`, `firmware`, `procedencia`, `cve`, `cvss`, `severidad`, `cvss_v4`, `vector_cvss_v4` (CVSS v4.0, informativas y vacías sin v4: la severidad y el orden siguen con v3; CISA no trae v4 como campo en CSAF 2.0 y se calcula del vector de una referencia o nota, o de las columnas `cvss_v4`/`vector_cvss_v4` del catálogo; con vector y puntuación distintos gana el calculado; D113), `aviso`, `producto_aviso`, `version_afectada`, `coincidencia`, `estado` (`version afectada`, `version no comparable: revisar`, `sin firmware: posible`), `kev` (con `--kev`), `en_plataforma` (el mismo CVE ya llega por `--vulnerabilidades`), `remediacion`, `fuente` y cuatro columnas de revisión vacías. Un firmware fuera del rango no se lista (se cuenta en la nota). |
| `alertas.csv` | Solo con `--alertas` (también hoja `Alertas` del libro). Una fila por alerta importada con `conducto_observado` (si/no) y los activos de origen y destino por IP. |

| `resultado.json` | Todo lo anterior, para alimentar otra herramienta: objeto con `entorno` (versiones, campos ignorados, SHA-256 de cada captura) y `capturas` (D23). |

Toda celda de texto de los CSV que empieza con `=`, `+`, `-`, `@`, tabulador o retorno de carro lleva un apóstrofo al
inicio, para que la hoja de cálculo no la ejecute como fórmula (los números y el marcador `-` quedan igual).

## Qué analiza

**Inventario.** Fabricante por OUI, hostname (DHCP, NetBIOS, CDP, LLDP, SMB),
modelo y firmware cuando el equipo los anuncia (V1b, D90: también cuando los
reporta en su propio protocolo OT, sin sondeo activo: respuesta ListIdentity y objeto
Identity de CIP, Read Device Identification de Modbus, SZL 0x0011/0x001C de S7comm
y Identify de PROFINET DCP; el fabricante que reporta el protocolo gana sobre el
OUI, y el modelo y firmware de CDP ganan sobre los del protocolo OT. Los ID de
fabricante se traducen con `ot_assess/data/fabricantes_ot.json`, ampliable; un ID
que no está sale como «CIP vendor N» o «PROFINET vendor N» y no se cruza con los
avisos). Rol y nivel Purdue inferidos del
comportamiento: qué puertos atiende, cuáles consulta y qué protocolos habla.

**Diagramas.** Dos vistas del mismo análisis, en SVG sin dependencias externas.
La de zonas y conductos escala a cualquier red y es la que se contrasta con el
modelo de IEC 62443. La de activos muestra cada equipo en su nivel, con el color
del trazo según la criticidad del conducto y la marca `W` en quien recibe
escrituras. En redes grandes se recorta a los equipos y trazos de mayor riesgo, y
el diagrama lo indica; el detalle completo queda en los CSV.

**Matriz de comunicaciones.** Un renglón por relación origen → destino →
servicio, con volumen, sentido, si cruza zonas y si transporta escrituras. La
criticidad combina esos factores. Incluye una vista de rejilla cuando el número
de activos lo permite.

**Protocolos OT.** Modbus/TCP, DNP3, IEC 60870-5-104, IEC 61850 (MMS, GOOSE, SV),
EtherNet/IP y CIP, S7comm, PROFINET, BACnet, OPC UA, FINS, MELSEC, GE SRTP y
PTP, entre otros.

**Operaciones de control.** Separa lectura de escritura. Detecta escrituras CIP
(incluidas las anidadas en Multiple Service Packet), funciones de escritura
Modbus, Operate y Direct Operate de DNP3, comandos IEC-104, y descarga, arranque
o paro de PLC en S7comm. Cada operación se cuenta una sola vez, en la petición.

**Seguridad de protocolo (T4).** Cuatro hallazgos propios: OPC UA con política de
seguridad None (Alta si el servidor también recibe Write o Call), TLS obsoleto o con
suite débil negociada (solo el ServerHello: SSL 3.0, TLS 1.0/1.1, NULL, EXPORT,
anónimas, RC4, DES, 3DES; Alta en equipos OT o niveles Purdue 0-2), Modbus FC 8 con
subfunción 1 o 4 que reinicia o silencia el equipo (Alta; las demás subfunciones, Baja)
y DNP3 Cold Restart, Warm Restart o Stop Application (Alta). Detalle en D54.

**Periodicidad (T5).** Sin plataforma OT, saca de la captura lo que una plataforma ve con series de tiempo.
Por cada conducto de sondeo (Modbus/TCP, S7comm, EtherNet/IP, BACnet/IP, OPC UA, FINS, MELSEC) calcula el
periodo medio y el coeficiente de variación (CV) de los intervalos entre peticiones con carga útil (los ACK no
cuentan) y lo clasifica: `periodico` (CV < 0.3), `variable`, `irregular` (CV >= 0.6) o `esporadico` (menos de 30
intervalos). Marca `hueco`, `termina_antes` y `aparece_tarde`. DNP3 e IEC 60870-5-104 mandan eventos
espontáneos: no se clasifican por regularidad (patrón `evento`). Tres hallazgos: pérdida de comunicación en un
conducto periódico (Alta si el conducto lleva escrituras o va a nivel 0-1; si no, Media), sondeo irregular
(Baja) y escritor de control que aparece a mitad de la captura (Alta; capturas de al menos 10 minutos). Es
evidencia técnica de una captura, no cumplimiento; un hueco puede ser una maniobra o el corte de la captura.
Salida `periodicidad.csv`. Umbrales y límites en D65.

**Acceso remoto de terceros (T8).** Detecta herramientas de soporte de proveedores y RMM (TeamViewer, AnyDesk,
RustDesk, ScreenConnect, Splashtop, LogMeIn/GoTo, BeyondTrust, Chrome Remote Desktop, Zoho Assist, DWService),
que casi siempre viajan por 443. Por nombre (consulta DNS, SNI de TLS, Host de HTTP y, en `diagrama`, la columna
de dominios del destino de xDome) y por los puertos propios de la herramienta; 80 y 443 solos nunca cuentan. El
nombre coincide por sufijo con límite de etiqueta (`x.teamviewer.com` sí; `teamviewer.com.evil.net` y
`noteamviewer.com` no). Un hallazgo agregado «Herramienta de acceso remoto de terceros en la red»: Alta si algún
cliente es OT (nivel Purdue 0-2) o el conducto llega a un equipo OT; si no, Media. El catálogo es
`ot_assess/data/acceso_remoto.json` (por herramienta: dominios, puertos, fuente y estado `verificado` o
`sin verificar`; la evidencia marca los indicadores sin verificar). Los puertos verificados se suman a «acceso
remoto» en cruces del firewall, rutas de ataque y conductos entre zonas. Salida `acceso_remoto.csv`. Es evidencia
técnica de que alguien usa o intenta usar la herramienta, no prueba una sesión ni que no esté autorizada. D68.

**Canales que evaden la inspección (T9).** DNS cifrado (DoH y DoQ), Tor, VPN, túneles y proxies hacia Internet, que
saltan el DNS interno, la segmentación y la inspección del firewall. Por nombre (DNS, SNI, Host de HTTP, dominios de
xDome), por IP de resolvedores públicos conocidos con TCP o UDP 443, por puerto (DoQ UDP/853, OpenVPN 1194, IKE 500,
NAT-T 4500, L2TP 1701, PPTP 1723, WireGuard 51820, SOCKS 1080, Squid 3128), por protocolo (GRE y ESP) y, con
`--tor-relays`, por IP de relay Tor. Puertos y protocolos solo cuentan hacia IP públicas, y un destino con más de 100
puertos distintos queda `descartado`. DoT (TCP/853) sigue en «DNS cifrado sin visibilidad (DoT)» y no se duplica; el
dominio canario de Firefox (`use-application-dns.net`) es solo indicio y va como nota. Dos hallazgos agregados: «DNS
cifrado hacia resolvedores externos (DoH o DoQ)» (Media si algún cliente es OT o el conducto llega a OT; si no, Baja) y
«Canal anonimizador o túnel hacia Internet (Tor, VPN o proxy)» (Alta con OT; si no, Media). Catálogo con fuente y estado
en `ot_assess/data/evasion.json`; salida `evasion.csv` (en `diagrama` solo si hay indicadores). Límites: Encrypted
Client Hello oculta el SNI, y los puentes Tor ofuscados y un DoH propio no se distinguen de HTTPS. Evidencia técnica,
no prueba una sesión ni que no esté autorizada. D71.

**Ataques de capa 2 y bucles (T10a).** Ocho hallazgos que una captura pasiva desde un SPAN alcanza a ver, además del
conflicto ARP, el barrido ARP y los cambios de topología STP que ya existían: «Más de un servidor DHCP respondiendo en
el segmento» (Alta; OFFER o ACK de más de un identificador de servidor), «Cambio del puente raíz de STP durante la
captura» (Alta; la raíz se sigue por VLAN porque PVST+ trae una por VLAN) y «BPDU enviadas por un equipo que no es
switch» (Alta; el origen de la BPDU también origina tráfico IP y no es de un fabricante de equipo de red),
«Indicios de salto de VLAN (doble etiqueta o DTP)» (Media), «Redundancia de puerta de enlace (HSRP/VRRP) sin
autenticación» (Media; texto claro o ninguna, o prioridad 255 desde un equipo que no fue el primero del grupo),
«Anuncios de router IPv6 no esperados» (Media; RA desde un equipo que no es de red, o en una red sin otro uso de IPv6),
«Posible inundación de la tabla MAC del switch» (Alta; más de 200 MAC de origen nuevas en 10 s, sin contar los primeros
30 s de la captura y con la mayoría de ellas con tres paquetes o menos) y «Indicios de bucle de capa 2 o de
enrutamiento» (Alta; difusión o multicast de al menos 1000 paquetes por segundo durante 3 s seguidos, el mismo paquete
IP visto con TTL decreciente al menos 4 veces en 5 paquetes, o 50 ICMP time exceeded en un segundo; los cambios de
topología STP y los duplicados de editcap solo acompañan, nunca disparan por sí solos). Los umbrales son constantes
con nombre (D72). Evidencia técnica de una captura: cada hallazgo dice también qué configuración legítima produce lo
mismo (par HSRP de respaldo, QinQ de proveedor, un switch industrial no reconocido, una captura desde varios puntos).

**Hallazgos.** Alrededor de veinte reglas: protocolos de descubrimiento de
Windows en la red de control, credenciales en texto claro, SNMP v1/v2c, software
fuera de soporte, direcciones APIPA, salida a Internet, subredes conviviendo en
un mismo dominio de difusión, conflictos de ARP, barridos y escaneos, tormentas
de difusión e inestabilidad de STP.

Cada hallazgo incluye una referencia orientativa a MITRE ATT&CK for ICS e
IEC 62443-3-3 (un JSON por marco en `ot_assess/marcos/`). Es un mapeo editable, no una
evaluación de cumplimiento: ajústalo al criterio del proyecto.

**Brecha de visibilidad.** Trunca­miento de captura, SPAN unidireccional, punto
que solo ve difusión, ausencia de paquetes de identidad, tráfico dominado por
I/O cíclico, ventana corta y pérdida de etiquetas VLAN. Cuando se analizan
varias capturas, compara qué alcanza a ver cada punto. El veredicto por punto de captura
(`validar-captura`, abajo) mide además la pérdida del espejo y las sesiones de un solo sentido.

## Estándares de referencia

Cada hallazgo se mapea a MITRE ATT&CK for ICS (siempre) y a los marcos que se elijan:

```bash
python ot_pcap_assess.py capturas/ -o reporte/ --estandar nerc-cip
python ot_pcap_assess.py capturas/ -o reporte/ --estandar iec62443,nerc-cip,nist-800-82
```

| Clave | Marco | Qué cambia |
|---|---|---|
| `iec62443` | IEC 62443 (requisitos SR de la parte 3-3 y la 2-3) | Los conductos que cruzan zonas se presentan "según el modelo de zonas y conductos". |
| `nerc-cip` | NERC CIP (CIP-005, -007, -010, -015) | Se presentan como candidatos a Puntos de Acceso Electrónico (EAP) del perímetro (ESP). |
| `nist-800-82` | NIST SP 800-82 Rev. 3 / controles SP 800-53 Rev. 5 | Se presentan como control de frontera entre zonas (SC-7). |
| `nist-csf` | NIST CSF 2.0 (subcategorías; la función es el prefijo) | Se presentan como protección de redes (PR.IR-01). Govern (GV) no tiene evidencia en el tráfico. |
| `tsa-sd-1580-82` | TSA SD 1580/82-2022-01E, sección III (derivado de SP 800-53, TSA2) | Se presentan como medida técnica de frontera entre zonas (III.B.1.b). Sin revisar. |

`ot_assess/marcos/iec62443_niveles.json` (módulo `niveles62443.py`, D75) es el catálogo de requisitos y niveles de seguridad
de ISA/IEC 62443: FR, SR y RE de la 3-3 con lo que se pide en SL 1-4, requisitos de componente (4-2), ZCR (3-2) y madurez y SPR
(TR 2-2). Solo ids y títulos propios; lo genera `scripts/extraer_niveles_62443.py` desde `normas/` y no afirma cumplimiento.

Con varios marcos, `hallazgos.csv` trae una columna por marco y el reporte los lista todos; el
primero rige la redacción.

**El mapeo es orientativo, no una evaluación de cumplimiento.** Relaciona cada hallazgo con el
requisito más cercano; cada marco lleva su aviso de alcance en el reporte. En NERC CIP se cita el
requisito sin número de versión, y su aplicabilidad depende de la categorización CIP-002 de los
activos, que no se puede inferir del tráfico. Los hallazgos sobre calidad de la captura no se
mapean a ningún marco, a propósito.

**Marco propio** (por ejemplo, una norma local) sin tocar el código: un JSON y `--estandar-archivo`.

```json
{
  "clave": "mi-norma",
  "nombre": "Norma técnica X",
  "cruce": "en los puntos de control definidos por la norma X",
  "alcance": "Las referencias a la norma X son orientativas.",
  "referencias": {
    "texto claro": "Art. 12; Art. 14",
    "IP publicas": "Art. 20"
  }
}
```

Cada clave de `referencias` es un fragmento (sin distinguir mayúsculas) del título del hallazgo;
los títulos están en `hallazgos.csv`. Luego: `--estandar-archivo mi-norma.json --estandar mi-norma`.

**MITRE ATT&CK for ICS v20.1.** `ot_assess/marcos/attack_ics.json` es un catálogo compacto (ids, nombres y tácticas;
sin descripciones) sacado del STIX oficial de MITRE; una prueba impide citar un id que no esté vigente en él. T0855
y T0857 están revocadas desde v19: se citan T1692.001 (Unauthorized Message: Command Message) y T1693.001 (Modify
Firmware: System Firmware). El mapeo hallazgo -> técnica sigue siendo propio ("sin revisar"). Para una versión
nueva: descarga `ics-attack-<versión>.json` de `mitre-attack/attack-stix-data` y ejecuta
`python3 scripts/actualizar_attack_ics.py ics-attack-<versión>.json` (con `--check` solo compara).

**Tácticas y matriz de cobertura de ATT&CK for ICS (AT2, D115).** `hallazgos.csv` agrega `mitre_ics_tacticas` tras
`mitre_ics`: nombres oficiales (en inglés en ambos idiomas) de las tácticas de las técnicas citadas, sin repetir y en
el orden de la matriz. `attack_ics_cobertura.csv` (hoja `ATT&CK ICS cobertura`) tiene una fila por par táctica-técnica
vigente (una técnica con dos tácticas sale dos veces) con `con_regla` (`si` si algún texto de `mitre-ics.json` la
cita), `referencias_que_la_citan`, `hallazgos_en_esta_corrida` (agrupados por título y severidad, como el reporte) y
`titulos`. **`con_regla = si` significa que la herramienta puede citar la técnica con su mapeo propio, sin revisar; no
que la detecte siempre ni que el cliente esté protegido.** Solo CSV y libro, no hay sección en HTML/Word/Markdown.

**Transición de NIST CSF 1.1 a 2.0 (CSFT, D116).** `ot_assess/marcos/csf_transicion.json` es la hoja oficial de NIST
«CSF 1.1 to 2.0 Core Transition Changes» (2024-09-19; obra del gobierno de EE. UU., dominio público, 17 U.S.C. 105) sin
los Implementation Examples ni los SORT-ID. Se regenera con `python3 scripts/actualizar_csf_transicion.py ARCHIVO.xlsx`
(con `--check` solo compara; el xlsx va en `normas/`, que git ignora). `csf_transicion.csv` (hoja `CSF 1.1 a 2.0`) dice,
para cada elemento 1.1, a qué elemento 2.0 pasó y cómo cambió, y cuántos hallazgos de la corrida citan ese id 2.0
exacto (agrupados por título y severidad, como el reporte; una categoría como `GV.OC` no cuenta como sus
subcategorías ni al revés; los ids de función no se cuentan). Un id 1.1 que pasó a varios elementos 2.0 sale en filas
separadas. Los textos oficiales y los valores de reubicación quedan en inglés en ambos idiomas. **El mapeo
hallazgo -> CSF 2.0 sigue «sin revisar»; esto no es un perfil ni una evaluación de CSF.** Solo CSV y libro.

**Evidencia observable de IEC 62351 (E62351, D117).** `ot_assess/marcos/iec62351_protocolos.json` es una tabla propia, «sin
revisar», que dice qué partes de IEC 62351 cubren cada protocolo (-3 TLS sobre TCP/IP, -4 MMS, -5 IEC 60870-5 y DNP3, -6 GOOSE y
SV, -8 roles), su puerto en claro y su puerto seguro. No contiene ni cita texto de la norma (sus términos de uso prohíben
usarlo con IA); el catálogo normativo lo hace el propietario. `iec62351_evidencia.csv` solo reporta lo visible en la captura:
conductos al puerto en claro y al seguro (19998, 19999, 3782), `tls_confirmado` (ServerHello visto desde el puerto seguro;
Wireshark puede no decodificar TLS ahí, por eso van separados), funciones 32, 33 y 131 de autenticación segura de DNP3, y MMS
frente a S7comm en 102/tcp por el protocolo decodificado (no por el puerto). GOOSE, SV y -8 salen como «no evaluable de forma
pasiva» (la extensión de seguridad de 62351-6 no se decodifica). Los protocolos OT fuera de la tabla salen como «no aplica»
solo si se vieron. **No es un dictamen ni dice cumple/no cumple;** no crea hallazgos. Solo capturas, no exportaciones de
plataformas. Solo CSV y libro.

**Evidencia IEC 62351 por flujo (E62351F, D125).** Con la clave de perfil `iec62351_flujos` (`true`, o un objeto
`{"estados": [2 a 10 textos únicos de 1 a 40 caracteres], "inicial": uno de ellos}`; por defecto `por revisar`, `confirmado`,
`no aplica`, `excepcion documentada`) o con `--iec62351-estados ARCHIVO`, la corrida principal y `diagrama` escriben
`iec62351_flujos.csv` (hoja `IEC 62351 flujos`): una fila por flujo (origen, destino, transporte, puerto) de un protocolo del
mapa, con `id_flujo` estable (`F62-` + 10 hex del sha256 de `protocolo|origen|destino|transporte|puerto`; no cambia con el
idioma), `canal`, `tls_confirmado` (con capturas, solo si hubo ServerHello de ese servidor a ese cliente en el puerto seguro),
`autenticacion_segura` (DNP3, por par), `evidencia`, `estado_equipo` (el inicial), `nota_equipo` (vacía) y `nota`. En 102/tcp
solo los pares vistos como MMS cuentan como MMS; los no decodificados salen como «MMS o S7comm (sin decodificar)» y no se
evalúan. GOOSE y SV (capa 2) solo con capturas. Con exportaciones las filas salen con `fuente` = `exportacion` y TLS vacío.
`--iec62351-estados` trae `estado_equipo` y `nota_equipo` de un CSV de una corrida anterior (coma o punto y coma, UTF-8; hasta
20 MB y 100000 filas; cabeceras en español o en inglés): un estado fuera de la lista permitida o un `id_flujo` repetido con
valores distintos termina con código 2 antes de escribir; un estado vacío conserva el inicial; los ids que ya no existen se
cuentan y se avisan. Los estados no se traducen (son del equipo). `resultado.json` lleva el bloque `iec62351_flujos`. Sin la
clave ni la opción no cambia ninguna salida. Mapeo propio sin revisar: evidencia observable, no un dictamen.

**Entregables del proyecto (ENT1, D126).** Clave opcional de perfil `entregables`: `{"catalogo": [...], "mapeo": {...}}`.
`catalogo` lista de 1 a 100 objetos `{"id" (1-20 de A-Z a-z 0-9 . _ -), "nombre" (1-120, sin saltos), "salidas"
(0 a 50 nombres de archivo, admite comodines como `cobertura_*.csv`)}`; ids únicos. `mapeo`: 1 a 2000 entradas
`"marco:requisito"` -> lista de 1 a 20 ids del catálogo. `marco` es una de: `iec62443`, `nerc-cip`, `nist-800-82`,
`nist-csf`, `tsa-sd-1580-82`, `mitre-ics`, `nist-800-53`, `cis`. `requisito` es un id exacto (sin distinguir mayúsculas ni
espacios repetidos) o un prefijo terminado en `*` (`iec62443:SR 1.*`, `nist-csf:PR.*`, `cis:4.*`; un id con mejora como
`AC-2(1)` también casa con el prefijo de su base). Un perfil inválido (marco desconocido, entregable fuera del catálogo,
límites) termina con error de perfil. Con la clave: columna `entregables` al final de `hallazgos.csv` (y su hoja; en
`diagrama`, también `hallazgos_importados.csv`), de `cobertura_<marco>.csv` y de `matriz_controles.csv` (ids del
catálogo, en su orden, separados por `; `); `entregables.csv` (id, nombre, requisitos mapeados, conteo de hallazgos, filas
de cobertura y de matriz, salidas presentes y patrones sin archivo; se escribe al final) y el bloque `entregables` de
`resultado.json`. Equivalencia de la columna `marco` de la matriz: `ISA/IEC 62443` e `ISA/IEC 62443-2-1:2024` =
`iec62443`; `NIST SP 800-82r3` = `nist-800-82` y `nist-800-53` (sus ids son controles SP 800-53); `NIST SP 800-53` =
`nist-800-53`; `CIS Controls v8.1` = `cis`; `CSF 2.0` = `nist-csf`; `TSA SD 1580/82-2022-01E` = `tsa-sd-1580-82`. Se
excluyen con aviso (consola y `resultado.json`) los ids exactos de CSF 1.1 que no existen en 2.0 (con su sustituto de la
transición oficial) y las técnicas ATT&CK revocadas u obsoletas; un id que ningún catálogo reconoce (CSF, 62443, ATT&CK)
se conserva y se cuenta como no reconocido. Solo ids de requisito, sin textos de normas; es trazabilidad documental, no un
dictamen. Sin la clave no cambia ninguna salida.

**Avisos de terceros (MITRE ATT&CK).** Copyright 2015-2026, The MITRE Corporation. MITRE ATT&CK and ATT&CK are
registered trademarks of The MITRE Corporation. The MITRE Corporation (MITRE) hereby grants you a non-exclusive,
royalty-free license to use ATT&CK(R) for research, development, and commercial purposes. Any copy you make for such
purposes is authorized provided that you reproduce MITRE's copyright designation and this license in any such copy.

**Avisos de terceros (calculadora CVSS v4.0).** `ot_assess/cvss4.py` es un port a Python de la calculadora oficial de
FIRST (repo FIRSTdotorg/cvss-v4-calculator: `cvss_score.js`, `cvss_lookup.js`, `max_composed.js`, `max_severity.js`,
`metrics.js`). Se usa para puntuar vectores CVSS v4.0 (columnas `cvss_v4` de `vulnerabilidades_firmware.csv` y
`vulnerabilidades.csv`, `cvss_v4_max` de `avisos_ics.csv`); solo decide severidad y orden con `version_cvss: "4"` en el perfil; la puntuación de entorno por criticidad declarada (CR/IR/AR) es informativa (D120, ver `criticidad_activos`). Licencia BSD-2-Clause:

> Copyright (c) 2023 FIRST.ORG, Inc., Red Hat, and contributors
>
> Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
> following conditions are met:
>
> 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the
>    following disclaimer.
>
> 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
>    following disclaimer in the documentation and/or other materials provided with the distribution.
>
> THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
> INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
> DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
> SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
> SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
> WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
> USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

## Perfil de proyecto

Un JSON por engagement con cliente, sitio, marcos y datos declarados. Ejemplo ficticio y completo:
[`docs/ejemplos/perfil.json`](docs/ejemplos/perfil.json). Lo aceptan el análisis de capturas y el
subcomando `diagrama` con `--perfil`, y reemplaza a `--titulo`, `--cliente` y `--estandar` (combinarlos
termina con error). La clave opcional `idioma` (`es` por defecto, o `en`) fija el idioma de los reportes; `--idioma` la reemplaza.
Limitaciones: `edicion` y `partes`
de cada marco se registran en el reporte, pero el mapeo de hallazgos aún no las distingue (pendiente, B2).
Restricciones de alcance por proyecto (SALP1, D121), ambas opcionales: `subcomandos_deshabilitados` (lista con
`politica-fmc` y/o `solicitud-cambio`; otro valor es error de perfil) y `leyenda_salidas` (texto de 1 a 200 caracteres sin
saltos de línea, que se imprime tal cual, sin traducir, en una línea propia bajo la clasificación en Word, HTML, Markdown y
resumen ejecutivo; el Excel no la muestra). Con la primera, `resultado.json` lleva `restricciones` y esos subcomandos
terminan con código 2 sin escribir nada. Sin las claves todo queda igual.
Clave opcional `avisos_solo_paquete` (booleano; AVK1, D124): con `true`, la corrida o `diagrama` que reciba `--avisos-ics`
o `--kev` directos termina con código 2 y exige `--paquete-avisos`. Otro tipo de valor es error de perfil.

### Paquete de avisos ICS y KEV para sitios sin red (`paquete-avisos`)

La herramienta no descarga nada. En un equipo con red se obtienen los avisos CSAF de CISA y el KEV, se arma el paquete,
se lleva en un medio y en la planta se verifica antes de usarlo:

```bash
python ot_pcap_assess.py paquete-avisos --avisos-ics ~/cisa/csaf --kev ~/cisa/known_exploited_vulnerabilities.json \
    -o ~/medio/avisos_2026-11 [--zip]
python ot_pcap_assess.py paquete-avisos --verificar ~/medio/avisos_2026-11      # carpeta o .zip; 0 intacto, 2 si no
python ot_pcap_assess.py --paquete-avisos ~/medio/avisos_2026-11 --vulnerabilidades ...   # también en `diagrama`
```

Al menos una de las dos fuentes. La carpeta de salida debe no existir o estar vacía (si no, código 2 sin escribir). El
paquete lleva `csaf/` (los JSON que la corrida leería, misma ruta relativa), `kev/` (el catálogo tal cual),
`manifiesto_avisos.json` (formato `ot_assess.avisos/1`: versión y commit de la herramienta, fecha UTC, ruta, tamaño y
SHA-256 por archivo; KEV: `catalogVersion`, `dateReleased` y registros; CSAF: archivos, avisos válidos, saltados y fecha
del aviso más reciente) y `manifiesto_avisos.sha256` (`sha256sum -c`). `--paquete-avisos` (solo carpeta; el ZIP se
descomprime antes) verifica igual y, si coincide, equivale a `--avisos-ics CARPETA/csaf --kev CARPETA/kev/<archivo>`; si
no, termina con código 2 antes de escribir. No se combina con `--avisos-ics` ni `--kev`. `resultado.json` (entorno) agrega
`paquete_avisos` y los reportes lo dicen en una línea. Es evidencia de integridad del medio: no firma ni cifra el paquete
ni prueba su origen.

Clases de evidencia del proyecto (EVID1, D122), clave opcional `modelo_evidencia`: objeto con `clases` (claves
`observado`, `importado`, `declarado`, `inferido`, `en conflicto`, `sin dato`) y `por_fuente` (claves: tipo de fuente
como `manual` o `plataforma`, o `tipo:nombre` como `plataforma:nozomi`; sin distinguir mayúsculas; gana la clave más larga);
cada valor es una etiqueta de 1 a 20 caracteres sin saltos de línea. `{}` es válido y usa la tabla propia de la
herramienta (`ot_assess/data/modelo_evidencia.json`: OBS, DEC, INF, N/E y DISCREPANCIA, sin revisar); lo que trae el perfil
reemplaza clave por clave. Con la clave, el inventario normalizado agrega `X_clase` tras cada `X_estado`, la procedencia
agrega `clase`, y `resultado.json` y la sección del reporte cuentan campos por clase. Las etiquetas no se traducen. Sin la
clave todo queda igual.

La clave opcional `criticidad_activos` (`{"10.10.1.20": "Critica"}`; niveles Critica, Alta, Media, Baja; solo IPv4)
declara la criticidad de un activo para el plan de remediación; sin ella se infiere del rol y el plan lo marca como
«inferida», a validar por el analista. Con vectores CVSS v4.0, `criticidad_activos` también agrega a `vulnerabilidades.csv` y
`vulnerabilidades_firmware.csv` (y a sus hojas) las columnas `cvss_v4_entorno` y `vector_cvss_v4_entorno` (D120): el vector de la
fila con CR, IR y AR (Security Requirements) tomados del nivel (Crítica y Alta: H; Media: M; Baja: L; con varias IP, la más
crítica) y su puntuación. Es informativa, con una tabla sin revisar (`marcos/cvss4_requisitos.json`), y no cambia severidad,
estado, hallazgos, riesgo ni priorización; sin criticidad o sin filas v4 de esas IP las salidas no cambian.
La clave opcional `dominios_internos` (`["planta.example"]`) lista dominios propios del cliente: el análisis DNS los
trata como internos (además de `local`, `lan`, `internal`, `intranet`, `corp` y `home.arpa`), así que no salen en el
hallazgo de resolución de dominios de Internet y el ámbito de `dns_registros.csv` los marca como internos.
La clave opcional `vlans_esperadas` (`[10, 20]`, números de 1 a 4094) lista las VLAN que la captura debe ver; las que no
aparezcan limitan el veredicto de `validar-captura` y de la sección «Validación de la captura».
La clave opcional `ajustes_riesgo` y el campo `impacto` de cada zona (`{"seguridad": 5, "financiero": 2}`) alimentan el
registro de riesgos (R1): ver `riesgos.csv` en la tabla de salidas. Los valores son enteros de 1 a 5.
La clave opcional `riesgo` (RM1, D123) admite `modo` (`"puntuado"`, por defecto, o `"candidatos"`), `dimensiones_impacto`
(1 a 8 identificadores únicos `[a-z0-9_]{1,30}`; reemplazan a las seis de la herramienta en `zonas[].impacto` y en el
desempate, y no se traducen) y `dimension_inferida` (por defecto `produccion` si está en la lista; si no, la primera).
En modo `candidatos` el registro no publica probabilidad, impacto, puntuación, nivel ni quick win: `origen` es `candidato`
y `motivo_probabilidad` lista los factores observados; el mapa queda en 0 salvo filas que `ajustes_riesgo` puntúe con
probabilidad e impacto (esas se puntúan como siempre y van primero). Sin la clave todo queda igual.
La clave opcional `madurez_objetivo` (`{"segmentacion": 3, "parches": 2}`; enteros de 0 a 4; claves `activos`,
`segmentacion`, `acceso`, `parches`, `monitoreo`, `incidentes`, `suministro`, `riesgo`) fija el nivel objetivo de cada
dominio de la madurez por dominio (M7); si falta, rige el número de `ml_objetivo` y, si tampoco, 2 propuesto por la herramienta.
La clave opcional `csf_tiers_objetivo` (`{"GV": "Repetible", "PR": 3}`; funciones `GV`, `ID`, `PR`, `DE`, `RS`, `RC`; tier 1 a 4
o su nombre) fija la meta de cada función de los Tiers de NIST CSF 2.0; ver «Niveles (Tiers) de NIST CSF 2.0 por función»
y la opción `--csf-tiers ARCHIVO`.
La clave opcional `zonas` declara las zonas del cliente (IEC 62443-3-2), con ejemplo en
[`docs/ejemplos/perfil_zonas.json`](docs/ejemplos/perfil_zonas.json): lista de
`{"nombre", "redes": [CIDR], "descripcion", "sl_t": "SL1".."SL4", "inferida": true|false}`. `inferida: true` marca una zona
que el analista dedujo y el cliente no confirmó. El nombre no se repite, la misma red no puede estar en dos zonas (una
red dentro de otra más grande de otra zona vale y gana la más específica, con aviso) y `sl_t` no puede contradecir
`sl_objetivo`. Cada activo recibe una zona y el origen de esa asignación, en este orden: `perfil`, `firewall` (interfaz
por la que se llega a la IP, con `--firewall` o `--rutas-firewall`; la ruta por defecto no asigna), `plataforma`,
`internet` (IP globales), `subred` (VLAN o /24) y `purdue`; sin nada, `sin zona`. Salidas: `zonas.csv` (hoja «Zonas»), las
columnas `zona_asignada` y `origen_asignacion` en el inventario y la sección «Zonas» del reporte; las zonas que no vienen
del perfil son inferidas y deben confirmarse con el cliente.
**Conductos entre zonas (ZCR de IEC 62443-3-2).** Con las zonas, los conductos observados se agrupan por par de zonas
en conductos `C-01`, `C-02`... (ordenados por número de conductos y luego por nombre). `conductos_zcr.csv` (hoja
«Conductos (ZCR)») trae sentido, servicios, equipos, firewalls del camino, reglas actuales, propuesta, etiquetas, SL-T y
brechas; `diagrama_zcr.svg`, `.mmd` y `.drawio` dibujan una caja por zona y una línea por conducto (los 40 con más
conductos), y el reporte añade la sección «Zonas y conductos». Las brechas son marcas para revisar, no juicios:
`sin firewall observado` (solo con `--firewall`), `servicios de riesgo`, `salta niveles Purdue`, `SL-T distinto` y
`zona inferida`. Con `--zonas-fw`, las zonas de origen `firewall` usan el nombre del CSV. Tres hallazgos nuevos
(sin firewall observado, servicios de riesgo y niveles Purdue saltados) entran al plan de remediación.
**Arquitectura TO-BE (segmentación propuesta, T1a, D85).** Con los conductos entre zonas, `allowlist_tobe.csv` (hoja
«Allowlist TO-BE», UTF-8 con BOM) propone una decisión por (zona origen, zona destino, servicio) en el sentido real del
conducto; no necesita `--firewall`. Método propio, sin revisar; la primera regla que aplique decide: **bloquear**
(origen Internet hacia una zona interna; DNS a resolvers públicos desde una zona interna; zona con equipos de nivel
Purdue 0 a 2 hacia Internet), **por DMZ** (conducto entre IT/empresa, nivel 4 o más o zona IT, y control, nivel 0 a 2,
en cualquier sentido; el motivo sugiere servidor de salto con MFA para acceso remoto, réplica del historiador para
datos de proceso, servidor de distribución para parches, u otro servicio intermedio), **revisar** (servicio de riesgo,
visto un solo día o puerto alto sin protocolo de aplicación) y **permitir** (el resto, restringido a los pares
origen/destino observados). La última regla implícita por cada par de zonas es «denegar el resto con registro». Los
conductos dentro de una misma zona y las respuestas de sesión no generan fila. La columna `ids_hallazgo` cita los `H-`
(R1) de los hallazgos de segmentación o conductos que tocan esos equipos (máximo 5); `estado_revision`, `revisado_por`,
`fecha` y `comentario` quedan vacías para el cliente. `matriz_tobe.csv` (hoja «Matriz TO-BE») cuenta las decisiones por
par de zonas y el reporte lo muestra como cuadrícula («P 3 · D 1 · R 2 · B 1»; celda vacía = denegar).
`diagrama_tobe.svg`, `.mmd` y `.drawio` dibujan las zonas de la empresa (arriba) al control (abajo), con la DMZ entre
ambas; solo se dibujan «permitir» (línea continua) y «por DMZ» (discontinua, en dos tramos origen → DMZ → destino); el
máximo son 40 aristas. DMZ: la zona con `"dmz": true` en el perfil o con «DMZ» en el nombre; si hace falta y no hay,
se propone «DMZ industrial (propuesta)». Es una propuesta a partir de lo observado que valida el cliente, no un diseño
de ingeniería ni un juicio de cumplimiento. También en `diagrama` y en la clave `tobe` de `resultado.json`.
**Hardening por tipo de equipo (T1b, D86).** Cada activo se asigna a uno de seis tipos (controlador, estación, servidor,
red, seguridad, otro) por su rol inferido o por el tipo que da la plataforma (`ot_assess/data/hardening.json`); sin
rol, por los puertos que sirve (puertos OT: controlador; DNS, LDAP, bases de datos: servidor; RDP/VNC: estación) y si
no, «otro». Cada activo es una fila del inventario normalizado: una MAC de enrutamiento se reparte en un activo por IP. Cada tipo trae de 10 a 12 puntos de configuración (`HB-CTL-01`, `HB-EST-01`, `HB-SRV-01`,
`HB-RED-01`, `HB-SEG-01`, `HB-OTR-01`…) en palabras propias, con su referencia a ISA/IEC 62443-4-2 (CR y
EDR/HDR/NDR) y a 3-3 (SR); los mapeos están sin revisar. `hardening_baseline.csv` (hoja «Hardening por tipo») es la
lista de verificación de la visita, solo de los tipos presentes: `resultado_visita`, `evidencia_presentada`,
`verificado_por`, `fecha` y `comentario` quedan vacías. `hardening_activos.csv` (hoja «Hardening por activo») trae
solo las filas «revisar: evidencia en contra»: un hallazgo de la corrida que toca la IP del activo (Telnet o HTTP de
administración, credenciales con cifrado reversible, controles de capa 2 ausentes, hora sin sincronizar, fuera de
soporte, KEV, SMBv1…; con su `H-` de R1) o un servicio en claro (Telnet, FTP, HTTP, SNMP v1/v2c, TFTP) que el inventario
dice que el activo sirve; la columna `base_tipo` dice de dónde salió el tipo (rol, hallazgo, servicios, sin rol; «hallazgo»: la IP
de gestión que nombra la configuración del switch). Todo lo demás es «verificar en sitio» (sin evidencia; no significa que esté bien) y el reporte
solo lo cuenta por tipo. La sección «Linea base de hardening por tipo de equipo» (HTML, Markdown, Word) trae la tabla
por tipo y los 15 puntos con más activos en contra. No lee configuraciones de equipos y nunca dice «cumple» ni
«endurecido». También en `diagrama` y en la clave `hardening` de `resultado.json`.
**Fuentes de log (G1a, D87).** Inventario de quién envía registros, a qué colector, por qué protocolo y si va en claro.
Un conducto (también dentro de una zona) hacia un puerto o una aplicación de registro de `ot_assess/data/fuentes_log.json`
(Syslog 514/udp y 601/tcp, Syslog sobre TLS, traps SNMP, NetFlow/IPFIX/sFlow, reenvío de eventos de Windows, agentes de
SIEM; ampliable) es un envío: el origen es el emisor y el destino el colector; las respuestas no cuentan y 514/tcp no es
Syslog salvo que la aplicación identificada lo sea. `fuentes_log.csv` (hoja «Fuentes de log») trae todos los activos del
inventario normalizado, con el tipo de T1b, si por su tipo se espera que envíen (red, seguridad, servidor, estación) o es
opcional (controlador, otro), el estado («envia (observado)», «colector», «sin envio observado: verificar», «sin envio
observado (opcional para el tipo)»), protocolos, colectores y `cifrado` (no, si, depende de la configuración);
`estado_revision`, `revisado_por`, `fecha` y `comentario` quedan vacías. `colectores_log.csv` (hoja «Colectores de log»)
trae cada colector con sus emisores y zonas emisoras. La sección «Fuentes de log (arquitectura de registro observada)»
(HTML, Markdown, Word) trae la tabla por tipo y los colectores (máximo 20); sin envíos dice «No se observo envio de
registros en la corrida.» y no se escribe `colectores_log.csv`. La ausencia en la captura no prueba que el equipo no envíe
(ventana, cobertura del SPAN, otra interfaz): las preguntas de servicios esperados (M6) siguen siendo la vía para confirmarlo.
No genera hallazgos, no lee la configuración de registro y nunca dice «cumple». También en `diagrama` y en la clave
`fuentes_log` de `resultado.json`.
**Direccionamiento IP observado (G1b, D88).** `direccionamiento_ip.csv` (hoja «Direccionamiento IP») lista las redes
del sitio: `red`, `origen_prefijo` (perfil, firewall, switch o «inferida /24»), `vlan` y `puerta_enlace` (de la SVI del
switch), `zonas`, `activos`, `primera_ip`, `ultima_ip`, `hosts_utiles`, `uso_pct` (mínimo: solo cuenta lo observado),
`tipos` (hasta 3, con la lógica de T1b) y `observaciones` para validar con el cliente («red declarada sin activos
observados», «IP fuera de las redes declaradas», «subred en varias zonas», «rango publico usado como red interna»,
«uso alto del rango»); `estado_revision`, `revisado_por`, `fecha` y `comentario` quedan vacías. Cada IP cae en el prefijo
declarado más específico (a igual prefijo: perfil, firewall, switch); sin prefijo, en su /24. Las IP de la zona Internet,
las públicas sin prefijo declarado y las IPv6 no entran a la tabla y se cuentan en el resumen. La sección «Direccionamiento
IP observado» (HTML, Markdown, Word) trae el resumen, las 30 redes con más activos y el conteo por observación. Sin
hallazgos y sin «cumple». También en `diagrama` y en la clave `direccionamiento` de `resultado.json`.
**Línea base ISA/IEC 62443 as-is / to-be (B7b, D76).** Con zonas (del perfil o inferidas), toda corrida, de capturas o de
`diagrama`, escribe `linea_base_especifica.csv` (por zona y requisito), `linea_base_conductos.csv` (por conducto C-xx,
requisitos de FR3, FR4 y FR5) y `linea_base_general.csv` (por FR y por nivel de madurez), con hojas equivalentes en
`reporte_ot.xlsx`, la clave `linea_base` de `resultado.json` y la sección «Linea base ISA/IEC 62443 (as-is / to-be)»
(tabla zona x FR, las 10 brechas de mayor prioridad y la nota de alcance). El objetivo (to-be) es lo que el catálogo
exige al SL-T de la zona (`sl_t`, `sl_objetivo` o SL2 propuesto por la herramienta); el estado (as-is) es
«brecha con evidencia», «control observado», «sin evidencia en los datos (verificar en sitio)» o «no evaluable con datos
de red»: nunca «cumple». La cota por FR es un techo según la evidencia, no un nivel medido. `ml_objetivo` (`"ML1"` a
`"ML4"`) en el perfil fija el nivel de madurez objetivo (por defecto ML 2 propuesto); el nivel logrado se evalúa con
entrevista (2 preguntas por FR en el CSV general). Reglas completas en D76. `linea_base_2_1.csv` (hoja «Linea base 2-1»)
agrupa el as-is por elementos del programa de ISA/IEC 62443-2-1:2024 (SPE, sub-SPE y requisito), con las
correspondencias publicadas con 3-3, 4-2 y 2-4; una correspondencia no es equivalencia ni prueba de cumplimiento (D104).

**Matriz de controles (B7c).** Con o sin zonas, escribe `matriz_controles.csv` (hoja «Matriz de controles», la clave
`matriz_controles` de `resultado.json` y una sección breve por marco y familia). Junta las filas de la línea base
62443 (zona y conducto), una fila por cada uno de los 87 requisitos de ISA/IEC 62443-2-1:2024 (solo con zonas; alcance
«programa», estado agregado de los SR de 3-3 que cita, sin objetivo; D106) y los controles y mejoras de la línea base OT de NIST SP 800-82 Rev. 3 (Tabla 22 del Apéndice
F.3, sobre SP 800-53 Rev. 5), elegida con `linea_base_nist` en el perfil (`"baja"`, `"moderada"` o `"alta"`; por
defecto moderada, propuesta por la herramienta). Estados as-is como en la línea base; nunca «cumple». Las seis últimas
columnas (`estado_validado`, `fuente_validacion`, `validado_por`, `revisado_por`, `fecha_validacion`, `comentario`)
salen vacías para que el analista las llene (entrevista, documento, observación en sitio o evidencia técnica).
`linea_base_general.csv` suma una fila por familia de SP 800-53. Reglas en D77.
**Filas de CIS Controls v8.1 (CIS1, D108).** Con `--cis ARCHIVO` (XLSX oficial de CIS que usted descargó, o un CSV
con sus columnas `CIS Control`, `CIS Safeguard`, `Asset Class`, `Security Function`, `Title`, `Description`, `IG1`,
`IG2`, `IG3`; la herramienta no descarga nada), la matriz suma, después de las NIST, una fila por salvaguarda del
grupo de implementación elegido con `cis_ig` en el perfil (`"IG1"`, `"IG2"` o `"IG3"`; por defecto IG2, propuesto
por la herramienta). Alcance `organizacion`, título tal cual del archivo (no se traduce) y las columnas de
validación vacías. Estado as-is: el agregado de las filas NIST de la corrida cuyos controles de SP 800-53 salen de
las referencias informativas públicas de NIST CSF 2.0 para esa salvaguarda (`ot_assess/marcos/csf2_referencias.json`,
solo identificadores; se regenera con `scripts/extraer_csf_referencias.py`). Sin correspondencia publicada: «sin
evidencia», o «no evaluable» si es de documentación o de gobierno; la evidencia lo dice y pide revisar a mano. Una
correspondencia no es equivalencia ni cumplimiento. Sin `--cis` la matriz no cambia.
**Mapeos oficiales de CIS (CIS1b, D111).** `--cis-mapeo ARCHIVO` (requiere `--cis`; repetible, uno por tipo) toma el
XLSX oficial de CIS que usted descargó (o un CSV con las mismas columnas) de v8.1 a SP 800-53 Rev 5 (columna
`Control Identifier`) o a CSF 2.0 (`CSF Subcategories`); el tipo sale de la columna. Con el mapeo a 800-53, los
controles de cada salvaguarda son los de ese mapeo; con el de CSF 2.0, las subcategorías; en ambos casos reemplazan a
las referencias de NIST. La evidencia lista cada destino con su relación (equivalente, subconjunto, superconjunto) y
los que están en la línea base. Salvaguarda sin destino: «Sin correspondencia en el mapeo oficial de CIS». Solo se
guardan ids y relación; ningún texto del archivo pasa a las salidas. Sin `--cis-mapeo` nada cambia. **Licencia:** CIS Controls es
CC BY-NC-ND 4.0 (no se distribuyen materiales derivados), por eso el repo no contiene ningún título ni texto de CIS,
solo identificadores; los títulos salen del archivo del analista en cada corrida. Referencia: www.cisecurity.org/controls/.
**Filas de la TSA SD 1580/82-2022-01E (TSA1, D109).** Con `tsa_sd: "01E"` en el perfil (única edición conocida; otra
falla), la matriz suma al final 38 filas, una por medida de la sección III («Cybersecurity Measures») de la directiva,
en su orden, con alcance `organizacion` y las columnas de validación vacías. Las medidas documentales salen «no
evaluable»; las técnicas, el agregado de las filas NIST de la corrida por un mapeo propio a SP 800-53 Rev. 5 sin revisar
(`ot_assess/marcos/tsa_sd_1580_82.json`: solo ids y títulos cortos propios). La sección del reporte suma una fila por
letra (III.A a III.F). Una correspondencia no es equivalencia ni cumplimiento; el Plan de Implementación del cliente
(CIP) es SSI, se contrasta a mano y nunca va al repo. Sin `tsa_sd` la matriz no cambia.

**Referencias de la TSA por hallazgo (TSA2, D118).** `--estandar tsa-sd-1580-82` (o `{"clave": "tsa-sd-1580-82"}` en
`marcos` del perfil) agrega la columna `tsa-sd-1580-82` a `hallazgos.csv` y la cita en los reportes como a los demás
marcos; no entra por defecto. No hay mapeo nuevo: se deriva al ejecutar de los dos existentes, hallazgo a controles
SP 800-53 (`nist-800-82.json`) y medida a controles SP 800-53 (`tsa_sd_1580_82.json`). Un hallazgo cita las medidas
**técnicas** (III.x) cuyo mapeo incluye el control base de alguno de sus controles (SC-7(3) cuenta como SC-7), en el
orden de la directiva y sin repetir; las documentales no se citan, y un hallazgo sin medidas queda sin referencia.
Mapeos propios sin revisar: una referencia no es equivalencia ni cumplimiento.

**Versión de CVSS que decide (CV4b, D114).** `version_cvss` del perfil: `"3"` (por defecto; también 3.0, 3.1) o `"4"` (4.0).
Con `"4"`, severidad, orden y umbral de Alta se calculan con CVSS v4.0 donde existe y con v3 donde no: en
`vulnerabilidades_firmware.csv` aparece la columna `cvss_decide` (`4.0`, `3.x` o vacía) tras `vector_cvss_v4`, `severidad`
sale de la puntuación efectiva, el hallazgo es Alta si hay KEV o efectiva >= 9.0 y su evidencia cita "CVSS v4.0" o "CVSS v3"
por CVE; `avisos_ics.csv` ordena por `cvss_v4_max` y, si está vacío, por `cvss_max`; en `--vulnerabilidades` la severidad
explícita de la plataforma se respeta siempre, la ausente se deriva de `cvss_v4` si existe, y una fila con solo `cvss_v4` o
su vector se acepta. Con `"3"` o sin la clave nada cambia.
En `importacion.json`, `perfil_proyecto` es este perfil y `perfil` sigue siendo el de columnas de la plataforma.

**Inventario normalizado (I1a, D78).** `inventario_normalizado.csv` (una fila por activo, id estable `A-` + 8 hex del
hash de la MAC, o de la IP si no hay MAC o es MAC de enrutamiento) y `inventario_procedencia.csv` (formato largo: id,
campo, valor, fuente, ultima_observacion, estado). En una captura tomada en un punto enrutado, una MAC con más de
4 IPv4 o alguna pública es de un router y no identifica un equipo: se parte en un activo por IP (servicios,
protocolos, zona y última observación salen de los flujos de esa IP; VLAN, rol y fabricante no se conocen por IP y
quedan vacíos), la MAC va en `mac_salto` y solo la IP que responde ARP con ella (si es única) la conserva en `mac`.
Campos: IP, MAC, MAC de salto, nombre, fabricante, modelo, firmware, sistema
operativo, rol, nivel Purdue, zona, VLAN, puerto de switch, servicios, protocolos y criticidad; cada uno con su
`_fuente` (`captura:<archivo>`, `plataforma:<nombre>`, `switch:<host>`, `firewall:<host>`, `manual`, `perfil`,
`inferido`) y su `_estado` (`observado`, `importado`, `declarado`, `inferido`, `en conflicto`). Valor mostrado en los
campos descriptivos: manual > perfil > plataforma > switch/firewall > captura > inferido; IP, MAC, VLAN, servicios y
protocolos son la unión de las fuentes. Dos fuentes que dicen cosas distintas (sin contar mayúsculas, espacios ni ceros
a la izquierda del firmware) dejan el campo «en conflicto» y la columna `conflictos` con ambos valores; un valor
inferido nunca provoca conflicto. `ultima_observacion`: hora del último paquete del activo en la captura (UTC), la
columna de última actividad de la exportación o, si no hay, el fin del periodo (hora local de la exportación); vacía
para manual y perfil. Las columnas `validado_por`, `revisado_por`, `fecha_validacion` y `comentario` salen vacías para
el QA de dos personas. `--inventario-manual` (CSV, JSON o XLSX; columnas por alias como el importador genérico, y
`--mapeo '{"manual": {...}}'` para corregirlas) marca `declarado, no observado` y `observado, no declarado`, que el
resumen cuenta. `equipos_propios` en el perfil (`[{"direccion": "192.0.2.10" | "192.0.2.0/28" | "aa:bb:...",
"etiqueta": "sensor"}]`) saca esos equipos del inventario, los conductos, las zonas, la política propuesta, la línea
base y la matriz de controles, y de `activos` en los hallazgos (un hallazgo que solo los involucra no se emite; el
texto de la evidencia de uno mixto no se reescribe). El reporte cuenta lo excluido.

**Obsolescencia (I1b, D79).** `obsolescencia.csv` y hoja «Obsolescencia»: un renglón por activo del inventario
normalizado y producto que case, con fecha de fin de soporte, días (negativo = vencido), estado, reemplazo sugerido y
fuente del dato; las columnas de QA salen vacías. `--fin-de-soporte ARCHIVO` (CSV o XLSX, ambos CLI, sin red):
columnas `fabricante`, `producto` (texto o patrón regex, sin distinguir mayúsculas; casa con el modelo o con el
sistema operativo), `version` (vacía = todas; texto exacto, prefijo `2.` o rango `<3.1` / `>=2.0,<2.4`; contra el
firmware o la versión que sigue al producto en el texto del SO), `fecha_fin_soporte` (AAAA-MM-DD) y opcionales
`fecha_fin_venta`, `reemplazo_sugerido`, `fuente`; hay alias en español e inglés (`vendor`, `product`/`model`,
`firmware`, `eos`/`eol`/`end_of_support`, `end_of_sale`, `replacement`, `source`). Una fila inválida se avisa con su
número y se omite. Sin archivo, o para lo que el archivo no cubre, rige la tabla integrada
`ot_assess/data/fin_soporte_so.json` (Windows, solo sistema operativo; fechas del propietario, no verificadas por la
herramienta). El fabricante de la fila solo se compara al casar contra el modelo (no contra el SO). Estados: «fuera de
soporte», «fin de soporte en 12 meses o menos», «con soporte», «sin dato de soporte» (hay datos y ninguna fila casa;
no es «con soporte») y «sin datos de version» (no se conoce firmware ni SO, o la fila exige una versión y no hay). La
fecha de referencia (fin de la captura o del periodo de la exportación; si no, la de la corrida) va en cada renglón y
en la sección. El hallazgo «Software o sistema operativo fuera de soporte» lista además los vencidos con fecha y
fuente; si no existía, nace «Activos fuera de soporte segun el reporte de obsolescencia» (Alta si algún activo es de criticidad Alta o
Purdue 0-2, si no Media). «Equipos con fin de soporte en los proximos 12 meses» es Baja.

**Rutas de ataque (A1).** Sobre los conductos observados (no negados por el firewall, con el sentido real) se arma un
grafo de activos y se busca, por BFS, el camino más corto desde Internet (IP globales con conductos entrantes) y desde
las zonas IT hasta los activos de criticidad Crítica o Alta. Orígenes: `--origen-ataque ZONA` (repetible; por defecto
las zonas cuyo nombre contiene IT, CORP o Internet). Objetivos extra: `--objetivo-ataque ZONA`. Máximo 6 saltos (los
que quedan más lejos solo se cuentan). `rutas_ataque.csv` trae el camino con servicio por salto, acceso remoto,
conductos ZCR y reglas del firewall; `rutas_ataque_puntos.csv` ordena los activos, conductos ZCR y reglas que más
caminos concentran (los mejores lugares para cortar). Es alcanzabilidad por comunicaciones observadas, no una prueba
de explotación. El hallazgo «Activos críticos alcanzables…» entra al plan de remediación. La sección «Rutas de ataque»
va en el reporte (HTML, MD, Word); la página de `diagrama` solo trae el CSV y el hallazgo.

## Diagramas desde una plataforma OT

Cuando no hay capturas y solo se tiene lo que exporta Nozomi, Claroty, Dragos u otra plataforma:

```bash
python ot_pcap_assess.py diagrama --activos activos.csv --enlaces comunicaciones.csv -o salida/ \
  --cliente "Central X" --estandar nerc-cip
python ot_pcap_assess.py diagrama --activos assets.xlsx --enlaces links.json --formato claroty -o salida/
```

Acepta CSV (cualquier delimitador y codificación habitual), JSON (incluidas respuestas de API
anidadas y JSON Lines) y XLSX, sin dependencias. Genera `diagramas.html` (página presentable con
ambos diagramas, el cuadro de datos de origen y los avisos), los SVG, Mermaid y draw.io, `inventario_importado.csv`,
`hallazgos_importados.csv` (hallazgos de las reglas de inventario, mismas columnas que `hallazgos.csv`; derivados
de la exportación, sin tráfico que los confirme y con formatos no validados) e `importacion.json` (clave `hallazgos`).

Además produce el mismo reporte completo que el análisis de capturas, con los mismos nombres de archivo:
`reporte_ot.html`, `reporte_ot.md`, `reporte_ot.xlsx`, `informe_ot.docx`, `resumen_ejecutivo.html`/`.docx`,
`plan_remediacion.csv`, `hallazgos.csv`, `cobertura_<marco>.csv`, `resultado.json` y los CSV de firewall, zonas,
rutas de ataque y fuentes. Sin capturas se omiten las secciones que dependen de ellas (paquetes, DNS, identidad,
detalle por captura, operaciones de control y brecha de visibilidad) y el resumen indica la plataforma, los archivos
importados y el periodo. `--max-rows` (por defecto 120) limita las filas de cada tabla en HTML, Markdown y Word; el
detalle completo queda en los CSV. `--solo-diagramas` omite todo esto y deja el comportamiento anterior.

**Qué exportar de Nozomi (Guardian, XLSX o CSV; formato validado con exportaciones reales, D74):**

| Exportación | Opción | Para qué sirve |
|---|---|---|
| Assets | `--activos` | Inventario: tipo (`type`; si está vacío, los `roles`), fabricante, firmware y sistema operativo. Un activo con solo IPv6, con varias IP o sin IP (solo MAC) también entra. `vlan_id` es un atributo, no un identificador. |
| Nodes | `--activos` (junto con Assets) | Completa el inventario con lo que Assets no trae. Se une a Assets por MAC y por IP sin duplicar, y mandan los datos de Assets. Si una MAC es de un equipo de enrutamiento (muchas IP, alguna pública, o router/firewall), solo se unen las IP que Assets ya trae y las link-local; las demás no se pegan al router (se avisa). Multicast y broadcast no son equipos. |
| Sessions | `--enlaces` | Los conductos con su puerto (`to_port`, el del servidor) y transporte. Es la exportación recomendada para la matriz de comunicaciones y la política de firewall. |
| Links | `--enlaces` | Solo une pares de equipos: no trae puerto ni transporte, los conductos quedan sin puerto (aviso). Úsela si no tiene Sessions. |
| CVE por nodo (`export_node_cves`) | `--vulnerabilidades` | Vulnerabilidades por activo, unidas por la MAC del nodo (`node_id`): CVSS, EPSS (columna `epss` en `vulnerabilidades.csv`) y KEV de la propia columna `cve_is_kev` (más el cruce con `--kev`, si se da). `resolved=1` no cuenta como abierta. Lo que no une con ningún activo se cuenta en un aviso. |

Los extremos `MAC@IP` (la IP vista con otra MAC) se resuelven al activo por su MAC. Las comunicaciones hacia multicast
(`224.0.0.0/4`, `ff00::/8`), broadcast (`255.255.255.255` y el `.255` de una red conocida) y `0.0.0.0` no se dibujan ni
generan reglas de firewall: se cuentan aparte por protocolo (clave `difusion` de `importacion.json` y un aviso). Las
fechas son números de serie de Excel sin zona horaria: el periodo (mínimo de `first_activity_time`, máximo de
`last_activity_time`) sale en el resumen como hora local de la exportación. Zones y Alerts de Nozomi aún no se leen.

| Opción | Para qué sirve |
|---|---|
| `--activos` | Inventario (recomendado: aporta tipo, nivel y zona). |
| `--enlaces` | Comunicaciones entre activos (obligatorio salvo que se den `--fuente-flujos NOMBRE=RUTA`). Son la fuente `principal`. |
| `--fuente-flujos` | `NOMBRE=ARCHIVO` o `NOMBRE=CARPETA` (todos sus CSV/XLSX): exportación o captura (`.pcap`/`.pcapng`/`.cap`, requiere tshark) de un sensor con nombre; repetible, y un mismo `NOMBRE` reúne varios archivos del mismo sensor. Ver [Varias fuentes](#varias-fuentes-de-flujos---fuente). |
| `--solo-diagramas` | Solo diagramas, CSV y `diagramas.html`; sin reporte, Excel, Word ni resumen ejecutivo (corridas rápidas). |
| `--max-rows` | Filas máximas por tabla en los reportes (por defecto 120). |
| `--formato` | `auto`, `nozomi`, `claroty`, `xdome`, `dragos` o `generico`. Solo rotula la fuente. |
| `--perfil` | Perfil del proyecto en JSON; reemplaza a `--titulo`, `--cliente` y `--estandar`. Ver [Perfil de proyecto](#perfil-de-proyecto). |
| `--mapeo` | JSON que fija columnas a mano. |
| `--agrupar` | `nivel` (Purdue), `zona` (zonas de la plataforma) o `interfaz` (interfaces del firewall; exige `--rutas-firewall`). Por defecto, la interfaz si se pasa `--rutas-firewall`; si no, el nivel cuando la mayoría de los activos lo trae. |
| `--firewall` | Salida de la CLI de un Cisco FTD/ASA ([detalle](#firewall-cisco-ftdasa---firewall)); agrega `firewall_reglas.csv`. |
| `--rutas-firewall` | Tabla de rutas de un firewall, como en el análisis de capturas ([formatos](#rutas-del-firewall)). Agrega `firewall_interfaces.csv`, `firewall_matriz.csv` y la sección «Flujos entre interfaces del firewall» a `diagramas.html`. |
| `--kev`, `--avisos-ics` | Igual que en el análisis de capturas (catálogo KEV y avisos ICS de CISA en CSAF, desde archivos locales; requieren `--vulnerabilidades`). |
| `--catalogo-vulnerabilidades` | Igual que en el análisis de capturas (V1a, D89); con `--avisos-ics` no necesita `--vulnerabilidades`. |
| `--tor-relays` | Igual que en el análisis de capturas (lista de relays Tor local; agrega `evasion.csv` y sus hallazgos). |
| `--vulnerabilidades` | CSV de vulnerabilidades por activo, con las mismas columnas que en el análisis de capturas. Se cruza con el inventario importado y agrega el hallazgo a `hallazgos_importados.csv`, `vulnerabilidades.csv`, la sección «Vulnerabilidades importadas» de `diagramas.html` y la clave `vulnerabilidades` de `importacion.json`. |
| `--alertas` | CSV de alertas, con las mismas columnas que en el análisis de capturas. Se asocia a los conductos importados y agrega el hallazgo a `hallazgos_importados.csv`, `alertas.csv`, la sección «Alertas importadas» de `diagramas.html` y la clave `alertas` de `importacion.json`. |

#### Varias fuentes de flujos (`--fuente-flujos`)

Para un cliente con varios sensores (p. ej. uno de IT, uno de Ciberseguridad y uno de OT):
`diagrama --activos inv.xlsx --fuente-flujos IT=carpeta_it/ --fuente-flujos CIBER=ciber.csv --fuente-flujos OT=ot1.csv --fuente-flujos OT=ot2.csv`.
Los conductos de todas las fuentes se unen sin contar dos veces lo que vieron varias (D46): con fecha (columna DATE de
xDome), por conducto y fecha se toma el **máximo** de bytes y paquetes entre fuentes y luego se suman las fechas; sin
fecha, el máximo de los totales de cada fuente. Dentro de una fuente se suma como siempre, salvo la fila idéntica con
fecha que se repite en otro archivo de la misma fuente (archivos solapados), que cuenta una vez y deja un aviso. Salidas, solo con `--fuente-flujos`: columna `fuentes`
en `firewall_cruces.csv` y `firewall_cruces_detalle.csv` (y en `comunicaciones.csv` del análisis de capturas),
`fuentes_resumen.csv` (por fuente: conductos, únicos de la fuente, compartidos, primera y última fecha),
`fuentes_cobertura.csv` (por segmento y fuente: conductos y equipos vistos, y los que solo vio esa fuente), la sección
«Fuentes de tráfico» y, si hay segmentos con equipos inventariados y ningún conducto, el hallazgo informativo
«Segmentos sin cobertura de las fuentes de tráfico». Segmento = interfaz del firewall (`firewall:interfaz` con varios) o,
sin firewall, la red /24 (/64 en IPv6). La cobertura es la de lo importado: un segmento sin conductos puede no tener
sensor o haber estado callado. Sin `--fuente-flujos` todo sale como antes.

**Capturas como fuente (M2b).** Una fuente también puede ser una captura (`.pcap`, `.pcapng`, `.cap`, o un archivo cuyos
primeros bytes son una cabecera pcap) o una carpeta que mezcle capturas y exportaciones:
`--fuente-flujos FW1=fw1.pcapng --fuente-flujos CLAROTY1=export1.csv --fuente-flujos MIXTA=carpeta/`. Requiere tshark
(`--tshark` si no está en el PATH; sin él hay un aviso y la fuente se procesa sin sus capturas). Se usa el mismo camino que
el análisis de capturas (flujos y conductos, sin el pase de detalle) y cada captura entra como un archivo más de su fuente:
suma dentro de la captura, máximo por conducto y fecha entre archivos y fuentes. Límites: el módulo de flujos guarda solo
la primera y la última marca de cada flujo, así que cada conducto de una captura cuenta como **un solo día** (UTC, el de su
primer paquete) aunque la captura abarque varios; el protocolo sale del puerto (como en una exportación sin protocolo);
los equipos no inventariados se dibujan por IP (no se usan sus MAC); y una exportación se une con una captura solo si trae
el transporte (TCP/UDP), porque la clave del conducto incluye `l4`. `fuentes_resumen.csv` añade la columna `tipo`
(`exportacion`, `captura` o `mixta`).

**Limitación importante: los nombres de columna no están validados contra exportaciones reales.**
Los fabricantes no publican el formato de sus exportaciones y cambia entre versiones. La
herramienta reconoce las columnas por alias habituales (`ip`, `IP Address`, `mac_address`,
`Purdue Level`, `zone_name`, `product_name`...) y los muestra en el cuadro «Datos de origen» del
reporte para que se revisen. Si una columna no se lee bien, se corrige sin tocar código:

```json
{"activos": {"nivel": "Capa Purdue", "tipo": "Clase de equipo"},
 "enlaces": {"origen": "Emisor", "destino": "Receptor"}}
```

Pasar el archivo con `--mapeo mapeo.json`. Si una exportación real no se reconoce, enviar una
muestra anonimizada de las columnas para agregar sus nombres a `importers/perfiles.py`.

### Claroty xDome

Perfil `xdome` (se detecta solo; el perfil `claroty` es el de CTD). Las columnas se basan en exportaciones
reales de xDome, pero el formato puede cambiar entre versiones: revisa el cuadro «Datos de origen».

- **Comunicaciones:** consulta de comunicaciones exportada a CSV (una fila por par, puerto, protocolo y día).
  Se pueden pasar varios archivos a `--enlaces`: el mismo par visto con los lados invertidos en dos consultas
  se junta en un solo conducto (bytes sumados, primera y última fecha, días distintos).
- **Inventario:** «All Devices» exportado a XLSX, en `--activos`. El tipo de equipo sale de `TYPE`, no de `CATEGORY`.
- **Dirección:** el lado A es el del filtro de la consulta, no el que inicia. `From B to A` invierte origen y
  destino; `From A to B` los deja; `Bidirectional` (u otro valor) junta ambos sentidos y conserva la orientación
  de la primera fila vista. `N/A` es «sin dato» en cualquier columna; con varias IP en `IP (CURRENT)` se usa `IP (COMM.)`.
- **Lo que aportan las comunicaciones al inventario:** el tipo de cada lado y el dominio del lado B (nombre) cuando
  el inventario no lo trae o no cubre el equipo; los destinos `(External)` se dibujan en la banda Externo.
- **Límite de 100000 filas:** xDome corta cada exportación en 100000 filas. Si un archivo trae exactamente
  esa cantidad, la importación avisa («posible exportación truncada»); divide la consulta por subred o por periodo.
- No se importan las Subnets de xDome.

#### Descarga por API (`xdome-descargar`)

Baja de la API de xDome (solo lectura) el inventario, los pares dispositivo-CVE, las alertas y los eventos, y los
deja como CSV que aceptan `--activos`, `--vulnerabilidades` y `--alertas` de `diagrama` y del análisis de capturas.

1. En xDome crea un usuario API de **solo lectura** y genera su token. Guárdalo en `~/.config/xdome/token`
   con `chmod 600` (si los permisos son más abiertos, el subcomando termina con código 2). El token no se
   imprime ni se escribe en ninguna salida. Base por defecto `https://api.claroty.com` (`--base`, solo https).
2. Descarga a una carpeta **fuera del repositorio** (son datos del cliente; dentro del repo se rechaza):

```bash
python ot_pcap_assess.py xdome-descargar -o ~/datos/cliente_xdome
python ot_pcap_assess.py diagrama --activos ~/datos/cliente_xdome/activos_xdome.csv \
    --enlaces comunicaciones.csv \
    --vulnerabilidades ~/datos/cliente_xdome/vulnerabilidades_xdome.csv \
    --alertas ~/datos/cliente_xdome/alertas_xdome.csv
```

La carpeta trae `crudo/<conjunto>.jsonl` (respuesta sin transformar) y `activos_xdome.csv`,
`vulnerabilidades_xdome.csv` y `alertas_xdome.csv`; la consola dice cuántos registros y campos usó cada conjunto y
qué omitió. Los mismos CSV sirven para el análisis de capturas (`--vulnerabilidades`, `--alertas`).

**Límites:** esta API no tiene mapa de comunicaciones ni flujos: `--enlaces` sigue viniendo de la exportación
«Communication» de la interfaz. Los campos que la licencia no cubre (403) se omiten y se avisa; si xDome no informa
la severidad de una alerta, el CSV usa `Medium` y la consola cuenta cuántas filas (no es dato de xDome). Los
dispositivos retirados no van al inventario. Detalle y alcance de lo probado: `docs/DECISIONES.md` (D42).

Cómo se interpretan los datos:

- **Nivel Purdue:** el que informa la plataforma. Si falta, se toma de la zona cuando se llama
  «DMZ» o «Level 2», y si no, del tipo de equipo (PLC en nivel 1, HMI en 2, servidores en 3,
  equipos de red en infraestructura). Todo lo inferido se avisa en el reporte. El nivel 0 es un
  nivel válido, no ausencia de dato.
- **Criticidad:** por tipo de servicio y cruce de zonas, con la misma regla que el análisis de
  capturas. Las exportaciones no distinguen lectura de escritura, así que **ningún conducto
  importado aparece como crítico por escrituras**: eso requiere las capturas.
- **Enlaces:** cada extremo se busca por IP, id, MAC o nombre. Los que no coinciden con ningún
  activo se dibujan como equipos no inventariados y se cuentan en los avisos.

### Exportar la política propuesta a Cisco FMC 7.6 (`politica-fmc`)

Si el `resultado.json` de la carpeta de `--propuesta` declara `restricciones.subcomandos_deshabilitados` con `politica-fmc`
(clave del mismo nombre en el perfil), el subcomando termina con código 2 sin escribir archivos (D121).

Toma `politica_propuesta.csv` y `politica_objetos.csv` (M3a), ya revisados por el analista (puede cambiar `decision`,
borrar filas o renombrar objetos), y genera la carga para la API REST de FMC. La herramienta **no se conecta a ningún
FMC**: el analista revisa y ejecuta el script.

```bash
python ot_pcap_assess.py politica-fmc --propuesta politica_propuesta.csv --objetos politica_objetos.csv \
    -o ~/datos/cliente_fmc [--politica NOMBRE] [--incluir-revisar]
cd ~/datos/cliente_fmc && python3 aplicar_fmc.py            # simula (por defecto)
python3 aplicar_fmc.py --aplicar                            # crea; pide escribir SI
```

- Solo `decision = permitir`; con `--incluir-revisar` también las `revisar`, **deshabilitadas** y con comentario
  «revisar: razones». `bloquear` nunca genera regla (lo hace la acción por defecto, BLOCK con registro).
- Política nueva `PROPUESTA_<firewall>_<AAAAMMDD>` (o `--politica`); nunca edita la vigente ni la asigna a un equipo.
- Salidas: `fmc_objetos.json`, `fmc_reglas.json`, `aplicar_fmc.py` (solo biblioteca estándar), `LEEME_FMC.txt` y, al
  ejecutar, `aplicar_fmc.log` (método, ruta y código; sin credenciales).
- Antes de escribir valida que cada objeto exista, los nombres (letras, dígitos, `_`, `-`, `.`, máx. 64), los valores y
  las zonas; avisa de reglas con más de 50 objetos por lado y de reglas con 0.0.0.0/0. Las zonas de seguridad deben
  existir en FMC (el script no las crea).
- Las rutas de la API salen de la documentación pública de FMC y no están validadas contra un equipo real: simular
  primero con la versión del cliente (7.6.4). La propuesta solo cubre lo observado (ver `LEEME_FMC.txt`). Decisión: D48.

#### Otros fabricantes: `--formato fortios|checkpoint|panos` (M4)

Con la misma entrada y la misma validación, `politica-fmc --formato ...` escribe archivos de comandos para que el
analista los revise y aplique (la herramienta no se conecta a ningún equipo):

| Formato | Archivos | Notas |
|---|---|---|
| `fortios` | `fortios_politica.conf`, `LEEME_FORTIOS.txt` | CLI: address, addrgrp, service custom/group y `config firewall policy` con `edit 0`; revisar = `set status disable`. No genera la denegación (implícita). Solo IPv4. |
| `checkpoint` | `checkpoint_mgmt_cli.txt`, `LEEME_CHECKPOINT.txt` | Un `mgmt_cli -s session.txt ...` por línea; `--capa` (defecto `Network`); `publish` comentado. Sin zonas: van en el comentario. Solo IPv4. |
| `panos` | `panos_set.txt`, `LEEME_PANOS.txt` | Comandos `set ...`; `--vsys vsys1` los prefija; `commit` comentado. |

Reglas de inclusión, servicio «cualquiera» (sin puertos) y comentarios igual que FMC. Los archivos no contienen
comandos de borrado; el `LEEME` lista lo creado y cómo quitarlo. Un nombre que pasa del límite del fabricante (63 en
Check Point y PAN-OS) se recorta con aviso; si dos chocan al recortar, no se genera nada. La sintaxis no se probó contra
equipos reales: validar en la versión del cliente (simulación o laboratorio). Decisión: D58.

### Solicitud de Cambio para el comité (`solicitud-cambio`)

Termina con código 2 sin escribir nada si el `resultado.json` de la carpeta de `--propuesta`, o el `--perfil` dado, declara
`solicitud-cambio` en `subcomandos_deshabilitados` (D121).

Arma la Solicitud de Cambio (RFC) con los archivos que el analista ya revisó; no se conecta a nada:

```bash
python ot_pcap_assess.py solicitud-cambio --propuesta politica_propuesta.csv --objetos politica_objetos.csv \
    --comparacion politica_comparacion.csv --rutas rutas_propuestas.csv --bloqueados politica_bloqueados.csv \
    --perfil perfil.json --firewall-nombre FTD-01 --solicitante "Nombre" --ventana "sábado 22:00" \
    --formato-carga fmc -o ~/datos/cliente_sc
```

Obligatorios: `--propuesta`, `--objetos`, `-o`. Sin `--comparacion`, `--rutas` o `--bloqueados` el documento lo dice
en la sección que corresponde (el impacto sobre lo observado no se evaluó). Escribe `solicitud_cambio.docx`,
`solicitud_cambio.md` y `solicitud_cambio_cambios.csv` (un renglón por cambio SC-001, SC-002...: fase, tipo, acción,
elemento, detalle, justificación, riesgo, validación, reversión). Mismas reglas que `politica-fmc`: permitir entra,
revisar entra deshabilitada y se habilita en la fase 2, bloquear no crea regla. Las reglas actuales «validar antes de
eliminar» solo entran con aciertos = 0 explícito; los bloqueos no se tocan. El texto es una propuesta a validar por el
comité, nunca «cumple/no cumple». Solo español.

**Plantilla (`--plantilla JSON`).** La estructura vive en `ot_assess/data/solicitud_cambio.json`; un JSON propio se
superpone a ella (lo que no pongas se hereda). Claves: `titulo`; `secciones` (lista ordenada de `{clave, titulo}`;
claves válidas `datos_generales`, `descripcion`, `alcance`, `impacto`, `plan`, `pruebas`, `reversion`,
`aprobaciones`, `anexos`; omitir una la quita); `columnas_csv` y `columnas_alcance` (de `id, fase, tipo, accion,
elemento, detalle, justificacion, riesgo, validacion, reversion`); `encabezados` (nombre visible de cada columna);
`datos_generales` (`tipo_cambio`, `campos` `{clave, etiqueta}`, `pendiente`); `textos` (textos fijos);
`fases` (las 4, con `titulo`, `descripcion`, `criterio`, `reversion`; admiten `{politica}`, `{formato}`, `{archivos}`,
`{dias}`); `dias_observacion`; `acciones` (riesgo, validación y reversión por acción); `aprobaciones` (`columnas`,
`roles`). Una clave desconocida o una forma inválida termina con código 2 y un mensaje. Decisión: D61.

### Validar la captura el primer día (`validar-captura`)

El sensor (SPAN o TAP) se deja de 3 a 15 días y el primer día hay que decidir si la captura sirve:

```bash
python ot_pcap_assess.py validar-captura capturas_sitio_a/ [-o validacion] [--perfil perfil.json] \
    [--switch sw1.txt] [--vlans-esperadas 10,20]
```

Una carpeta es un punto de captura (con un solo archivo suelto, el punto es el archivo). Lee cada archivo **una vez**
con tshark y los campos mínimos, sin inventario, hallazgos ni reportes (mucho más rápido que el análisis completo; no
muestrea). Escribe `cobertura_captura.csv` (una fila por punto y una por archivo, columna `nivel`), `cobertura_zonas.csv`
(zona o subred inferida por punto: `vista`, `solo difusion` o `sin trafico`) y `validacion_captura.html`. Por punto y
por archivo: inicio, fin, duración, huecos de más de 5 min, paquetes, bytes, pps y Mbps (promedio, p95 y máximo por
minuto), % de difusión y multidifusión, truncados, duplicados exactos (solo en el análisis completo, con editcap),
fragmentos IP, % de segmentos TCP con pérdida (`tcp.analysis.lost_segment` o `ack_lost_segment`), % de
retransmisiones, % de sesiones TCP con datos de un solo lado, VLAN vistas y protocolos industriales vistos. Las VLAN
esperadas salen de `vlans_esperadas` del perfil, de `--vlans-esperadas` y, con `--switch`, de las sesiones SPAN.
El **veredicto** (heurísticas sin calibrar, D80; no es cumplimiento): *no apta* si la pérdida TCP supera 5 %, las
sesiones de un solo sentido 50 %, la duración es menor de 10 min o no hay paquetes con IP; *apta con limitaciones* si la
pérdida supera 1 %, el sentido único 20 %, hay huecos, truncados, duración menor de 24 h, VLAN o zonas esperadas sin
tráfico o ningún protocolo industrial; *apta* en otro caso. El análisis completo agrega la misma validación como
sección «Validación de la captura» al inicio del reporte (HTML, Markdown y Word), la hoja «Cobertura de captura» y la
clave `cobertura_captura` de `resultado.json`; allí, si la captura se muestreó (`--max-packets`), la duración no se
evalúa. Decisión: D80.

### Salud de la red y línea base de tráfico (análisis completo y `diagrama`)

Entregable «Infrastructure analysis and network health». Reutiliza la lectura de C1 (no vuelve a leer la captura) y,
con `--switch`, el `show interfaces` de la sesión. Sección «Salud de la red y línea base de tráfico» en HTML, Markdown y
Word (tablas cortas, sin IP cuando el nombre basta) y el detalle, con IP, en CSV y hojas del Excel: `salud_red.csv`
(por punto de captura y total: Mbps, % y pps de difusión, ARP por minuto y los 5 equipos que más ARP emiten,
retransmisiones y pérdida TCP), `top_equipos.csv` (10 por bytes y 10 por paquetes, con su % del total; el % cuenta cada
paquete en sus dos extremos, la suma puede pasar de 100 %), `top_conductos.csv` (10 por bytes), `mezcla_protocolos.csv`
(servicio o protocolo, % de bytes y de paquetes; industriales primero), `tcp_conductos.csv` (conductos con al menos 200
segmentos) e `interfaces_switch.csv` (solo con `--switch`: BW, tasa de 5 minutos, utilización, errores, CRC y
descartes de salida por interfaz). Hallazgos (umbrales sin calibrar, D81): **Tormenta de difusión o multidifusión**
(p95 de pps de difusión por minuto mayor de 500, o más de 5000 paquetes en un segundo; Alta si la captura toca el nivel
Purdue 0-2), **Retransmisiones TCP elevadas en un conducto OT** (más de 5 % con al menos 200 segmentos, puertos
industriales) e **Interfaz de switch saturada o con descartes** (utilización de 70 % o más en 5 minutos, descartes de
salida de más de 0,1 % o más de 1000 CRC; troncales primero; el destino del SPAN no se repite, ya es un hallazgo de
T10c). La **línea base de tráfico** (`linea_base_trafico.json` y `.csv`) guarda por conducto, con la identidad de
`comunicaciones.csv`, los bytes y paquetes por minuto p50 y p95 dentro de la ventana (los minutos sin tráfico cuentan
cero), la clase de periodicidad de T5, el primer y último visto y los metadatos de la corrida. Es un artefacto para
comparar después; `comparar` aún no lo lee (lo usa la línea base aprobada, abajo). En `diagrama` no hay series por
minuto: solo bytes y paquetes por conducto, y la sección lo dice. Decisión: D81.

### Línea base aprobada del sitio (`linea-base` y `--linea-base`)

El equipo revisa una corrida de un sitio y la aprueba como referencia; cada corrida nueva se compara con ella y lo que
se desvía sale como hallazgo con su playbook.

```bash
python ot_pcap_assess.py linea-base aprobar ~/datos/cliente_corrida -o ~/datos/cliente_linea_base \
    --sitio "Planta 1" --aprobado-por "Ana Perez" --revisado-por "Luis Gomez" --nota "Operación normal"
python ot_pcap_assess.py linea-base verificar ~/datos/cliente_linea_base
python ot_pcap_assess.py ~/capturas_nuevas -o ~/datos/cliente_nueva --linea-base ~/datos/cliente_linea_base
```

`aprobar` copia de la corrida solo lo necesario (`resultado.json`, `inventario.csv`, `inventario_normalizado.csv`,
`comunicaciones.csv`, `control.csv`, `hallazgos.csv` y, si existen, `linea_base_trafico.json`, `periodicidad.csv` y
`firewall_contraste.csv`), nunca capturas, caché ni mapas de anonimización, y escribe `linea_base_aprobada.json` (sitio,
versión, ventana y puntos de captura, perfil, quién aprobó y quién revisó, fecha, nota y el manifiesto SHA-256) y
`linea_base_aprobada.sha256`. Si se dan `--aprobado-por` y `--revisado-por` deben ser personas distintas. La carpeta es
inmutable: `verificar` recalcula los hash y, si algo cambió, falla nombrando el archivo; para cambiar la línea base se
aprueba otra en otra carpeta. Las salidas quedan con permisos 600/700.

`--linea-base CARPETA` (capturas y `diagrama`) verifica el manifiesto (si falla, avisa y no compara) y compara la
corrida con la aprobada con el motor de `comparar` (E4) y la línea base de tráfico (L1). Desviaciones, cada una con
atención (criterios de E4), zona y detalle: activo nuevo no aprobado; activo aprobado no visto; conducto nuevo (par,
puerto o protocolo); conducto aprobado sin tráfico; escritor nuevo (operaciones de control hacia un equipo que no las
recibía de ese origen); cambio de firmware, modelo o MAC de una IP (del inventario normalizado, solo si la línea base ya
tenía el dato); volumen de un conducto por encima de 3 veces su p95 aprobado y cambio de periódico a irregular (solo si
ambas corridas tienen series por minuto, es decir, vienen de capturas); hallazgo nuevo. Hallazgos (mapeos «sin
revisar»): **Escritor nuevo hacia equipos de control fuera de la línea base aprobada** (Alta), **Conducto nuevo fuera de
la línea base aprobada** (Alta si entra a un nivel 0-2 o viene de Internet; si no, Media), **Activo nuevo no aprobado en
la red** (Media), **Cambio de firmware, modelo o MAC respecto de la línea base aprobada** (Media; Alta si es un
controlador), **Tráfico fuera de la línea base aprobada** (Baja) y **Conductos aprobados sin tráfico** (Baja). Salidas:
`desviaciones_linea_base.csv` y su hoja (con `estado_revision` —esperado, no esperado o por investigar—, `revisado_por`,
`fecha` y `comentario` vacías para el control de calidad), la sección «Desviaciones respecto de la línea base aprobada» y
la clave `linea_base_aprobada` de `resultado.json`. Si el sitio de la línea base no coincide con el del perfil, avisa y
compara igual. Limitaciones: la herramienta trabaja por lotes (no hay monitoreo continuo ni alertas); las columnas de los
CSV dependen del idioma, así que la línea base y la corrida deben generarse en el mismo (si no, esa comparación se omite
con un aviso); los umbrales (3 veces el p95) no están calibrados. Decisión: D82.

### Madurez por dominio (`madurez` y `--madurez`, D84)

La madurez se mide con una entrevista estructurada; la herramienta da el cuestionario, lo lee y lo contrasta con la
evidencia técnica. Ocho dominios con 4 preguntas cada uno (32), con ID `ACT-01` a `RIE-04`, redactadas para contestarse
con personal de OT, mantenimiento, ingeniería, TI y ciberseguridad. Cada pregunta cita su categoría de NIST CSF 2.0 y su
FR o SR de IEC 62443 (mapeos sin revisar).

```bash
python ot_pcap_assess.py madurez cuestionario -o cuestionario_madurez.csv          # plantilla (--idioma en)
# en la entrevista: columna "respuesta" con 0 a 4, N/A o vacío; evidencia_presentada, entrevistado, fecha, comentario
python ot_pcap_assess.py ~/capturas -o ~/datos/cliente --madurez cuestionario_madurez.csv --perfil perfil.json
```

Escala 0 a 4, alineada a ML1 a ML4 de IEC 62443: 0 no existe; 1 inicial (ad hoc, depende de personas); 2 gestionado
(documentado y repetible en el sitio); 3 definido (estandarizado, se practica y se verifica); 4 mejora continua (se
mide y se mejora). `--madurez` valida todo antes de analizar: una respuesta fuera de 0 a 4 o un ID desconocido es un
error con el número de línea y no se escribe nada. Nivel actual del dominio = promedio de sus respuestas numéricas (un
decimal; N/A no cuenta); con menos de la mitad contestadas, o sin ninguna numérica, queda «insuficiente», sin nivel.
Objetivo: `madurez_objetivo` del perfil, si no el número de `ml_objetivo`, si no 2 (propuesto; lo fija el cliente).
Brecha = objetivo - actual (mínimo 0). El promedio general usa los dominios con nivel.

Con o sin cuestionario salen las **señales técnicas** de cada dominio: los hallazgos de la corrida asignados al dominio
por severidad (asignación título a dominio en `ot_assess/data/madurez.json`, sin revisar), el porcentaje de activos con
fabricante, modelo y firmware (activos), los activos fuera de soporte y con CVE en KEV (parches) y el veredicto de la
cobertura de captura (monitoreo). Incidentes y riesgo son «no evaluables con datos de red». Un dominio declarado en
nivel 3 o más con al menos un hallazgo Alta asignado se marca «revisar: la evidencia de red no respalda el nivel
declarado»; no cambia el nivel. El nivel es lo que el sitio declara: la herramienta nunca dice «cumple» ni «no cumple».

Salidas: `madurez.csv`, `cuestionario_madurez.csv` (la plantilla para la visita, o el cuestionario con lo contestado),
hojas «Madurez por dominio» y «Cuestionario de madurez», sección en HTML (tabla y radar actual contra objetivo en SVG
en línea, sin JavaScript; el radar solo aparece si hay niveles), Markdown y Word (tabla) y la clave `madurez` de
`resultado.json`. Sin cuestionario la sección muestra objetivo y señales y apunta a la plantilla. La línea base 62443
(B7b) no cambia.

#### Niveles (Tiers) de NIST CSF 2.0 por función (CSF2T)

Cuando el cliente mide la madurez con los Tiers de NIST CSF 2.0 y fija una meta por función (por ejemplo Gobernar,
Proteger, Detectar y Recuperar en «Repetible»; Identificar y Responder en «Adaptativo»), la herramienta entrega la hoja
de trabajo; **no mide los tiers** (caracterizan el rigor del gobierno y la gestión del riesgo; los declara la
organización en la entrevista, NIST SP 1302). Se activa con la clave `csf_tiers_objetivo` del perfil, con `--csf-tiers
ARCHIVO`, o con ambos; sin ninguno no sale nada nuevo.

```json
"csf_tiers_objetivo": {"GV": "Repetible", "ID": "Adaptativo", "PR": 3, "DE": 3, "RS": 4, "RC": "Repetible"}
```

Claves: `GV` Gobernar, `ID` Identificar, `PR` Proteger, `DE` Detectar, `RS` Responder, `RC` Recuperar. Tier: 1 a 4 (número
o texto) o el nombre, en español o inglés y sin distinguir mayúsculas: 1 Parcial (Partial), 2 Informado por el riesgo
(Risk Informed), 3 Repetible (Repeatable), 4 Adaptativo (Adaptive). Una función desconocida o un tier inválido es un
error. La función sin meta en el perfil, o sin perfil, queda en Tier 2 «propuesto por la herramienta; lo fija el
cliente».

La corrida escribe `csf_tiers.csv` (una fila por función, en el orden del CSF): meta y su origen, `tier_actual` y
`brecha` vacíos, y por función el conteo de filas NIST de la matriz de controles en brecha con evidencia, control
observado, sin evidencia y no evaluables, más cuántas subcategorías y controles de SP 800-53 la alcanzan. Las filas de
una función son las del control base citado por las referencias informativas de CSF 2.0 de sus subcategorías
(`marcos/csf2_referencias.json`); son evidencia relacionada, no un veredicto. Después de la entrevista se llenan
`tier_actual` (1 a 4 o el nombre; vacío = sin tier) y `evidencia_presentada`, `entrevistado`, `fecha`, `comentario`, y
se entrega el mismo archivo con `--csf-tiers csf_tiers.csv` (también en `diagrama`). Se leen solo esas columnas
(separador `,` o `;`, BOM aceptado, cabeceras en español o inglés); una función repetida o desconocida o un tier
inválido detiene la corrida con el número de línea. Brecha = máx(0, meta - actual). Con un tier declarado de 3 o más y un
hallazgo de severidad Alta en las filas NIST de la función, la columna `revision` lo marca («revisar: la evidencia de red
no respalda el tier declarado»); no cambia el tier.

Salidas: `csf_tiers.csv` (hoja «Tiers CSF 2.0»), sección «Niveles (Tiers) de NIST CSF 2.0 por función» en HTML, Markdown
y Word después de la de madurez, y la clave `csf_tiers` de `resultado.json`. Nunca «cumple» ni «no cumple».

### Validar la política propuesta contra otra ventana (`politica-validar`)

Antes de aplicar la política en el firewall: «qué rompería esta propuesta». Evalúa `politica_propuesta.csv` y
`politica_objetos.csv` (revisados por el analista) contra los cruces de **otra** ventana (otra captura, otra
exportación, otro periodo) analizada con `--firewall` del **mismo** equipo:

```bash
python ot_pcap_assess.py politica-validar --propuesta politica_propuesta.csv --objetos politica_objetos.csv \
    --cruces salida_otra_ventana/ [--cruces otra_mas/] [--incluir-revisar] -o ~/datos/cliente_validacion
```

`--cruces` es la carpeta de salida de una corrida (o su `firewall_cruces_detalle.csv`); repetido, los cruces iguales
se suman. Las reglas se evalúan en `orden`, gana la primera que coincide (interfaces `ENTRADA -> SALIDA`, origen,
destino y servicio; grupos anidados; `ANY_INTERNET` = IP pública). Las `revisar` solo cuentan con `--incluir-revisar`.
Categorías por cruce: `sigue_permitido`, **`se_romperia`** (hoy cruza y la propuesta no lo permite), `bloqueo_decidido`
(una fila `bloquear`, o lo que M3a ya cierra a propósito: entrante desde Internet y DNS externo), `sigue_bloqueado` y
`se_abriria` (hoy denegado y la propuesta lo permite) y `probable_respuesta` (puerto destino >= 49152 con el cruce
inverso presente en la entrada a un puerto bajo: el firewall la deja pasar por estado; no entra en «lo que se
rompería»). Para cada `se_romperia` se busca la regla que casa en todo menos
una dimensión y se sugiere qué agregar. Escribe `validacion_cruces.csv`, `validacion_reglas.csv` (`sin_uso` marca las
reglas sin tráfico: es un dato, no una orden de borrarlas) y `validacion.md`. Código de salida 0 aunque haya
`se_romperia`; una propuesta inválida (objeto inexistente, IP o puerto no válido, orden repetido) termina en 2 con el
número de fila. Las respuestas de sesión (`respuesta`) no se evalúan. La ventana nueva también es parcial: no prueba que
no falte nada. Decisión: D67.

### Comparar dos corridas (`comparar`)

Qué cambió entre una corrida y otra (política nueva en el firewall, línea base contra un mes después):

```bash
python ot_pcap_assess.py comparar --antes ~/datos/cliente_antes --despues ~/datos/cliente_despues \
    -o ~/datos/cliente_cambios [--umbral-volumen 10]
```

Lee los CSV públicos de ambas carpetas (`inventario`, `comunicaciones`, `control`, `hallazgos` y, si están en las dos,
`firewall_contraste`); un CSV ausente en una corrida omite esa comparación con aviso. Escribe
`comparacion_activos.csv`, `comparacion_conductos.csv`, `comparacion_escritores.csv`, `comparacion_hallazgos.csv`,
`comparacion_firewall.csv`, `comparacion.json`, `comparacion.md` y `comparacion.html`. Cada fila lleva `atencion`
(alta/media/baja) con su razón; no es un hallazgo del motor de reglas. El volumen depende de la ventana de cada
corrida. Avisa de versiones, perfiles o tipos de corrida distintos y de corridas que casi no comparten activos.
Solo español. Decisión: D62.

### Consolidado de varios sitios (`sitios`)

El consolidado mezcla sitios: `-o` no puede ser una carpeta de sitio ni quedar dentro de una (código 2 sin escribir nada).
`consolidado_sitios.json` lleva `uso` («interno; no se entrega a un sitio») y la consola lo repite (D121).

```bash
python ot_pcap_assess.py sitios ~/datos/planta_a ~/datos/planta_b ~/datos/planta_c -o ~/datos/programa
```

Lee las carpetas de salida de cada sitio (solo los CSV públicos `hallazgos`, `riesgos`, `madurez`,
`inventario_normalizado`, `vulnerabilidades_firmware`, `eventos_ingenieria` y `salud_red`; de `resultado.json`, cliente,
sitio, idioma y versión). El nombre del sitio es `perfil.sitio` o, si falta, el de la carpeta; si dos coinciden, falla
con código 2 y se resuelve con `--nombre CARPETA=NOMBRE` (repetible). Escribe `sitios.csv`, `hallazgos_comunes.csv`
(qué se repite entre sitios), `hallazgos_sitios.csv`, `riesgos_sitios.csv` (un solo orden por puntuación),
`madurez_sitios.csv` (con filas "Promedio"), `inventario_sitios.csv`, `vulnerabilidades_sitios.csv`,
`consolidado_sitios.json` y `consolidado_sitios.xlsx`, con las mismas 8 hojas y columnas siempre (Sitios, Hallazgos
comunes, Hallazgos por sitio, Riesgos, Madurez, Inventario, Vulnerabilidades, Fuentes con sha256 de cada CSV leído).
Un archivo ausente da un aviso y una hoja sin filas de ese sitio. Avisa de clientes, versiones o idiomas distintos; los
conteos se normalizan al español interno: lee carpetas generadas con `--idioma en` (cabeceras y valores de severidad,
nivel, categoría y título con traducción exacta). `--idioma {es,en}` (defecto: el del primer sitio).
Es evidencia técnica agregada, no cumplimiento. Decisión: D94.

### Cadena de custodia (`custodia`)

Registro `.jsonl` de solo agregar; cada evento (recepcion, copia, transferencia, analisis, entrega, devolucion,
destruccion) lleva el SHA-256 de la linea anterior, asi que editar o borrar un evento en medio se detecta.

```bash
python3 ot_pcap_assess.py custodia registrar --registro custodia.jsonl --evento recepcion \
    --entrega "Ing. A" --recibe "Analista B" --medio "USB 64 GB" --cifrado BitLocker captura.pcap
python3 ot_pcap_assess.py custodia verificar --registro custodia.jsonl [captura.pcap ...]   # 0 / 1 / 2
python3 ot_pcap_assess.py custodia exportar --registro custodia.jsonl -o salida/             # csv + html con firmas
python3 ot_pcap_assess.py capturas/ --custodia custodia.jsonl                                # estado por captura
```

`exportar --idioma {es,en}` (defecto es) traduce el texto fijo de `custodia.html` y las cabeceras de `custodia.csv`; los
datos del registro no se traducen y la consola sigue en español.

La herramienta no cifra: el cifrado en reposo es del volumen o contenedor y solo se declara. Comunique la huella
que imprime `verificar` por un canal aparte (sin ella, borrar los ultimos eventos no se detecta). El registro es
dato del cliente (nombres de personas): no lo suba al repositorio.

### Paquete de entrega (`empaquetar`)

Arma lo que se entrega al cliente desde una o más carpetas de salida (capturas, `diagrama`, `comparar`,
`solicitud-cambio`, política) y permite comprobar después que nada cambió:

```bash
python ot_pcap_assess.py empaquetar ~/datos/cliente_capturas ~/datos/cliente_cambios \
    -o ~/entregas/cliente_2026-11 --titulo "Evaluación OT, sitio X" [--zip] [--excluir PATRON]
python ot_pcap_assess.py empaquetar --verificar ~/entregas/cliente_2026-11      # carpeta o .zip
```

Cada carpeta de salida va en su subcarpeta (mismo nombre: sufijo `_2`). Se agregan `manifiesto.json` (herramienta y
versión, fecha UTC, título, cliente y sitio del perfil, y por carpeta: tipo de corrida, versión que la produjo, entradas
con nombre y SHA-256 —las entradas originales no se copian— y salidas con tamaño y SHA-256), `manifiesto.sha256`
(formato `sha256sum`: `sha256sum -c manifiesto.sha256`) y `LEEME_ENTREGA.txt`. Nunca entran enlaces simbólicos, archivos
ocultos, `*.log`, carpetas `crudo/`, la caché de E6 ni mapas o listas de términos de `anonimizar`; la consola lista lo
excluido con el motivo. Los textos pierden la ruta absoluta del equipo (`comparacion.json` guarda las de `--antes` y
`--despues`). `--zip` es determinista (orden y fechas fijos). `--verificar` informa modificados, faltantes y sobrantes
(código 0 si coincide, 1 si no, 2 si el paquete no se puede leer o el ZIP trae rutas `..` o absolutas). Sin firma ni
cifrado: quien cambie archivos y manifiesto a la vez no se detecta sin un hash guardado aparte. Es evidencia técnica,
no dictamen de cumplimiento. Decisión: D64.

## Estructura del código

```
ot_pcap_assess.py     punto de entrada (compatibilidad)
ot_assess/
  cli.py              orquesta el análisis de punta a punta
  tools.py            localiza y envuelve tshark, capinfos y editcap
  fields.py           campos y filtros de tshark
  catalog.py          puertos OT, fabricantes, software obsoleto, severidades
  texts.py            textos fijos del reporte
  util.py, model.py   funciones puras; Capture y Assessment
  flows.py            pase 1: activos y flujos
  detail/             pase 2: un colector por tema (identidad, texto claro, control, L2)
  roles.py            rol y nivel Purdue
  rules/              hallazgos, un archivo por categoría
  standards.py        marcos de referencia por hallazgo: MITRE, IEC 62443, NERC CIP, NIST
  importers/          lectura de exportaciones (CSV, JSON, XLSX) y alias de columnas
  cli_diagrama.py     subcomando `diagrama`
  anonimizar.py, anonimizar_pcap.py, cli_anonimizar.py   subcomando `anonimizar` (mapa, transformaciones y capturas)
  cli_xdome.py, importers/xdome_api.py   subcomando `xdome-descargar` (cliente de la API de xDome y conversion a CSV)
  switches/           lector de switches Cisco IOS/IOS-XE (`--switch`), ubicación por MAC y cobertura SPAN
  consolidate.py      inventario único y matriz de comunicaciones
  diagram/            grafo, layout, SVG, Mermaid y draw.io
  report/             un escritor por formato: md, html, csv, json, diagramas
tests/                capturas sintéticas y pruebas
```

### Cómo extender

| Quiero... | Dónde |
|---|---|
| Una regla de hallazgo nueva | Una función `@RULES` en `ot_assess/rules/<categoría>.py` que llame a `finding(...)`. Si es de una categoría nueva, un módulo nuevo y su `import` en `rules/__init__.py`. El orden de importación es el orden de los hallazgos. |
| Mapearla a MITRE, IEC 62443, NERC CIP o NIST | Una entrada en `referencias` del JSON del marco, en `ot_assess/marcos/` (una prueba obliga a decidirlo para toda regla nueva). |
| Reconocer una columna de una exportación | Su nombre normalizado en `ACTIVOS` o `ENLACES` de `importers/perfiles.py`. |
| Soportar un protocolo con código de función | Una fila en `PROTOCOLOS` de `detail/control.py`, más sus campos en `fields.py`. |
| Extraer otro dato de los paquetes | Una función `@COLLECTORS` en `ot_assess/detail/` y su `import` en `detail/__init__.py`. |
| Un playbook de remediación nuevo | Un JSON en `ot_assess/playbooks/` (formato y reglas en D55; el nombre del archivo es su `id`), sus textos en `catalogos/en.json` y `tests/test_playbooks.py` valida el resto. |
| Un puerto o fabricante nuevo | `catalog.py`. |
| Un formato de salida nuevo | Una función `(Assessment, Path)` en `ot_assess/report/` y una fila en `ESCRITORES`. |
| Otra vista de diagrama | Un constructor de grafo en `diagram/graph.py` y una fila en `VISTAS` de `diagram/__init__.py`. |

## Documentación

| Documento | Contenido |
|---|---|
| [docs/ALCANCE.md](docs/ALCANCE.md) | Qué es el proyecto, para quién, entradas, salidas, marcos, límites y arquitectura objetivo |
| [docs/PROPUESTAS.md](docs/PROPUESTAS.md) | Banco de propuestas con valor, esfuerzo y dependencias |
| [docs/AUDITORIA.md](docs/AUDITORIA.md) | **Punto de entrada para auditar**: alcance, paquete de evidencia, registro de hallazgos conocidos, lista de verificación |
| [docs/ARQUITECTURA.md](docs/ARQUITECTURA.md) | Flujo de datos, contratos entre módulos, invariantes, modos de fallo |
| [docs/SEGURIDAD.md](docs/SEGURIDAD.md) | Modelo de amenazas, controles y recomendaciones al operador |
| [docs/PRUEBAS.md](docs/PRUEBAS.md) | Estrategia, cobertura medida, brechas |
| [docs/CATALOGO.md](docs/CATALOGO.md) | Reglas, marcos, protocolos, puertos, opciones y columnas (generado del código) |
| [docs/DECISIONES.md](docs/DECISIONES.md) | Decisiones de diseño y su motivo |
| [docs/ESTADO.md](docs/ESTADO.md) | Avance y pendientes (para quien continúa el desarrollo) |

`scripts/evidencia.sh` reúne en una carpeta todo lo que un auditor necesita (versión, pruebas, cobertura,
dependencias y revisión estática). La versión del código se consulta con `--version`.

## Pruebas

```bash
scripts/setup.sh      # una vez: tshark, scapy y pyflakes (solo desarrollo)
scripts/verificar.sh  # lint + pruebas, salida corta
```

`tests/gen_pcaps.py` genera capturas sintéticas (Modbus, S7comm, IEC-104, DNP3,
CIP, CDP, DHCP, texto claro, conflicto ARP) sin datos de cliente. La prueba de
extremo a extremo se omite sola si faltan `tshark` o scapy; las de los diagramas, los
estándares y la importación solo usan la biblioteca estándar.

`tests/gen_exports.py` genera exportaciones **sintéticas** de una planta ficticia en cuatro
estilos de columnas (CSV con ids, CSV por nombre con punto y coma, JSON anidado y XLSX). No son
formatos reales de ninguna plataforma: sirven para comprobar que la importación tolera
encabezados distintos, valores múltiples y JSON anidado.

## Notas de interpretación

Los roles, zonas y criticidades son **inferidos del tráfico observado**, no
declarados por los equipos. Hay que validarlos con el personal de planta antes
de usarlos en una entrega.

El script **no emite identificadores de CVE**. Extrae el fingerprint exacto
(fabricante, modelo, versión) y lo presenta para contrastarlo contra el aviso de
seguridad del fabricante: Cisco PSIRT, Siemens SSA, Rockwell SD, Belden, Moxa.
Es a propósito: una base de CVEs embebida envejece mal y lleva a afirmar cosas
que no se sostienen frente al cliente.

La ausencia de un hallazgo no prueba la ausencia del riesgo. Si la captura no
contiene los paquetes que revelan identidad, ninguna herramienta pasiva —esta ni
ninguna otra— puede enumerar vulnerabilidades. Esa es justamente la lectura que
la sección de brecha de visibilidad busca dejar documentada.

## Anonimizar exportaciones y configuraciones

Para compartir una muestra o usarla como dato de prueba sin llevar datos del cliente:

```bash
python ot_pcap_assess.py anonimizar exportaciones/ config_fw.txt -o muestra/ \
  --mapa ~/mapas/cliente.json --terminos terminos.txt
```

`terminos.txt` lleva un término por línea (cliente, sitios, dominios internos; `#` comenta):

```
# cliente
Acme
acme.local
Planta Norte
```

- Entradas: archivos o carpetas (recursivo). Salida: los mismos nombres relativos dentro de `-o`, más
  `anonimizacion.csv` (conteos por archivo). CSV, XLSX y JSON se tratan como tablas; el resto de los
  archivos de texto (`.txt`, `.cfg`, `.conf`, `.log`) como configuración. Los binarios se saltan con aviso.
- **Capturas** (`.pcap`, `.pcapng`): se seudonimizan las cabeceras con el mismo mapa (MAC, ARP, IPv4 y la
  IPv4 citada en ICMP de error; Ethernet con 802.1Q/QinQ e IPv4 crudo) y se recalculan las sumas IP, TCP,
  UDP e ICMP; el análisis de la salida da los mismos activos, conductos y hallazgos. La salida siempre es
  `.pcap` (un `.pcapng` se convierte antes con `editcap`; si tiene varias interfaces de distinto tipo,
  sepárelo por interfaz). Se leen en flujo, así que el tamaño no importa (40 MB con 3000 IP conocidas en unos 15 s).

```bash
python ot_pcap_assess.py anonimizar capturas/planta.pcap -o muestra/ --mapa ~/mapas/cliente.json
python ot_pcap_assess.py anonimizar capturas/planta.pcap -o muestra/ --mapa ~/mapas/cliente.json --carga recortar
```

  `--carga mantener` (por defecto) seudonimiza también la carga útil **sin cambiar ninguna longitud** (así
  TCP, DNS y los protocolos OT siguen siendo válidos): IP y MAC conocidas en binario (respuestas DNS A, DHCP,
  LLDP, PROFINET...), IPv4 en texto (si el seudónimo mide distinto, se enmascara: `10.11.12.5` ->
  `xx.xx.xx.x`, sin reversa), y los términos (`--terminos`) y nombres del mapa de 4 o más caracteres, en
  ASCII y UTF-16LE, con un seudónimo de la misma longitud (el mapa guarda la correspondencia en `carga`).
  Una coincidencia de 4 bytes de un valor OT (p. ej. un registro Modbus) con una IP conocida también se
  cambia: se cuenta en `carga_ot_modificada` y se avisa. **El texto libre que no sea IP, MAC, término o
  nombre conocido se conserva** (p. ej. dominios internos): para sacar un buen resultado, corra primero el
  análisis, tome los dominios internos de `dns_registros.csv` y agréguelos a `--terminos`; aun así, revise
  la salida o use `recortar` antes de compartir fuera.
  `--carga recortar` corta cada paquete tras la cabecera L4 (`caplen` baja, `origlen` se conserva): ya no
  hay datos que filtrar, pero el análisis pierde la detección de protocolos OT, DNS y TLS (solo quedan
  flujos, puertos y volúmenes). `anonimizacion.csv` agrega `paquetes`, `sumas_sin_recalcular` (segmentos
  recortados por snaplen o fragmentos: se deja la suma original) y `carga_recortada`; con `mantener` suma `ip_binarias`, `mac_binarias`, `ip_texto`, `ip_texto_enmascaradas`,
  `terminos_carga` y `carga_ot_modificada`. IPv6 y otros tipos de
  enlace no se soportan (IPv6 se cuenta y se avisa; un enlace distinto omite el archivo).
- **Es seudonimización reversible, no anonimato garantizado.** El mapa (`--mapa`, JSON con permisos 0600)
  guarda la clave y la tabla real -> seudónimo: con él se revierte todo. Guárdelo fuera del repositorio y
  de la carpeta de salida (el comando lo rechaza dentro del repo) y no lo comparta. Con el mismo mapa, la
  misma entrada da exactamente la misma salida.
- Se conservan a propósito las subredes (prefijos hasta /24 y el último octeto), el OUI de las MAC, los
  conteos y las longitudes de las tablas: el análisis sigue dando lo mismo. Eso también puede filtrar
  información; ver D41 en `docs/DECISIONES.md`.
- Se omiten las líneas con contraseñas, claves, comunidades SNMP o tokens, los bloques `certificate ...
  quit` y las descripciones y columnas de texto libre. IPv6 no se cambia (el resumen cuenta cuántas hay).
- **Revise la salida antes de compartirla.** No se tocan los nombres de archivo ni el texto libre de las
  configuraciones que no esté en los términos dados.

## Manejo de datos del cliente

Las capturas y los reportes generados contienen direccionamiento, inventario y
topología de la planta. El `.gitignore` de este repositorio los excluye a
propósito. Conviene no versionarlos ni moverlos fuera del canal acordado con el
cliente.

El perfil de proyecto real lleva datos del cliente: guárdalo fuera del repositorio, junto a las
capturas. Solo `docs/ejemplos/perfil.json` (ficticio) se versiona.
