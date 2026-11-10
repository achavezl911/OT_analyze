# OT_analisis en una página

Documento de presentación: qué es, qué resuelve, qué entrega y con qué límites. El detalle de uso está en el
[README](../README.md); el alcance en [ALCANCE.md](ALCANCE.md); cada opción, regla, puerto y salida, generado del
código, en [CATALOGO.md](CATALOGO.md).

## Qué es y para quién

Herramienta de línea de comandos para **analistas de ciberseguridad OT** que hacen evaluaciones (assessments) y
rediseños de segmentación en proyectos donde no hay una plataforma comercial (Nozomi, Claroty, Dragos) o donde la
plataforma no entrega lo que el cliente pide. Sectores atendidos: energía, gas y ductos, minería, alimentos,
construcción y ferrocarril, en México, Estados Unidos y Chile; cada cliente puede exigir un marco distinto.

## Qué problema resuelve

1. **Evidencia sin plataforma.** Con una captura de red o con lo que ya exporta una plataforma, produce el inventario,
   la matriz de comunicaciones y los hallazgos que normalmente salen de una herramienta comercial.
2. **Del análisis a la política.** Contrasta el tráfico observado con la configuración real de los firewalls y propone
   una política nueva "desde cero" que solo permite lo necesario, lista para el comité de cambios y para cargarse en
   Cisco FMC (u otros fabricantes como archivo de comandos).
3. **Entregables listos para el cliente.** Informe Word, reporte HTML, Excel, resumen ejecutivo de una página, plan de
   remediación con playbooks y diagramas editables, en español o inglés.

## Cómo funciona

```
Entradas (solo lectura)                Análisis local                       Entregables
- capturas pcap/pcapng                 inventario y roles (Purdue)          informe Word, reporte HTML, Excel
- exportaciones xDome/Nozomi/          conductos, zonas IEC 62443           resumen ejecutivo, plan de remediación
  Claroty/Dragos (o API de xDome)      reglas de hallazgo + marcos          diagramas SVG / draw.io / Mermaid
- firewalls FTD/ASA, FortiGate,   ->   contraste tráfico vs. política  ->   política propuesta + carga a FMC
  Palo Alto, Check Point               rutas de ataque entre zonas          Solicitud de Cambio
- switches Cisco IOS, AOS-CX o SNMP    vulnerabilidades, KEV, alertas       comparación entre corridas
- perfil del proyecto (JSON)           periodicidad del sondeo OT           paquete de entrega con hashes
```

Python 3.9 o superior con la biblioteca estándar, más Wireshark (tshark). Sin dependencias en ejecución, sin
servicios, sin base de datos y **sin salir a Internet**: todo corre en el equipo del analista.

## Capacidades

- **Inventario pasivo:** fabricante, modelo, firmware y nombre de cada equipo cuando el propio tráfico lo anuncia;
  rol y nivel Purdue inferidos; más de 30 protocolos industriales reconocidos (Modbus/TCP, S7comm, EtherNet/IP y CIP,
  DNP3, IEC 60870-5-104, IEC 61850 MMS, OPC UA, BACnet, PROFINET, OMRON FINS, MELSEC, HART-IP, MQTT, entre otros).
- **Validación de la captura (día 1):** veredicto por punto de captura (apta, apta con limitaciones, no apta)
  con pérdida TCP en el espejo, sesiones de un solo sentido, huecos, tasa promedio y p95 por minuto, VLAN y
  zonas esperadas sin tráfico; el subcomando `validar-captura` lo hace en una pasada rápida para usarlo en sitio.
- **Línea base de hardening por tipo de equipo:** lista de verificación propia por tipo (controlador, estación,
  servidor, red, seguridad, otro) alineada a ISA/IEC 62443-4-2 y 3-3, lista para la visita, y por cada activo del
  inventario los puntos que la corrida ya contradice (hallazgo con su ID o servicio en claro) y los que quedan por
  verificar en sitio; nunca dice cumple ni endurecido.
- **Identidad por protocolos OT en capturas:** lee el fabricante, el modelo y el firmware que los equipos reportan
  en sus propios protocolos (CIP ListIdentity y objeto Identity, identificacion de dispositivo de Modbus, SZL de
  S7 y PROFINET DCP), sin sondeo activo y por IP aun detras de un enrutador; asi un sitio solo con captura tambien
  cruza con los avisos.
- **Vulnerabilidades por fabricante, modelo y firmware sin plataforma:** cruza el inventario (también el manual)
  con los avisos ICS de CISA descargados (CSAF) y un catálogo propio del analista, sin red; separa el modelo
  exacto de la familia y entrega candidatos a confirmar con el aviso, con KEV y remediación del fabricante.
  Si la plataforma no trae el modelo, lo toma del CPE de su exportación de CVE como valor inferido (no pisa
  ninguna otra fuente y queda en la procedencia).
- **Direccionamiento IP observado:** redes del sitio con el origen del prefijo (perfil, firewall, switch o inferido),
  VLAN, zonas, tipos de equipo, uso mínimo del rango y observaciones para validar con el cliente.
- **Fuentes de log:** inventario de quién envía registros (Syslog, traps SNMP, NetFlow, eventos de Windows, agentes de
  SIEM), a qué colector, por qué protocolo y si va en claro, y qué equipos que por su tipo suelen enviar no se vio que
  lo hagan (a verificar; la ausencia en la captura no prueba que no envíen).
- **Arquitectura TO-BE (segmentación propuesta):** lista de comunicaciones entre zonas con decisión propuesta
  (permitir solo los pares observados, pasar por la DMZ industrial con el servicio intermedio sugerido, revisar o
  bloquear), matriz zona x zona, diagrama del estado propuesto y trazabilidad a los IDs de los hallazgos; descarta
  las respuestas probables y propone una DMZ si hace falta y no existe.
- **Madurez por dominio:** cuestionario de entrevista de 32 preguntas en 8 dominios (activos, segmentación,
  acceso, parches, monitoreo, incidentes, cadena de suministro y riesgo; escala 0-4 alineada a los niveles de
  madurez de ISA/IEC 62443, referencias a NIST CSF 2.0), nivel actual, objetivo y brecha por dominio con radar,
  señales técnicas de la corrida por dominio y aviso cuando la evidencia de red no respalda el nivel declarado.
- **Registro de riesgos y mapa de calor:** cada hallazgo lleva un ID estable y entra a un registro de riesgos
  (probabilidad por severidad y exposición desde Internet o IT o CVE en KEV, impacto en seis dimensiones
  declarado por zona o inferido de la criticidad del activo, técnicas MITRE ATT&CK for ICS), un mapa de calor
  5×5 y una lista de quick wins (riesgo alto con esfuerzo estimado bajo). Método propio con ajuste del
  analista justificado; no cambia el plan de remediación. El resumen ejecutivo muestra los cinco primeros
  riesgos de ese registro, en el mismo orden y con el mismo ID.
- **Línea base aprobada del sitio:** el equipo aprueba una corrida como referencia (quien aprueba y quien
  revisa son personas distintas; manifiesto SHA-256 inmutable) y cada corrida nueva se compara contra ella:
  activos y conductos nuevos, escritores nuevos hacia equipos de control, cambios de firmware, modelo o MAC,
  volumen sobre 3 veces el p95 aprobado y conductos aprobados sin tráfico, como hallazgos con playbook y una
  lista de desviaciones con columnas de revisión.
- **Salud de la red y línea base de tráfico:** top de equipos y conductos, mezcla de protocolos, difusión y ARP
  por minuto, retransmisiones por conducto, utilización y descartes de las interfaces del switch, y una línea
  base por conducto (bytes y paquetes por minuto, p50 y p95) para comparar corridas.
- **Inventario normalizado:** un activo por equipo con id estable y, en cada campo, su fuente (captura,
  plataforma, switch, firewall, inventario del cliente, perfil o inferencia), última observación y estado
  (observado, importado, declarado, inferido o en conflicto); cruza el inventario del cliente (declarados no
  observados y observados no declarados), separa por IP los equipos que están detrás de un router y excluye los
  equipos del propio equipo de evaluación; columnas para validación por dos personas.
- **Obsolescencia:** fin de soporte por activo (vencido, vence en 12 meses, con soporte, sin dato) con una tabla
  local del analista por fabricante, modelo y versión, más fechas integradas de Windows; sin Internet.
- **Hallazgos:** unos 80 tipos (texto claro, protocolos sin autenticación, escrituras de control, exposición a
  Internet, DNS, TLS débil, anomalías ARP y STP, pérdida de comunicación en conductos periódicos, vulnerabilidades en
  el catálogo KEV, higiene de firewalls y switches...), cada uno con evidencia, recomendación, playbook de remediación y
  referencia a **IEC 62443, NIST SP 800-82, NIST CSF 2.0, NERC CIP y MITRE ATT&CK for ICS**.
- **Actividad de ingeniería en controladores:** clasifica cada operación de control como descarga o carga de
  programa, cambio de modo, reinicio, firmware, forzado, configuración o escritura (S7comm, CIP, DNP3,
  IEC 60870-5-104, Modbus, UMAS de Schneider, GE SRTP y FINS de Omron) y arma la línea de tiempo de sesiones
  de ingeniería con su técnica de MITRE ATT&CK for ICS (eventos_ingenieria.csv).
- **Accesos no autorizados y capa 2:** herramientas de acceso remoto de terceros (TeamViewer, AnyDesk, RustDesk,
  ScreenConnect...), DNS cifrado hacia resolvedores externos, Tor, VPN, túneles y proxies hacia Internet;
  servidores DHCP no autorizados, cambios de raíz STP, BPDU desde equipos finales, salto de VLAN, HSRP/VRRP sin
  autenticación, inundación de MAC y bucles en la captura; controles de capa 2 ausentes e inestabilidad de STP
  en la configuración y el registro del switch; bucles físicos contenidos solo por STP, pérdidas en el puerto
  destino del espejo (SPAN), hora sin sincronizar y raíz de STP con la prioridad de fábrica.
- **Línea base ISA/IEC 62443 (as-is / to-be):** por zona y conducto, lo que exige el SL objetivo (SR y RE de la
  3-3, verificados contra el texto de la norma) frente a lo que muestra la evidencia: brecha con evidencia,
  control observado, sin evidencia (verificar en sitio) o no evaluable con datos de red; cota del nivel alcanzado
  por requisito fundamental y una vista general con madurez objetivo y preguntas de entrevista. Nunca dictamina
  cumplimiento.
- **Matriz de controles (Controls Matrix):** ISA/IEC 62443 por zona y conducto y NIST SP 800-82r3 (overlay OT de
  SP 800-53r5, línea base baja, moderada o alta según la Tabla 22, con lo que el overlay agrega o quita), con el
  mismo estado as-is, evidencia y playbooks, y columnas vacías para que dos personas validen cada control.
- **Firewalls:** lee rutas, zonas y política (nunca secretos) de Cisco FTD/ASA, FortiGate, Palo Alto y Check Point;
  dice qué regla permite cada conducto observado, qué tráfico se deniega, qué reglas no se usan y qué se ve en varios
  firewalls en cadena.
- **Rediseño de política:** propuesta de reglas con objetos, justificación y decisión (`permitir`, `revisar`,
  `bloquear`) con las IP reales aunque haya NAT estático, comparación con la política actual, validación contra el
  tráfico de otra ventana (qué se rompería antes del corte), preguntas al cliente por los servicios esperados que no
  se vieron (una lista corta, agrupada por servicio), exportación a Cisco FMC 7.6 por API (simula por defecto) y Solicitud
  de Cambio en Word.
- **Seguimiento:** comparación entre dos corridas (qué se cortó, qué se abrió, qué activo o escritor es nuevo) y
  paquete de entrega con manifiesto SHA-256 verificable por un tercero.
- **Consolidado multi-sitio:** junta las salidas de varios sitios en un libro con hojas fijas (sitios, hallazgos
  que se repiten entre sitios, registro de riesgos de todos los sitios, madurez por dominio, inventario y
  vulnerabilidades por fabricante y modelo, y el hash de cada archivo leído) para las recomendaciones del programa.
  Acepta carpetas generadas en español o en inglés (las normaliza para contar y agrupar) y sale en el idioma pedido.
- **Cadena de custodia de la evidencia:** registro de solo agregar encadenado por SHA-256 (quién entrega y recibe,
  cuándo, medio y cifrado declarado), verificación que detecta ediciones y borrados, formato imprimible con
  firmas y marca de cada captura analizada como registrada o no. La herramienta no cifra: lo hace el volumen.
  El formato imprimible sale en español o en inglés (`--idioma`).
- **Ubicación de sensores:** qué puntos de captura ven todos los conductos OT observados (aproximación voraz),
  cuáles son redundantes o hay que corregir, y qué zonas o VLAN no ve ningún punto.
- **Switches de cualquier fabricante por SNMP:** lee recorridos `snmpwalk` de MIB estándar (puertos, VLAN, tabla
  MAC, vecinos LLDP, contadores y STP) como fuente de switch, igual que la CLI de Cisco. Solo lee el archivo: no
  consulta SNMP, descarta sin guardar toda línea que no sea un valor (la comunidad nunca se lee) y no afirma si
  sus VLAN están espejadas.
- **Switches Aruba AOS-CX por CLI:** lee la sesión guardada (`show system`, `interface`, `vlan`,
  `mac-address-table`, `lldp`, `mirror`, `spanning-tree`) como fuente de switch: ubicación de cada equipo por MAC,
  enlaces entre switches, sesiones de espejo, contadores y STP. Con la running-config pegada agrega la higiene
  de configuración como con Cisco (gestión, AAA de login, BPDU guard, puertos sin uso, VLAN 1, raíz de STP), sin
  DTP (AOS-CX no negocia troncales) y sin evaluar storm-control, port-security, DHCP snooping ni inspección ARP;
  de secretos y comunidades solo cuenta cuántos hay. Sin `show mirror` usa las sesiones de espejo habilitadas de
  la configuración y, sin ninguna de las dos, no afirma si sus VLAN están espejadas.

## Calidad y control

- Más de 950 pruebas automáticas con capturas y exportaciones sintéticas; integración continua en GitHub con Python
  3.9 y 3.13 en cada versión; nada se publica sin la CI en verde.
- Cada decisión técnica con su motivo en [DECISIONES.md](DECISIONES.md); auditoría interna en
  [AUDITORIA.md](AUDITORIA.md); estado y pendientes en [ESTADO.md](ESTADO.md).
- La referencia a cada marco se marca "sin revisar" hasta que la valide un especialista. La herramienta **nunca
  afirma cumplimiento**: entrega evidencia técnica relacionada.

## Manejo de datos del cliente

Nada sale del equipo del analista. Las salidas se crean con permisos solo para su dueño (en Linux y macOS). De las
configuraciones de red se leen solo rutas, zonas, objetos y política; usuarios, contraseñas, comunidades SNMP y llaves
se cuentan, nunca se copian. Hay un anonimizador para compartir muestras y un paquete de entrega que excluye registros,
cachés y el mapa de anonimización. Ver [SEGURIDAD.md](SEGURIDAD.md).

## Límites (lo que conviene decir al cliente)

- **Pasivo y por ventana:** solo ve lo que pasa por el punto de captura o lo que exporta la plataforma, en el periodo
  dado. Lo mensual o lo de contingencia puede no aparecer: la política propuesta se despliega primero con registro.
- **Sin base de CVE propia:** cruza las vulnerabilidades que importa el analista y los avisos de CISA que descarga
  (por CVE, y por fabricante, modelo y firmware como candidatos a confirmar); no consulta NVD ni otra fuente en
  línea, y sin modelo en el inventario (ni CPE en la exportación de CVE) no hay cruce.
- **Cifrado:** no descifra tráfico. Encrypted Client Hello oculta el nombre del servidor, y un DoH propio o un
  puente Tor ofuscado no se distinguen de otro HTTPS: no ver indicadores no demuestra que no existan. Tor se
  confirma solo con una lista de relays que aporte el analista (la herramienta no descarga nada).
- **NAT:** modelado el estático de Cisco FTD/ASA, con sus contadores de aciertos si la sesión trae
  `show nat detail`; el dinámico (PAT) se marca pero no se puede invertir, y el de otros
  fabricantes aún no se modela. Nozomi validado con exportaciones reales de una Guardian; Dragos sin validar con datos reales;
  probado de forma automática en Linux (Windows y macOS por diseño, sin prueba automática).

## Para una IA que lea este repositorio

Orden de lectura recomendado: este documento → [README](../README.md) → [ALCANCE.md](ALCANCE.md) →
[ARQUITECTURA.md](ARQUITECTURA.md) → [CATALOGO.md](CATALOGO.md) (generado del código: la lista exacta de reglas,
opciones y salidas) → [DECISIONES.md](DECISIONES.md). `CLAUDE.md` y `AGENTS.md` son reglas para quien desarrolla, no
descripción del producto.
