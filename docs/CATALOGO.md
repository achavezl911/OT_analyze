# Catalogo generado del codigo

> **No editar a mano.** Lo genera `scripts/generar_catalogo.py` (version del codigo: 0.67.0). Si cambias una regla, un puerto, una opcion o una columna: ejecuta el script. `scripts/verificar.sh` y `tests/test_docs.py` fallan si este archivo esta desactualizado.

## Reglas de hallazgo

55 reglas registradas, 56 titulos de hallazgo; **32 de 56** se afirman en la prueba de extremo a extremo (`tests/test_pipeline.py`), 24 no. Ver docs/PRUEBAS.md, "Brechas conocidas".

Marcos: `M` MITRE ATT&CK for ICS, `I` IEC 62443, `C` NERC CIP, `N` NIST 800-82, `CSF` NIST CSF 2.0; `-` sin referencia directa (a proposito, ver D2). El orden de la tabla es el orden de ejecucion y de los hallazgos.

| # | Regla | Modulo | Severidad | Categoria | Titulo | Deteccion probada de extremo a extremo | Marcos |
|---|---|---|---|---|---|---|---|
| 1 | `descubrimiento_windows` | exposure | Media | Exposicion | Protocolos de descubrimiento de Windows activos en la red de control | si | MICNCSF+ |
| 2 | `sentinel_hasp` | exposure | Media | Exposicion | Servicio de licenciamiento Sentinel HASP (puerto 1947) en difusion | si | MICNCSF+ |
| 3 | `texto_claro` | exposure | Alta | Exposicion | Credenciales o administracion en texto claro | si | MICNCSF+ |
| 4 | `gestion_sin_cifrar` | exposure | Media | Exposicion | Protocolos de gestion sin cifrar en uso | si | MICNCSF+ |
| 5 | `software_obsoleto` | exposure | Alta | Obsolescencia | Software o sistema operativo fuera de soporte | si | MICNCSF+ |
| 6 | `firmware_expuesto` | exposure | Informativa | Identidad | Version de firmware expuesta en protocolos de descubrimiento | si | MICNCSF+ |
| 7 | `apipa` | segmentation | Media | Configuracion | Equipos con direccion APIPA (169.254.x.x) | si | ICNCSF+ |
| 8 | `ip_publicas` | segmentation | Alta | Segmentacion | Trafico con direcciones IP publicas desde la red OT | si | MICNCSF+ |
| 9 | `multiples_subredes` | segmentation | Media | Segmentacion | Multiples subredes conviviendo en el mismo dominio de difusion | si | ICNCSF+ |
| 10 | `sin_vlan` | segmentation | Informativa | Visibilidad | Sin segmentacion por VLAN visible en el punto de captura | si | ICNCSF+ |
| 11 | `rip` | config | Media | Configuracion | RIP activo en la red de control | si | MICNCSF+ |
| 12 | `dhcp` | config | Baja | Configuracion | DHCP activo en el segmento de control | si | ICNCSF |
| 13 | `conflicto_arp` | anomaly | Alta | Anomalia | Conflicto de direcciones: una misma IP anunciada por varias MAC | si | MICNCSF+ |
| 14 | `arp_duplicado` | anomaly | Alta | Anomalia | Wireshark marco deteccion de direccion duplicada en ARP | si | MICNCSF+ |
| 15 | `barrido_arp` | anomaly | Media | Anomalia | Barrido ARP: un equipo pregunta por muchas direcciones | si | MICNCSF+ |
| 16 | `escaneo_red` | anomaly | Media | Anomalia | Patron compatible con escaneo de red | si | MICNCSF+ |
| 17 | `difusion` | anomaly | Media | Desempeno | Proporcion alta de trafico de difusion | si | MINCSF |
| 18 | `stp` | anomaly | Media | Desempeno | Cambios de topologia STP frecuentes | si | MINCSF |
| 19 | `operaciones_control` | control | Alta | Control | Operaciones de escritura o control observadas en la captura | si | MICNCSF+ |
| 19 | `operaciones_control` | control | Informativa | Control | No se observaron escrituras ni comandos de control | si | - |
| 20 | `actividad_ingenieria` | control | Alta | Control | Actividad de ingenieria sobre controladores (descarga, arranque o paro) | si | MICNCSF |
| 21 | `captura_ilegible` | visibility | Alta | Captura | Captura ilegible o sin paquetes | si | - |
| 22 | `truncamiento` | visibility | Alta | Visibilidad | Captura truncada (snaplen por debajo del MTU) | si | - |
| 23 | `un_solo_sentido` | visibility | Alta | Visibilidad | La mayoria de las conversaciones aparece en un solo sentido | si | - |
| 24 | `sin_unicast` | visibility | Alta | Visibilidad | El punto de captura casi no ve trafico unicast | si | - |
| 25 | `paquetes_identidad` | visibility | Alta | Visibilidad | La captura no contiene ningun paquete que revele identidad de equipos | si | - |
| 25 | `paquetes_identidad` | visibility | Media | Visibilidad | Muy pocos paquetes de identidad en la captura | si | - |
| 26 | `io_ciclico` | visibility | Informativa | Visibilidad | El trafico es casi todo I/O ciclico, que no revela identidad | si | - |
| 27 | `duplicados` | visibility | Baja | Visibilidad | Paquetes duplicados en la captura | si | - |
| 28 | `ventana_corta` | visibility | Media | Visibilidad | Ventana de captura corta | si | - |
| 29 | `dns_wpad` | dns | Media | Exposicion | Busqueda de proxy WPAD por DNS | **no** | MICNCSF+ |
| 30 | `dns_publico` | dns | Media | Segmentacion | Consultas DNS a servidores publicos | si | MICNCSF+ |
| 31 | `dns_dominios_internet` | dns | Baja | Segmentacion | Resolucion de dominios de Internet desde la red | si | ICNCSF+ |
| 32 | `dns_fallas` | dns | Baja | Configuracion | Fallas de resolucion DNS | **no** | INCSF |
| 33 | `dns_nxdomain` | dns | Baja | Anomalia | Cliente con muchas respuestas NXDOMAIN | **no** | ICNCSF+ |
| 34 | `dns_tunel` | dns | Media | Anomalia | Posible tunel DNS | **no** | MICNCSF+ |
| 35 | `dns_transferencia_zona` | dns | Media | Exposicion | Intento de transferencia de zona DNS | **no** | MICNCSF+ |
| 36 | `dns_dot` | dns | Baja | Visibilidad | DNS cifrado sin visibilidad (DoT) | **no** | ICNCSF+ |
| 37 | `opcua_sin_seguridad` | protocolos | Media | Cifrado | OPC UA sin seguridad de mensajes (politica None) | **no** | MICNCSF+ |
| 38 | `tls_obsoleto` | protocolos | Media | Cifrado | TLS obsoleto o con suite debil negociado por el servidor | **no** | MICNCSF+ |
| 39 | `modbus_fc8` | protocolos | Alta | Control | Modbus FC8 que reinicia o silencia el equipo | **no** | MICNCSF |
| 39 | `modbus_fc8` | protocolos | Baja | Control | Modbus FC8 de diagnostico (sin reinicio ni silencio) | **no** | MICNCSF |
| 40 | `dnp3_reinicio` | protocolos | Alta | Control | DNP3 con reinicio o paro de aplicacion (Cold Restart, Warm Restart, Stop Application) | **no** | MICNCSF |
| 41 | `perdida_comunicacion_periodica` | periodicidad | Media | Anomalia | Perdida de comunicacion en un conducto de control periodico | **no** | MICNCSF+ |
| 42 | `sondeo_irregular` | periodicidad | Baja | Anomalia | Sondeo irregular en conductos de control | **no** | MICNCSF+ |
| 43 | `escritor_tardio` | periodicidad | Alta | Control | Escritor de control que aparece a mitad de la captura | **no** | MICNCSF+ |
| 46 | `dhcp_no_autorizado` | ataques_l2 | Alta | Anomalia | Mas de un servidor DHCP respondiendo en el segmento | **no** | MICNCSF+ |
| 47 | `cambio_raiz_stp` | ataques_l2 | Alta | Anomalia | Cambio del puente raiz de STP durante la captura | **no** | MINCSF+ |
| 48 | `bpdu_equipo_final` | ataques_l2 | Alta | Anomalia | BPDU enviadas por un equipo que no es switch | **no** | MICNCSF+ |
| 49 | `salto_vlan` | ataques_l2 | Media | Anomalia | Indicios de salto de VLAN (doble etiqueta o DTP) | **no** | MICNCSF+ |
| 50 | `ha_sin_autenticacion` | ataques_l2 | Media | Anomalia | Redundancia de puerta de enlace (HSRP/VRRP) sin autenticacion | **no** | MINCSF |
| 51 | `ra_no_esperado` | ataques_l2 | Media | Anomalia | Anuncios de router IPv6 no esperados | **no** | MICNCSF+ |
| 52 | `inundacion_mac` | ataques_l2 | Alta | Anomalia | Posible inundacion de la tabla MAC del switch | **no** | MICNCSF+ |
| 53 | `bucle_l2` | ataques_l2 | Alta | Desempeno | Indicios de bucle de capa 2 o de enrutamiento | **no** | MINCSF+ |
| 54 | `tormenta_difusion` | salud_red | Media | Anomalia | Tormenta de difusion o multidifusion | **no** | MINCSF |
| 55 | `retransmisiones_ot` | salud_red | Media | Anomalia | Retransmisiones TCP elevadas en un conducto OT | **no** | INCSF+ |

## Reglas sobre inventario importado

Reglas que corren sobre los activos y conductos de una exportacion de plataforma (sin captura). Heredan las referencias de las reglas de captura por el fragmento del titulo.

3 reglas registradas, 3 titulos de hallazgo; **3 de 3** se afirman en la prueba de extremo a extremo (`tests/test_inventario.py`), 0 no. Ver docs/PRUEBAS.md, "Brechas conocidas".

Marcos: `M` MITRE ATT&CK for ICS, `I` IEC 62443, `C` NERC CIP, `N` NIST 800-82, `CSF` NIST CSF 2.0; `-` sin referencia directa (a proposito, ver D2). El orden de la tabla es el orden de ejecucion y de los hallazgos.

| # | Regla | Modulo | Severidad | Categoria | Titulo | Deteccion probada de extremo a extremo | Marcos |
|---|---|---|---|---|---|---|---|
| 1 | `gestion_sin_cifrar_exportacion` | inventario | Media | Exposicion | Protocolos de gestion sin cifrar en uso (segun la exportacion) | si | MICNCSF+ |
| 2 | `software_obsoleto_exportacion` | inventario | Alta | Obsolescencia | Software o sistema operativo fuera de soporte (segun el inventario) | si | MICNCSF+ |
| 3 | `ip_publicas_exportacion` | inventario | Alta | Segmentacion | Trafico con direcciones IP publicas desde la red OT (segun la exportacion) | si | MICNCSF+ |

## Marcos de referencia

| Clave | Nombre | Filas con referencia | Version de la fuente | Validacion | Aviso de alcance |
|---|---|---|---|---|---|
| mitre-ics | MITRE ATT&CK for ICS | 53 | ATT&CK for ICS v20.1 (2026-11-05) | sin revisar | Siempre presente; no se elige. |
| iec62443 | IEC 62443 | 83 | IEC 62443-3-3:2013 | sin revisar | Las referencias a IEC 62443 son orientativas. El nivel de seguridad (SL) objetivo de cada zona se define con la evaluacion de riesgo de IEC 62443-3-2, que esta herramienta no realiza. |
| nerc-cip | NERC CIP | 62 | sin declarar: la version vigente varia por estandar | sin revisar | Las referencias a NERC CIP son orientativas y no constituyen una determinacion de cumplimiento. La aplicabilidad de cada requisito depende de la categorizacion de impacto de los BES Cyber Systems (CIP-002) y de la version vigente del estandar, que no pueden inferirse del trafico ni de un inventario. |
| nist-800-82 | NIST SP 800-82 / 800-53 | 83 | SP 800-53 Rev. 5; SP 800-82 Rev. 3 | sin revisar | Los controles citados son de NIST SP 800-53 Rev. 5, el catalogo sobre el que NIST SP 800-82 Rev. 3 define la guia para OT. Son orientativos y no equivalen a una evaluacion de cumplimiento. |
| nist-csf | NIST CSF 2.0 | 83 | CSF 2.0 (2024-02-26) | sin revisar | Las subcategorias citadas son de NIST CSF 2.0. Son orientativas: un analisis pasivo aporta evidencia tecnica relacionada, no un perfil de CSF ni una evaluacion de cumplimiento. La funcion es el prefijo del identificador (GV, ID, PR, DE, RS, RC); Govern (GV) no tiene evidencia observable en el trafico. |
| tsa-sd-1580-82 | TSA SD 1580/82-2022-01E (seccion III) | 71 | TSA SD 1580/82-2022-01E; SP 800-53 Rev. 5 | sin revisar | Referencias derivadas de dos mapeos propios sin revisar (hallazgo a controles de NIST SP 800-53 y medida de la TSA a controles de NIST SP 800-53). Una referencia no es equivalencia ni prueba de cumplimiento; las medidas documentales de la directiva no se citan. |

## Cobertura por marco

La cobertura indica que requisitos pueden relacionarse con evidencia de trafico; no es una evaluacion de cumplimiento. Texto de los requisitos: fuente oficial en ingles. La clasificacion se calcula: `directa` si algun hallazgo del marco cita el requisito, `apoyo` si solo lo respaldan salidas de la herramienta, `no evidenciable` el resto.

| Clave | Marco | Requisitos | Directa | Apoyo | No evidenciable | Salida |
|---|---|---|---|---|---|---|
| iec62443 | IEC 62443 | 51 | 18 | 0 | 33 | `cobertura_iec62443.csv` |
| nist-csf | NIST CSF 2.0 | 106 | 19 | 1 | 86 | `cobertura_nist-csf.csv` |

## Operaciones de control detectadas

Operaciones de escritura o comando que se registran en `control.csv`. La lectura no se registra.

| Protocolo | Campo de tshark | Puerto del servidor | Codigos | Mecanismo |
|---|---|---|---|---|
| Modbus/TCP | `modbus.func_code` | 502 | 10 | tabla `PROTOCOLOS` |
| DNP3 | `dnp3.al.func` | 20000 | 16 | tabla `PROTOCOLOS` |
| IEC 60870-5-104 | `iec60870_asdu.typeid` | 2404 | 13 | tabla `PROTOCOLOS` |
| S7comm | `s7comm.param.func` | 102 | 9 | tabla `PROTOCOLOS` |
| CIP / EtherNet/IP | `cip.service` | (cualquiera) | 10 | colector propio; solo peticiones (bit de respuesta 0x80 descartado) |
| IEC 61850 MMS | `mms.confirmedServiceRequest` | (cualquiera) | todas | colector propio |

## Puertos y servicios del catalogo

`ot`: protocolo industrial; `claro`: administracion sin cifrar que en OT merece revision; `it`: servicio de TI relevante.

| Puerto | Transporte | Servicio | Categoria |
|---|---|---|---|
| 102 | tcp | IEC 61850 MMS / S7comm (ISO-TSAP) | ot |
| 135 | tcp | DCOM / OPC DA (endpoint mapper) | ot |
| 319 | udp | PTP evento (IEEE 1588) | ot |
| 320 | udp | PTP general (IEEE 1588) | ot |
| 502 | tcp | Modbus/TCP | ot |
| 789 | tcp | Red Lion / Crimson | ot |
| 802 | tcp | Modbus/TCP seguro | ot |
| 1883 | tcp | MQTT | ot |
| 1911 | tcp | Niagara Fox | ot |
| 1962 | tcp | PCWorx | ot |
| 2222 | udp | EtherNet/IP I/O ciclico (CIP Class 1) | ot |
| 2404 | tcp | IEC 60870-5-104 | ot |
| 2455 | tcp | CODESYS V2 / WAGO-IO-SYSTEM | ot |
| 2455 | udp | CODESYS V2 / WAGO-IO-SYSTEM | ot |
| 3671 | udp | KNXnet/IP (EIBnet/IP) | ot |
| 4059 | tcp | DLMS/COSEM | ot |
| 4059 | udp | DLMS/COSEM | ot |
| 4840 | tcp | OPC UA | ot |
| 4843 | tcp | OPC UA sobre TLS | ot |
| 5007 | tcp | Mitsubishi MELSEC | ot |
| 5094 | tcp | HART-IP | ot |
| 5094 | udp | HART-IP | ot |
| 8016 | tcp | Beckhoff Secure ADS | ot |
| 8883 | tcp | MQTT sobre TLS | ot |
| 9600 | tcp | OMRON FINS | ot |
| 18245 | tcp | GE SRTP | ot |
| 20000 | tcp | DNP3 | ot |
| 20000 | udp | DNP3 | ot |
| 20547 | tcp | ProConOS | ot |
| 34962 | udp | PROFINET RT | ot |
| 34963 | udp | PROFINET RT | ot |
| 34964 | udp | PROFINET CM | ot |
| 44818 | tcp | EtherNet/IP explicito (CIP) | ot |
| 44818 | udp | EtherNet/IP descubrimiento | ot |
| 47808 | udp | BACnet/IP | ot |
| 48898 | tcp | Beckhoff ADS/AMS | ot |
| 48899 | udp | Beckhoff ADS descubrimiento | ot |
| 21 | tcp | FTP | claro |
| 23 | tcp | Telnet | claro |
| 69 | udp | TFTP | claro |
| 80 | tcp | HTTP | claro |
| 161 | udp | SNMP | claro |
| 162 | udp | SNMP trap | claro |
| 512 | tcp | rexec | claro |
| 513 | tcp | rlogin | claro |
| 514 | tcp | rsh | claro |
| 514 | udp | Syslog | claro |
| 22 | tcp | SSH | it |
| 53 | udp | DNS | it |
| 67 | udp | DHCP servidor | it |
| 68 | udp | DHCP cliente | it |
| 123 | udp | NTP | it |
| 137 | udp | NetBIOS nombres (NBT-NS) | it |
| 138 | udp | NetBIOS datagrama | it |
| 139 | tcp | NetBIOS sesion (SMB) | it |
| 443 | tcp | HTTPS | it |
| 445 | tcp | SMB | it |
| 520 | udp | RIP | it |
| 1900 | udp | SSDP / UPnP | it |
| 1947 | tcp | Sentinel HASP / licenciamiento | it |
| 1947 | udp | Sentinel HASP / licenciamiento | it |
| 3389 | tcp | RDP | it |
| 5353 | udp | mDNS | it |
| 5355 | udp | LLMNR | it |
| 5900 | tcp | VNC | it |
| 5938 | tcp | TeamViewer | it |
| 5938 | udp | TeamViewer | it |
| 6568 | tcp | AnyDesk | it |
| 21114 | tcp | RustDesk (servidor propio) | it |
| 21115 | tcp | RustDesk (servidor propio) | it |
| 21116 | tcp | RustDesk (servidor propio) | it |
| 21116 | udp | RustDesk (servidor propio) | it |
| 21117 | tcp | RustDesk (servidor propio) | it |
| 21118 | tcp | RustDesk cliente web | it |
| 21119 | tcp | RustDesk cliente web | it |

## Opciones de linea de comandos

### `python ot_pcap_assess.py` (capturas)

| Opcion | Obligatoria | Por defecto | Descripcion |
|---|---|---|---|
| `inputs` | si | - | Archivos .pcap/.pcapng o carpetas |
| `--version` | no | - | show program's version number and exit |
| `-o, --out` | no | reporte_ot | Carpeta de salida |
| `--tshark` | no | - | Carpeta de Wireshark si no esta en el PATH |
| `--max-packets` | no | 1000000 | Tope de paquetes para el mapa de flujos (0 = todos). Por defecto 1000000. |
| `--max-rows` | no | 120 | Filas maximas por tabla en los reportes |
| `--idioma` | no | - | Idioma de los reportes (por defecto es; manda sobre el idioma del perfil). |
| `--perfil` | no | - | Perfil del proyecto en JSON (cliente, sitio, marcos...). Reemplaza a --titulo, --cliente y --estandar; no se pueden combinar. |
| `--reglas-firewall` | no | - | Reglas de firewall/ACL en CSV (columnas origen, destino, puerto, protocolo, accion; id opcional). Contrasta la politica con los conductos observados. |
| `--rutas-firewall` | no | - | Tabla de rutas de un firewall (CSV/XLSX con interfaz y red, comandos route de Cisco ASA o salida de show route). Asigna a cada IP la interfaz por la que el firewall la alcanza y marca los conductos que lo cruzan. |
| `--firewall` | no | - | Salida de la CLI de un Cisco FTD/ASA (archivo o carpeta: show route, nameif, access-list, rule hits...). Da interfaz y rutas reales (como --rutas-firewall) y contrasta las reglas con los conductos. Se puede repetir (firewalls en cadena: enlaces, camino de cada conducto y coherencia entre ellos). No se combina con --reglas-firewall; manda sobre --rutas-firewall. |
| `--switch` | no | - | Salida de la CLI de un switch Cisco IOS/IOS-XE (sesion pegada: show running-config, show mac address-table, show interfaces description, show cdp neighbors detail, show version). Ubica cada activo con MAC en su puerto y VLAN y dice que VLAN espeja cada sesion SPAN. Se puede repetir. No guarda contrasenas ni comunidades SNMP. |
| `--firewall-contadores` | no | - | Aciertos por regla: CSV de politicas de la GUI de una FortiGate (columnas ID o Name y Hit Count) o salida de `show rule-hit-count ...` de un Palo Alto. Requiere --firewall; FortiOS no los trae en la configuracion. |
| `--zonas-fw` | no | - | Zonas de seguridad por interfaz para la politica propuesta (columnas firewall, interfaz, zona; firewall = hostname o nombre del archivo). Requiere --firewall. Sin ella se usa la zona del firewall o SZ_<nameif>, con aviso. |
| `--origen-ataque` | no | - | Zona desde la que se buscan rutas de ataque (se puede repetir). Por defecto, las zonas cuyo nombre contiene IT, CORP o Internet; ademas siempre se evalua Internet. |
| `--objetivo-ataque` | no | - | Zona cuyos activos son objetivo de las rutas de ataque (se puede repetir), ademas de los activos de criticidad Critica o Alta. |
| `--vulnerabilidades` | no | - | Vulnerabilidades por activo en CSV de un escaner o plataforma (columnas cve, severidad o cvss, y activo, ip o mac; estado opcional). Se cruzan con el inventario observado; no se consultan bases de CVE. |
| `--kev` | no | - | Catalogo KEV de CISA (known_exploited_vulnerabilities.json o su CSV), descargado por usted; marca las vulnerabilidades importadas que estan en el catalogo. Requiere --vulnerabilidades. La herramienta no descarga nada. |
| `--cis` | no | - | CIS Controls v8.1 (XLSX oficial de CIS o CSV con sus columnas), descargado por usted: agrega a matriz_controles.csv una fila por salvaguarda del grupo IG1, IG2 o IG3 (perfil cis_ig; por defecto IG2). Los titulos se leen del archivo; la herramienta no los distribuye (licencia CC BY-NC-ND 4.0). |
| `--cis-mapeo` | no | - | Mapeo oficial de CIS v8.1 a SP 800-53 Rev 5 o a CSF 2.0 (XLSX oficial de CIS o CSV con las mismas columnas), descargado por usted; repetible, uno por tipo. Requiere --cis: el estado de las filas CIS sale de este mapeo y no de las referencias de NIST. No se copia al repo ni a las salidas mas que ids y relacion. |
| `--avisos-ics` | no | - | Un aviso ICS de CISA en CSAF 2.0 (JSON) o una carpeta con muchos (recursiva); se cruzan por CVE exacto con --vulnerabilidades y generan avisos_ics.csv; ademas se comparan fabricante, modelo y firmware del inventario con sus productos afectados (vulnerabilidades_firmware.csv, candidatos a confirmar). |
| `--catalogo-vulnerabilidades` | no | - | Catalogo del analista (CSV o XLSX; columnas fabricante, producto, version_afectada, cve; cvss, aviso, remediacion y fuente opcionales) con vulnerabilidades por fabricante, modelo y firmware; se compara con el inventario sin red (vulnerabilidades_firmware.csv). |
| `--alertas` | no | - | Alertas de un IDS o plataforma OT en CSV (columnas firma, origen y/o destino, severidad o prioridad; puerto, protocolo, fecha, categoria y conteo opcionales). Se asocian a los conductos observados; no se validan las firmas. |
| `--tor-relays` | no | - | Lista de relays Tor descargada por usted: texto con una IP por linea (como la lista de salidas de check.torproject.org) o JSON de Onionoo (summary o details). Un conducto hacia una IP de la lista se reporta como Tor; sin lista solo se ven los puertos por defecto 9001 y 9030. La herramienta no descarga nada. |
| `--linea-base` | no | - | Linea base aprobada del sitio (la crea 'linea-base aprobar'). Verifica sus hash y compara esta corrida con ella: activos, conductos, escritores, firmware/modelo/MAC, volumen y periodicidad. Escribe desviaciones_linea_base.csv y hallazgos. |
| `--madurez` | no | - | Cuestionario de madurez contestado (la plantilla la escribe 'madurez cuestionario'): respuesta 0 a 4, N/A o vacio por pregunta. Calcula nivel actual, objetivo y brecha por dominio y senala donde la evidencia de red no respalda lo declarado. Escribe madurez.csv. Objetivo: madurez_objetivo o ml_objetivo del perfil. |
| `--csf-tiers` | no | - | csf_tiers.csv llenado por el analista (la corrida lo escribe con la meta de csf_tiers_objetivo del perfil): columna tier_actual con 1 a 4 o el nombre del tier (Parcial, Informado por el riesgo, Repetible, Adaptativo) por funcion de NIST CSF 2.0. Calcula la brecha frente a la meta y agrega la evidencia de las filas NIST de la matriz de controles. La herramienta no mide los tiers. |
| `--inventario-manual` | no | - | Hoja de inventario del cliente o del equipo (CSV, JSON o XLSX, encabezados libres: se reconocen por alias). Sus valores quedan como declarados en inventario_normalizado.csv; cuenta los activos declarados que no se observaron y los observados que no estan. |
| `--fin-de-soporte` | no | - | Fechas de fin de soporte del analista (CSV o XLSX; columnas fabricante, producto, version, fecha_fin_soporte AAAA-MM-DD y opcionales fecha_fin_venta, reemplazo_sugerido, fuente). Genera obsolescencia.csv; manda sobre la tabla integrada de sistemas operativos. Sin red. |
| `--mapeo` | no | - | Fija a mano las columnas del inventario manual: {"manual": {"ip": "Direccion"}} |
| `--titulo` | no | - | Titulo que aparece en la portada del reporte HTML. Por defecto Assessment de ciberseguridad OT. |
| `--cliente` | no | - | Subtitulo de la portada: nombre del cliente o del sitio. Por defecto Analisis de trafico de planta. |
| `--cache` | no | - | Carpeta donde guardar (y reutilizar) la lectura de cada captura, para regenerar el informe con otro perfil, firewall, zonas o idioma sin releer capturas grandes. Contiene datos del cliente (archivos 600): guardela junto a sus salidas, no en el repositorio. La clave incluye el contenido del pcap, la version y tshark. |
| `--custodia` | no | - | Registro de cadena de custodia (subcomando custodia): marca cada captura analizada como registrada o no registrada (por SHA-256) y verifica la cadena. No es un hallazgo. |
| `--cache-renovar` | no | - | Ignora lo guardado en --cache y lo reescribe. |
| `--no-detail` | no | - | Omitir el pase de detalle (mas rapido, sin identidad ni control) |
| `--no-diagrams` | no | - | No generar los diagramas de red |
| `--diagram-max-nodes` | no | 40 | Equipos maximos en el diagrama por activo (los de mayor riesgo primero). Por defecto 40. |
| `--diagram-max-edges` | no | 60 | Trazos maximos en el diagrama por activo; se conservan los de mayor criticidad y volumen. Por defecto 60. |
| `--estandar` | no | - | Marco(s) de referencia de los hallazgos, separados por coma; el primero rige el texto del reporte. Disponibles: iec62443, nerc-cip, nist-800-82, nist-csf, tsa-sd-1580-82 (mas los de --estandar-archivo). Por defecto iec62443. |
| `--estandar-archivo` | no | - | Marco propio en JSON (ver README). Se puede repetir. |

### `python ot_pcap_assess.py diagrama` (exportaciones de plataformas)

| Opcion | Obligatoria | Por defecto | Descripcion |
|---|---|---|---|
| `--activos` | no | - | Inventario de activos (CSV, JSON o XLSX). Recomendado: aporta tipo, nivel y zona. |
| `--enlaces` | no | - | Comunicaciones o enlaces entre activos (CSV, JSON o XLSX). Son la fuente 'principal'. Obligatorio salvo que se den fuentes con --fuente-flujos NOMBRE=ARCHIVO. |
| `--formato` | no | auto | Plataforma de origen; auto la deduce de las columnas. Por defecto auto. |
| `--mapeo` | no | - | Fija columnas a mano: {"activos": {"nivel": "Purdue"}, "enlaces": {"origen": "Src"}} |
| `--agrupar` | no | auto | Agrupar por nivel Purdue, zona de la plataforma o interfaz del firewall (requiere --rutas-firewall). Por defecto auto: interfaz si hay --rutas-firewall. |
| `--version` | no | - | show program's version number and exit |
| `-o, --out` | no | diagramas_ot | Carpeta de salida |
| `--idioma` | no | - | Idioma de los reportes (por defecto es; manda sobre el idioma del perfil). |
| `--perfil` | no | - | Perfil del proyecto en JSON (cliente, sitio, marcos...). Reemplaza a --titulo, --cliente y --estandar; no se pueden combinar. |
| `--titulo` | no | - | Titulo de la portada. Por defecto Diagramas de red OT. |
| `--cliente` | no | - | Subtitulo de la portada. Por defecto Analisis de inventario de planta. |
| `--vulnerabilidades` | no | - | Vulnerabilidades por activo en CSV (como en el analisis de capturas); se cruzan con el inventario importado. Tambien acepta la exportacion de CVE por nodo de Nozomi (CSV o XLSX, se detecta por sus columnas). |
| `--tor-relays` | no | - | Lista de relays Tor descargada por usted (texto con una IP por linea o JSON de Onionoo, como en el analisis de capturas); un conducto hacia una IP de la lista se reporta como Tor. La herramienta no descarga nada. |
| `--kev` | no | - | Catalogo KEV de CISA en JSON o CSV (como en el analisis de capturas); requiere --vulnerabilidades. |
| `--cis` | no | - | CIS Controls v8.1 (XLSX oficial o CSV; como en el analisis de capturas): filas del grupo IG del perfil (cis_ig; por defecto IG2) en matriz_controles.csv. |
| `--cis-mapeo` | no | - | Mapeo oficial de CIS v8.1 a SP 800-53 Rev 5 o a CSF 2.0 (XLSX oficial de CIS o CSV con las mismas columnas; repetible, uno por tipo; requiere --cis). El estado de las filas CIS sale de este mapeo; no se copia al repo ni a las salidas mas que ids y relacion. |
| `--avisos-ics` | no | - | Avisos ICS de CISA en CSAF 2.0: un JSON o una carpeta (como en el analisis de capturas). |
| `--catalogo-vulnerabilidades` | no | - | Catalogo del analista (CSV o XLSX) con vulnerabilidades por fabricante, producto y version afectada (como en el analisis de capturas). |
| `--alertas` | no | - | Alertas de un IDS o plataforma OT en CSV (como en el analisis de capturas); se asocian a los conductos importados. |
| `--rutas-firewall` | no | - | Tabla de rutas de un firewall (como en el analisis de capturas); asigna la interfaz a cada IP y marca los enlaces que cruzan el firewall. |
| `--firewall` | no | - | Salida de la CLI de un Cisco FTD/ASA (archivo o carpeta). Como --rutas-firewall pero con las rutas reales y la tabla de reglas con su uso (firewall_reglas.csv). Se puede repetir (firewalls en cadena: enlaces, camino de cada conducto y coherencia entre ellos); manda sobre --rutas-firewall. |
| `--switch` | no | - | Salida de la CLI de un switch Cisco IOS/IOS-XE (sesion pegada: show running-config, show mac address-table, show interfaces description, show cdp neighbors detail, show version). Ubica cada activo con MAC en su puerto y VLAN y dice que VLAN espeja cada sesion SPAN. Se puede repetir. No guarda contrasenas ni comunidades SNMP. |
| `--firewall-contadores` | no | - | Aciertos por regla: CSV de politicas de la GUI de una FortiGate (columnas ID o Name y Hit Count) o salida de `show rule-hit-count ...` de un Palo Alto. Requiere --firewall; FortiOS no los trae en la configuracion. |
| `--zonas-fw` | no | - | Zonas de seguridad por interfaz para la politica propuesta (columnas firewall, interfaz, zona; firewall = hostname o nombre del archivo). Requiere --firewall. Sin ella se usa la zona del firewall o SZ_<nameif>, con aviso. |
| `--origen-ataque` | no | - | Zona desde la que se buscan rutas de ataque (se puede repetir). Por defecto, las zonas cuyo nombre contiene IT, CORP o Internet; ademas siempre se evalua Internet. |
| `--objetivo-ataque` | no | - | Zona cuyos activos son objetivo de las rutas de ataque (se puede repetir), ademas de los activos de criticidad Critica o Alta. |
| `--linea-base` | no | - | Linea base aprobada del sitio (la crea 'linea-base aprobar'). Verifica sus hash y compara esta corrida con ella (activos, conductos, escritores, firmware/modelo/MAC); el volumen y la periodicidad solo se comparan si ambas corridas vienen de capturas. |
| `--madurez` | no | - | Cuestionario de madurez contestado (la plantilla la escribe 'madurez cuestionario'): respuesta 0 a 4, N/A o vacio por pregunta. Calcula nivel actual, objetivo y brecha por dominio y senala donde la evidencia de red no respalda lo declarado. Escribe madurez.csv. Objetivo: madurez_objetivo o ml_objetivo del perfil. |
| `--csf-tiers` | no | - | csf_tiers.csv llenado por el analista (la corrida lo escribe con la meta de csf_tiers_objetivo del perfil): columna tier_actual con 1 a 4 o el nombre del tier por funcion de NIST CSF 2.0. Calcula la brecha frente a la meta y agrega la evidencia de las filas NIST de la matriz de controles. La herramienta no mide los tiers. |
| `--inventario-manual` | no | - | Hoja de inventario del cliente o del equipo (CSV, JSON o XLSX, encabezados libres: se reconocen por alias; --mapeo con la clave "manual" corrige columnas). Sus valores quedan como declarados en inventario_normalizado.csv y se cuentan los activos declarados que no se observaron y los observados que no estan. |
| `--fin-de-soporte` | no | - | Fechas de fin de soporte del analista (CSV o XLSX; columnas fabricante, producto, version, fecha_fin_soporte AAAA-MM-DD y opcionales fecha_fin_venta, reemplazo_sugerido, fuente). Genera obsolescencia.csv; manda sobre la tabla integrada de sistemas operativos. Sin red. |
| `--fuente` | no | - | Texto de fuente para el encabezado (por defecto, la plataforma) |
| `--fuente-flujos` | no | - | NOMBRE=ARCHIVO o NOMBRE=CARPETA: exportacion de un sensor con nombre (se puede repetir, tambien con el mismo NOMBRE para varios archivos del mismo sensor). Los conductos de varias fuentes se unen sin contar dos veces lo que vieron varios sensores, cada uno lleva sus fuentes y se arma el mapa de cobertura por segmento. Tambien acepta capturas (.pcap, .pcapng, .cap o una carpeta con ellas, mezcladas o no con exportaciones): requieren tshark; cada conducto cuenta como un solo dia (el de su primer paquete, UTC). |
| `--tshark` | no | - | Carpeta de Wireshark si no esta en el PATH (para las capturas de --fuente-flujos) |
| `--estandar` | no | - | Marco de referencia (como en el analisis de capturas). Por defecto iec62443. |
| `--estandar-archivo` | no | - |  |
| `--max-rows` | no | 120 | Filas maximas por tabla en los reportes (el detalle completo queda en los CSV) |
| `--solo-diagramas` | no | - | Solo diagramas, CSV y la pagina diagramas.html; sin reporte, Excel, Word ni resumen ejecutivo (corridas rapidas). |
| `--diagram-max-nodes` | no | 40 |  |
| `--diagram-max-edges` | no | 60 |  |

## Archivos de salida

| Archivo | Columnas (en orden) |
|---|---|
| `alertas.csv` |  |
| `avisos_ics.csv` |  |
| `hallazgos_importados.csv` |  |
| `inventario_importado.csv` | `nombre`, `ips`, `id`, `fabricante`, `modelo`, `firmware`, `tipo`, `nivel`, `zona`, `interfaz_firewall`, `zona_asignada`, `origen_asignacion`, `switch_puerto`, `vlan`, `nota_nat`, `sistema_operativo`, `protocolos`, `vlans` |
| `vulnerabilidades.csv` |  |

Cada hallazgo (`finding()` en `ot_assess/rules/base.py`, tambien en `resultado.json`) tiene las claves: `id`, `severidad`, `titulo`, `categoria`, `evidencia`, `por_que_importa`, `recomendacion`, `captura`, `referencias`. `referencias` es un dict {clave de marco: texto}.
