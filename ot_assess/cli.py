"""Linea de comandos: orquesta el analisis de punta a punta."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from . import allowlist_proyecto as _alp
from . import confirmacion_vulns as _vconf
from . import entregables as _entregables
from . import inventario_normalizado as _in
from . import inventario_presentado as _ip
from . import obsolescencia as _ob
from . import paquete_avisos as _pa
from . import registro_evidencias as _registro
from . import valoraciones_riesgo as _val
from .cache_capturas import CacheCapturas
from .consolidate import build_conduits, merge_assets
from .detail import analyze_detail
from .diagram import Opciones, diagrama_tobe, diagrama_zcr
from .diagram import build_all as build_diagrams
from .entorno import construir as construir_entorno
from .fields import DETAIL_FIELDS, DETAIL_FILTER_PARTS, FLOW_FIELDS
from .firewall import contrastar
from .flows import analyze_flows
from .i18n import t
from .importers import cargar_mapeo
from .model import Assessment, Capture
from .perfil import aplicar as aplicar_perfil
from .permisos import salida_privada
from .report import write_all
from .roles import infer_roles
from .rules import evaluate
from .standards import ESTANDARES, cargar_archivo, elegir
from .tools import CapturaIlegible, Tshark, find_tool, run
from .util import human

DOC = """
Uso:
    python ot_pcap_assess.py captura.pcapng
    python ot_pcap_assess.py carpeta_de_capturas/ -o reporte/
    python ot_pcap_assess.py *.pcapng --max-packets 0        # sin muestreo

Requiere Wireshark instalado (tshark y capinfos en el PATH, o --tshark).

Codigo de salida: 0 correcto · 1 error, o ninguna captura legible (no se genera reporte) ·
2 reporte generado, pero alguna captura estaba corrupta, truncada o vacia y no se analizo.

Diagramas desde exportaciones de Nozomi, Claroty o Dragos (sin capturas):
    python ot_pcap_assess.py diagrama --help

Copias seudonimizadas de exportaciones y configuraciones (para compartir muestras):
    python ot_pcap_assess.py anonimizar --help
    python ot_pcap_assess.py xdome-descargar --help

Politica propuesta (politica_propuesta.csv, ya revisada) a Cisco FMC 7.6, solo simula por defecto:
    python ot_pcap_assess.py politica-fmc --help
    python ot_pcap_assess.py solicitud-cambio --help
    python ot_pcap_assess.py politica-validar --help        # que romperia la propuesta con trafico de otra ventana

Primer dia en sitio: sirve esta captura? (perdidas, un solo sentido, huecos, VLAN y zonas sin trafico):
    python ot_pcap_assess.py validar-captura --help

Que cambio entre dos corridas (antes y despues):
    python ot_pcap_assess.py comparar --help

Consolidado de varios sitios (carpetas de salida de cada sitio en un libro de hojas fijas):
    python ot_pcap_assess.py sitios --help

Linea base aprobada del sitio (aprobar una corrida como referencia y verificarla; despues, --linea-base):
    python ot_pcap_assess.py linea-base --help

Madurez de ciberseguridad OT por dominio (plantilla del cuestionario de entrevista; despues, --madurez):
    python ot_pcap_assess.py madurez --help

Cadena de custodia de la evidencia (registro encadenado por hash, verificacion y formato imprimible):
    python ot_pcap_assess.py custodia --help

Paquete de entrega con manifiesto y verificacion:
    python ot_pcap_assess.py empaquetar --help
"""


def collect_inputs(paths: list[str]) -> list[Path]:
    exts = {".pcap", ".pcapng", ".cap", ".pcapng.gz", ".pcap.gz"}
    found: list[Path] = []
    for p in paths:
        pp = Path(p)
        if pp.is_dir():
            for f in sorted(pp.rglob("*")):
                if f.is_file() and (f.suffix.lower() in exts
                                    or f.name.lower().endswith((".pcap.gz", ".pcapng.gz"))):
                    found.append(f)
        elif pp.is_file():
            found.append(pp)
        else:
            print(f"[!] No existe: {p}", file=sys.stderr)
    return found


def marcar_ilegible(f: Path, causa: str) -> Capture:
    """Captura sin datos y con la causa; evaluate() solo emite el hallazgo de ilegible (COR-01)."""
    cap = Capture(f)
    cap.error = causa
    print(f"    [!] ILEGIBLE, no se analiza: {causa}", file=sys.stderr)
    evaluate(cap)
    return cap


def analyze_capture(ts: Tshark, f: Path, info: dict, flow_fields, detail_fields, detail_filter,
                    args, dominios=(), cache=None, tor_relays=None, propios=None) -> Capture:
    cap = cache.tomar(f) if cache else None
    if cap is not None:
        print("    desde cache (sin leer la captura)")
    else:
        cap = Capture(f)
        cap.info = info
        try:
            print("    - jerarquia de protocolos...")
            cap.protos = ts.phs(f)
            print(f"    - flujos y activos"
                  f"{f' (muestra de {args.max_packets:,})' if args.max_packets else ''}...")
            analyze_flows(ts, cap, flow_fields, args.max_packets)
            if not args.no_detail:
                print("    - identidad, control y anomalias...")
                analyze_detail(ts, cap, detail_fields, detail_filter)
        except CapturaIlegible as e:      # tshark fallo a mitad: lo leido es parcial y se descarta
            return marcar_ilegible(f, str(e))
        if cache:
            print("    leida")
            cache.guardar(f, cap)
    cap.dominios_internos = tuple(dominios)      # del perfil actual, no del guardado
    cap.tor_relays = tor_relays                  # de --tor-relays de esta corrida, no del guardado
    _in.excluir_captura(cap, propios)            # I1a: equipos propios del perfil, tambien sobre lo de la cache
    infer_roles(cap)
    evaluate(cap)
    _in.filtrar_hallazgos(cap, propios)
    print(f"    => {len(cap.hosts)} equipos, {len(cap.flows)} flujos, "
          f"{len(cap.identity)} datos de identidad, "
          f"{len(cap.control_ops)} operaciones de control, "
          f"{len(cap.findings)} hallazgos")
    return cap


def crear_parser() -> argparse.ArgumentParser:
    """Parser de argumentos; aparte de main() para que el catalogo de opciones salga del codigo."""
    ap = argparse.ArgumentParser(
        description="Analisis OT de capturas de red para assessment.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=DOC,
    )
    ap.add_argument("inputs", nargs="+", help="Archivos .pcap/.pcapng o carpetas")
    ap.add_argument("--version", action="version", version=f"ot_assess {__version__}")
    ap.add_argument("-o", "--out", default="reporte_ot", help="Carpeta de salida")
    ap.add_argument("--tshark", help="Carpeta de Wireshark si no esta en el PATH")
    ap.add_argument("--max-packets", type=int, default=1_000_000,
                    help="Tope de paquetes para el mapa de flujos (0 = todos). "
                         "Por defecto 1000000.")
    ap.add_argument("--max-rows", type=int, default=120,
                    help="Filas maximas por tabla en los reportes")
    ap.add_argument("--idioma", choices=["es", "en"], default=None,
                    help="Idioma de los reportes (por defecto es; manda sobre el idioma del perfil).")
    ap.add_argument("--perfil", metavar="JSON",
                    help="Perfil del proyecto en JSON (cliente, sitio, marcos...). Reemplaza a "
                         "--titulo, --cliente y --estandar; no se pueden combinar.")
    ap.add_argument("--reglas-firewall", metavar="CSV",
                    help="Reglas de firewall/ACL en CSV (columnas origen, destino, puerto, "
                         "protocolo, accion; id opcional). Contrasta la politica con los "
                         "conductos observados.")
    ap.add_argument("--rutas-firewall", metavar="ARCHIVO",
                    help="Tabla de rutas de un firewall (CSV/XLSX con interfaz y red, comandos route de "
                         "Cisco ASA o salida de show route). Asigna a cada IP la interfaz por la que el "
                         "firewall la alcanza y marca los conductos que lo cruzan.")
    ap.add_argument("--firewall", action="append", default=[], metavar="ARCHIVO",
                    help="Salida de la CLI de un Cisco FTD/ASA (archivo o carpeta: show route, nameif, "
                         "access-list, rule hits...). Da interfaz y rutas reales (como --rutas-firewall) y "
                         "contrasta las reglas con los conductos. Se puede repetir (firewalls en cadena: enlaces, "
                         "camino de cada conducto y coherencia entre ellos). "
                         "No se combina con --reglas-firewall; manda sobre --rutas-firewall.")
    ap.add_argument("--switch", action="append", default=[], metavar="ARCHIVO",
                    help="Salida de la CLI de un switch Cisco IOS/IOS-XE (sesion pegada: show running-config, "
                         "show mac address-table, show interfaces description, show cdp neighbors detail, "
                         "show version). Ubica cada activo con MAC en su puerto y VLAN y dice que VLAN espeja "
                         "cada sesion SPAN. Se puede repetir. No guarda contrasenas ni comunidades SNMP.")
    ap.add_argument("--firewall-contadores", metavar="CSV",
                    help="Aciertos por regla: CSV de politicas de la GUI de una FortiGate (columnas ID o Name y Hit "
                         "Count) o salida de `show rule-hit-count ...` de un Palo Alto. Requiere --firewall; "
                         "FortiOS no los trae en la configuracion.")
    ap.add_argument("--zonas-fw", metavar="CSV",
                    help="Zonas de seguridad por interfaz para la politica propuesta (columnas firewall, "
                         "interfaz, zona; firewall = hostname o nombre del archivo). Requiere --firewall. Sin "
                         "ella se usa la zona del firewall o SZ_<nameif>, con aviso.")
    ap.add_argument("--origen-ataque", action="append", default=[], metavar="ZONA",
                    help="Zona desde la que se buscan rutas de ataque (se puede repetir). Por defecto, las zonas "
                         "cuyo nombre contiene IT, CORP o Internet; ademas siempre se evalua Internet.")
    ap.add_argument("--objetivo-ataque", action="append", default=[], metavar="ZONA",
                    help="Zona cuyos activos son objetivo de las rutas de ataque (se puede repetir), ademas de "
                         "los activos de criticidad Critica o Alta.")
    ap.add_argument("--vulnerabilidades", metavar="CSV",
                    help="Vulnerabilidades por activo en CSV de un escaner o plataforma (columnas "
                         "cve, severidad o cvss, y activo, ip o mac; estado opcional). Se cruzan con "
                         "el inventario observado; no se consultan bases de CVE.")
    ap.add_argument("--kev", metavar="ARCHIVO",
                    help="Catalogo KEV de CISA (known_exploited_vulnerabilities.json o su CSV), descargado por "
                         "usted; marca las vulnerabilidades importadas que estan en el catalogo. Requiere "
                         "--vulnerabilidades. La herramienta no descarga nada.")
    ap.add_argument("--cis", metavar="ARCHIVO",
                    help="CIS Controls v8.1 (XLSX oficial de CIS o CSV con sus columnas), descargado por usted: "
                         "agrega a matriz_controles.csv una fila por salvaguarda del grupo IG1, IG2 o IG3 "
                         "(perfil cis_ig; por defecto IG2). Los titulos se leen del archivo; la herramienta no "
                         "los distribuye (licencia CC BY-NC-ND 4.0).")
    ap.add_argument("--cis-mapeo", metavar="ARCHIVO", action="append", dest="cis_mapeo",
                    help="Mapeo oficial de CIS v8.1 a SP 800-53 Rev 5 o a CSF 2.0 (XLSX oficial de CIS o CSV con "
                         "las mismas columnas), descargado por usted; repetible, uno por tipo. Requiere --cis: "
                         "el estado de las filas CIS sale de este mapeo y no de las referencias de NIST. No se "
                         "copia al repo ni a las salidas mas que ids y relacion.")
    ap.add_argument("--iec62351-estados", metavar="ARCHIVO", dest="iec62351_estados",
                    help="Un iec62351_flujos.csv de una corrida anterior que el equipo lleno: traslada estado_equipo "
                         "y nota_equipo por id_flujo y activa la tabla aunque el perfil no tenga iec62351_flujos. "
                         "Un estado fuera de la lista permitida termina con codigo 2.")
    ap.add_argument("--avisos-ics", metavar="RUTA", dest="avisos_ics",
                    help="Un aviso ICS de CISA en CSAF 2.0 (JSON) o una carpeta con muchos (recursiva); "
                         "se cruzan por CVE exacto con --vulnerabilidades y generan avisos_ics.csv; ademas se "
                         "comparan fabricante, modelo y firmware del inventario con sus productos afectados "
                         "(vulnerabilidades_firmware.csv, candidatos a confirmar).")
    ap.add_argument("--paquete-avisos", metavar="CARPETA", dest="paquete_avisos",
                    help="Paquete verificado de avisos ICS y KEV (subcomando paquete-avisos), solo carpeta. Se "
                         "verifica antes de usarlo (codigo 2 si no coincide) y equivale a --avisos-ics y --kev "
                         "con sus archivos; no se combina con ellos. La herramienta no descarga nada.")
    ap.add_argument("--registro-evidencias", metavar="ARCHIVO", dest="registro_evidencias",
                    help="Un registro_evidencias.csv de una corrida anterior que el equipo lleno: traslada por "
                         "id_evidencia recolector, planta, metodo, sensibilidad, entregables y nota_equipo, y activa "
                         "el registro aunque el perfil no tenga registro_evidencias. Un archivo que no sirve termina "
                         "con codigo 2.")
    ap.add_argument("--vulnerabilidades-revision", metavar="ARCHIVO", dest="vulnerabilidades_revision",
                    help="Un vulnerabilidades_revision.csv (o vulnerabilidades.csv / vulnerabilidades_firmware.csv con "
                         "id_vulnerabilidad) de una corrida anterior que el equipo lleno: traslada por id_vulnerabilidad "
                         "estado, confirmado_por, fecha y motivo, y activa la confirmacion aunque el perfil no tenga "
                         "confirmacion_vulnerabilidades. Un archivo que no sirve termina con codigo 2.")
    ap.add_argument("--valoraciones-riesgo", metavar="ARCHIVO", dest="valoraciones_riesgo",
                    help="Un valoraciones_riesgo.csv de una corrida anterior que el equipo lleno: traslada por "
                         "id_riesgo (o id_hallazgo) la valoracion inherente y objetivo, controles, tratamiento, "
                         "responsable, fecha_objetivo y justificacion, y activa la valoracion aunque el perfil no "
                         "tenga riesgo.valoraciones. Un archivo que no sirve termina con codigo 2.")
    ap.add_argument("--allowlist-revision", metavar="ARCHIVO", dest="allowlist_revision",
                    help="Un allowlist_tobe.csv de una corrida anterior que el equipo lleno: traslada por id_flujo "
                         "(o zona_origen + zona_destino + servicio) decision_equipo, las columnas del equipo y "
                         "estado_revision, revisado_por, fecha y comentario; conserva los flujos declarados que no se "
                         "observaron, y activa la allowlist con vocabulario del proyecto aunque el perfil no tenga "
                         "allowlist_tobe. Un archivo que no sirve termina con codigo 2.")
    ap.add_argument("--catalogo-vulnerabilidades", metavar="ARCHIVO", dest="catalogo_vulnerabilidades",
                    help="Catalogo del analista (CSV o XLSX; columnas fabricante, producto, version_afectada, cve; "
                         "cvss, aviso, remediacion y fuente opcionales) con vulnerabilidades por fabricante, "
                         "modelo y firmware; se compara con el inventario sin red (vulnerabilidades_firmware.csv).")
    ap.add_argument("--alertas", metavar="CSV",
                    help="Alertas de un IDS o plataforma OT en CSV (columnas firma, origen y/o destino, "
                         "severidad o prioridad; puerto, protocolo, fecha, categoria y conteo opcionales). "
                         "Se asocian a los conductos observados; no se validan las firmas.")
    ap.add_argument("--tor-relays", metavar="ARCHIVO", dest="tor_relays",
                    help="Lista de relays Tor descargada por usted: texto con una IP por linea (como la lista de "
                         "salidas de check.torproject.org) o JSON de Onionoo (summary o details). Un conducto "
                         "hacia una IP de la lista se reporta como Tor; sin lista solo se ven los puertos por "
                         "defecto 9001 y 9030. La herramienta no descarga nada.")
    ap.add_argument("--linea-base", metavar="CARPETA", dest="linea_base",
                    help="Linea base aprobada del sitio (la crea 'linea-base aprobar'). Verifica sus hash y "
                         "compara esta corrida con ella: activos, conductos, escritores, firmware/modelo/MAC, "
                         "volumen y periodicidad. Escribe desviaciones_linea_base.csv y hallazgos.")
    ap.add_argument("--madurez", metavar="ARCHIVO",
                    help="Cuestionario de madurez contestado (la plantilla la escribe 'madurez cuestionario'): "
                         "respuesta 0 a 4, N/A o vacio por pregunta. Calcula nivel actual, objetivo y brecha por "
                         "dominio y senala donde la evidencia de red no respalda lo declarado. Escribe madurez.csv. "
                         "Objetivo: madurez_objetivo o ml_objetivo del perfil.")
    ap.add_argument("--csf-tiers", metavar="ARCHIVO", dest="csf_tiers",
                    help="csf_tiers.csv llenado por el analista (la corrida lo escribe con la meta de "
                         "csf_tiers_objetivo del perfil): columna tier_actual con 1 a 4 o el nombre del tier "
                         "(Parcial, Informado por el riesgo, Repetible, Adaptativo) por funcion de NIST CSF 2.0. "
                         "Calcula la brecha frente a la meta y agrega la evidencia de las filas NIST de la matriz "
                         "de controles. La herramienta no mide los tiers.")
    ap.add_argument("--inventario-manual", metavar="ARCHIVO",
                    help="Hoja de inventario del cliente o del equipo (CSV, JSON o XLSX, encabezados libres: se "
                         "reconocen por alias). Sus valores quedan como declarados en inventario_normalizado.csv; "
                         "cuenta los activos declarados que no se observaron y los observados que no estan.")
    ap.add_argument("--fin-de-soporte", metavar="ARCHIVO", dest="fin_de_soporte",
                    help="Fechas de fin de soporte del analista (CSV o XLSX; columnas fabricante, producto, version, "
                         "fecha_fin_soporte AAAA-MM-DD y opcionales fecha_fin_venta, reemplazo_sugerido, fuente). "
                         "Genera obsolescencia.csv; manda sobre la tabla integrada de sistemas operativos. Sin red.")
    ap.add_argument("--mapeo", metavar="JSON",
                    help='Fija a mano las columnas del inventario manual: {"manual": {"ip": "Direccion"}}')
    ap.add_argument("--titulo", default=None,
                    help="Titulo que aparece en la portada del reporte HTML. "
                         "Por defecto Assessment de ciberseguridad OT.")
    ap.add_argument("--cliente", default=None,
                    help="Subtitulo de la portada: nombre del cliente o del sitio. "
                         "Por defecto Analisis de trafico de planta.")
    ap.add_argument("--cache", metavar="CARPETA",
                    help="Carpeta donde guardar (y reutilizar) la lectura de cada captura, para regenerar el "
                         "informe con otro perfil, firewall, zonas o idioma sin releer capturas grandes. "
                         "Contiene datos del cliente (archivos 600): guardela junto a sus salidas, no en el "
                         "repositorio. La clave incluye el contenido del pcap, la version y tshark.")
    ap.add_argument("--custodia", metavar="REGISTRO",
                    help="Registro de cadena de custodia (subcomando custodia): marca cada captura analizada como "
                         "registrada o no registrada (por SHA-256) y verifica la cadena. No es un hallazgo.")
    ap.add_argument("--cache-renovar", action="store_true",
                    help="Ignora lo guardado en --cache y lo reescribe.")
    ap.add_argument("--no-detail", action="store_true",
                    help="Omitir el pase de detalle (mas rapido, sin identidad ni control)")
    ap.add_argument("--no-diagrams", action="store_true",
                    help="No generar los diagramas de red")
    ap.add_argument("--diagram-max-nodes", type=int, default=40,
                    help="Equipos maximos en el diagrama por activo (los de mayor riesgo "
                         "primero). Por defecto 40.")
    ap.add_argument("--diagram-max-edges", type=int, default=60,
                    help="Trazos maximos en el diagrama por activo; se conservan los de mayor "
                         "criticidad y volumen. Por defecto 60.")
    ap.add_argument("--estandar", default=None,
                    help="Marco(s) de referencia de los hallazgos, separados por coma; el primero "
                         "rige el texto del reporte. Disponibles: " + ", ".join(ESTANDARES)
                         + " (mas los de --estandar-archivo). Por defecto iec62443.")
    ap.add_argument("--estandar-archivo", action="append", default=[], metavar="JSON",
                    help="Marco propio en JSON (ver README). Se puede repetir.")
    return ap


@salida_privada
def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == "diagrama" and not Path("diagrama").exists():
        from .cli_diagrama import main as main_diagrama
        return main_diagrama(argv[1:])
    if argv and argv[0] == "anonimizar" and not Path("anonimizar").exists():
        from .cli_anonimizar import main as main_anonimizar
        return main_anonimizar(argv[1:])
    if argv and argv[0] == "xdome-descargar" and not Path("xdome-descargar").exists():
        from .cli_xdome import main as main_xdome
        return main_xdome(argv[1:])
    if argv and argv[0] == "politica-fmc" and not Path("politica-fmc").exists():
        from .cli_politica import main as main_politica
        return main_politica(argv[1:])
    if argv and argv[0] == "politica-validar" and not Path("politica-validar").exists():
        from .cli_validar import main as main_validar
        return main_validar(argv[1:])
    if argv and argv[0] == "validar-captura" and not Path("validar-captura").exists():
        from .cli_validar_captura import main as main_validar_captura
        return main_validar_captura(argv[1:])
    if argv and argv[0] == "solicitud-cambio" and not Path("solicitud-cambio").exists():
        from .cli_solicitud import main as main_solicitud
        return main_solicitud(argv[1:])
    if argv and argv[0] == "comparar" and not Path("comparar").exists():
        from .cli_comparar import main as main_comparar
        return main_comparar(argv[1:])
    if argv and argv[0] == "sitios" and not Path("sitios").exists():
        from .cli_sitios import main as main_sitios
        return main_sitios(argv[1:])
    if argv and argv[0] == "linea-base" and not Path("linea-base").exists():
        from .cli_linea_base import main as main_linea_base
        return main_linea_base(argv[1:])
    if argv and argv[0] == "madurez" and not Path("madurez").exists():
        from .cli_madurez import main as main_madurez
        return main_madurez(argv[1:])
    if argv and argv[0] == "custodia" and not Path("custodia").exists():
        from .cli_custodia import main as main_custodia
        return main_custodia(argv[1:])
    if argv and argv[0] == "empaquetar" and not Path("empaquetar").exists():
        from .cli_entrega import main as main_entrega
        return main_entrega(argv[1:])
    if argv and argv[0] == "paquete-avisos" and not Path("paquete-avisos").exists():
        from .cli_paquete_avisos import main as main_paquete_avisos
        return main_paquete_avisos(argv[1:])
    ap =crear_parser()
    args = ap.parse_args(argv)
    if args.firewall and args.reglas_firewall:
        ap.error("--firewall ya trae las reglas: no se combina con --reglas-firewall")
    if args.cis_mapeo and not args.cis:
        ap.error("--cis-mapeo requiere --cis")
    if args.cache_renovar and not args.cache:
        ap.error("--cache-renovar requiere --cache")
    if args.custodia and not Path(args.custodia).is_file():
        ap.error(f"--custodia espera un archivo existente: '{args.custodia}'")
    for f in args.switch:
        if not Path(f).is_file():
            ap.error(f"--switch espera un archivo existente: '{f}'")
    if args.firewall_contadores and not args.firewall:
        ap.error("--firewall-contadores requiere --firewall")
    zonas = None
    if args.zonas_fw:
        from .firewalls import politica as _po
        if not args.firewall:
            ap.error("--zonas-fw requiere --firewall")
        try:
            zonas = _po.cargar_zonas(args.zonas_fw)
        except ValueError as e:
            ap.error(str(e))
    perfil = aplicar_perfil(ap, args, {"titulo": "Assessment de ciberseguridad OT",
                                       "cliente": "Analisis de trafico de planta",
                                       "estandar": "iec62443"})
    _pa.resolver(ap, args, perfil)       # AVK1 (D124)
    _entregables.avisos(perfil)          # ENT1 (D126)
    _registro.leer_opcion(ap, args, perfil)      # EVID2 (D127): antes de crear salidas
    _vconf.leer_opcion(ap, args, perfil)      # VCONF (D128): antes de crear salidas
    _val.leer_opcion(ap, args, perfil)      # RM2b (D130): antes de crear salidas
    _alp.leer_opcion(ap, args, perfil)      # ALLOW1 (D133): antes de crear salidas
    plan_vc = _vconf.de_args(args)
    for archivo in args.estandar_archivo:
        cargar_archivo(archivo)
    estandares = elegir(args.estandar)
    propios = _in.Propios.de_perfil(perfil)
    if args.linea_base and not Path(args.linea_base).is_dir():
        ap.error(f"--linea-base espera una carpeta existente: '{args.linea_base}'")
    from . import madurez as _ma
    respuestas_madurez = _ma.leer_opcion(ap, args.madurez, perfil)
    from . import csf_tiers as _ct
    declarados_tiers = _ct.leer_opcion(ap, args.csf_tiers)
    if args.mapeo and not args.inventario_manual:
        ap.error("--mapeo requiere --inventario-manual")
    if args.inventario_manual and not Path(args.inventario_manual).is_file():
        ap.error(f"--inventario-manual espera un archivo existente: '{args.inventario_manual}'")
    if args.catalogo_vulnerabilidades and not Path(args.catalogo_vulnerabilidades).is_file():
        ap.error(f"--catalogo-vulnerabilidades espera un archivo existente: '{args.catalogo_vulnerabilidades}'")
    manual, avisos_manual = [], []
    if args.inventario_manual:
        mapeo = cargar_mapeo(args.mapeo) if args.mapeo else {}
        manual, avisos_manual = _in.cargar_manual(args.inventario_manual, mapeo.get("manual"))
    tabla_eos, avisos_eos = [], []
    if args.fin_de_soporte:
        if not Path(args.fin_de_soporte).is_file():
            ap.error(f"--fin-de-soporte espera un archivo existente: '{args.fin_de_soporte}'")
        tabla_eos, avisos_eos = _ob.cargar_analista(args.fin_de_soporte)

    files = collect_inputs(args.inputs)
    if not files:
        print("[!] No hay capturas que analizar.", file=sys.stderr)
        return 1

    tshark_bin = find_tool("tshark", args.tshark)
    capinfos_bin = find_tool("capinfos", args.tshark)
    editcap_bin = find_tool("editcap", args.tshark)

    outdir = Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)

    ts = Tshark(tshark_bin, capinfos_bin, editcap_bin, outdir / ".probe")
    print(f"[*] tshark: {tshark_bin}")
    infos: dict[Path, dict] = {}
    causas: dict[Path, str] = {}
    def campos():
        ff = ts.valid_fields(FLOW_FIELDS)
        df = ts.valid_fields(DETAIL_FIELDS)
        filtro = ts.valid_filter(DETAIL_FILTER_PARTS)
        caidos = set(DETAIL_FIELDS) - set(df)
        ign = (set(FLOW_FIELDS) - set(ff)) | caidos | {
            p for p in DETAIL_FILTER_PARTS if f"({p})" not in filtro}
        if caidos:
            print(f"[*] Campos no soportados por este tshark (ignorados): "
                  f"{', '.join(sorted(caidos))}")
        return ff, df, filtro, ign

    cache = None
    if args.cache:       # la clave lleva los campos efectivos, que dependen del tshark: sonda antes
        for f in files:
            ts.make_probe(f)
            if ts.probe:
                break
        flow_fields, detail_fields, detail_filter, ignorados = campos()
        cache = CacheCapturas(args.cache, run, tshark_bin, flow_fields, detail_fields,
                              detail_filter, args, renovar=args.cache_renovar)
    for f in files:                   # COR-01: se valida todo antes de analizar nada
        if cache is not None:
            guardada = cache.cargar(f)
            if guardada is not None:
                infos[f] = guardada.info
                continue
        try:
            infos[f] = ts.capinfos(f)
            n = ts.duplicados(f)      # COR-02: capinfos no lo reporta
            if n is not None:
                infos[f]["Number of duplicate packets"] = str(n)
                infos[f]["Metodo de duplicados"] = "editcap -d (ventana de 5 paquetes)"
        except CapturaIlegible as e:
            causas[f] = str(e)
    if not infos:
        for f, causa in causas.items():
            print(f"[!] {f.name}: {causa}", file=sys.stderr)
        print("[!] Ninguna captura es legible; no se genera reporte.", file=sys.stderr)
        return 1
    if cache is None:
        ts.make_probe(next(iter(infos)))
        flow_fields, detail_fields, detail_filter, ignorados = campos()
    else:
        args.sha_capturas = cache.sha      # entorno.py reutiliza los SHA-256 ya calculados

    caps: list[Capture] = []
    from . import evasion as _ev
    tor_relays = _ev.preparar(args)
    for i, f in enumerate(files, 1):
        print(f"\n[{i}/{len(files)}] {f.name} ({human(f.stat().st_size)})")
        caps.append(marcar_ilegible(f, causas[f]) if f in causas else
                    analyze_capture(ts, f, infos[f], flow_fields, detail_fields, detail_filter, args,
                                    perfil.get("dominios_internos", ()), cache, tor_relays, propios))
    if cache is not None:
        print(f"\n[*] cache: {cache.aciertos} de {len(files)} capturas desde cache")

    print("\n[*] Consolidando inventario y matriz de comunicaciones...")
    assets, ip_index = merge_assets(caps)
    conduits = build_conduits(caps, ip_index)
    res = Assessment(caps, assets, conduits, args, estandares=estandares)
    print(f"    => {_ip.contar(res)} activos unicos, {len(conduits)} conductos "
          f"({sum(1 for k in conduits if k['cruza_zona'])} cruzan zonas)")
    res.tor_relays = tor_relays
    res.perfil = perfil
    if args.reglas_firewall:
        res.firewall = contrastar(args.reglas_firewall, conduits)
    if args.firewall:
        from .firewalls import integracion as _fi
        if args.rutas_firewall:
            print("[!] --firewall y --rutas-firewall a la vez: manda --firewall")
        res.rutas, res.firewall = _fi.integrar(args.firewall, assets, conduits, zonas, args.firewall_contadores)
        for adv in res.firewall["avisos"]:
            print(f"[!] {adv}")
        from .firewalls import esperados as _es
        lin = _es.registrar(res.firewall, caps, conduits)
        if lin:
            print(f"    {lin}")
        from .firewalls import higiene as _hg
        extra = Capture(Path(f"firewall {res.firewall['archivo']}"))
        _hg.agregar_hallazgos(extra, res.firewall)
        res.extras.append(extra)
    elif args.rutas_firewall:
        from . import rutas_firewall as _rf
        res.rutas = _rf.aplicar(args.rutas_firewall, assets, conduits)
    if res.rutas:
        print(f"    rutas de firewall: {res.rutas['rutas']} rutas, "
              f"{sum(1 for k in conduits if k['cruza_firewall'])} conductos cruzan el firewall")
        for adv in res.rutas["avisos"]:
            print(f"[!] {adv}")
    if args.switch:
        from .switches import integracion as _sw
        try:
            res.switches = _sw.integrar(args.switch, assets)
        except ValueError as e:
            ap.error(str(e))
        print(f"    switches: {len(res.switches['switches'])} leidos, {res.switches['ubicados']} de "
              f"{res.switches['con_mac']} activos con MAC ubicados, "
              f"{len(res.switches['sin_espejo'])} VLAN con equipos sin espejo SPAN")
        for adv in res.switches["avisos"]:
            print(f"[!] {adv}")
        from .switches import higiene as _shg
        extra = Capture(Path("switches " + ", ".join(res.switches["archivos"])))
        _shg.agregar_hallazgos(extra, res.switches)
        res.extras.append(extra)
    from . import cobertura_captura as _cc
    res.cobertura_captura = _cc.construir([_cc.de_captura(c) for c in caps], perfil,
                                          span=_cc.vlans_del_span(res.switches) if res.switches else frozenset())
    if res.cobertura_captura:
        r = res.cobertura_captura["resumen"]
        print(f"    cobertura de la captura: {r['puntos']} puntos, {r[_cc.APTA]} aptos, "
              f"{r[_cc.LIMITADA]} con limitaciones, {r[_cc.NO_APTA]} no aptos")
    from . import salud_red as _sr
    res.salud_red = _sr.construir(res.cobertura_captura, caps, assets, conduits, res.switches, perfil)   # L1 (D81)
    if res.salud_red:
        extra = Capture(Path("salud de la red (switches)"))
        _sr.agregar_hallazgos(extra, res.salud_red)
        if extra.findings:
            res.extras.append(extra)
        n_lb = len((res.salud_red.get("linea_base") or {}).get("conductos", ()))
        print(f"    salud de la red: linea base de trafico con {n_lb} conductos")
    from . import sensores as _se
    res.sensores = _se.construir(res.cobertura_captura, caps, conduits, res.switches, res.fuentes)   # S1 (D96)
    if res.sensores:
        r = res.sensores["resumen"]
        print(f"    sensores: {r['elegidos']} de {r['puntos']} puntos cubren {r['conductos_ot']} conductos OT, "
              f"{r['brechas']} brechas")
    from . import zonas as _zo
    res.zonas = _zo.asignar(assets, perfil, res.rutas, res.firewall, zonas)
    for adv in _zo.presentada(res.zonas, _ip.filas(res))["avisos"]:   # Z-I3 (D107): las zonas vacias de la tabla
        print(f"[!] {adv}")
    from . import iec62351 as _ie
    _ie.preparar(ap, args, perfil, caps, conduits, assets)      # E62351F (D125)
    from . import conductos_zcr as _zc
    res.zcr = _zc.construir(assets, conduits, res.zonas, res.firewall)
    if _zc.hay(res.zcr):
        extra = Capture(Path("conductos entre zonas"))
        _zc.agregar_hallazgos(extra, res.zcr)
        res.extras.append(extra)
    from . import rutas_ataque as _ra
    res.rutas_ataque = _ra.construir(assets, conduits, res.zonas, res.firewall, perfil, res.zcr,
                                     args.origen_ataque, args.objetivo_ataque)
    for adv in res.rutas_ataque.get("avisos", ()):
        print(f"[!] {adv}")
    if _ra.hay(res.rutas_ataque):
        extra = Capture(Path("rutas de ataque"))
        _ra.agregar_hallazgos(extra, res.rutas_ataque)
        res.extras.append(extra)
    from . import avisos_cisa as _ac
    from . import cvss4_entorno as _ce
    from . import vuln_firmware as _vf  # V1a (D89)
    vulns = cruces = None
    inferidos, fuente_cpe = None, ""
    if args.vulnerabilidades:
        from . import vulnerabilidades as _vu
        vulns = _vu.cargar(args.vulnerabilidades, (perfil or {}).get("version_cvss", "3"))
        cruces = _vu.cruzar(vulns, assets)
        inferidos, ambiguos = _vu.inferir_equipos(cruces)      # N2 (D101)
        fuente_cpe = "cpe " + Path(args.vulnerabilidades).name
        if ambiguos:
            print(f"[!] {_vu.aviso_cpe_ambiguo(ambiguos)}")
    registros = _in.registros_activos(assets, [c for c in caps if not c.error], firewall=res.firewall,
                                     zonas=res.zonas, inferidos=inferidos, fuente_inferida=fuente_cpe)
    indice_vf = _vf.de_args(args, [*registros, *manual])
    kev_cat, avisos = None, None
    if args.vulnerabilidades:
        kev, avisos = _ac.preparar(args, vulns, visitante=indice_vf.visitar if indice_vf else None)
        kev_cat = kev
        _ac.anotar(cruces, kev, avisos)
        kev = _ac.kev_efectivo(cruces, kev)
        nombre_v = Path(args.vulnerabilidades).name
        if _vu.aviso_sin_activo(cruces, nombre_v):
            print(f"[!] {_vu.aviso_sin_activo(cruces, nombre_v)}")
        extra = Capture(Path(f"vulnerabilidades {nombre_v}"))
        cruces_h = plan_vc.filtrar_cruces(cruces) if plan_vc else cruces      # VCONF (D128)
        _vu.agregar_hallazgo(extra, cruces_h, assets)
        if kev:
            _ac.agregar_hallazgo_kev(extra, cruces_h, assets, kev)
        res.extras.append(extra)
        res.vulns_cruces = cruces
        if _vu.con_entorno(cruces, (perfil or {}).get("criticidad_activos")):
            print(f"[i] {_ce.nota()}")
        res.vulnerabilidades = {**_vu.resumen(cruces, nombre_v), **_ac.resumen_cisa(cruces, kev, avisos)}
    else:
        _ac.preparar(args, None)
    if indice_vf:
        kev_cat, avisos = _vf.completar(indice_vf, args, kev_cat, avisos, bool(args.vulnerabilidades))
    if args.alertas:
        from . import alertas as _al
        asoc = _al.asociar(_al.cargar(args.alertas), conduits, assets)
        nombre_a = Path(args.alertas).name
        extra = Capture(Path(f"alertas {nombre_a}"))
        _al.agregar_hallazgo(extra, asoc, assets)
        res.extras.append(extra)
        res.alertas_asoc = asoc
        res.alertas = _al.resumen_completo(asoc, nombre_a)
    res.inventario_normalizado = _in.construir([*registros, *manual], perfil, bool(args.inventario_manual), propios)
    if indice_vf:        # V1a (D89): despues del inventario normalizado
        res.vuln_firmware = _vf.construir(indice_vf, res.inventario_normalizado, res.vulns_cruces, assets,
                                          kev_cat, avisos, (perfil or {}).get("version_cvss", "3"),
                                          (perfil or {}).get("criticidad_activos"), plan_vc)
        extra = Capture(Path("vulnerabilidades por firmware"))
        _vf.agregar_hallazgo(extra, plan_vc.filtrar_vf(res.vuln_firmware) if plan_vc else res.vuln_firmware)
        if extra.findings:
            res.extras.append(extra)
    _vconf.preparar(args, res.vulns_cruces, assets, res.vuln_firmware)      # VCONF (D128)
    ref, ref_origen = _ob.referencia_de([c for c in caps if not c.error])
    res.obsolescencia = _ob.construir(res.inventario_normalizado, tabla_eos, ref, ref_origen,
                                   (perfil or {}).get("obsolescencia"))
    extra = _ob.agregar_hallazgos([f for c in [*res.caps, *res.extras] for f in c.findings], res.obsolescencia)
    if extra:
        res.extras.append(extra)
    if args.linea_base:      # LB1 (D82): antes de la linea base 62443 y del plan para que ya cuenten
        from . import linea_base_aprobada as _lba
        from .rules.linea_base_aprobada import agregar_hallazgos as _hl_lba
        res.linea_base_aprobada = _lba.evaluar_corrida(res, args.linea_base,
                                                       [f for c in [*res.caps, *res.extras] for f in c.findings],
                                                       (perfil or {}).get("sitio", ""))
        extra = Capture(Path("linea base aprobada"))
        _hl_lba(extra, res.linea_base_aprobada)
        if extra.findings:
            res.extras.append(extra)
        _lba.imprimir(res.linea_base_aprobada)
    from . import linea_base as _lb
    res.linea_base = _lb.construir(assets, res.zonas,res.zcr, res.firewall, res.switches,
                                   [f for c in [*res.caps, *res.extras] for f in c.findings], perfil)
    if not res.linea_base:
        print("[!] linea base ISA/IEC 62443: no hay zonas, no se genera")
    from . import cis_controles as _cis
    from . import matriz_controles as _mc
    cis, cis_mapeo = _cis.cargar_con_mapeos(args.cis, args.cis_mapeo) if args.cis else (None, None)
    res.matriz_controles = _mc.construir(assets, res.zcr, res.firewall,
                                         [f for c in [*res.caps, *res.extras] for f in c.findings], perfil,
                                         cis, cis_mapeo)
    from . import tobe as _tb
    res.tobe = _tb.construir(assets, conduits, res.zonas, res.zcr, res.firewall,      # T1a (D85)
                             [f for c in [*res.caps, *res.extras] for f in c.findings], perfil)
    if _tb.aviso(res.tobe):
        print(_tb.aviso(res.tobe))
    for linea in _alp.combinar(res.tobe, _alp.de_args(args)):      # ALLOW1 (D133)
        print("[!] " + linea)
    from . import acceso_remoto as _arm
    from . import rutas_acceso as _rac
    res.rutas_acceso = _rac.construir(assets, conduits, res.zcr, res.firewall, perfil,
                                      _arm.indicadores(res))       # RUTA1 (D134)
    if _rac.hay(res.rutas_acceso):
        extra = Capture(Path("rutas de acceso a OT"))
        _rac.agregar_hallazgos(extra, res.rutas_acceso)
        res.extras.append(extra)
    from . import hardening as _hd
    res.hardening = _hd.construir(assets, [f for c in [*res.caps, *res.extras] for f in c.findings],
                               res.inventario_normalizado)   # T1b (D86)
    from . import fuentes_log as _fl
    res.fuentes_log = _fl.construir(assets, conduits, [f for c in [*res.caps, *res.extras] for f in c.findings],
                                    res.inventario_normalizado, res.firewall)     # G1a (D87)
    from . import direccionamiento as _dr
    res.direccionamiento = _dr.construir(assets, res.zonas, res.switches, res.inventario_normalizado,
                                         [f for c in [*res.caps, *res.extras] for f in c.findings])   # G1b (D88)
    res.madurez = _ma.construir(res, respuestas_madurez)       # M7 (D84): con los hallazgos ya completos
    _ma.imprimir(res.madurez)
    res.csf_tiers = _ct.construir(res, declarados_tiers)       # CSF2T (D110)
    _ct.imprimir(res.csf_tiers)
    inv = res.inventario_normalizado["resumen"]
    print(f"    inventario normalizado: {inv['activos']} activos, {inv['campos_en_conflicto']} campos en conflicto")
    if args.inventario_manual:
        print(f"    inventario manual: {inv['declarados_no_observados']} declarados no observados, "
              f"{inv['observados_no_declarados']} observados no declarados")
    for adv in avisos_manual:
        print(f"[!] {adv}")
    if _ob.hay(res.obsolescencia):
        por = res.obsolescencia["resumen"]["por_estado"]
        print(f"    obsolescencia (referencia {res.obsolescencia['referencia']}): "
              + ", ".join(f"{n} {e}" for e, n in por.items() if n))
    for adv in avisos_eos:
        print(f"[!] {adv}")
    if propios:
        x = propios.resumen()
        print(f"    equipos propios excluidos: {x['equipos']} equipos, {x['paquetes']} paquetes, "
              f"{x['conductos']} conductos, {x['hallazgos']} hallazgos omitidos")
    res.entorno = construir_entorno(run, tshark_bin, caps, args, list(ignorados))
    _registro.preparar(args, perfil, res.entorno, caps)      # EVID2 (D127)
    cust = res.entorno.get("custodia")
    if cust:
        if cust["cadena"] != "integra":
            print(f"[!] Cadena de custodia {cust['cadena']}: no es confiable.", file=sys.stderr)
        for c in cust["capturas"]:
            if c["estado"] != "registrada":
                print(f"[!] Captura no registrada en la cadena de custodia: {c['archivo']}", file=sys.stderr)
    if not args.no_diagrams:
        res.diagrams = build_diagrams(assets, conduits, Opciones(
            max_nodos=args.diagram_max_nodes, max_aristas=args.diagram_max_edges,
            agrupar="interfaz" if res.rutas else "nivel", estandar=estandares[0], titulo=args.titulo, cliente=args.cliente,
            fuente=t("Analisis pasivo de capturas")))
        res.diagrama_zcr = diagrama_zcr(res.zcr, Opciones(
            estandar=estandares[0], titulo=args.titulo, cliente=args.cliente, fuente=t("Analisis pasivo de capturas")))
        res.diagrama_tobe = diagrama_tobe(res.tobe, Opciones(
            estandar=estandares[0], titulo=args.titulo, cliente=args.cliente, fuente=t("Analisis pasivo de capturas")))

    print("[*] Escribiendo reportes...")
    paths = write_all(res, outdir)
    _entregables.write_entregables(res, outdir)      # ENT1 (D126): al final, ve todas las salidas

    probe = outdir / ".probe"
    if probe.exists():
        for p in probe.iterdir():
            p.unlink(missing_ok=True)
        probe.rmdir()

    print(f"\n[OK] {paths['html']}   <- reporte presentable a cliente")
    print(f"     {paths['md']}")
    for p in paths["diagramas"]:
        print(f"     {p}")
    for n in ("informe_ot.docx", "reporte_ot.xlsx", "inventario.csv", "comunicaciones.csv", "activos.csv", "flujos.csv",
              "identidad.csv", "hallazgos.csv", "control.csv", "resultado.json"):
        print(f"     {outdir / n}")
    ilegibles = [c.name for c in caps if c.error]
    if ilegibles:
        print(f"\n[!] {len(ilegibles)} de {len(caps)} capturas ilegibles, no analizadas: "
              f"{', '.join(ilegibles)}. El reporte no las incluye. Codigo de salida 2.",
              file=sys.stderr)
        return 2
    return 0
