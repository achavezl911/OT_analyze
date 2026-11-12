"""Subcomando `diagrama`: genera los diagramas a partir de exportaciones de una plataforma OT."""
from __future__ import annotations

import argparse
import collections
import json
from pathlib import Path

from . import __version__
from . import acceso_remoto as _ar
from . import alertas as _al
from . import avisos_cisa as _ac
from . import cis_controles as _cis
from . import conductos_zcr as _zc
from . import confirmacion_vulns as _vconf
from . import cvss4_entorno as _ce
from . import direccionamiento as _dr
from . import entregables as _entregables
from . import evasion as _ev
from . import fuentes as _fu
from . import fuentes_log as _fl
from . import hardening as _hd
from . import iec62351 as _ie
from . import inventario_normalizado as _in
from . import linea_base as _lb
from . import matriz_controles as _mc
from . import obsolescencia as _ob
from . import paquete_avisos as _pa
from . import registro_evidencias as _registro
from . import rutas_ataque as _ra
from . import rutas_firewall as _rf
from . import salud_red as _sr
from . import tobe as _tb
from . import vuln_firmware as _vf
from . import vulnerabilidades as _vu
from . import zonas as _zo
from .catalog import SEV_ORDER
from .diagram import Opciones, build_all, diagrama_tobe, diagrama_zcr
from .entorno import NO_DISPONIBLE, commit_corto, sha256_archivo
from .firewalls import cruces as _cr
from .firewalls import esperados as _es
from .firewalls import higiene as _hg
from .firewalls import integracion as _fi
from .firewalls import nat as _nt
from .firewalls import politica as _po
from .firewalls import rutas_propuestas as _rp
from .firewalls import topologia as _tp
from .importers import PERFILES, cargar_mapeo, importar
from .model import Assessment, Capture
from .perfil import aplicar as aplicar_perfil
from .permisos import salida_privada
from .report import write_all
from .report.common import escritor_csv
from .report.csvout import cabecera_hallazgos, cabecera_t, fila_hallazgo
from .report.diagrams import write_diagrams
from .report.pagina import write_pagina
from .rules.acceso_remoto import hallazgo as _hallazgo_ar
from .rules.evasion import hallazgo as _hallazgo_ev
from .rules.inventario import evaluar_inventario
from .standards import cargar_archivo, elegir
from .switches import integracion as _sw

AYUDA = """
Ejemplos:
  python ot_pcap_assess.py diagrama --activos nodos.csv --enlaces enlaces.csv -o salida/
  python ot_pcap_assess.py diagrama --activos assets.xlsx --enlaces comms.xlsx --formato claroty \\
      --estandar nerc-cip --cliente "Central X" -o salida/
  python ot_pcap_assess.py diagrama --activos a.csv --enlaces e.csv --mapeo mapeo.json -o salida/

Los alias de columna NO estan validados contra exportaciones reales de cada plataforma: revise
el cuadro "Datos de origen" del reporte y corrija con --mapeo lo que no se haya leido bien.
"""


def crear_parser() -> argparse.ArgumentParser:
    """Parser de argumentos; aparte de main() para que el catalogo de opciones salga del codigo."""
    ap = argparse.ArgumentParser(
        prog="ot_pcap_assess.py diagrama",
        description="Diagramas de red desde exportaciones de Nozomi, Claroty, Dragos u otra plataforma OT.",
        epilog=AYUDA, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--activos", nargs="*", default=[], metavar="ARCHIVO",
                    help="Inventario de activos (CSV, JSON o XLSX). Recomendado: aporta tipo, nivel y zona.")
    ap.add_argument("--enlaces", nargs="*", default=[], metavar="ARCHIVO",
                    help="Comunicaciones o enlaces entre activos (CSV, JSON o XLSX). Son la fuente "
                         "'principal'. Obligatorio salvo que se den fuentes con --fuente-flujos NOMBRE=ARCHIVO.")
    ap.add_argument("--formato", default="auto", choices=["auto", *PERFILES],
                    help="Plataforma de origen; auto la deduce de las columnas. Por defecto auto.")
    ap.add_argument("--mapeo", metavar="JSON",
                    help='Fija columnas a mano: {"activos": {"nivel": "Purdue"}, "enlaces": {"origen": "Src"}}')
    ap.add_argument("--agrupar", default="auto", choices=["auto", "nivel", "zona", "interfaz"],
                    help="Agrupar por nivel Purdue, zona de la plataforma o interfaz del firewall "
                         "(requiere --rutas-firewall). Por defecto auto: interfaz si hay "
                         "--rutas-firewall.")
    ap.add_argument("--version", action="version", version=f"ot_assess {__version__}")
    ap.add_argument("-o", "--out", default="diagramas_ot", help="Carpeta de salida")
    ap.add_argument("--idioma", choices=["es", "en"], default=None,
                    help="Idioma de los reportes (por defecto es; manda sobre el idioma del perfil).")
    ap.add_argument("--perfil", metavar="JSON",
                    help="Perfil del proyecto en JSON (cliente, sitio, marcos...). Reemplaza a "
                         "--titulo, --cliente y --estandar; no se pueden combinar.")
    ap.add_argument("--titulo", default=None,
                    help="Titulo de la portada. Por defecto Diagramas de red OT.")
    ap.add_argument("--cliente", default=None,
                    help="Subtitulo de la portada. Por defecto Analisis de inventario de planta.")
    ap.add_argument("--vulnerabilidades", metavar="ARCHIVO",
                    help="Vulnerabilidades por activo en CSV (como en el analisis de capturas); se cruzan "
                         "con el inventario importado. Tambien acepta la exportacion de CVE por nodo de "
                         "Nozomi (CSV o XLSX, se detecta por sus columnas).")
    ap.add_argument("--tor-relays", metavar="ARCHIVO", dest="tor_relays",
                    help="Lista de relays Tor descargada por usted (texto con una IP por linea o JSON de Onionoo, "
                         "como en el analisis de capturas); un conducto hacia una IP de la lista se reporta como "
                         "Tor. La herramienta no descarga nada.")
    ap.add_argument("--kev", metavar="ARCHIVO",
                    help="Catalogo KEV de CISA en JSON o CSV (como en el analisis de capturas); requiere "
                         "--vulnerabilidades.")
    ap.add_argument("--cis", metavar="ARCHIVO",
                    help="CIS Controls v8.1 (XLSX oficial o CSV; como en el analisis de capturas): filas del "
                         "grupo IG del perfil (cis_ig; por defecto IG2) en matriz_controles.csv.")
    ap.add_argument("--cis-mapeo", metavar="ARCHIVO", action="append", dest="cis_mapeo",
                    help="Mapeo oficial de CIS v8.1 a SP 800-53 Rev 5 o a CSF 2.0 (XLSX oficial de CIS o CSV con "
                         "las mismas columnas; repetible, uno por tipo; requiere --cis). El estado de las filas "
                         "CIS sale de este mapeo; no se copia al repo ni a las salidas mas que ids y relacion.")
    ap.add_argument("--iec62351-estados", metavar="ARCHIVO", dest="iec62351_estados",
                    help="Un iec62351_flujos.csv de una corrida anterior que el equipo lleno (como en el analisis "
                         "de capturas): traslada estado_equipo y nota_equipo por id_flujo.")
    ap.add_argument("--avisos-ics", metavar="RUTA", dest="avisos_ics",
                    help="Avisos ICS de CISA en CSAF 2.0: un JSON o una carpeta (como en el analisis de capturas).")
    ap.add_argument("--paquete-avisos", metavar="CARPETA", dest="paquete_avisos",
                    help="Paquete verificado de avisos ICS y KEV (subcomando paquete-avisos), solo carpeta; "
                         "como en el analisis de capturas.")
    ap.add_argument("--registro-evidencias", metavar="ARCHIVO", dest="registro_evidencias",
                    help="Un registro_evidencias.csv de una corrida anterior que el equipo lleno (como en el analisis "
                         "de capturas): traslada recolector, planta, metodo, sensibilidad, entregables y nota_equipo "
                         "por id_evidencia.")
    ap.add_argument("--vulnerabilidades-revision", metavar="ARCHIVO", dest="vulnerabilidades_revision",
                    help="Un vulnerabilidades_revision.csv de una corrida anterior que el equipo lleno (como en el "
                         "analisis de capturas): traslada estado, confirmado_por, fecha y motivo por id_vulnerabilidad. "
                         "Un archivo que no sirve termina con codigo 2.")
    ap.add_argument("--catalogo-vulnerabilidades", metavar="ARCHIVO", dest="catalogo_vulnerabilidades",
                    help="Catalogo del analista (CSV o XLSX) con vulnerabilidades por fabricante, producto y "
                         "version afectada (como en el analisis de capturas).")
    ap.add_argument("--alertas", metavar="CSV",
                    help="Alertas de un IDS o plataforma OT en CSV (como en el analisis de capturas); se "
                         "asocian a los conductos importados.")
    ap.add_argument("--rutas-firewall", metavar="ARCHIVO",
                    help="Tabla de rutas de un firewall (como en el analisis de capturas); asigna la "
                         "interfaz a cada IP y marca los enlaces que cruzan el firewall.")
    ap.add_argument("--firewall", action="append", default=[], metavar="ARCHIVO",
                    help="Salida de la CLI de un Cisco FTD/ASA (archivo o carpeta). Como --rutas-firewall "
                         "pero con las rutas reales y la tabla de reglas con su uso (firewall_reglas.csv). "
                         "Se puede repetir (firewalls en cadena: enlaces, camino de cada conducto y "
                         "coherencia entre ellos); manda sobre --rutas-firewall.")
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
    ap.add_argument("--linea-base", metavar="CARPETA", dest="linea_base",
                    help="Linea base aprobada del sitio (la crea 'linea-base aprobar'). Verifica sus hash y "
                         "compara esta corrida con ella (activos, conductos, escritores, firmware/modelo/MAC); "
                         "el volumen y la periodicidad solo se comparan si ambas corridas vienen de capturas.")
    ap.add_argument("--madurez", metavar="ARCHIVO",
                    help="Cuestionario de madurez contestado (la plantilla la escribe 'madurez cuestionario'): "
                         "respuesta 0 a 4, N/A o vacio por pregunta. Calcula nivel actual, objetivo y brecha por "
                         "dominio y senala donde la evidencia de red no respalda lo declarado. Escribe madurez.csv. "
                         "Objetivo: madurez_objetivo o ml_objetivo del perfil.")
    ap.add_argument("--csf-tiers", metavar="ARCHIVO", dest="csf_tiers",
                    help="csf_tiers.csv llenado por el analista (la corrida lo escribe con la meta de "
                         "csf_tiers_objetivo del perfil): columna tier_actual con 1 a 4 o el nombre del tier por "
                         "funcion de NIST CSF 2.0. Calcula la brecha frente a la meta y agrega la evidencia de las "
                         "filas NIST de la matriz de controles. La herramienta no mide los tiers.")
    ap.add_argument("--inventario-manual", metavar="ARCHIVO",
                    help="Hoja de inventario del cliente o del equipo (CSV, JSON o XLSX, encabezados libres: se "
                         "reconocen por alias; --mapeo con la clave \"manual\" corrige columnas). Sus valores "
                         "quedan como declarados en inventario_normalizado.csv y se cuentan los activos "
                         "declarados que no se observaron y los observados que no estan.")
    ap.add_argument("--fin-de-soporte", metavar="ARCHIVO", dest="fin_de_soporte",
                    help="Fechas de fin de soporte del analista (CSV o XLSX; columnas fabricante, producto, version, "
                         "fecha_fin_soporte AAAA-MM-DD y opcionales fecha_fin_venta, reemplazo_sugerido, fuente). "
                         "Genera obsolescencia.csv; manda sobre la tabla integrada de sistemas operativos. Sin red.")
    ap.add_argument("--fuente", help="Texto de fuente para el encabezado (por defecto, la plataforma)")
    ap.add_argument("--fuente-flujos", action="append", default=[], metavar="NOMBRE=RUTA",
                    help="NOMBRE=ARCHIVO o NOMBRE=CARPETA: exportacion de un sensor con nombre (se puede repetir, "
                         "tambien con el mismo NOMBRE para varios archivos del mismo sensor). Los conductos "
                         "de varias fuentes se unen sin contar dos veces lo que vieron varios sensores, cada "
                         "uno lleva sus fuentes y se arma el mapa de cobertura por segmento. Tambien acepta "
                         "capturas (.pcap, .pcapng, .cap o una carpeta con ellas, mezcladas o no con "
                         "exportaciones): requieren tshark; cada conducto cuenta como un solo dia (el de su "
                         "primer paquete, UTC).")
    ap.add_argument("--tshark", help="Carpeta de Wireshark si no esta en el PATH (para las capturas de --fuente-flujos)")
    ap.add_argument("--estandar", default=None,
                    help="Marco de referencia (como en el analisis de capturas). Por defecto iec62443.")
    ap.add_argument("--estandar-archivo", action="append", default=[], metavar="JSON")
    ap.add_argument("--max-rows", type=int, default=120,
                    help="Filas maximas por tabla en los reportes (el detalle completo queda en los CSV)")
    ap.add_argument("--solo-diagramas", action="store_true",
                    help="Solo diagramas, CSV y la pagina diagramas.html; sin reporte, Excel, Word ni "
                         "resumen ejecutivo (corridas rapidas).")
    ap.add_argument("--diagram-max-nodes", type=int, default=40)
    ap.add_argument("--diagram-max-edges", type=int, default=60)
    return ap


def _completar(imp) -> None:
    """Rellena las claves que los escritores de reporte esperan de un activo o conducto de captura
    (nombres, roles, zonas de origen y destino, procedencia), sin pisar las que ya existen."""
    banda = (lambda a: a["zona"]) if imp.agrupar == "zona" else (lambda a: a["purdue"])
    por_id = {}
    for a in imp.assets.values():
        por_id[a["mac"]] = a
        for alias in a.get("alias", ()):
            por_id.setdefault(alias, a)
        for ip in a["ips"]:
            por_id.setdefault(ip, a)
        for campo, valor in (("role_why", ""), ("bytes", 0), ("hostnames", set()), ("identidad", []),
                             ("capturas", {imp.fuente}), ("protos", collections.Counter()),
                             ("ports_served", collections.Counter())):
            a.setdefault(campo, valor)
    for k in imp.conduits:
        ao, ad = por_id.get(k["src"]), por_id.get(k["dst"])
        k.setdefault("src_nombre", ao["nombre"] if ao else k["src"])
        k.setdefault("dst_nombre", ad["nombre"] if ad else k["dst"])
        k.setdefault("src_rol", ao["role"] if ao else "")
        k.setdefault("dst_rol", ad["role"] if ad else "")
        k.setdefault("src_zona", banda(ao) if ao else "")
        k.setdefault("dst_zona", banda(ad) if ad else "")
        k.setdefault("capturas", set(k.get("fuentes") or [imp.fuente]))


def _entorno_exportacion(args, imp, fuentes) -> dict:
    """Entorno de un analisis desde exportaciones: archivos de entrada con su SHA-256 (sin tshark)."""
    def _arch(rutas):
        return [{"archivo": Path(r).name, "sha256": sha256_archivo(Path(r))}
                for r in rutas if Path(r).is_file()]
    perfil = getattr(args, "perfil", None)
    uno = lambda r: (_arch([r]) or [None])[0] if r else None
    return {
        "modo": "exportacion", "plataforma": imp.fuente,
        "perfil": uno(perfil), "reglas_firewall": None,
        "vulnerabilidades": uno(args.vulnerabilidades), "alertas": uno(args.alertas),
        "kev": getattr(args, "kev_entrada", None), "tor_relays": getattr(args, "tor_entrada", None),
        "avisos_ics": getattr(args, "avisos_entrada", None),
        "catalogo_vulnerabilidades": uno(args.catalogo_vulnerabilidades),
        "ot_assess": __version__, "commit": commit_corto(), "tshark": NO_DISPONIBLE,
        "estandares": str(args.estandar), "max_packets": 0, "campos_ignorados": [],
        "capturas": [], "entradas": _arch([*args.activos, *args.enlaces]),
        **({"paquete_avisos": args.paquete_avisos_info} if getattr(args, "paquete_avisos_info", None) else {}),
    }


@salida_privada
def main(argv: list | None = None) -> int:
    ap = crear_parser()
    args = ap.parse_args(argv)
    perfil = aplicar_perfil(ap, args, {"titulo": "Diagramas de red OT",
                                       "cliente": "Analisis de inventario de planta",
                                       "estandar": "iec62443"})

    _pa.resolver(ap, args, perfil)       # AVK1 (D124)
    _entregables.avisos(perfil)          # ENT1 (D126)
    _registro.leer_opcion(ap, args, perfil)      # EVID2 (D127): antes de crear salidas
    _vconf.leer_opcion(ap, args, perfil)      # VCONF (D128): antes de crear salidas
    plan_vc = _vconf.de_args(args)
    for archivo in args.estandar_archivo:
        cargar_archivo(archivo)
    estandares = elegir(args.estandar)
    mapeo = cargar_mapeo(args.mapeo) if args.mapeo else None

    if args.cis_mapeo and not args.cis:
        ap.error("--cis-mapeo requiere --cis")
    for f in args.switch:
        if not Path(f).is_file():
            ap.error(f"--switch espera un archivo existente: '{f}'")
    if args.firewall_contadores and not args.firewall:
        ap.error("--firewall-contadores requiere --firewall")
    zonas = None
    if args.zonas_fw:
        if not args.firewall:
            ap.error("--zonas-fw requiere --firewall")
        try:
            zonas = _po.cargar_zonas(args.zonas_fw)
        except ValueError as e:
            ap.error(str(e))
    if args.agrupar == "interfaz" and not (args.rutas_firewall or args.firewall):
        ap.error("--agrupar interfaz requiere --rutas-firewall o --firewall")
    fuentes = _fu.separar(args.fuente_flujos, ap.error)
    texto_fuente = args.fuente
    if not args.enlaces and not fuentes:
        ap.error("falta --enlaces o al menos una --fuente-flujos NOMBRE=ARCHIVO")
    if args.linea_base and not Path(args.linea_base).is_dir():
        ap.error(f"--linea-base espera una carpeta existente: '{args.linea_base}'")
    from . import madurez as _ma
    respuestas_madurez = _ma.leer_opcion(ap, args.madurez)
    from . import csf_tiers as _ct
    declarados_tiers = _ct.leer_opcion(ap, args.csf_tiers)
    if args.inventario_manual and not Path(args.inventario_manual).is_file():
        ap.error(f"--inventario-manual espera un archivo existente: '{args.inventario_manual}'")
    if args.catalogo_vulnerabilidades and not Path(args.catalogo_vulnerabilidades).is_file():
        ap.error(f"--catalogo-vulnerabilidades espera un archivo existente: '{args.catalogo_vulnerabilidades}'")
    tabla_eos, avisos_eos = [], []
    if args.fin_de_soporte:
        if not Path(args.fin_de_soporte).is_file():
            ap.error(f"--fin-de-soporte espera un archivo existente: '{args.fin_de_soporte}'")
        tabla_eos, avisos_eos = _ob.cargar_analista(args.fin_de_soporte)
    imp = importar(args.activos, args.enlaces, args.formato, mapeo,
                   "auto" if args.agrupar == "interfaz" else args.agrupar, fuentes, args.tshark)
    propios = _in.Propios.de_perfil(perfil)
    _in.excluir_importacion(imp, propios)          # I1a: antes de conductos, zonas, politica y linea base
    r = imp.resumen
    print(f"[*] Plataforma: {imp.fuente}" + (" (deducida de las columnas)" if args.formato == "auto" else ""))
    print(f"    {r['activos']} activos, {r['conductos']} conductos; agrupado por "
          f"{'zona' if imp.agrupar == 'zona' else 'nivel Purdue'}")
    if r.get("periodo"):
        p = r["periodo"]
        print(f"    periodo de la exportacion: {p['desde']} a {p['hasta']} (hora local de la exportacion, "
              f"{p['zona']})")
    for tabla, m in imp.mapeos.items():
        if m:
            print(f"    columnas de {tabla}: " + ", ".join(f"{c}='{col}'" for c, col in m.items()))
    for adv in imp.advertencias:
        print(f"[!] {adv}")

    rutas: dict = {}
    reglas_fw: dict = {}
    if args.firewall:
        if args.rutas_firewall:
            print("[!] --firewall y --rutas-firewall a la vez: manda --firewall")
        rutas, reglas_fw = _fi.integrar(args.firewall, imp.assets, imp.conduits, zonas, args.firewall_contadores)
        for adv in reglas_fw["avisos"]:
            print(f"[!] {adv}")
        lin = _es.registrar(reglas_fw, (), imp.conduits)
        if lin:
            print(f"    {lin}")
    elif args.rutas_firewall:
        rutas = _rf.aplicar(args.rutas_firewall, imp.assets, imp.conduits)
    if rutas:
        print(f"    rutas de firewall: {rutas['rutas']} rutas, "
              f"{sum(1 for k in imp.conduits if k['cruza_firewall'])} conductos cruzan el firewall")
        for adv in rutas["avisos"]:
            print(f"[!] {adv}")
        if args.agrupar in ("auto", "interfaz"):
            imp.agrupar = "interfaz"
            print("    agrupado por interfaz del firewall")

    switches: dict = {}
    if args.switch:
        switches = _sw.integrar(args.switch, imp.assets)
        print(f"    switches: {len(switches['switches'])} leidos, {switches['ubicados']} de "
              f"{switches['con_mac']} activos con MAC ubicados, "
              f"{len(switches['sin_espejo'])} VLAN con equipos sin espejo SPAN")
        for adv in switches["avisos"]:
            print(f"[!] {adv}")

    zon = _zo.asignar(imp.assets, perfil, rutas, reglas_fw, zonas)
    for adv in zon["avisos"]:
        print(f"[!] {adv}")
    _ie.preparar(ap, args, perfil, [], imp.conduits, imp.assets)      # E62351F (D125)
    zcr = _zc.construir(imp.assets, imp.conduits, zon, reglas_fw)
    ra = _ra.construir(imp.assets, imp.conduits, zon, reglas_fw, perfil, zcr, args.origen_ataque,
                       args.objetivo_ataque)
    for adv in ra.get("avisos", ()):
        print(f"[!] {adv}")
    diagramas = build_all(imp.assets, imp.conduits, Opciones(
        max_nodos=args.diagram_max_nodes, max_aristas=args.diagram_max_edges, agrupar=imp.agrupar,
        origen="plataforma", estandar=estandares[0], titulo=args.titulo, cliente=args.cliente,
        fuente=texto_fuente or f"Datos de {imp.fuente}"))
    if not diagramas:
        print("[!] No se pudo armar ningun diagrama: ningun enlace une dos equipos distintos.")
        return 1

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    if not args.solo_diagramas:
        _completar(imp)
    res =Assessment([], imp.assets, imp.conduits, args, diagramas, estandares)
    res.rutas = rutas
    res.acceso_remoto = _ar.de_exportacion(f"exportacion {imp.fuente}", imp.dominios, imp.conduits, imp.assets)
    res.tor_relays = _ev.preparar(args)
    res.evasion = _ev.de_exportacion(f"exportacion {imp.fuente}", imp.dominios, imp.conduits, imp.assets,
                                     res.tor_relays)
    res.firewall = reglas_fw
    res.switches = switches
    res.zonas = zon
    res.zcr = zcr
    res.rutas_ataque = ra
    res.diagrama_zcr = diagrama_zcr(zcr, Opciones(
        estandar=estandares[0], titulo=args.titulo, cliente=args.cliente,
        fuente=texto_fuente or f"Datos de {imp.fuente}"))
    cob: dict = {}
    if imp.fuentes:
        cob = _fu.calcular(imp.conduits, imp.assets, imp.fuentes, _fu.segmentador(rutas, reglas_fw),
                           _sw.espejo_por_vlan(switches) if switches else None)
        res.fuentes = cob
        print(f"    fuentes de trafico: {', '.join(cob['nombres'])}; segmentos sin cobertura: "
              f"{len(cob['sin_cobertura'])}")
    multiple = _tp.es_multiple(reglas_fw)
    tablas_fw = [("zonas.csv", _zo.COLUMNAS, _zo.filas_tabla(zon))]
    tablas_fw += [(a, c, f) for a, _h, c, f in _sw.tablas(switches)]
    tablas_fw += [(a, cabecera_t(res, c), f) for a, _h, c, f in _ie.tablas_flujos(args)]      # E62351F (D125)
    if _zc.hay(zcr):
        tablas_fw.append((_zc.ARCHIVO, _zc.COLUMNAS, _zc.filas_tabla(zcr)))
    tablas_fw += [(a, c, f) for a, _h, c, f in _ra.tablas(ra)]
    if res.acceso_remoto:
        tablas_fw.append((_ar.ARCHIVO, _ar.COLUMNAS, _ar.filas(res)))
    if res.evasion:
        tablas_fw.append((_ev.ARCHIVO, _ev.COLUMNAS, _ev.filas(res)))
    if cob:
        tablas_fw += [("fuentes_resumen.csv", _fu.COL_RESUMEN, _fu.filas_resumen(cob)),
                      ("fuentes_cobertura.csv", _fu.COL_COBERTURA, cob["filas"])]
    if multiple:
        tablas_fw += [(a, c, f) for a, _h, c, f in _tp.tablas(reglas_fw)]
    elif reglas_fw:
        tablas_fw.append(("firewall_reglas.csv", _fi.COL_REGLAS, _fi.filas_reglas(reglas_fw)))
        if reglas_fw.get("rutas_estado"):
            tablas_fw.append(("firewall_rutas.csv", _fi.COL_RUTAS, _fi.filas_rutas(reglas_fw)))
    if _cr.hay(reglas_fw):
        tablas_fw += [("firewall_cruces.csv", _cr.columnas_agregado(reglas_fw["cruces"]),
                       _cr.filas_agregado(reglas_fw["cruces"])),
                      ("firewall_cruces_detalle.csv", _cr.columnas_detalle(reglas_fw["cruces"]),
                       _cr.filas_detalle(reglas_fw["cruces"]))]
    if _nt.hay(reglas_fw):
        tablas_fw.append(("firewall_nat.csv", _nt.columnas(reglas_fw["nat"]), _nt.filas_tabla(reglas_fw["nat"])))
    if _po.hay(reglas_fw):
        tablas_fw += [(a, c, f) for a, _h, c, f in _po.tablas(reglas_fw["politica"])]
    if _rp.hay(reglas_fw):
        tablas_fw += [(a, c, f) for a, _h, c, f in _rp.tablas(reglas_fw["rutas_propuestas"])]
    if rutas and not multiple:
        tablas_fw += [("firewall_interfaces.csv", _rf.COL_INTERFACES, _rf.filas_interfaces(rutas)),
                      ("firewall_matriz.csv", _rf.COL_MATRIZ, _rf.filas_matriz(rutas))]
    for archivo, cab, filas in tablas_fw:
        with open(out / archivo, "w", newline="", encoding="utf-8-sig") as fh:
            w = escritor_csv(fh)
            w.writerow(cab)
            w.writerows(filas)
    hallazgos = [(f"exportacion {imp.fuente}", f)
                 for f in evaluar_inventario(imp.assets, imp.conduits, imp.fuente)]
    if reglas_fw:
        extra = Capture(Path(f"firewall {reglas_fw['archivo']}"))
        _hg.agregar_hallazgos(extra, reglas_fw)
        hallazgos += [(extra.name, f) for f in extra.findings]
    if _sw.hay(switches):
        from .switches import higiene as _shg
        extra = Capture(Path("switches " + ", ".join(switches["archivos"])))
        _shg.agregar_hallazgos(extra, switches)
        hallazgos += [(extra.name, f) for f in extra.findings]
    res.salud_red = _sr.de_exportacion(imp.assets, imp.conduits, perfil)      # L1 (D81): sin series por minuto
    sw_sr = _sr.interfaces_switch(switches)
    if sw_sr:
        res.salud_red = {**(res.salud_red or {"origen": "exportacion", "exportacion": True}), "switch": sw_sr}
        extra = Capture(Path("salud de la red (switches)"))
        _sr.agregar_hallazgos(extra, res.salud_red)
        hallazgos += [(extra.name, f) for f in extra.findings]
    if _zc.hay(zcr):
        extra = Capture(Path("conductos entre zonas"))
        _zc.agregar_hallazgos(extra, zcr)
        hallazgos += [(extra.name, f) for f in extra.findings]
    if _ra.hay(ra):
        extra = Capture(Path("rutas de ataque"))
        _ra.agregar_hallazgos(extra, ra)
        hallazgos += [(extra.name, f) for f in extra.findings]
    if res.acceso_remoto:
        extra = Capture(Path(f"exportacion {imp.fuente}"))
        _hallazgo_ar(extra, res.acceso_remoto)
        hallazgos += [(extra.name, f) for f in extra.findings]
    if res.evasion:
        extra = Capture(Path(f"exportacion {imp.fuente}"))
        _hallazgo_ev(extra, res.evasion)
        hallazgos += [(extra.name, f) for f in extra.findings]
    if cob:
        extra = Capture(Path("fuentes de trafico"))
        _fu.agregar_hallazgo(extra, cob)
        hallazgos += [(extra.name, f) for f in extra.findings]
    vuln_resumen: dict = {}
    manual, avisos_manual = [], []
    if args.inventario_manual:
        manual, avisos_manual = _in.cargar_manual(args.inventario_manual, (mapeo or {}).get("manual"))
    vulns = cruces = inferidos = None
    fuente_cpe = ""
    if args.vulnerabilidades:
        vulns = _vu.cargar(args.vulnerabilidades, (perfil or {}).get("version_cvss", "3"))
        cruces = _vu.cruzar(vulns, imp.assets)
        inferidos, ambiguos = _vu.inferir_equipos(cruces)      # N2 (D101)
        fuente_cpe = "cpe " + Path(args.vulnerabilidades).name
        if ambiguos:
            print(f"[!] {_vu.aviso_cpe_ambiguo(ambiguos)}")
    registros = _in.registros_activos(imp.assets, (), imp.perfil, (imp.resumen.get("periodo") or {}).get("hasta", ""),
                                      reglas_fw, inferidos=inferidos, fuente_inferida=fuente_cpe)
    indice_vf = _vf.de_args(args, [*registros, *manual])        # V1a (D89)
    kev_cat, avisos = None, None
    if args.vulnerabilidades:
        nombre_v = Path(args.vulnerabilidades).name
        kev, avisos = _ac.preparar(args, vulns, visitante=indice_vf.visitar if indice_vf else None)
        kev_cat = kev
        _ac.anotar(cruces, kev, avisos)
        kev = _ac.kev_efectivo(cruces, kev)
        if _vu.aviso_sin_activo(cruces, nombre_v):
            print(f"[!] {_vu.aviso_sin_activo(cruces, nombre_v)}")
        extra = Capture(Path(f"vulnerabilidades {nombre_v}"))
        cruces_h = plan_vc.filtrar_cruces(cruces) if plan_vc else cruces      # VCONF (D128)
        _vu.agregar_hallazgo(extra, cruces_h, imp.assets)
        if kev:
            _ac.agregar_hallazgo_kev(extra, cruces_h, imp.assets, kev)
        hallazgos += [(extra.name, f) for f in extra.findings]
        vuln_resumen = {**_vu.resumen(cruces, nombre_v), **_ac.resumen_cisa(cruces, kev, avisos)}
        res.vulns_cruces = cruces
        res.vulnerabilidades = vuln_resumen
        crit_decl = (perfil or {}).get("criticidad_activos")
        if _vu.con_entorno(cruces, crit_decl):
            print(f"[i] {_ce.nota()}")
        with open(out / "vulnerabilidades.csv", "w", newline="", encoding="utf-8-sig") as fh:
            w = escritor_csv(fh)
            w.writerow(_vu.columnas(cruces, crit_decl, plan_vc))
            w.writerows(_vu.filas_tabla(cruces, imp.assets, crit_decl, plan_vc))
        if avisos and "avisos_ics" in res.vulnerabilidades and _ac.filas_avisos(cruces, imp.assets, (perfil or {}).get("version_cvss", "3")):
            with open(out / "avisos_ics.csv", "w", newline="", encoding="utf-8-sig") as fh:
                w = escritor_csv(fh)
                w.writerow(_ac.COLUMNAS_AVISOS)
                w.writerows(_ac.filas_avisos(cruces, imp.assets, (perfil or {}).get("version_cvss", "3")))
    else:
        _ac.preparar(args, None)
    if indice_vf:
        kev_cat, avisos = _vf.completar(indice_vf, args, kev_cat, avisos, bool(args.vulnerabilidades))
    alertas_resumen: dict = {}
    if args.alertas:
        nombre_a = Path(args.alertas).name
        asoc = _al.asociar(_al.cargar(args.alertas), imp.conduits, imp.assets)
        extra = Capture(Path(f"alertas {nombre_a}"))
        _al.agregar_hallazgo(extra, asoc, imp.assets)
        hallazgos += [(extra.name, f) for f in extra.findings]
        alertas_resumen = _al.resumen_completo(asoc, nombre_a)
        res.alertas_asoc = asoc
        res.alertas = alertas_resumen
        with open(out / "alertas.csv", "w", newline="", encoding="utf-8-sig") as fh:
            w = escritor_csv(fh)
            w.writerow(_al.COLUMNAS)
            w.writerows(_al.filas_tabla(asoc, imp.assets))
    res.inventario_normalizado = _in.construir([*registros, *manual], perfil, bool(args.inventario_manual), propios)
    if indice_vf:        # V1a (D89): despues del inventario normalizado
        res.vuln_firmware = _vf.construir(indice_vf, res.inventario_normalizado, res.vulns_cruces, imp.assets,
                                          kev_cat, avisos, (perfil or {}).get("version_cvss", "3"),
                                          (perfil or {}).get("criticidad_activos"), plan_vc)
        extra = Capture(Path("vulnerabilidades por firmware"))
        _vf.agregar_hallazgo(extra, plan_vc.filtrar_vf(res.vuln_firmware) if plan_vc else res.vuln_firmware)
        hallazgos += [(extra.name, f) for f in extra.findings]
    _vconf.preparar(args, res.vulns_cruces, imp.assets, res.vuln_firmware)      # VCONF (D128)
    ref, ref_origen = _ob.referencia_de((), (imp.resumen.get("periodo") or {}).get("hasta", ""))
    res.obsolescencia = _ob.construir(res.inventario_normalizado, tabla_eos, ref, ref_origen)
    extra = _ob.agregar_hallazgos([f for _o, f in hallazgos], res.obsolescencia)
    if extra:
        hallazgos += [(extra.name, f) for f in extra.findings]
    if args.linea_base:      # LB1 (D82)
        from . import linea_base_aprobada as _lba
        from .rules.linea_base_aprobada import agregar_hallazgos as _hl_lba
        res.linea_base_aprobada = _lba.evaluar_corrida(res, args.linea_base, [f for _o, f in hallazgos],
                                                       (perfil or {}).get("sitio", ""))
        extra = Capture(Path("linea base aprobada"))
        _hl_lba(extra, res.linea_base_aprobada)
        hallazgos += [(extra.name, f) for f in extra.findings]
        _lba.imprimir(res.linea_base_aprobada)
    hallazgos.sort(key=lambda x: SEV_ORDER.get(x[1]["severidad"], 9))
    por_origen: dict = {}
    for _o, f in hallazgos:
        por_origen.setdefault(f["captura"], []).append(f)
    for nombre, lista in por_origen.items():
        extra = Capture(Path("x"))
        extra.name = nombre
        extra.findings = lista
        res.extras.append(extra)
    origenes = [o for o, _f in hallazgos]
    hallazgos = [f for _o, f in hallazgos]
    res.perfil = perfil
    res.linea_base = _lb.construir(imp.assets, zon, zcr, reglas_fw, switches, hallazgos, perfil)
    if not res.linea_base:
        print("[!] linea base ISA/IEC 62443: no hay zonas, no se genera")
    cis, cis_mapeo = _cis.cargar_con_mapeos(args.cis, args.cis_mapeo) if args.cis else (None, None)
    res.matriz_controles = _mc.construir(imp.assets, zcr, reglas_fw, hallazgos, perfil, cis, cis_mapeo)
    res.tobe = _tb.construir(imp.assets, imp.conduits, zon, zcr, reglas_fw, hallazgos, perfil)    # T1a (D85)
    if _tb.aviso(res.tobe):
        print(_tb.aviso(res.tobe))
    res.hardening = _hd.construir(imp.assets, hallazgos, res.inventario_normalizado)      # T1b (D86)
    res.fuentes_log = _fl.construir(imp.assets, imp.conduits, hallazgos, res.inventario_normalizado,
                                    res.firewall)    # G1a (D87)
    res.direccionamiento = _dr.construir(imp.assets, zon, switches, res.inventario_normalizado, hallazgos)   # G1b (D88)
    res.diagrama_tobe = diagrama_tobe(res.tobe, Opciones(
        estandar=estandares[0], titulo=args.titulo, cliente=args.cliente,
        fuente=texto_fuente or f"Datos de {imp.fuente}"))
    archivos = write_diagrams(res, out)       # despues de los hallazgos: el TO-BE cita sus IDs
    res.madurez = _ma.construir(res, respuestas_madurez)       # M7 (D84)
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
              f"{x['conductos']} conductos")
    res.entorno = _entorno_exportacion(args, imp, fuentes)
    _registro.preparar(args, perfil, res.entorno)      # EVID2 (D127)
    pagina = write_pagina(diagramas, imp, estandares, out, args.titulo, args.cliente, perfil, hallazgos,
                          vuln_resumen, alertas_resumen, rutas, cob, zon, zcr, res.diagrama_zcr)

    with open(out / "hallazgos_importados.csv", "w", newline="", encoding="utf-8-sig") as fh:
        w = escritor_csv(fh)
        plan_ent = _entregables.plan(perfil)      # ENT1 (D126)
        w.writerow(cabecera_hallazgos(estandares, plan_ent))
        for o, f in zip(origenes, hallazgos):
            w.writerow(fila_hallazgo(o, f, estandares, plan_ent))

    con_nat = any(a.get("nat_nota") for a in imp.assets.values())     # D70: columna solo si hay marcas
    con_so = any(a.get("so") or a.get("protocolos") or a.get("vlans") for a in imp.assets.values())   # D74
    with open(out / "inventario_importado.csv", "w", newline="", encoding="utf-8-sig") as fh:
        w = escritor_csv(fh)
        w.writerow(["nombre", "ips", "id", "fabricante", "modelo", "firmware", "tipo", "nivel", "zona",
                    "interfaz_firewall", "zona_asignada", "origen_asignacion",
                    *(["switch_puerto", "vlan"] if switches else []), *(["nota_nat"] if con_nat else []),
                    *(["sistema_operativo", "protocolos", "vlans"] if con_so else [])])
        for a in sorted(imp.assets.values(), key=lambda x: x["nombre"]):
            w.writerow([a["nombre"], ";".join(sorted(a["ips"])), a["mac"], a["vendor"], a["modelo"],
                        a["firmware"], a["tipo_texto"], a["purdue"], a["zona"],
                        a.get("interfaz_firewall", ""), *_zo.columnas_activo(a),
                        *([a.get("switch_puerto", ""), a.get("vlan", "")] if switches else []),
                        *([a.get("nat_nota", "")] if con_nat else []),
                        *([a.get("so", ""), ";".join(sorted(a.get("protocolos") or ())),
                           ";".join(sorted(a["vlans"], key=int))] if con_so else [])])
    (out / "importacion.json").write_text(json.dumps({
        "plataforma": imp.fuente, "perfil": imp.perfil, "perfil_proyecto": perfil,"agrupar": imp.agrupar, "columnas": imp.mapeos,
        "resumen": r, "advertencias": imp.advertencias, "hallazgos": hallazgos,
        "vulnerabilidades": vuln_resumen, "alertas": alertas_resumen,
        **({"fuentes": {"archivos": imp.fuentes["archivos"], "resumen": imp.fuentes["resumen"],
                        "sin_cobertura": cob["sin_cobertura"]}} if cob else {})},
        indent=2, ensure_ascii=False), encoding="utf-8")

    if not args.solo_diagramas:
        print("[*] Escribiendo reportes...")
        paths = write_all(res, out, omitir=("diagramas",))
        _entregables.write_entregables(res, out)      # ENT1 (D126)
        print(f"     {paths['html']}\n     {paths['md']}")
        for n in ("informe_ot.docx", "reporte_ot.xlsx", "hallazgos.csv", "plan_remediacion.csv"):
            print(f"     {out / n}")

    print(f"\n[OK] {pagina}   <- pagina presentable con ambos diagramas")
    for p in archivos:
        print(f"     {p}")
    print(f"     {out / 'inventario_importado.csv'}\n     {out / 'hallazgos_importados.csv'}\n"
          f"     {out / 'importacion.json'}")
    return 0
