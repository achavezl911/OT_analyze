"""Reporte HTML autocontenido, presentable a cliente."""
from __future__ import annotations

import collections
from datetime import datetime
from html import escape as esc
from pathlib import Path

from .. import __version__
from .. import alertas as _al
from .. import cobertura as _cobertura
from .. import cobertura_captura as _cc
from .. import conductos_zcr as _zc
from .. import direccionamiento as _dr
from .. import entorno as _entorno
from .. import firewall as _firewall
from .. import fuentes as _fu
from .. import fuentes_log as _fl
from .. import hardening as _hd
from .. import inventario_normalizado as _in
from .. import inventario_presentado as _ip
from .. import linea_base as _lb
from .. import linea_base_aprobada as _lba
from .. import madurez as _ma
from .. import matriz_controles as _mc
from .. import obsolescencia as _ob
from .. import perfil as _perfil
from .. import playbooks as _pb
from .. import registros_dns as _rd
from .. import remediacion as _rem
from .. import riesgo as _rg
from .. import rutas_ataque as _ra
from .. import rutas_firewall as _rf
from .. import salud_red as _sr
from .. import sensores as _se
from .. import tobe as _tb
from .. import vuln_firmware as _vf
from .. import vulnerabilidades as _vuln
from .. import zonas as _zo
from ..firewalls import cruces as _cr
from ..firewalls import integracion as _fi
from ..firewalls import politica as _po
from ..firewalls import rutas_propuestas as _rp
from ..firewalls import topologia as _tp
from ..i18n import idioma as _idioma
from ..i18n import t
from ..model import Assessment
from ..roles import mostrar as mostrar_rol
from ..standards import ESTANDARES
from ..standards import avisos as _avisos
from ..switches import integracion as _sw
from ..texts import client_questions, verify_with_client, vis_checks
from ..util import human, human_duration, port_info
from .common import (
    Numerador,
    agrupar_hallazgos,
    crit_tag,
    filas_fuentes,
    referencias_visibles,
)
from .style import HTML_CSS
from .validacion import cuerpo as cuerpo_validacion


def flujos_fw(a, rutas: dict, conductos: list) -> None:
    """Seccion 'Flujos entre interfaces del firewall' (XD-c); tambien la usa la pagina de diagrama."""
    s = _rf.seccion(rutas, conductos)
    a("<h2>" + esc(t("Flujos entre interfaces del firewall")) + "</h2>")
    a(f'<div class="nota">{esc(t(_rf.NOTA))}</div>')
    a(f"<p>{esc(s['resumen'])}</p>")
    for aviso in s["avisos"]:
        a(f'<div class="nota">{esc(aviso)}</div>')
    for cab, filas in ((s["cab_matriz"], s["matriz"]), (s["cab_interfaces"], s["interfaces"])):
        a("<table><thead><tr>" + "".join(f"<th>{esc(c)}</th>" for c in cab) + "</tr></thead><tbody>")
        for fila in filas:
            a("<tr>" + "".join(f"<td>{esc(str(c))}</td>" for c in fila) + "</tr>")
        a("</tbody></table>")
        if s["mas"] and cab is s["cab_matriz"]:
            a(f'<div class="nota">{esc(s["mas"])}</div>')


def fuentes_html(a, cob: dict) -> None:
    """Seccion 'Fuentes de trafico' (M2); tambien la usa la pagina de diagrama."""
    a("<h2>" + esc(t(_fu.TITULO)) + "</h2>")
    a(f'<div class="nota">{esc(t(_fu.NOTA))}</div>')
    a(f"<p>{esc(_fu.resumen_texto(cob))}</p>")
    cab = _fu.cabecera_resumen()
    a("<table><thead><tr>" + "".join(f"<th>{esc(c)}</th>" for c in cab) + "</tr></thead><tbody>")
    for fila in _fu.filas_resumen(cob):
        a("<tr>" + "".join(f"<td>{esc(str(c))}</td>" for c in fila) + "</tr>")
    a("</tbody></table>")


def _ths(cabs, num: bool = False) -> str:
    """Celdas de encabezado traducidas."""
    cls = ' class="num"' if num else ""
    return "".join(f"<th{cls}>{esc(t(c))}</th>" for c in cabs)


def _nada(_texto) -> None:
    """Escritor que descarta: omite una seccion que no aplica sin sangrar su codigo."""


def write_html(res: Assessment, outdir: Path) -> Path:
    caps, conduits, args = res.caps, res.conduits, res.args
    filas_inv = _ip.filas(res)      # I3 (D105): una fila por IP para las MAC de enrutamiento
    estandares = res.estandares or [ESTANDARES["iec62443"]]
    principal = estandares[0]
    now = datetime.now().astimezone().strftime("%d/%m/%Y %H:%M")
    findings = [f for c in [*caps, *res.extras] for f in c.findings]
    by_sev = collections.Counter(f["severidad"] for f in findings)
    h: list[str] = []
    a = h.append
    num = Numerador()

    a(f'<!doctype html><html lang="{_idioma()}"><head><meta charset="utf-8">')
    a("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">")
    a(f"<title>{esc(args.titulo)}</title><style>{HTML_CSS}</style></head><body>")
    a('<header class="port"><div class="inner">')
    a(f"<h1>{esc(args.titulo)}</h1>")
    a(f"<p>{esc(args.cliente)} &middot; "
      f"{esc(t('Analisis pasivo de trafico de red' if caps else 'Analisis de exportaciones de plataformas'))} "
      f"&middot; {esc(t('Generado el {now}', now=now))}</p>")
    a("</div></header><div class=\"wrap\">")
    if res.perfil:
        a("<h2>" + esc(t("Perfil del proyecto")) + "</h2><table><tbody>")
        for k, v in _perfil.etiquetas(res.perfil):
            a(f"<tr><th>{esc(k)}</th><td>{esc(v)}</td></tr>")
        a(f"</tbody></table><p>{esc(t(_perfil.NOTA))}</p>")
    if _cc.hay(res.cobertura_captura):      # C1 (D80): al inicio, antes del resumen
        a(cuerpo_validacion(res.cobertura_captura))

    # ---------------- resumen ---------------- #
    ot_conduits = [c for c in conduits if c["categoria"] == "ot"]
    ctl_conduits = [c for c in conduits if c["escrituras"]]
    cross = [c for c in conduits if c["cruza_zona"]]
    a("<h2>" + esc(t("Resumen")) + "</h2>")
    a('<div class="kpis">')
    for n, l in (
        (len(filas_inv), "Activos"),
        (len(conduits), "Conductos"),
        (len(ot_conduits), "Conductos OT"),
        (len(ctl_conduits), "Con escritura"),
        *(((len(caps), "Capturas"), (sum(c.flow_packets for c in caps), "Paquetes")) if caps else ()),
    ):
        a(f'<div class="kpi"><div class="n">{n:,}</div><div class="l">{esc(t(l))}</div></div>')
    a("</div>")
    a('<div class="kpis">')
    for sev, rot in (("Alta", "Hallazgo alta"), ("Media", "Hallazgo media"),
                     ("Baja", "Hallazgo baja"), ("Informativa", "Hallazgo informativa")):
        a(f'<div class="kpi"><div class="n">{by_sev.get(sev, 0)}</div>'
          f'<div class="l">{esc(t(rot))}</div></div>')
    a("</div>")
    if caps:
        a('<div class="nota">' + esc(t(
            "Todo lo que sigue proviene exclusivamente del analisis "
            "pasivo de las capturas entregadas. No se genero trafico hacia la red del "
            "cliente. Los roles y zonas son inferidos del comportamiento observado y "
            "deben validarse con el personal de planta.")) + "</div>")
    else:
        a("<h3>" + esc(t("Fuentes")) + "</h3><table><tbody>")
        for k, v in filas_fuentes(res):
            a(f"<tr><th>{esc(k)}</th><td>{esc(v)}</td></tr>")
        a("</tbody></table>")
        a('<div class="nota">' + esc(t(
            "Todo lo que sigue proviene de las exportaciones entregadas, sin capturas. No se "
            "genero trafico hacia la red del cliente. Los roles y zonas dependen de lo que la "
            "plataforma exporto o se infieren del tipo de equipo, y deben validarse con el "
            "personal de planta.")) + "</div>")

    # ---------------- inventario ---------------- #
    a("<h2>" + esc(num("1. Inventario de activos", a is not _nada)) + "</h2>")
    a('<p class="lead">' + esc(t(
        "Equipos identificados en las capturas, consolidados entre "
        "todos los puntos de monitoreo. Modelo y firmware provienen de los anuncios "
        "de descubrimiento (CDP, LLDP) y de los banners de servicio.") if caps else t(
        "Equipos del inventario exportado, con los datos que la plataforma entrego.")) + "</p>")
    a('<div class="tbl"><table><thead><tr><th>#</th>' + _ths(
        ("Equipo", "Direccion IP", "MAC", "Fabricante", "Modelo / descripcion", "Firmware",
         "Rol inferido", "Zona", "VLAN")) + _ths(("Paquetes",), True) + "</tr></thead><tbody>")
    rows = filas_inv
    for i, ast in enumerate(rows, 1):
        a("<tr>"
          f"<td class=\"num\">{i}</td>"
          f"<td><strong>{esc(ast['nombre'])}</strong></td>"
          f"<td class=\"mono\">{esc(', '.join(sorted(ast['ips'])[:3]) or '—')}</td>"
          f"<td class=\"mono\">{esc(_ip.mac_mostrada(ast))}</td>"
          f"<td>{esc(ast['vendor'] or '—')}</td>"
          f"<td>{esc(ast.get('modelo') or '—')}</td>"
          f"<td class=\"mono\">{esc(ast.get('firmware') or '—')}</td>"
          f"<td>{esc(mostrar_rol(ast['role']) if ast['role'] else t('Indeterminado'))}</td>"
          f"<td>{esc(mostrar_rol(ast['purdue']) or '—')}</td>"
          f"<td>{esc(', '.join(sorted(ast['vlans'])) or '—')}</td>"
          f"<td class=\"num\">{ast['pkts']:,}</td></tr>")
    a("</tbody></table></div>")
    if _ip.hay_partidas(rows):
        a(f'<div class="nota">{esc(_ip.nota())}</div>')

    con_fw = [x for x in rows if x.get("firmware")]
    a('<div class="nota">' + t(
        "<strong>{n} de {total}</strong> activos "
        "revelaron version de firmware de forma pasiva. Solo sobre esos puede un "
        "motor de vulnerabilidades hacer correspondencia con su base de CVEs; para "
        "el resto haria falta sondeo activo o inventario manual.",
        n=len(con_fw), total=len(rows)) + "</div>")

    if _zo.hay(res.zonas):
        a("<h3>" + esc(t(_zo.TITULO)) + "</h3>")
        a(f'<div class="nota">{esc(t(_zo.NOTA))}</div>')
        zon = _zo.presentada(res.zonas, filas_inv)
        if _zo.nota_partidas(zon):
            a(f'<div class="nota">{esc(_zo.nota_partidas(zon))}</div>')
        a(f'<p>{esc(_zo.resumen_texto(zon))}</p>')
        cab, filas = _zo.tabla_reporte(zon)
        a('<div class="tbl"><table><thead><tr>' + "".join(f"<th>{esc(c)}</th>" for c in cab)
          + "</tr></thead><tbody>")
        for fila in filas[: args.max_rows]:
            a("<tr>" + "".join(f"<td>{esc(str(c))}</td>" for c in fila) + "</tr>")
        a("</tbody></table></div>")
    if _in.hay(res.inventario_normalizado):
        s = _in.seccion(res.inventario_normalizado)
        a("<h3>" + esc(s["titulo"]) + "</h3>")
        a(f'<div class="nota">{esc(s["nota"])}</div>')
        a(f'<p>{esc(s["resumen"])}</p>')
        cab, filas = s["tabla"]
        a('<div class="tbl"><table><thead><tr>' + "".join(f"<th>{esc(c)}</th>" for c in cab) + "</tr></thead><tbody>")
        for fila in filas:
            a("<tr>" + "".join(f"<td>{esc(str(c))}</td>" for c in fila) + "</tr>")
        a("</tbody></table></div>")
    if _ob.hay(res.obsolescencia):
        s = _ob.seccion(res.obsolescencia)
        a("<h3>" + esc(s["titulo"]) + "</h3>")
        a(f'<div class="nota">{esc(s["nota"])}</div>')
        a(f'<p>{esc(s["resumen"])}</p>')
        cab, filas = s["tabla"]
        a('<div class="tbl"><table><thead><tr>' + "".join(f"<th>{esc(c)}</th>" for c in cab) + "</tr></thead><tbody>")
        for fila in filas:
            a("<tr>" + "".join(f"<td>{esc(str(c))}</td>" for c in fila) + "</tr>")
        a("</tbody></table></div>")
    if _zc.hay(res.zcr):
        a("<h3>" + esc(t(_zc.TITULO)) + "</h3>")
        a(f'<div class="nota">{esc(t(_zc.NOTA))}</div>')
        a(f'<p>{esc(_zc.resumen_texto(res.zcr))}</p>')
        cab, filas = _zc.tabla_reporte(res.zcr)
        a('<div class="tbl"><table><thead><tr>' + "".join(f"<th>{esc(c)}</th>" for c in cab)
          + "</tr></thead><tbody>")
        for fila in filas:
            a("<tr>" + "".join(f"<td>{esc(str(c))}</td>" for c in fila) + "</tr>")
        a("</tbody></table></div>")
        if res.diagrama_zcr:
            a(f'<div class="diagrama">{res.diagrama_zcr.svg}</div>')
            if res.diagrama_zcr.nota:
                a(f'<div class="nota">{esc(res.diagrama_zcr.nota)}</div>')
    if _tb.hay(res.tobe):       # T1a (D85)
        s = _tb.seccion(res.tobe)
        a("<h3>" + esc(s["titulo"]) + "</h3>")
        a(f'<div class="nota">{esc(s["nota"])}</div>')
        a(f'<p>{esc(s["resumen"])}</p>')
        for cab, filas in ((s["cab_matriz"], s["matriz"]), (s["cab"], s["filas"])):
            a('<div class="tbl"><table><thead><tr>' + "".join(f"<th>{esc(c)}</th>" for c in cab)
              + "</tr></thead><tbody>")
            for fila in filas:
                a("<tr>" + "".join(f"<td>{esc(str(c))}</td>" for c in fila) + "</tr>")
            a("</tbody></table></div>")
            if cab is s["cab_matriz"]:
                a(f'<p class="nota">{esc(s["leyenda"])}</p>')
        if s["mas"]:
            a(f'<p>{esc(s["mas"])}</p>')
        if res.diagrama_tobe:
            a(f'<div class="diagrama">{res.diagrama_tobe.svg}</div>')
            a(f'<div class="nota">{esc(res.diagrama_tobe.nota)}</div>')
    elif _tb.hay_seccion(res.tobe):
        s = _tb.seccion_vacia(res.tobe)
        a("<h3>" + esc(s["titulo"]) + "</h3>")
        a(f'<p>{esc(s["texto"])}</p>')
        if s["nota"]:
            a(f'<div class="nota">{esc(s["nota"])}</div>')
    if _hd.hay(res.hardening):       # T1b (D86)
        s = _hd.seccion(res.hardening)
        a("<h3>" + esc(s["titulo"]) + "</h3>")
        a(f'<div class="nota">{esc(s["nota"])}</div>')
        a(f'<p>{esc(s["resumen"])}</p>')
        for cab, filas in ((s["cab_tipos"], s["tipos"]), (s["cab_top"], s["top"])):
            if cab is s["cab_top"]:
                if not filas:
                    a(f'<p>{esc(s["sin_top"])}</p>')
                    continue
                a("<h4>" + esc(s["titulo_top"]) + "</h4>")
            a('<div class="tbl"><table><thead><tr>' + "".join(f"<th>{esc(c)}</th>" for c in cab)
              + "</tr></thead><tbody>")
            for fila in filas:
                a("<tr>" + "".join(f"<td>{esc(str(c))}</td>" for c in fila) + "</tr>")
            a("</tbody></table></div>")
    if _vf.hay(res.vuln_firmware):     # V1a (D89)
        s = _vf.seccion(res.vuln_firmware)
        a("<h3>" + esc(s["titulo"]) + "</h3>")
        a(f'<div class="nota">{esc(s["nota"])}</div>')
        a(f'<p>{esc(s["resumen"])}</p>')
        cab, filas = s["tabla"]
        if filas:
            a('<div class="tbl"><table><thead><tr>' + "".join(f"<th>{esc(c)}</th>" for c in cab)
              + "</tr></thead><tbody>")
            for fila in filas:
                a("<tr>" + "".join(f"<td>{esc(str(c))}</td>" for c in fila) + "</tr>")
            a("</tbody></table></div>")
        for texto in (s["mas"], s["vacio"]):
            if texto:
                a(f"<p>{esc(texto)}</p>")
    if _fl.hay(res.fuentes_log):       # G1a (D87)
        s = _fl.seccion(res.fuentes_log)
        a("<h3>" + esc(s["titulo"]) + "</h3>")
        a(f'<div class="nota">{esc(s["nota"])}</div>')
        a(f'<p>{esc(s["resumen"])}</p>')
        for cab, filas in ((s["cab_tipos"], s["tipos"]), (s["cab_colectores"], s["colectores"])):
            if not filas:
                continue
            a('<div class="tbl"><table><thead><tr>' + "".join(f"<th>{esc(c)}</th>" for c in cab)
              + "</tr></thead><tbody>")
            for fila in filas:
                a("<tr>" + "".join(f"<td>{esc(str(c))}</td>" for c in fila) + "</tr>")
            a("</tbody></table></div>")
        for texto in (s["mas"], s["vacio"]):
            if texto:
                a(f'<p>{esc(texto)}</p>')
    if _dr.hay(res.direccionamiento):       # G1b (D88)
        s = _dr.seccion(res.direccionamiento)
        a("<h3>" + esc(s["titulo"]) + "</h3>")
        a(f'<div class="nota">{esc(s["nota"])}</div>')
        a(f'<p>{esc(s["resumen"])}</p>')
        for cab, filas in ((s["cab_redes"], s["redes"]), (s["cab_obs"], s["observaciones"])):
            if not filas:
                continue
            a('<div class="tbl"><table><thead><tr>' + "".join(f"<th>{esc(c)}</th>" for c in cab)
              + "</tr></thead><tbody>")
            for fila in filas:
                a("<tr>" + "".join(f"<td>{esc(str(c))}</td>" for c in fila) + "</tr>")
            a("</tbody></table></div>")
        if s["mas"]:
            a(f'<p>{esc(s["mas"])}</p>')
    if _lb.hay(res.linea_base):
        s = _lb.seccion(res.linea_base)
        a("<h3>" + esc(s["titulo"]) + "</h3>")
        a(f'<div class="nota">{esc(s["nota"])}</div>')
        a(f'<p>{esc(s["resumen"])}</p>')
        for cab, filas in (s["pivote"], s["top"]):
            a('<div class="tbl"><table><thead><tr>' + "".join(f"<th>{esc(c)}</th>" for c in cab)
              + "</tr></thead><tbody>")
            for fila in filas:
                a("<tr>" + "".join(f"<td>{esc(str(c))}</td>" for c in fila) + "</tr>")
            a("</tbody></table></div>")
        a(f'<div class="nota">{esc(s["nota_cota"])}</div>')
    if _mc.hay(res.matriz_controles):
        s = _mc.seccion(res.matriz_controles, res.linea_base)
        a("<h3>" + esc(s["titulo"]) + "</h3>")
        a(f'<div class="nota">{esc(s["nota"])}</div>')
        a(f'<p>{esc(s["resumen"])}</p>')
        cab, filas = s["tabla"]
        a('<div class="tbl"><table><thead><tr>' + "".join(f"<th>{esc(c)}</th>" for c in cab) + "</tr></thead><tbody>")
        for fila in filas:
            a("<tr>" + "".join(f"<td>{esc(str(c))}</td>" for c in fila) + "</tr>")
        a("</tbody></table></div>")
    if _sr.hay(res.salud_red):
        s = _sr.seccion(res.salud_red)
        a("<h3>" + esc(s["titulo"]) + "</h3>")
        a(f'<div class="nota">{esc(s["nota"])}</div>')
        a(f'<p>{esc(s["resumen"])}</p>')
        for titulo, cab, filas in s["tablas"]:
            a("<h4>" + esc(titulo) + "</h4>")
            a('<div class="tbl"><table><thead><tr>' + "".join(f"<th>{esc(c)}</th>" for c in cab)
              + "</tr></thead><tbody>")
            for fila in filas:
                a("<tr>" + "".join(f"<td>{esc(str(c))}</td>" for c in fila) + "</tr>")
            a("</tbody></table></div>")
    if _se.hay(res.sensores):
        s = _se.seccion(res.sensores)
        a("<h3>" + esc(s["titulo"]) + "</h3>")
        a(f'<div class="nota">{esc(s["nota"])}</div>')
        a(f'<p>{esc(s["resumen"])}</p>')
        for titulo, cab, filas in s["tablas"]:
            a("<h4>" + esc(titulo) + "</h4>")
            a('<div class="tbl"><table><thead><tr>' + "".join(f"<th>{esc(c)}</th>" for c in cab)
              + "</tr></thead><tbody>")
            for fila in filas:
                a("<tr>" + "".join(f"<td>{esc(str(c))}</td>" for c in fila) + "</tr>")
            a("</tbody></table></div>")
    if _lba.hay(res.linea_base_aprobada):
        s = _lba.seccion(res.linea_base_aprobada)
        a("<h3>" + esc(s["titulo"]) + "</h3>")
        a(f'<div class="nota">{esc(s["nota"])}</div>')
        a(f'<p>{esc(s["resumen"])}</p>')
        for titulo, cab, filas in s["tablas"]:
            a("<h4>" + esc(titulo) + "</h4>")
            a('<div class="tbl"><table><thead><tr>' + "".join(f"<th>{esc(c)}</th>" for c in cab)
              + "</tr></thead><tbody>")
            for fila in filas:
                a("<tr>" + "".join(f"<td>{esc(str(c))}</td>" for c in fila) + "</tr>")
            a("</tbody></table></div>")
    if _ra.hay(res.rutas_ataque):
        a("<h3>" + esc(t(_ra.TITULO)) + "</h3>")
        a(f'<div class="nota">{esc(t(_ra.NOTA))}</div>')
        a(f'<p>{esc(_ra.resumen_texto(res.rutas_ataque))}</p>')
        for cab, filas in (_ra.tabla_caminos(res.rutas_ataque), _ra.tabla_puntos(res.rutas_ataque)):
            a('<div class="tbl"><table><thead><tr>' + "".join(f"<th>{esc(c)}</th>" for c in cab)
              + "</tr></thead><tbody>")
            for fila in filas:
                a("<tr>" + "".join(f"<td>{esc(str(c))}</td>" for c in fila) + "</tr>")
            a("</tbody></table></div>")

    # ---------------- matriz de comunicaciones ---------------- #
    a("<h2>" + esc(num("2. Matriz de comunicaciones", a is not _nada)) + "</h2>")
    a('<p class="lead">' + esc(t(
        "Cada renglon es una relacion de comunicacion observada: "
        "un origen, un destino y un servicio. La criticidad combina el tipo de "
        "servicio, si cruza zonas y si transporta operaciones de escritura.")) + "</p>")
    for d in res.diagrams:
        a(f"<h3>{esc(d.titulo)}</h3>")
        a(f'<p class="lead">{esc(d.descripcion)}</p>')
        a(f'<div class="diagrama">{d.svg}</div>')
        if d.nota:
            a(f'<div class="nota">{esc(d.nota)}</div>')
    if res.diagrams:
        a("<h3>" + esc(t("Detalle de conductos")) + "</h3>")
    a('<div class="tbl"><table><thead><tr><th>#</th>'
      + _ths(("Origen", "Zona", "Destino", "Zona", "Servicio", "Puerto", "Sentido"))
      + _ths(("Paquetes", "Volumen", "Escrituras"), True) + _ths(("Criticidad",))
      + "</tr></thead><tbody>")

    nombres_dns = _rd.nombre_de_ip(res)

    def celda(nombre: str, ip: str, dns: bool = False) -> str:
        """Evita repetir la IP cuando el equipo no tiene nombre propio."""
        extra = nombres_dns.get(ip, "") if dns else ""
        extra = f'<br><span style="font-size:.8em">{esc(extra)}</span>' if extra else ""
        if nombre == ip:
            return f'<td class="mono">{esc(ip)}{extra}</td>'
        return (f"<td><strong>{esc(nombre)}</strong><br>"
                f'<span class="mono">{esc(ip)}</span>{extra}</td>')

    for i, k in enumerate(conduits[: args.max_rows], 1):
        cruza = ' <span class="cruza">&#8594;</span>' if k["cruza_zona"] else ""
        a("<tr>"
          f"<td class=\"num\">{i}</td>"
          f"{celda(k['src_nombre'], k['src'])}"
          f"<td>{esc(mostrar_rol(k['src_zona']) or '—')}{cruza}</td>"
          f"{celda(k['dst_nombre'], k['dst'], True)}"
          f"<td>{esc(mostrar_rol(k['dst_zona']) or '—')}</td>"
          f"<td>{esc(k['servicio'])}</td>"
          f"<td class=\"mono\">{esc(k['l4'])}/{esc(k['port'] or '—')}</td>"
          f"<td>{t('bidireccional') if k['bidireccional'] else t('unidireccional')}</td>"
          f"<td class=\"num\">{k['pkts']:,}</td>"
          f"<td class=\"num\">{human(k['bytes'])}</td>"
          f"<td class=\"num\">{format(k['escrituras'], ',') if k['escrituras'] else '—'}</td>"
          f"<td>{crit_tag(k['criticidad'])}</td></tr>")
    a("</tbody></table></div>")
    if len(conduits) > args.max_rows:
        a('<div class="nota">' + t(
            "Se muestran los {max} conductos de mayor "
            "criticidad y volumen. Los {resto} restantes "
            "estan en <code>comunicaciones.csv</code>.",
            max=args.max_rows, resto=len(conduits) - args.max_rows) + "</div>")
    if cross:
        a('<div class="nota">' + t(
            "<strong>{n} conductos cruzan zonas.</strong> "
            "Son los candidatos naturales a control por firewall OT segun el modelo "
            "{modelo}.", n=len(cross), modelo=esc(t(principal.cruce))) + "</div>")

    # ---------------- rejilla ---------------- #
    srcs = sorted({k["src_nombre"] for k in conduits})
    dsts = sorted({k["dst_nombre"] for k in conduits})
    if len(srcs) <= 30 and len(dsts) <= 30:
        cell: dict[tuple, dict] = {}
        for k in conduits:
            c0 = cell.setdefault((k["src_nombre"], k["dst_nombre"]),
                                 {"svc": set(), "ctl": 0})
            c0["svc"].add(k["servicio"])
            c0["ctl"] += k["escrituras"]
        a("<h3>" + esc(t("Vista de rejilla")) + "</h3>")
        a('<p class="lead">' + esc(t(
            "Filas: origen. Columnas: destino. En rojo, las "
            "relaciones que transportan escrituras al proceso.")) + "</p>")
        a('<div class="grid-matrix"><table><thead><tr><th class="row">'
          + esc(t("Origen \\ Destino")) + "</th>")
        for d in dsts:
            a(f'<th class="v">{esc(d)}</th>')
        a("</tr></thead><tbody>")
        for s in srcs:
            a(f'<tr><th class="row">{esc(s)}</th>')
            for d in dsts:
                c0 = cell.get((s, d))
                if not c0:
                    a("<td></td>")
                elif c0["ctl"]:
                    a(f'<td class="ctl" title="{esc(", ".join(sorted(c0["svc"])))}">W</td>')
                else:
                    a(f'<td class="on" title="{esc(", ".join(sorted(c0["svc"])))}">&bull;</td>')
            a("</tr>")
        a("</tbody></table></div>")

    # ---------------- hallazgos ---------------- #
    a("<h2>" + esc(num("3. Hallazgos", a is not _nada)) + "</h2>")
    avisos = _avisos(estandares)
    if avisos:
        a(f'<div class="nota">{esc(" ".join(avisos))}</div>')
    ordered = agrupar_hallazgos([*caps, *res.extras])
    for i, f in enumerate(ordered, 1):
        a(f'<div class="finding s-{f["severidad"].lower()}">')
        a(f'<h4>{i}. {esc(t(f["titulo"]))} {crit_tag(f["severidad"])} '
          f'<span class="id-hallazgo">{esc(f["id"])}</span></h4>')
        a(f'<div class="meta">{esc(t(f["categoria"]))} &middot; '
          f'{esc(", ".join(sorted(set(f["capturas"]))))}</div>')
        a(f'<div class="ev">{esc(t(f["evidencia"]))}</div>')
        a("<dl>")
        a(f"<dt>{esc(t('Por que importa'))}</dt><dd>{esc(t(f['por_que_importa']))}</dd>")
        a(f"<dt>{esc(t('Recomendacion'))}</dt><dd>{esc(t(f['recomendacion']))}</dd>")
        refs = referencias_visibles(f, estandares)
        if refs:
            a("<dt>" + esc(t("Referencias")) + "</dt><dd>"
              + " &middot; ".join(f"{esc(n)}: {esc(t)}" for n, t in refs) + "</dd>")
        a("</dl></div>")

    # ---------------- resolucion de nombres (DNS) ---------------- #
    # Sin capturas no hay trafico DNS ni brecha de visibilidad: esas secciones se omiten.
    if not caps:
        a = _nada
    a("<h2>" + esc(t("Resolucion de nombres (DNS)")) + "</h2>")
    sd = _rd.seccion(res)
    if sd is None:
        a(f"<p>{esc(t(_rd.SIN_DNS))}</p>")
    else:
        def tabla_dns(cab, filas):
            a("<table><thead><tr>" + "".join(f"<th>{esc(c)}</th>" for c in cab)
              + "</tr></thead><tbody>")
            for fila in filas:
                a("<tr>" + "".join(f"<td>{esc(str(c))}</td>" for c in fila) + "</tr>")
            a("</tbody></table>")
        a(f"<p>{esc(sd['resumen'])}</p>")
        tabla_dns(sd["cab_nombres"], sd["nombres"])
        if sd["mas"]:
            a(f'<div class="nota">{esc(t(_rd.NOTA_MAS))}</div>')
        tabla_dns(sd["cab_servidores"], sd["servidores"])
    a = h.append
    if res.rutas and not res.firewall:
        flujos_fw(a, res.rutas, conduits)

    # ---------------- plan de remediacion ---------------- #
    pr = _rem.resumen(res)
    a("<h2>" + esc(t("Plan de remediacion")) + "</h2>")
    a(f'<div class="nota">{esc(t(_rem.NOTA))}</div>')
    if pr["filas"]:
        a("<p>" + esc("; ".join(f"{k}: {v}" for k, v in pr["conteo"].items())) + ".</p>")
        a("<table><thead><tr>" + "".join(f"<th>{esc(t(c))}</th>" for c in _rem.CAB_REPORTE)
          + "</tr></thead><tbody>")
        for fila in pr["filas"]:
            a("<tr>" + "".join(f"<td>{esc(str(c))}</td>" for c in fila) + "</tr>")
        a("</tbody></table>")
        a(f"<p>{esc(t(_rem.NOTA_ESFUERZO))}</p>")
    else:
        a(f"<p>{esc(t(_rem.SIN_PRIORIZAR))}</p>")
    if pr["playbooks"]:
        a("<h2>" + esc(t(_pb.TITULO)) + "</h2>")
        a(f'<div class="nota">{esc(t(_pb.NOTA))}</div>')
        for pb in pr["playbooks"]:
            a(f"<h3>{esc(pb['titulo'])} ({esc(pb['id'])})</h3>")
            for etiqueta, items, ordenada in pb["bloques"]:
                tag = "ol" if ordenada else "ul"
                a(f"<p><strong>{esc(etiqueta)}</strong></p><{tag}>"
                  + "".join(f"<li>{esc(x)}</li>" for x in items) + f"</{tag}>")

    # ---------------- registro de riesgos (R1, D83) ---------------- #
    rs = _rg.seccion(_rg.de(res))
    a("<h2>" + esc(rs["titulo"]) + "</h2>")
    a(f'<div class="nota">{esc(rs["nota"])}</div>')
    if rs["vacia"]:
        a(f"<p>{esc(rs['vacia'])}</p>")
    else:
        cab, filas, niveles = rs["mapa"]
        a(f"<p>{esc(rs['resumen'])}</p>")
        a('<table class="mapa-calor"><thead><tr>' + "".join(f"<th>{esc(str(c))}</th>" for c in cab)
          + "</tr></thead><tbody>")
        for fila, niv in zip(filas, niveles):
            a(f"<tr><th>{esc(fila[0])}</th>"
              + "".join(f'<td class="{_rg.CLASES[n]}" title="{esc(t(n))}">{c}</td>'
                        for c, n in zip(fila[1:], niv[1:])) + "</tr>")
        a("</tbody></table>")
        a("<table><thead><tr>" + "".join(f"<th>{esc(str(c))}</th>" for c in rs["cab_top"]) + "</tr></thead><tbody>")
        for fila in rs["top"]:
            a("<tr>" + "".join(f"<td>{esc(str(c))}</td>" for c in fila) + "</tr>")
        a("</tbody></table>")
        a(f"<p>{esc(rs['nota_quick'])}</p>")
        if rs["quick"]:
            a("<table><thead><tr>" + "".join(f"<th>{esc(str(c))}</th>" for c in rs["cab_quick"])
              + "</tr></thead><tbody>")
            for fila in rs["quick"]:
                a("<tr>" + "".join(f"<td>{esc(str(c))}</td>" for c in fila) + "</tr>")
            a("</tbody></table>")
        else:
            a(f"<p>{esc(rs['sin_quick'])}</p>")

    # ---------------- madurez por dominio (M7, D84) ---------------- #
    if _ma.hay(res.madurez):
        ms = _ma.seccion(res.madurez)
        a("<h2>" + esc(ms["titulo"]) + "</h2>")
        a(f'<div class="nota">{esc(ms["nota"])}</div>')
        a(f"<p>{esc(ms['resumen'])}</p>")
        a(f"<p>{esc(t('Origen del objetivo'))}: {esc(ms['origen_objetivo'])}</p>")
        a('<div class="tbl"><table><thead><tr>' + "".join(f"<th>{esc(str(c))}</th>" for c in ms["cab"])
          + "</tr></thead><tbody>")
        for fila in ms["filas"]:
            a("<tr>" + "".join(f"<td>{esc(str(c))}</td>" for c in fila) + "</tr>")
        a("</tbody></table></div>")
        if ms["radar"]:
            a('<div class="radar">' + _ma.radar_svg(res.madurez) + "</div>")

    # ---------------- visibilidad ---------------- #
    if not caps:
        a = _nada
    a("<h2>" + esc(num("4. Alcance y brecha de visibilidad", a is not _nada)) + "</h2>")
    a('<p class="lead">' + esc(t(
        "Dos plataformas pasivas conectadas en puntos distintos "
        "producen inventarios distintos. Antes de comparar conteos de hallazgos "
        "entre herramientas hay que igualar el punto de captura y la ventana.")) + "</p>")
    a("<table><thead><tr>" + _ths(("Captura",)) + _ths(("Activos", "Datos de identidad"), True)
      + _ths(("Protocolos OT",)) + _ths(("Escrituras",), True) + _ths(("Duracion",))
      + "</tr></thead><tbody>")
    for c in caps:
        ot = sorted({port_info(f["dport"], f["l4"])[0] for f in c.flows.values()
                     if port_info(f["dport"], f["l4"])[1] == "ot"})
        ilegible = " " + t("(ILEGIBLE, no analizada)") if c.error else ""
        a(f"<tr><td>{esc(c.name)}{esc(ilegible)}</td>"
          f"<td class=\"num\">{len(c.hosts)}</td>"
          f"<td class=\"num\">{len(c.identity)}</td><td>{esc(', '.join(ot) or '—')}</td>"
          f"<td class=\"num\">{len(c.control_ops):,}</td>"
          f"<td>{esc(human_duration(c.info.get('Capture duration', '')))}</td></tr>")
    a("</tbody></table>")
    if len(caps) > 1:
        macs = [set(c.hosts) for c in caps]
        common, union = set.intersection(*macs), set.union(*macs)
        a('<div class="nota">' + t(
            "Equipos visibles desde <strong>todos</strong> los "
            "puntos: <strong>{n}</strong> de <strong>{total}</strong>. "
            "Un sensor conectado en un solo punto nunca inventariaria los "
            "{resto} restantes, y por lo tanto nunca les "
            "asignaria vulnerabilidades.",
            n=len(common), total=len(union), resto=len(union) - len(common)) + "</div>")

    vis_titles = {f["titulo"] for f in findings if f["categoria"] == "Visibilidad"}
    a("<h3>" + esc(t("Causas tecnicas de una diferencia entre herramientas")) + "</h3>")
    a("<table><thead><tr>" + _ths(("Causa", "Confirmada en estas capturas"))
      + "</tr></thead><tbody>")
    for label, title in vis_checks():
        marca = "<strong>" + esc(t("Si")) + "</strong>" if title in vis_titles else esc(t("No"))
        a(f"<tr><td>{esc(label)}</td><td>{marca}</td></tr>")
    a("</tbody></table>")
    a("<h3>" + esc(t("Pendiente de verificar con el cliente")) + "</h3><ul class=\"q\">")
    for q in verify_with_client():
        a(f"<li>{q}</li>")
    a("</ul>")
    a = h.append

    a("<h2>" + esc(num("5. Preguntas para la sesion", a is not _nada)) + "</h2><ul class=\"q\">")
    for q in client_questions():
        a(f"<li>{esc(q)}</li>")
    a("</ul>")

    if res.vulnerabilidades:
        vr = res.vulnerabilidades
        a("<h2>" + esc(t("Vulnerabilidades importadas")) + "</h2>")
        a(f'<div class="nota">{esc(t(_vuln.NOTA))}</div>')
        a("<p>" + esc(vr["archivo"]) + ": " + esc(t(
            "{total} filas, {asoc} asociadas a un activo, "
            "{sin} sin activo en el inventario. Detalle en vulnerabilidades.csv.",
            total=vr["total"], asoc=vr["asociadas"], sin=vr["sin_activo"])) + "</p>")
        a("<table><thead><tr>" + _ths(("Severidad",)) + "".join(f'<th class="num">{esc(t(e))}</th>' for e in _vuln._ESTADOS)
          + "</tr></thead><tbody>")
        for s, fila in vr["matriz"].items():
            a(f"<tr><td>{esc(t(s))}</td>" + "".join(f'<td class="num">{fila[e]}</td>' for e in _vuln._ESTADOS) + "</tr>")
        a("</tbody></table>")

    if res.alertas:
        a("<h2>" + esc(t("Alertas importadas")) + "</h2>")
        a(f'<div class="nota">{esc(t(_al.NOTA))}</div>')
        a(f"<p>{esc(_al.intro(res.alertas))}</p>")
        for cab, filas in _al.tablas_resumen(res.alertas):
            a("<table><thead><tr>" + "".join(f"<th>{esc(h)}</th>" for h in cab) + "</tr></thead><tbody>")
            for f in filas:
                a(f'<tr><td>{esc(f[0])}</td><td class="num">{f[1]}</td></tr>')
            a("</tbody></table>")

    if _fu.hay(res.fuentes):
        fuentes_html(a, res.fuentes)

    if _sw.hay(res.switches):
        a("<h2>" + esc(t(_sw.TITULO)) + "</h2>")
        a(f'<div class="nota">{esc(t(_sw.NOTA))}</div>')
        a(f"<p>{esc(_sw.resumen_texto(res.switches))}</p>")
        for tit, cab, filas in _sw.tablas_reporte(res.switches):
            a("<h3>" + esc(tit) + "</h3>")
            a("<table><thead><tr>" + "".join(f"<th>{esc(c)}</th>" for c in cab) + "</tr></thead><tbody>")
            for fila in filas:
                a("<tr>" + "".join(f"<td>{esc(str(c))}</td>" for c in fila) + "</tr>")
            a("</tbody></table>")

    if res.firewall:
        fw = res.firewall
        a("<h2>" + esc(t("Politica de firewall contra trafico observado")) + "</h2>")
        a(f'<div class="nota">{esc(t(_firewall.NOTA))}</div>')
        a("<table><thead><tr>" + _ths(("Resultado",)) + _ths(("Cantidad",), True)
          + "</tr></thead><tbody>")
        for clave, rot in (("permitido", "Permitido por una regla"),
                           ("denegado_observado", "Denegado por una regla pero observado"),
                           ("respuesta", "Respuesta de una sesion permitida"),
                           ("sin_regla", "Trafico sin regla"),
                           ("no_cruza", "No cruza este firewall"),
                           ("reglas_sin_trafico", "Reglas de permitir sin trafico")):
            if clave not in fw["resumen"]:
                continue
            a(f"<tr><td>{esc(t(rot))}</td><td class=\"num\">{fw['resumen'][clave]}</td></tr>")
        a("</tbody></table>")
        if fw.get("reglas"):
            a(f'<div class="nota">{esc(_fi.resumen_texto(fw))}</div>')
        if fw.get("rutas_estado"):
            a(f'<div class="nota">{esc(_fi.resumen_rutas_texto(fw))}</div>')
        if _tp.es_multiple(fw):
            a("<h3>" + esc(t(_tp.TITULO)) + "</h3>")
            a(f'<div class="nota">{esc(t(_tp.NOTA))}</div>')
            a(f'<div class="nota">{esc(_tp.resumen_texto(fw))}</div>')
            for cab, filas in _tp.tablas_reporte(fw):
                a("<table><thead><tr>" + "".join(f"<th>{esc(c)}</th>" for c in cab) + "</tr></thead><tbody>")
                for fila in filas:
                    a("<tr>" + "".join(f"<td>{esc(str(c))}</td>" for c in fila) + "</tr>")
                a("</tbody></table>")
        if _cr.hay(fw):
            a("<h3>" + esc(t(_cr.TITULO)) + "</h3>")
            a(f'<div class="nota">{esc(t(_cr.NOTA))}</div>')
            a(f'<div class="nota">{esc(_cr.resumen_texto(fw["cruces"]))}</div>')
            a("<table><thead><tr>" + _ths(_cr.cabecera_pares()[:2]) + _ths(_cr.cabecera_pares()[2:], True)
              + "</tr></thead><tbody>")
            for o, d_, n, sv in _cr.pares_top(fw["cruces"]):
                a(f'<tr><td>{esc(o)}</td><td>{esc(d_)}</td><td class="num">{n}</td><td class="num">{sv}</td></tr>')
            a("</tbody></table>")
        if _po.hay(fw):
            a("<h3>" + esc(t(_po.TITULO)) + "</h3>")
            a(f'<div class="nota">{esc(t(_po.NOTA))}</div>')
            a(f'<div class="nota">{esc(_po.resumen_texto(fw["politica"]))}</div>')
            for _tit, cab, filas in _po.tablas_reporte(fw["politica"]):
                a("<table><thead><tr>" + "".join(f"<th>{esc(c)}</th>" for c in cab) + "</tr></thead><tbody>")
                for fila in filas:
                    a("<tr>" + "".join(f"<td>{esc(str(c))}</td>" for c in fila) + "</tr>")
                a("</tbody></table>")
        if _rp.hay(fw):
            a("<h3>" + esc(t(_rp.TITULO)) + "</h3>")
            a(f'<div class="nota">{esc(t(_rp.NOTA))}</div>')
            a(f'<div class="nota">{esc(_rp.resumen_texto(fw["rutas_propuestas"]))}</div>')
            for _tit, cab, filas in _rp.tablas_reporte(fw["rutas_propuestas"]):
                a("<table><thead><tr>" + "".join(f"<th>{esc(c)}</th>" for c in cab) + "</tr></thead><tbody>")
                for fila in filas:
                    a("<tr>" + "".join(f"<td>{esc(str(c))}</td>" for c in fila) + "</tr>")
                a("</tbody></table>")
        dudosos = [(k, r) for k, r in _firewall.filas_contraste(conduits, fw)
                   if r["resultado"] not in ("permitido", "no_cruza")]
        if dudosos:
            a("<table><thead><tr>" + _ths(("Origen", "Destino", "Servicio", "Puerto", "Resultado", "Regla"))
              + "</tr></thead><tbody>")
            for k, r in dudosos[: args.max_rows]:
                a(f"<tr><td>{esc(k['src_nombre'])} ({esc(k['src'])})</td>"
                  f"<td>{esc(k['dst_nombre'])} ({esc(k['dst'])})</td><td>{esc(k['servicio'])}</td>"
                  f"<td>{k['port']}/{esc(k['l4'])}</td><td>{esc(t(r['resultado']))}</td>"
                  f"<td>{esc(r['regla'])}</td></tr>")
            a("</tbody></table>")
            if len(dudosos) > args.max_rows:
                a('<div class="nota">' + esc(t(
                    "Se muestran {max} de {total} filas; detalle completo en firewall_contraste.csv.",
                    max=args.max_rows, total=len(dudosos))) + "</div>")
        if res.rutas:
            flujos_fw(a, res.rutas, conduits)

    for e, filas, resum in _cobertura.de_corrida(res):
        a("<h2>" + esc(t("Anexo: cobertura de {nombre}", nombre=e.nombre)) + "</h2>")
        a(f'<div class="nota">{esc(t(_cobertura.NOTA))}</div>')
        if e.clave in _cobertura.NOTAS_MARCO:
            a(f'<div class="nota">{esc(t(_cobertura.NOTAS_MARCO[e.clave]))}</div>')
        a("<table><thead><tr>" + _ths(("Grupo",)) + _ths(("Total", "Directa", "Apoyo", "No evidenciable"), True)
          + "</tr></thead><tbody>")
        for fn, s in resum.items():
            a(f"<tr><td>{esc(fn)}</td><td class=\"num\">{s['total']}</td>"
              f"<td class=\"num\">{s[_cobertura.DIRECTA]}</td><td class=\"num\">{s[_cobertura.APOYO]}</td>"
              f"<td class=\"num\">{s[_cobertura.NO_EVID]}</td></tr>")
        a("</tbody></table>")
        a("<details><summary>" + esc(t("Tabla completa de requisitos")) + "</summary><table><thead><tr>"
          + _ths(("Id", "Categoria", "Requisito", "Cobertura", "Apoyo / hallazgos que lo citan"))
          + _ths(("En esta corrida",), True) + "</tr></thead><tbody>")
        for f in filas:
            det = t(f["apoyo"]) if f["apoyo"] else "; ".join(f["fragmentos"])
            a(f"<tr><td>{esc(f['id'])}</td><td>{esc(f['categoria'])}</td><td>{esc(f['texto'])}</td>"
              f"<td>{esc(t(f['cobertura']))}</td><td>{esc(det)}</td><td class=\"num\">{f['hallazgos']}</td></tr>")
        a("</tbody></table></details>")

    a("<h2>" + esc(num("6. Entorno de analisis", a is not _nada)) + "</h2><table><tbody>")
    for k, v in _entorno.lineas(res.entorno):
        a(f"<tr><th>{esc(k)}</th><td>{esc(v)}</td></tr>")
    a("</tbody></table>")
    if caps:
        a("<table><thead><tr>" + _ths(("Captura", "SHA-256", "Muestreada")) + "</tr></thead><tbody>")
        for ce in res.entorno["capturas"]:
            a(f"<tr><td>{esc(ce['archivo'])}</td><td><code>{esc(ce['sha256'])}</code></td>"
              f"<td>{esc(t('Si') if ce['muestreada'] else t('No'))}</td></tr>")
        a("</tbody></table>")
    elif res.entorno.get("entradas"):
        a("<table><thead><tr>" + _ths(("Archivo", "SHA-256")) + "</tr></thead><tbody>")
        for ce in res.entorno["entradas"]:
            a(f"<tr><td>{esc(ce['archivo'])}</td><td><code>{esc(ce['sha256'])}</code></td></tr>")
        a("</tbody></table>")

    a("<footer>" + esc(t(
        "Generado con ot_assess {version} el {now}. "
        "Analisis pasivo sobre {n} captura(s). "
        "Los roles, zonas y criticidades son inferidos y requieren validacion "
        "con el personal de planta.", version=__version__, now=now, n=len(caps)) if caps else t(
        "Generado con ot_assess {version} el {now}. Analisis de exportaciones de plataformas. "
        "Los roles, zonas y criticidades dependen de la exportacion y requieren validacion "
        "con el personal de planta.", version=__version__, now=now)) + "</footer>")
    a("</div></body></html>")

    path = outdir / "reporte_ot.html"
    path.write_text("\n".join(h), encoding="utf-8")
    return path
