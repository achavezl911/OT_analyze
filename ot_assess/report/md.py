"""Reporte en Markdown (anexo tecnico)."""
from __future__ import annotations

import collections
from datetime import datetime
from pathlib import Path

from .. import __version__
from .. import alertas as _al
from .. import cobertura as _cobertura
from .. import cobertura_captura as _cc
from .. import conductos_zcr as _zc
from .. import csf_tiers as _ct
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
from ..detail.control import op_visible
from ..firewalls import cruces as _cr
from ..firewalls import integracion as _fi
from ..firewalls import politica as _po
from ..firewalls import rutas_propuestas as _rp
from ..firewalls import topologia as _tp
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
    filas_fuentes,
    md_escape,
    referencias_visibles,
    strip_tags,
)


class _Descarte:
    """Sustituye a la lista de salida para omitir una seccion que no aplica sin sangrar su codigo."""

    def append(self, _x) -> None:
        pass


def _cab(*columnas) -> str:
    """Encabezado de una tabla Markdown con las columnas traducidas."""
    return "| " + " | ".join(t(c) for c in columnas) + " |"


def _flujos_fw(out: list, res: Assessment) -> None:
    """Seccion 'Flujos entre interfaces del firewall' (XD-c)."""
    s = _rf.seccion(res.rutas, res.conduits)
    out.append("## " + t("Flujos entre interfaces del firewall") + "\n")
    out.append("> " + t(_rf.NOTA) + "\n")
    out.append(md_escape(s["resumen"]) + "\n")
    for aviso in s["avisos"]:
        out.append("> " + md_escape(aviso) + "\n")
    for cab, filas in ((s["cab_matriz"], s["matriz"]), (s["cab_interfaces"], s["interfaces"])):
        out.append("| " + " | ".join(cab) + " |")
        out.append("|" + "---|" * len(cab))
        for fila in filas:
            out.append("| " + " | ".join(md_escape(str(c)) for c in fila) + " |")
        out.append("")
        if s["mas"] and cab is s["cab_matriz"]:
            out.append(md_escape(s["mas"]) + "\n")


def write_md(res: Assessment, outdir: Path) -> Path:
    caps, conduits, args = res.caps, res.conduits, res.args
    filas_inv = _ip.filas(res)      # I3 (D105): una fila por IP para las MAC de enrutamiento
    estandares = res.estandares or [ESTANDARES["iec62443"]]
    principal = estandares[0]
    out = []
    num = Numerador()
    now =datetime.now().astimezone().strftime("%Y-%m-%d %H:%M %Z")
    out.append("# " + t("Reporte de assessment OT sobre capturas de red" if caps
                         else "Reporte de assessment OT sobre exportaciones de plataformas") + "\n")
    out.append("_" + t("Generado el {now} con `ot_assess {version}`.",
                       now=now, version=__version__) + "_\n")
    if res.perfil:
        out.append("## " + t("Perfil del proyecto") + "\n")
        for k, v in _perfil.etiquetas(res.perfil):
            out.append(f"- **{k}:** {md_escape(v)}")
        out.append(f"\n{t(_perfil.NOTA)}\n")
    if _cc.hay(res.cobertura_captura):      # C1 (D80): al inicio, antes del resumen
        s = _cc.seccion(res.cobertura_captura)
        out.append("## " + s["titulo"] + "\n")
        out.append("> " + s["nota"] + "\n")
        out.append(s["resumen"] + "\n")
        for cab, filas in (s["tabla"], s["tabla_zonas"]):
            out.append("| " + " | ".join(cab) + " |")
            out.append("|" + "---|" * len(cab))
            for fila in filas:
                out.append("| " + " | ".join(md_escape(str(c)) for c in fila) + " |")
            out.append("")

    # --- resumen -------------------------------------------------------- #
    total_pkts = sum(c.flow_packets for c in caps)
    all_hosts = {}
    for c in caps:
        for mac, h in c.hosts.items():
            all_hosts.setdefault(mac, h)
    all_findings = [f for c in [*caps, *res.extras] for f in c.findings]
    by_sev = collections.Counter(f["severidad"] for f in all_findings)

    out.append("## " + num("1. Resumen", not isinstance(out, _Descarte)) + "\n")
    ilegibles = [c.name for c in caps if c.error]
    solo_legibles = t(" (solo sobre las capturas legibles)") if ilegibles else ""
    if caps:
        out.append("- " + t("Capturas analizadas: **{n}** de {total}",
                            n=len(caps) - len(ilegibles), total=len(caps)))
    else:
        out.extend(f"- {k}: **{md_escape(v)}**" for k, v in filas_fuentes(res))
    if ilegibles:
        out.append("- " + t("**Capturas ilegibles, no analizadas:** {lista}",
                            lista=md_escape(", ".join(ilegibles))))
    if caps:
        out.append("- " + t("Paquetes procesados: **{n}**", n=f"{total_pkts:,}"))
        out.append("- " + t("Equipos distintos (por MAC): **{n}**", n=len(all_hosts)))
    else:
        out.append("- " + t("Equipos del inventario: **{n}**", n=len(filas_inv)))
        out.append("- " + t("Conductos: **{n}**", n=len(conduits)))
    out.append("- " + t("Hallazgos:") + " " + ", ".join(
        f"**{by_sev.get(s, 0)}** {t(s).lower()}" for s in ("Alta", "Media", "Baja", "Informativa")
    ))
    if any(c.sampled for c in caps):
        out.append("\n> " + t(
            "Nota: una o mas capturas se analizaron sobre una muestra de {n} paquetes para el "
            "mapa de flujos. Los conteos de protocolo vienen del archivo completo. Use "
            "`--max-packets 0` para procesar todo.", n=f"{args.max_packets:,}"))
    out.append("")

    # --- hallazgos ------------------------------------------------------ #
    out.append("## " + num("2. Hallazgos", not isinstance(out, _Descarte)) + "\n")
    avisos = _avisos(estandares)
    if avisos:
        out.append("> " + " ".join(avisos) + "\n")
    # Se agrupan hallazgos iguales que aparecen en varias capturas.
    ordered = agrupar_hallazgos([*caps, *res.extras], "_")

    etq_origen = "Capturas" if caps else "Fuentes"
    out.append(_cab("#", "Severidad", "Categoria", "Hallazgo", etq_origen))
    out.append("|---|---|---|---|---|")
    for i, f in enumerate(ordered, 1):
        out.append(f"| {i} | {t(f['severidad'])} | {t(f['categoria'])} | "
                   f"{md_escape(t(f['titulo']))} | {len(f['capturas'])} |")
    out.append("")

    for i, f in enumerate(ordered, 1):
        out.append(f"### {i}. [{t(f['severidad'])}] {t(f['titulo'])} ({f['id']})\n")
        out.append(f"**{t('Categoria')}:** {t(f['categoria'])}  ")
        out.append(f"**{t(etq_origen)}:** {', '.join(sorted(set(f['capturas'])))}\n")
        out.append("**" + t("Evidencia") + "**\n")
        out.append("```")
        out.append(t(f["evidencia"]))
        out.append("```\n")
        out.append(f"**{t('Por que importa')}.** {t(f['por_que_importa'])}\n")
        out.append(f"**{t('Recomendacion')}.** {t(f['recomendacion'])}\n")
        refs = referencias_visibles(f, estandares)
        if refs:
            out.append("**" + t("Referencias (orientativas).") + "** "
                       + " ".join(f"{n}: {txt}." for n, txt in refs) + "\n")

    # --- resolucion de nombres (DNS) ------------------------------------ #
    # Sin capturas no hay DNS, identidad, detalle por captura, control ni brecha de visibilidad.
    todo, out = out, (out if caps else _Descarte())
    out.append("## " + t("Resolucion de nombres (DNS)") + "\n")
    sd = _rd.seccion(res)
    if sd is None:
        out.append(t(_rd.SIN_DNS) + "\n")
    else:
        out.append(md_escape(sd["resumen"]) + "\n")
        for cab, filas in ((sd["cab_nombres"], sd["nombres"]), (sd["cab_servidores"], sd["servidores"])):
            out.append("| " + " | ".join(cab) + " |")
            out.append("|" + "---|" * len(cab))
            for fila in filas:
                out.append("| " + " | ".join(md_escape(str(c)) for c in fila) + " |")
            out.append("")
            if sd["mas"] and cab is sd["cab_nombres"]:
                out.append(t(_rd.NOTA_MAS) + "\n")
    out = todo
    if res.rutas and not res.firewall:
        _flujos_fw(out, res)

    # --- plan de remediacion -------------------------------------------- #
    pr = _rem.resumen(res)
    out.append("## " + t("Plan de remediacion") + "\n")
    out.append("> " + t(_rem.NOTA) + "\n")
    if pr["filas"]:
        out.append("; ".join(f"{k}: {v}" for k, v in pr["conteo"].items()) + ".\n")
        out.append("| " + " | ".join(t(c) for c in _rem.CAB_REPORTE) + " |")
        out.append("|" + "---|" * len(_rem.CAB_REPORTE))
        for fila in pr["filas"]:
            out.append("| " + " | ".join(md_escape(str(c)) for c in fila) + " |")
        out.append("")
        out.append(t(_rem.NOTA_ESFUERZO) + "\n")
    else:
        out.append(t(_rem.SIN_PRIORIZAR) + "\n")
    if pr["playbooks"]:
        out.append("## " + t(_pb.TITULO) + "\n")
        out.append("> " + t(_pb.NOTA) + "\n")
        for pb in pr["playbooks"]:
            out.append(f"### {md_escape(pb['titulo'])} ({pb['id']})\n")
            for etiqueta, items, ordenada in pb["bloques"]:
                out.append(f"**{etiqueta}**\n")
                out += [(f"{i}. " if ordenada else "- ") + md_escape(x) for i, x in enumerate(items, 1)]
                out.append("")

    # --- registro de riesgos (R1, D83) ---------------------------------- #
    rs = _rg.seccion(_rg.de(res))
    out.append("## " + rs["titulo"] + "\n")
    out.append("> " + rs["nota"] + "\n")
    if rs["vacia"]:
        out.append(rs["vacia"] + "\n")
    else:
        out.append(rs["resumen"] + "\n")
        for cab_r, filas_r in (rs["mapa_texto"], (rs["cab_top"], rs["top"])):
            out.append("| " + " | ".join(md_escape(str(c)) for c in cab_r) + " |")
            out.append("|" + "---|" * len(cab_r))
            out += ["| " + " | ".join(md_escape(str(c)) for c in fila) + " |" for fila in filas_r]
            out.append("")
        out.append(rs["nota_quick"] + "\n")
        if rs["quick"]:
            out.append("| " + " | ".join(md_escape(str(c)) for c in rs["cab_quick"]) + " |")
            out.append("|" + "---|" * len(rs["cab_quick"]))
            out += ["| " + " | ".join(md_escape(str(c)) for c in fila) + " |" for fila in rs["quick"]]
            out.append("")
        else:
            out.append(rs["sin_quick"] + "\n")
        vs = rs["valoracion"]
        if vs:      # RM2b (D130)
            out.append("### " + vs["titulo"] + "\n")
            for cab_r, filas_r in ((vs["cab"], vs["filas"]), ):
                out.append("| " + " | ".join(md_escape(str(c)) for c in cab_r) + " |")
                out.append("|" + "---|" * len(cab_r))
                out += ["| " + " | ".join(md_escape(str(c)) for c in fila) + " |" for fila in filas_r]
                out.append("")
            out.append(vs["frase"] + "\n")
            for titulo, _grid, (cab_r, filas_r) in vs["mapas"]:
                out.append("### " + titulo + "\n")
                out.append("| " + " | ".join(md_escape(str(c)) for c in cab_r) + " |")
                out.append("|" + "---|" * len(cab_r))
                out += ["| " + " | ".join(md_escape(str(c)) for c in fila) + " |" for fila in filas_r]
                out.append("")

    # --- madurez por dominio (M7, D84) ---------------------------------- #
    if _ma.hay(res.madurez):
        ms = _ma.seccion(res.madurez)
        out.append("## " + ms["titulo"] + "\n")
        out.append("> " + ms["nota"] + "\n")
        out.append(ms["resumen"] + "\n")
        out.append(t("Origen del objetivo") + ": " + md_escape(ms["origen_objetivo"]) + "\n")
        out.append("| " + " | ".join(md_escape(str(c)) for c in ms["cab"]) + " |")
        out.append("|" + "---|" * len(ms["cab"]))
        out += ["| " + " | ".join(md_escape(str(c)) for c in fila) + " |" for fila in ms["filas"]]
        out.append("")
        if ms["equivalencia"]:      # MAD2 (D131)
            eq = ms["equivalencia"]
            out.append("### " + eq["titulo"] + "\n")
            out.append("| " + " | ".join(md_escape(str(c)) for c in eq["cab"]) + " |")
            out.append("|" + "---|" * len(eq["cab"]))
            out += ["| " + " | ".join(md_escape(str(c)) for c in fila) + " |" for fila in eq["filas"]]
            out.append("")

    # --- niveles (Tiers) de NIST CSF 2.0 por funcion (CSF2T, D110) ------- #
    if _ct.hay(res.csf_tiers):
        cs = _ct.seccion(res.csf_tiers)
        out.append("## " + cs["titulo"] + "\n")
        out.append("> " + cs["nota"] + "\n")
        out.append(cs["resumen"] + "\n")
        out.append(t("Origen del objetivo") + ": " + md_escape(cs["origen_objetivo"]) + "\n")
        out.append("| " + " | ".join(md_escape(str(c)) for c in cs["cab"]) + " |")
        out.append("|" + "---|" * len(cs["cab"]))
        out += ["| " + " | ".join(md_escape(str(c)) for c in fila) + " |" for fila in cs["filas"]]
        out.append("")

    # --- inventario ----------------------------------------------------- #
    out.append("## " + num("3. Inventario de activos", not isinstance(out, _Descarte)) + "\n")
    out.append(t("Consolidado entre todos los puntos de captura. Rol y zona son "
                 "inferidos del comportamiento observado, no declarados por el "
                 "equipo: hay que validarlos con el personal de planta.") + "\n")
    out.append(_cab("#", "Equipo", "IP", "MAC", "Fabricante", "Modelo / descripcion",
                    "Firmware", "Rol inferido", "Zona", "VLAN", "Paquetes"))
    out.append("|---|---|---|---|---|---|---|---|---|---|---|")
    rows = filas_inv
    for i, ast in enumerate(rows[: args.max_rows], 1):
        out.append(
            f"| {i} | {md_escape(ast['nombre'])} "
            f"| {md_escape(', '.join(sorted(ast['ips'])[:3]) or '-')} "
            f"| `{_ip.mac_mostrada(ast)}` | {md_escape(ast['vendor'] or '-')} "
            f"| {md_escape(ast.get('modelo') or '-')} "
            f"| {md_escape(ast.get('firmware') or '-')} "
            f"| {md_escape(mostrar_rol(ast['role']) if ast['role'] else t('Indeterminado'))} "
            f"| {mostrar_rol(ast['purdue']) or '-'} "
            f"| {', '.join(sorted(ast['vlans'])) or '-'} | {ast['pkts']:,} |"
        )
    if _ip.hay_partidas(rows):
        out.append("\n> " + _ip.nota())
    if len(rows) > args.max_rows:
        out.append("\n_(" + t("{n} equipos mas en `inventario.csv`.",
                              n=len(rows) - args.max_rows) + ")_")
    con_fw = [x for x in rows if x.get("firmware")]
    out.append("\n" + t("**{n} de {total}** activos revelaron version de firmware de forma "
                        "pasiva. Solo sobre esos puede un motor de vulnerabilidades hacer "
                        "correspondencia con su base de CVEs.",
                        n=len(con_fw), total=len(rows)) + "\n")

    if _zo.hay(res.zonas):
        out.append("### " + t(_zo.TITULO) + "\n")
        out.append("> " + t(_zo.NOTA) + "\n")
        zon = _zo.presentada(res.zonas, filas_inv)
        if _zo.nota_partidas(zon):
            out.append("> " + _zo.nota_partidas(zon) + "\n")
        out.append(_zo.resumen_texto(zon) + "\n")
        cab, filas = _zo.tabla_reporte(zon)
        out.append("| " + " | ".join(cab) + " |")
        out.append("|" + "---|" * len(cab))
        for fila in filas[: args.max_rows]:
            out.append("| " + " | ".join(md_escape(str(c)) for c in fila) + " |")
        out.append("")
    if _in.hay(res.inventario_normalizado):
        s = _in.seccion(res.inventario_normalizado)
        out.append("### " + s["titulo"] + "\n")
        out.append("> " + s["nota"] + "\n")
        out.append(s["resumen"] + "\n")
        cab, filas = s["tabla"]
        out.append("| " + " | ".join(cab) + " |")
        out.append("|" + "---|" * len(cab))
        for fila in filas:
            out.append("| " + " | ".join(md_escape(str(c)) for c in fila) + " |")
        out.append("")
    if _ob.hay(res.obsolescencia):
        s = _ob.seccion(res.obsolescencia)
        out.append("### " + s["titulo"] + "\n")
        out.append("> " + s["nota"] + "\n")
        out.append(s["resumen"] + "\n")
        cab, filas = s["tabla"]
        out.append("| " + " | ".join(cab) + " |")
        out.append("|" + "---|" * len(cab))
        for fila in filas:
            out.append("| " + " | ".join(md_escape(str(c)) for c in fila) + " |")
        out.append("")
    if _zc.hay(res.zcr):
        out.append("### " + t(_zc.TITULO) + "\n")
        out.append("> " + t(_zc.NOTA) + "\n")
        out.append(_zc.resumen_texto(res.zcr) + "\n")
        cab, filas = _zc.tabla_reporte(res.zcr)
        out.append("| " + " | ".join(cab) + " |")
        out.append("|" + "---|" * len(cab))
        for fila in filas:
            out.append("| " + " | ".join(md_escape(str(c)) for c in fila) + " |")
        out.append("")
        if res.diagrama_zcr:
            d = res.diagrama_zcr
            out.append(f"![{d.titulo}]({d.slug}.svg)\n")
            if d.nota:
                out.append(f"> {d.nota}\n")
    if _tb.hay(res.tobe):       # T1a (D85)
        s = _tb.seccion(res.tobe)
        out.append("### " + s["titulo"] + "\n")
        out.append("> " + s["nota"] + "\n")
        out.append(s["resumen"] + "\n")
        for cab, filas in ((s["cab_matriz"], s["matriz"]), (s["cab"], s["filas"])):
            out.append("| " + " | ".join(md_escape(str(c)) for c in cab) + " |")
            out.append("|" + "---|" * len(cab))
            for fila in filas:
                out.append("| " + " | ".join(md_escape(str(c)) for c in fila) + " |")
            out.append("")
            if cab is s["cab_matriz"]:
                out.append(s["leyenda"] + "\n")
        if s["mas"]:
            out.append(s["mas"] + "\n")
        if res.diagrama_tobe:
            d = res.diagrama_tobe
            out.append(f"![{d.titulo}]({d.slug}.svg)\n")
            out.append(f"> {d.nota}\n")
    elif _tb.hay_seccion(res.tobe):
        s = _tb.seccion_vacia(res.tobe)
        out.append("### " + s["titulo"] + "\n")
        out.append(s["texto"] + "\n")
        if s["nota"]:
            out.append("> " + s["nota"] + "\n")
    if _hd.hay(res.hardening):       # T1b (D86)
        s = _hd.seccion(res.hardening)
        out.append("### " + s["titulo"] + "\n")
        out.append("> " + s["nota"] + "\n")
        out.append(s["resumen"] + "\n")
        for cab, filas in ((s["cab_tipos"], s["tipos"]), (s["cab_top"], s["top"])):
            if cab is s["cab_top"]:
                if not filas:
                    out.append(s["sin_top"] + "\n")
                    continue
                out.append("#### " + s["titulo_top"] + "\n")
            out.append("| " + " | ".join(md_escape(str(c)) for c in cab) + " |")
            out.append("|" + "---|" * len(cab))
            for fila in filas:
                out.append("| " + " | ".join(md_escape(str(c)) for c in fila) + " |")
            out.append("")
    if _vf.hay(res.vuln_firmware):     # V1a (D89)
        s = _vf.seccion(res.vuln_firmware)
        out.append("### " + s["titulo"] + "\n")
        out.append("> " + s["nota"] + "\n")
        out.append(s["resumen"] + "\n")
        cab, filas = s["tabla"]
        if filas:
            out.append("| " + " | ".join(cab) + " |")
            out.append("|" + "---|" * len(cab))
            for fila in filas:
                out.append("| " + " | ".join(md_escape(str(c)) for c in fila) + " |")
            out.append("")
        for texto in (s["mas"], s["vacio"]):
            if texto:
                out.append(texto + "\n")
    if _fl.hay(res.fuentes_log):       # G1a (D87)
        s = _fl.seccion(res.fuentes_log)
        out.append("### " + s["titulo"] + "\n")
        out.append("> " + s["nota"] + "\n")
        out.append(s["resumen"] + "\n")
        for cab, filas in ((s["cab_tipos"], s["tipos"]), (s["cab_colectores"], s["colectores"])):
            if not filas:
                continue
            out.append("| " + " | ".join(md_escape(str(c)) for c in cab) + " |")
            out.append("|" + "---|" * len(cab))
            for fila in filas:
                out.append("| " + " | ".join(md_escape(str(c)) for c in fila) + " |")
            out.append("")
        for texto in (s["mas"], s["vacio"]):
            if texto:
                out.append(texto + "\n")
    if _dr.hay(res.direccionamiento):       # G1b (D88)
        s = _dr.seccion(res.direccionamiento)
        out.append("### " + s["titulo"] + "\n")
        out.append("> " + s["nota"] + "\n")
        out.append(s["resumen"] + "\n")
        for cab, filas in ((s["cab_redes"], s["redes"]), (s["cab_obs"], s["observaciones"])):
            if not filas:
                continue
            out.append("| " + " | ".join(md_escape(str(c)) for c in cab) + " |")
            out.append("|" + "---|" * len(cab))
            for fila in filas:
                out.append("| " + " | ".join(md_escape(str(c)) for c in fila) + " |")
            out.append("")
        if s["mas"]:
            out.append(s["mas"] + "\n")
    if _lb.hay(res.linea_base):
        s = _lb.seccion(res.linea_base)
        out.append("### " + s["titulo"] + "\n")
        out.append("> " + s["nota"] + "\n")
        out.append(s["resumen"] + "\n")
        for cab, filas in (s["pivote"], s["top"]):
            out.append("| " + " | ".join(cab) + " |")
            out.append("|" + "---|" * len(cab))
            for fila in filas:
                out.append("| " + " | ".join(md_escape(str(c)) for c in fila) + " |")
            out.append("")
        out.append("> " + s["nota_cota"] + "\n")
    if _mc.hay(res.matriz_controles):
        s = _mc.seccion(res.matriz_controles, res.linea_base)
        out.append("### " + s["titulo"] + "\n")
        out.append("> " + s["nota"] + "\n")
        out.append(s["resumen"] + "\n")
        cab, filas = s["tabla"]
        out.append("| " + " | ".join(cab) + " |")
        out.append("|" + "---|" * len(cab))
        for fila in filas:
            out.append("| " + " | ".join(md_escape(str(c)) for c in fila) + " |")
        out.append("")
    if _sr.hay(res.salud_red):
        s = _sr.seccion(res.salud_red)
        out.append("### " + s["titulo"] + "\n")
        out.append("> " + s["nota"] + "\n")
        out.append(s["resumen"] + "\n")
        for titulo, cab, filas in s["tablas"]:
            out.append("**" + titulo + "**\n")
            out.append("| " + " | ".join(cab) + " |")
            out.append("|" + "---|" * len(cab))
            for fila in filas:
                out.append("| " + " | ".join(md_escape(str(c)) for c in fila) + " |")
            out.append("")
    if _se.hay(res.sensores):
        s = _se.seccion(res.sensores)
        out.append("### " + s["titulo"] + "\n")
        out.append("> " + s["nota"] + "\n")
        out.append(s["resumen"] + "\n")
        for titulo, cab, filas in s["tablas"]:
            out.append("**" + titulo + "**\n")
            out.append("| " + " | ".join(cab) + " |")
            out.append("|" + "---|" * len(cab))
            for fila in filas:
                out.append("| " + " | ".join(md_escape(str(c)) for c in fila) + " |")
            out.append("")
    if _lba.hay(res.linea_base_aprobada):
        s = _lba.seccion(res.linea_base_aprobada)
        out.append("### " + s["titulo"] + "\n")
        out.append("> " + s["nota"] + "\n")
        out.append(s["resumen"] + "\n")
        for titulo, cab, filas in s["tablas"]:
            out.append("**" + titulo + "**\n")
            out.append("| " + " | ".join(cab) + " |")
            out.append("|" + "---|" * len(cab))
            for fila in filas:
                out.append("| " + " | ".join(md_escape(str(c)) for c in fila) + " |")
            out.append("")
    if _ra.hay(res.rutas_ataque):
        out.append("### " + t(_ra.TITULO) + "\n")
        out.append("> " + t(_ra.NOTA) + "\n")
        out.append(_ra.resumen_texto(res.rutas_ataque) + "\n")
        for cab, filas in (_ra.tabla_caminos(res.rutas_ataque), _ra.tabla_puntos(res.rutas_ataque)):
            out.append("| " + " | ".join(cab) + " |")
            out.append("|" + "---|" * len(cab))
            for fila in filas:
                out.append("| " + " | ".join(md_escape(str(c)) for c in fila) + " |")
            out.append("")

    # --- matriz de comunicaciones --------------------------------------- #
    out.append("## " + num("4. Matriz de comunicaciones", not isinstance(out, _Descarte)) + "\n")
    out.append(t("Cada renglon es una relacion origen -> destino -> servicio. La "
                 "criticidad combina el tipo de servicio, si cruza zonas y si "
                 "transporta operaciones de escritura al proceso.") + "\n")
    for d in res.diagrams:
        out.append(f"### {d.titulo}\n")
        out.append(f"{d.descripcion}\n")
        out.append(f"![{d.titulo}]({d.slug}.svg)\n")
        out.append("_" + t("Fuente editable: `{slug}.mmd` (Mermaid).", slug=d.slug) + "_\n")
        if d.nota:
            out.append(f"> {d.nota}\n")
    if res.diagrams:
        out.append("### " + t("Detalle de conductos") + "\n")
    out.append(_cab("#", "Origen", "Zona", "Destino", "Zona", "Servicio", "Puerto",
                    "Sentido", "Paquetes", "Volumen", "Escrituras", "Criticidad"))
    out.append("|---|---|---|---|---|---|---|---|---|---|---|---|")
    for i, k in enumerate(conduits[: args.max_rows], 1):
        out.append(
            f"| {i} | {md_escape(k['src_nombre'])} ({k['src']}) "
            f"| {mostrar_rol(k['src_zona']) or '-'}{' **>**' if k['cruza_zona'] else ''} "
            f"| {md_escape(k['dst_nombre'])} ({k['dst']}) | {mostrar_rol(k['dst_zona']) or '-'} "
            f"| {md_escape(k['servicio'])} | {k['l4']}/{k['port'] or '-'} "
            f"| {t('bidireccional') if k['bidireccional'] else t('unidireccional')} "
            f"| {k['pkts']:,} | {human(k['bytes'])} "
            f"| {k['escrituras'] or '-'} | {k['criticidad']} |"
        )
    if len(conduits) > args.max_rows:
        out.append("\n_(" + t("{n} conductos mas en `comunicaciones.csv`.",
                              n=len(conduits) - args.max_rows) + ")_")
    cross = [k for k in conduits if k["cruza_zona"]]
    if cross:
        out.append("\n" + t("**{n} conductos cruzan zonas.** Son los candidatos naturales a "
                            "control por firewall OT bajo el modelo de zonas {modelo}.",
                            n=len(cross), modelo=t(principal.cruce)) + "\n")
    out.append("")

    # --- identidad ------------------------------------------------------ #
    out = out if caps else _Descarte()
    out.append("## " + num("5. Identidad de equipos observada (insumo para CVEs)", not isinstance(out, _Descarte)) + "\n")
    out.append(t("Esto es lo que un motor pasivo de vulnerabilidades usa para hacer "
                 "match contra su base. Si esta tabla sale vacia o corta, la herramienta "
                 "no tiene con que trabajar.") + "\n")
    idents = [i for c in caps for i in c.identity]
    seen = set()
    uniq = []
    for i in idents:
        k = (i["tipo"], i["valor"], i["detalle"][:80])
        if k not in seen:
            seen.add(k)
            uniq.append(i)
    if uniq:
        out.append(_cab("Origen", "Tipo", "Valor", "Detalle"))
        out.append("|---|---|---|---|")
        for i in uniq[: args.max_rows]:
            out.append(f"| {i['ip'] or i['mac']} | {i['tipo']} | "
                       f"{md_escape(i['valor'][:60])} | {md_escape(i['detalle'][:160])} |")
        if len(uniq) > args.max_rows:
            out.append("\n_(" + t("{n} mas en `identidad.csv`.", n=len(uniq) - args.max_rows) + ")_")
    else:
        out.append("_" + t("No se observo ningun paquete con informacion de identidad{solo}.",
                           solo=solo_legibles) + "_")
    out.append("")

    # --- protocolos ----------------------------------------------------- #
    out.append("## " + num("6. Detalle por captura", not isinstance(out, _Descarte)) + "\n")
    for c in caps:
        out.append(f"### {c.name}\n")
        info = c.info
        meta = []
        for k in ("Number of packets", "Capture duration", "First packet time",
                  "Last packet time", "Packet size limit", "Data byte rate",
                  "Number of duplicate packets", "Metodo de duplicados"):
            if info.get(k):
                propio = k == "Metodo de duplicados"      # texto nuestro; el resto viene de capinfos
                meta.append(f"- **{t(k) if propio else k}**: {t(info[k]) if propio else info[k]}")
        out.append("\n".join(meta) + "\n")

        top = sorted(c.protos.items(), key=lambda kv: -kv[1])[:18]
        if top:
            out.append(_cab("Protocolo", "Tramas"))
            out.append("|---|---|")
            for p, n in top:
                out.append(f"| {p} | {n:,} |")
            out.append("")

        flows = sorted(c.flows.values(), key=lambda f: -f["pkts"])[:20]
        if flows:
            out.append("**" + t("Flujos principales") + "**\n")
            out.append(_cab("Origen", "Destino", "Puerto", "Servicio", "Protocolo",
                            "Paquetes", "Bytes"))
            out.append("|---|---|---|---|---|---|---|")
            for f in flows:
                svc, _ = port_info(f["dport"], f["l4"])
                out.append(
                    f"| {f['src']} | {f['dst']} | {f['l4']}/{f['dport'] or '-'} | "
                    f"{svc or '-'} | {md_escape(f['proto'])} | {f['pkts']:,} | "
                    f"{human(f['bytes'])} |"
                )
            out.append("")

    # --- control -------------------------------------------------------- #
    out.append("## " + num("7. Operaciones de control observadas", not isinstance(out, _Descarte)) + "\n")
    ops = [o for c in caps for o in c.control_ops]
    if ops:
        agg = collections.Counter(
            (o["proto"], o["op"], o["src"], o["dst"]) for o in ops
        )
        out.append(_cab("Protocolo", "Operacion", "Origen", "Destino", "Veces"))
        out.append("|---|---|---|---|---|")
        for (proto, op, src, dst), n in agg.most_common(args.max_rows):
            out.append(f"| {proto} | {md_escape(op_visible({'proto': proto, 'op': op}))} | {src} | {dst} | {n} |")
    else:
        out.append("_" + t("No se observaron escrituras ni comandos de control{solo}. "
                           "Solo lectura e I/O ciclico.", solo=solo_legibles) + "_")
    out.append("")

    # --- brecha de visibilidad ------------------------------------------ #
    out.append("## " + num("8. Brecha de visibilidad entre herramientas", not isinstance(out, _Descarte)) + "\n")
    out.append(t(
        "Cuando dos plataformas pasivas analizan la misma red y una reporta "
        "vulnerabilidades y la otra no, casi siempre es por una de estas razones. "
        "Las marcadas con **si** se confirmaron en estas capturas.") + "\n")
    if len(caps) > 1:
        out.append("### " + t("Que alcanza a ver cada punto de captura") + "\n")
        out.append(t(
            "Dos sensores en puntos distintos producen inventarios distintos. "
            "Esta tabla muestra cuanto difiere la visibilidad entre los puntos "
            "capturados, que es el primer argumento a revisar antes de comparar "
            "conteos de hallazgos entre herramientas.") + "\n")
        out.append(_cab("Captura", "Equipos", "Datos de identidad", "Protocolos OT",
                        "Operaciones de control", "Duracion"))
        out.append("|---|---|---|---|---|---|")
        for c in caps:
            ot_protos = sorted({
                port_info(f["dport"], f["l4"])[0]
                for f in c.flows.values()
                if port_info(f["dport"], f["l4"])[1] == "ot"
            })
            out.append(
                f"| {c.name} | {len(c.hosts)} | {len(c.identity)} | "
                f"{', '.join(ot_protos) or '-'} | {len(c.control_ops)} | "
                f"{human_duration(c.info.get('Capture duration', ''))} |"
            )
        macs = [set(c.hosts) for c in caps]
        common = set.intersection(*macs) if macs else set()
        union = set.union(*macs) if macs else set()
        out.append("\n" + t(
            "Equipos vistos por **todos** los puntos: **{n}** de **{total}** en total. "
            "Los {resto} restantes solo son visibles desde algunos puntos: un sensor "
            "conectado en un solo lugar nunca los inventariaria, y por lo tanto nunca "
            "les asignaria vulnerabilidades.",
            n=len(common), total=len(union), resto=len(union) - len(common)) + "\n")

    vis = [f for c in caps for f in c.findings if f["categoria"] == "Visibilidad"]
    vis_titles = {f["titulo"] for f in vis}
    out.append(_cab("Causa posible", "Confirmada aqui"))
    out.append("|---|---|")
    for label, title in vis_checks():
        out.append(f"| {label} | {'**' + t('si') + '**' if title in vis_titles else t('no')} |")
    out.append("")
    out.append(t("Causas que esta captura no puede confirmar y hay que verificar "
                 "con el cliente:") + "\n")
    for q in verify_with_client():
        out.append(f"- {strip_tags(q)}")
    out.append("")
    out = todo

    # --- preguntas ------------------------------------------------------ #
    out.append("## " + num("9. Preguntas para la sesion con el cliente", not isinstance(out, _Descarte)) + "\n")
    for i, q in enumerate(client_questions(), 1):
        out.append(f"{i}. {q}")
    out.append("")

    if res.vulnerabilidades:
        vr = res.vulnerabilidades
        out.append("## " + t("Vulnerabilidades importadas") + "\n")
        out.append("> " + t(_vuln.NOTA) + "\n")
        out.append(t("`{archivo}`: {total} filas, {asoc} asociadas a un activo, {sin} sin activo "
                     "en el inventario. Detalle en `vulnerabilidades.csv`.",
                     archivo=vr["archivo"], total=vr["total"], asoc=vr["asociadas"],
                     sin=vr["sin_activo"]) + "\n")
        out.append("| " + t("Severidad") + " | " + " | ".join(t(e) for e in _vuln._ESTADOS) + " |\n|---|---|---|---|")
        for s, fila in vr["matriz"].items():
            out.append(f"| {t(s)} | " + " | ".join(str(fila[e]) for e in _vuln._ESTADOS) + " |")
        out.append("")

    if res.alertas:
        out.append("## " + t("Alertas importadas") + "\n")
        out.append("> " + t(_al.NOTA) + "\n")
        out.append(_al.intro(res.alertas).replace("alertas.csv", "`alertas.csv`") + "\n")
        for cab, filas in _al.tablas_resumen(res.alertas):
            out.append("| " + " | ".join(cab) + " |\n|---|---|")
            for f in filas:
                out.append(f"| {f[0]} | {f[1]} |")
            out.append("")

    if _fu.hay(res.fuentes):
        out.append("## " + t(_fu.TITULO) + "\n")
        out.append("> " + t(_fu.NOTA) + "\n")
        out.append(_fu.resumen_texto(res.fuentes) + "\n")
        cab = _fu.cabecera_resumen()
        out.append("| " + " | ".join(cab) + " |")
        out.append("|" + "---|" * len(cab))
        for fila in _fu.filas_resumen(res.fuentes):
            out.append("| " + " | ".join(md_escape(str(c)) for c in fila) + " |")
        out.append("")

    if _sw.hay(res.switches):
        out.append("## " + t(_sw.TITULO) + "\n")
        out.append("> " + t(_sw.NOTA) + "\n")
        out.append(_sw.resumen_texto(res.switches) + "\n")
        for tit, cab, filas in _sw.tablas_reporte(res.switches):
            out.append("**" + tit + "**\n")
            out.append("| " + " | ".join(cab) + " |")
            out.append("|" + "---|" * len(cab))
            for fila in filas:
                out.append("| " + " | ".join(md_escape(str(c)) for c in fila) + " |")
            out.append("")

    if res.firewall:
        r = res.firewall["resumen"]
        out.append("## " + t("Politica de firewall contra trafico observado") + "\n")
        out.append("> " + t(_firewall.NOTA) + "\n")
        out.append(_cab("Resultado", "Cantidad") + "\n|---|---|")
        out.append(f"| {t('Permitido por una regla')} | {r['permitido']} |")
        out.append(f"| {t('Denegado por una regla pero observado')} | {r['denegado_observado']} |")
        if "respuesta" in r:
            out.append(f"| {t('Respuesta de una sesion permitida')} | {r['respuesta']} |")
        out.append(f"| {t('Trafico sin regla')} | {r['sin_regla']} |")
        if "no_cruza" in r:
            out.append(f"| {t('No cruza este firewall')} | {r['no_cruza']} |")
        out.append(f"| {t('Reglas de permitir sin trafico')} | {r['reglas_sin_trafico']} |")
        out.append("\n" + t("Detalle en `firewall_contraste.csv`.") + "\n")
        if res.firewall.get("reglas"):
            out.append(_fi.resumen_texto(res.firewall) + "\n")
        if res.firewall.get("rutas_estado"):
            out.append(_fi.resumen_rutas_texto(res.firewall) + "\n")
        if _tp.es_multiple(res.firewall):
            out.append("### " + t(_tp.TITULO) + "\n")
            out.append("> " + t(_tp.NOTA) + "\n")
            out.append(_tp.resumen_texto(res.firewall) + "\n")
            for cab, filas in _tp.tablas_reporte(res.firewall):
                out.append("| " + " | ".join(cab) + " |")
                out.append("|" + "---|" * len(cab))
                for fila in filas:
                    out.append("| " + " | ".join(md_escape(str(c)) for c in fila) + " |")
                out.append("")
        if _cr.hay(res.firewall):
            out.append("### " + t(_cr.TITULO) + "\n")
            out.append("> " + t(_cr.NOTA) + "\n")
            out.append(_cr.resumen_texto(res.firewall["cruces"]) + "\n")
            cab = _cr.cabecera_pares()
            out.append("| " + " | ".join(cab) + " |")
            out.append("|" + "---|" * len(cab))
            for fila in _cr.pares_top(res.firewall["cruces"]):
                out.append("| " + " | ".join(md_escape(str(c)) for c in fila) + " |")
            out.append("")
        if _po.hay(res.firewall):
            out.append("### " + t(_po.TITULO) + "\n")
            out.append("> " + t(_po.NOTA) + "\n")
            out.append(_po.resumen_texto(res.firewall["politica"]) + "\n")
            for tit, cab, filas in _po.tablas_reporte(res.firewall["politica"]):
                out.append("**" + tit + "**\n")
                out.append("| " + " | ".join(cab) + " |")
                out.append("|" + "---|" * len(cab))
                for fila in filas:
                    out.append("| " + " | ".join(md_escape(str(c)) for c in fila) + " |")
                out.append("")
        if _rp.hay(res.firewall):
            out.append("### " + t(_rp.TITULO) + "\n")
            out.append("> " + t(_rp.NOTA) + "\n")
            out.append(_rp.resumen_texto(res.firewall["rutas_propuestas"]) + "\n")
            for tit, cab, filas in _rp.tablas_reporte(res.firewall["rutas_propuestas"]):
                out.append("**" + tit + "**\n")
                out.append("| " + " | ".join(cab) + " |")
                out.append("|" + "---|" * len(cab))
                for fila in filas:
                    out.append("| " + " | ".join(md_escape(str(c)) for c in fila) + " |")
                out.append("")
        if res.rutas:
            _flujos_fw(out, res)

    for e, _filas, resum in _cobertura.de_corrida(res):
        out.append("## " + t("Anexo: cobertura de {nombre}", nombre=e.nombre) + "\n")
        nota_marco = t(_cobertura.NOTAS_MARCO[e.clave]) if e.clave in _cobertura.NOTAS_MARCO else ""
        out.append(("> " + t(_cobertura.NOTA) + " " + nota_marco).rstrip() + "\n")
        out.append(_cab("Grupo", "Total", "Directa", "Apoyo", "No evidenciable")
                   + "\n|---|---|---|---|---|")
        for fn, s in resum.items():
            out.append(f"| {fn} | {s['total']} | {s[_cobertura.DIRECTA]} | {s[_cobertura.APOYO]} "
                       f"| {s[_cobertura.NO_EVID]} |")
        out.append("\n" + t("Detalle en `cobertura_{clave}.csv`.", clave=e.clave) + "\n")

    out.append("## " + num("10. Entorno de analisis", not isinstance(out, _Descarte)) + "\n")
    for k, v in _entorno.lineas(res.entorno):
        out.append(f"- {k}: {md_escape(v)}")
    if caps:
        out.append("\n" + _cab("Captura", "SHA-256", "Muestreada") + "\n|---|---|---|")
        for ce in res.entorno["capturas"]:
            out.append(f"| {md_escape(ce['archivo'])} | `{ce['sha256']}` | "
                       f"{t('Si') if ce['muestreada'] else t('No')} |")
    elif res.entorno.get("entradas"):
        out.append("\n" + _cab("Archivo", "SHA-256") + "\n|---|---|")
        for ce in res.entorno["entradas"]:
            out.append(f"| {md_escape(ce['archivo'])} | `{ce['sha256']}` |")
    out.append("")

    report = outdir / "reporte_ot.md"
    report.write_text("\n".join(out), encoding="utf-8")
    return report
