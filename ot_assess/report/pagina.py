"""Pagina HTML autonoma con los diagramas importados de una plataforma OT."""
from __future__ import annotations

from datetime import datetime
from html import escape as esc
from pathlib import Path

from .. import __version__
from .. import alertas as _al
from .. import conductos_zcr as _zc
from .. import fuentes as _fu
from .. import perfil as _perfil
from .. import vulnerabilidades as _vuln
from .. import zonas as _zo
from ..i18n import idioma as _idioma
from ..i18n import t
from ..importers import Importacion
from ..importers.perfiles import ACTIVOS, ENLACES
from ..standards import avisos as _avisos
from .common import referencias_visibles
from .html import flujos_fw, fuentes_html
from .style import HTML_CSS

AGRUPACIONES = {"zona": "zona de seguridad definida en la plataforma",
                "interfaz": "interfaz del firewall (segun su tabla de rutas)"}

ETIQUETAS = {
    "id": "Identificador", "ip": "Direccion IP", "mac": "MAC", "nombre": "Nombre", "vendor": "Fabricante",
    "modelo": "Modelo", "firmware": "Firmware", "tipo": "Tipo / rol", "nivel": "Nivel Purdue", "zona": "Zona",
    "origen": "Origen", "destino": "Destino", "protocolo": "Protocolo", "puerto": "Puerto",
    "l4": "Transporte", "paquetes": "Paquetes", "bytes": "Bytes",
    "direccion": "Direccion", "fecha": "Fecha", "tipo_origen": "Tipo del origen",
    "tipo_destino": "Tipo del destino", "nombre_destino": "Nombre del destino", "ambito": "Ambito",
}


def _tabla_mapeo(titulo: str, alias: dict, mapeo: dict) -> str:
    filas = "".join(
        f"<tr><td>{esc(t(ETIQUETAS[c]))}</td><td class=\"mono\">{esc(mapeo[c]) if c in mapeo else '—'}</td></tr>"
        for c in alias if c in ETIQUETAS)
    return (f'<div class="tbl"><table><thead><tr><th>{esc(t(titulo))}</th>'
            f"<th>{esc(t('Columna interpretada'))}</th></tr></thead><tbody>{filas}</tbody></table></div>")


def write_pagina(diagramas: list, imp: Importacion, estandares: list, outdir: Path,
                 titulo: str, cliente: str, perfil: dict | None = None,
                 hallazgos: list | None = None, vulnerabilidades: dict | None = None,
                 alertas: dict | None = None, rutas: dict | None = None,
                 fuentes: dict | None = None, zonas: dict | None = None, zcr: dict | None = None,
                 diagrama_zcr=None) -> Path:
    ahora = datetime.now().astimezone().strftime("%d/%m/%Y %H:%M")
    r = imp.resumen
    h: list = []
    a = h.append
    a(f'<!doctype html><html lang="{_idioma()}"><head><meta charset="utf-8">')
    a("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">")
    a(f"<title>{esc(titulo)}</title><style>{HTML_CSS}</style></head><body>")
    a('<header class="port"><div class="inner">')
    a(f"<h1>{esc(titulo)}</h1>")
    datos_de = t("Datos de {fuente}", fuente=imp.fuente)
    generado = t("Generado el {now}", now=ahora)
    a(f"<p>{esc(cliente)} &middot; {esc(datos_de)} &middot; {esc(generado)}</p>")
    a("</div></header><div class=\"wrap\">")
    if perfil:
        a("<h2>" + esc(t("Perfil del proyecto")) + "</h2><table><tbody>")
        for k, v in _perfil.etiquetas(perfil):
            a(f"<tr><th>{esc(k)}</th><td>{esc(v)}</td></tr>")
        a(f"</tbody></table><p>{esc(t(_perfil.NOTA))}</p>")

    a("<h2>" + esc(t("Resumen")) + "</h2><div class=\"kpis\">")
    for n, etiqueta in ((r["activos"], "Activos"), (r["conductos"], "Conductos"),
                        (r["activos_sin_nivel"], "Sin nivel"), (len(imp.advertencias), "Advertencias")):
        a(f'<div class="kpi"><div class="n">{n:,}</div><div class="l">{esc(t(etiqueta))}</div></div>')
    a("</div>")
    if r.get("periodo"):
        a("<p>" + esc(t("Periodo de la exportacion: {desde} a {hasta} (hora local de la exportacion, sin zona "
                        "horaria).", desde=r["periodo"]["desde"], hasta=r["periodo"]["hasta"])) + "</p>")
    a('<div class="nota">' + esc(t(
        "Los diagramas se construyen exclusivamente con los archivos exportados de la plataforma; "
        "no se genero trafico ni se consulto la red. Las exportaciones de inventario y de "
        "comunicaciones no distinguen lectura de escritura, por lo que ningun conducto aparece como "
        "critico por escrituras: esa distincion requiere el analisis de las capturas.")) + "</div>")

    a("<h2>" + esc(t("Hallazgos segun la exportacion")) + "</h2>")
    a('<div class="nota">' + esc(t(
        "Hallazgos derivados de los archivos exportados; los formatos de exportacion no estan "
        "validados con exportaciones reales (P1) y no hay trafico que los confirme.")) + "</div>")
    if not hallazgos:
        a("<p>" + esc(t("Sin hallazgos de las reglas de inventario.")) + "</p>")
    for f in hallazgos or []:
        a(f"<h3>{esc(t(f['severidad']))}: {esc(t(f['titulo']))}</h3>")
        a(f"<p>{esc(t(f['evidencia']))}</p>")
        refs = referencias_visibles(f, estandares)
        if refs:
            a("<ul>" + "".join(f"<li>{esc(n)}: {esc(txt)}</li>" for n, txt in refs) + "</ul>")

    if vulnerabilidades:
        vr = vulnerabilidades
        a("<h2>" + esc(t("Vulnerabilidades importadas")) + "</h2>")
        a(f'<div class="nota">{esc(t(_vuln.NOTA))}</div>')
        a("<p>" + esc(t("{total} filas en {archivo}: {asoc} asociadas a un activo, {sin} sin activo "
                        "en el inventario. Detalle en vulnerabilidades.csv.",
                        total=vr["total"], archivo=vr["archivo"], asoc=vr["asociadas"],
                        sin=vr["sin_activo"])) + "</p>")
        a("<table><thead><tr><th>" + esc(t("Severidad")) + "</th>"
          + "".join(f'<th class="num">{esc(t(e))}</th>' for e in _vuln._ESTADOS)
          + "</tr></thead><tbody>")
        for s, fila in vr["matriz"].items():
            a(f"<tr><td>{esc(t(s))}</td>" + "".join(f'<td class="num">{fila[e]}</td>' for e in _vuln._ESTADOS) + "</tr>")
        a("</tbody></table>")

    if alertas:
        a("<h2>" + esc(t("Alertas importadas")) + "</h2>")
        a(f'<div class="nota">{esc(t(_al.NOTA))}</div>')
        a(f"<p>{esc(_al.intro(alertas))}</p>")
        for cab, filas in _al.tablas_resumen(alertas):
            a("<table><thead><tr>" + "".join(f"<th>{esc(h)}</th>" for h in cab) + "</tr></thead><tbody>")
            for f in filas:
                a(f'<tr><td>{esc(f[0])}</td><td class="num">{f[1]}</td></tr>')
            a("</tbody></table>")

    if _zo.hay(zonas):
        a("<h2>" + esc(t(_zo.TITULO)) + "</h2>")
        a(f'<div class="nota">{esc(t(_zo.NOTA))}</div>')
        a(f'<p>{esc(_zo.resumen_texto(zonas))}</p>')
        cab, filas = _zo.tabla_reporte(zonas)
        a("<table><thead><tr>" + "".join(f"<th>{esc(c)}</th>" for c in cab) + "</tr></thead><tbody>")
        for fila in filas:
            a("<tr>" + "".join(f"<td>{esc(str(c))}</td>" for c in fila) + "</tr>")
        a("</tbody></table>")

    if _zc.hay(zcr):
        a("<h2>" + esc(t(_zc.TITULO)) + "</h2>")
        a(f'<div class="nota">{esc(t(_zc.NOTA))}</div>')
        a(f'<p>{esc(_zc.resumen_texto(zcr))}</p>')
        cab, filas = _zc.tabla_reporte(zcr)
        a("<table><thead><tr>" + "".join(f"<th>{esc(c)}</th>" for c in cab) + "</tr></thead><tbody>")
        for fila in filas:
            a("<tr>" + "".join(f"<td>{esc(str(c))}</td>" for c in fila) + "</tr>")
        a("</tbody></table>")
        if diagrama_zcr:
            a(f'<div class="diagrama">{diagrama_zcr.svg}</div>')
            if diagrama_zcr.nota:
                a(f'<div class="nota">{esc(diagrama_zcr.nota)}</div>')

    if rutas:
        flujos_fw(a, rutas, imp.conduits)

    if _fu.hay(fuentes):
        fuentes_html(a, fuentes)

    for i, d in enumerate(diagramas, 1):
        a(f"<h2>{i}. {esc(d.titulo)}</h2>")
        a(f'<p class="lead">{esc(d.descripcion)}</p>')
        a(f'<div class="diagrama">{d.svg}</div>')
        if d.nota:
            a(f'<div class="nota">{esc(d.nota)}</div>')

    n = len(diagramas) + 1
    a(f"<h2>{n}. " + esc(t("Datos de origen y calidad")) + "</h2>")
    a('<p class="lead">' + esc(t(
        "Plataforma: {fuente}. Agrupacion de los diagramas: {agrupacion}. "
        "Revise que cada campo se haya leido de la columna correcta.",
        fuente=imp.fuente, agrupacion=t(AGRUPACIONES.get(imp.agrupar, "nivel Purdue")))) + "</p>")
    if imp.mapeos["activos"] or r["activos"]:
        a(_tabla_mapeo("Activos", ACTIVOS, imp.mapeos["activos"]))
    a(_tabla_mapeo("Enlaces / comunicaciones", ENLACES, imp.mapeos["enlaces"]))
    if r["activos_nivel_por_tipo"]:
        a('<div class="nota">' + esc(t(
            "{n} activos no traian nivel Purdue y se ubicaron segun su tipo (PLC en nivel 1, HMI en "
            "nivel 2, servidores en nivel 3, equipos de red en infraestructura). Validar con el "
            "personal de planta.", n=r["activos_nivel_por_tipo"])) + "</div>")
    if imp.advertencias:
        a("<h3>" + esc(t("Advertencias")) + "</h3><ul class=\"q\">"
          + "".join(f"<li>{esc(x)}</li>" for x in imp.advertencias) + "</ul>")

    a("<h2>" + esc(t("Alcance")) + "</h2>")
    avisos = _avisos(estandares)
    a(f'<div class="nota">{esc(" ".join(avisos))}</div>' if avisos else "")
    a("<footer>" + esc(t(
        "Generado con ot_assess {version} el {ahora}. Los niveles y zonas son los informados por la "
        "plataforma cuando existen; los demas se infieren y requieren validacion.",
        version=__version__, ahora=ahora)) + "</footer></div></body></html>")
    out = outdir / "diagramas.html"
    out.write_text("\n".join(h), encoding="utf-8")
    return out
