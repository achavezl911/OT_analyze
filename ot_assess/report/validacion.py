"""validacion_captura.html: pagina simple del subcomando `validar-captura` (C1, D80). Solo lee el resultado."""
from __future__ import annotations

from datetime import datetime
from html import escape as esc
from pathlib import Path

from .. import __version__
from .. import cobertura_captura as cc
from ..i18n import idioma, t
from .style import HTML_CSS

ARCHIVO = "validacion_captura.html"


def tabla_html(cab: list, filas: list) -> str:
    return ('<div class="tbl"><table><thead><tr>' + "".join(f"<th>{esc(str(c))}</th>" for c in cab)
            + "</tr></thead><tbody>"
            + "".join("<tr>" + "".join(f"<td>{esc(str(c))}</td>" for c in f) + "</tr>" for f in filas)
            + "</tbody></table></div>")


def cuerpo(rep: dict) -> str:
    """Titulo, nota, resumen y las dos tablas de la seccion (la usa tambien el reporte completo)."""
    s = cc.seccion(rep)
    return (f"<h2>{esc(s['titulo'])}</h2><div class=\"nota\">{esc(s['nota'])}</div><p>{esc(s['resumen'])}</p>"
            + tabla_html(*s["tabla"]) + tabla_html(*s["tabla_zonas"]))


def write_validacion(rep: dict, outdir: Path, perfil: dict | None = None) -> Path:
    ahora = datetime.now().astimezone().strftime("%d/%m/%Y %H:%M")
    cliente = (perfil or {}).get("cliente", "")
    titulo = t(cc.TITULO)
    html = (f'<!doctype html><html lang="{idioma()}"><head><meta charset="utf-8">'
            f"<title>{esc(titulo)}</title><style>{HTML_CSS}</style></head><body>"
            f'<header class="port"><div class="inner"><h1>{esc(titulo)}</h1>'
            f"<p>{esc(cliente)} &middot; {esc(t('Generado el {now}', now=ahora))} &middot; ot_assess "
            f'{esc(__version__)}</p></div></header><div class="wrap">{cuerpo(rep)}</div></body></html>')
    p = outdir / ARCHIVO
    p.write_text(html, encoding="utf-8")
    return p
