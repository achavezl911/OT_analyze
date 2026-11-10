"""Exportacion a Mermaid: texto editable que GitHub, GitLab, Notion o draw.io entienden."""
from __future__ import annotations

from ..i18n import t
from .graph import Grafo, titulo_banda
from .svg import CRIT, _ancho_linea


def _q(s: str) -> str:
    """Texto seguro dentro de comillas de Mermaid."""
    return (s or "").replace('"', "'").replace("#", "").replace("<", "(").replace(">", ")")


def render_mermaid(g: Grafo) -> str:
    ids = {n.id: f"n{i}" for i, n in enumerate(g.nodos)}

    def caja(n) -> str:
        texto = _q(n.etiqueta) + (f"<br/>{_q(n.sub)}" if n.sub else "")
        return f'{ids[n.id]}["{texto}"]'

    out = ["flowchart TB"]
    if g.zonas:
        out += [f"  {caja(n)}" for n in g.nodos]
    else:
        for k, b in enumerate(g.bandas):
            out.append(f'  subgraph s{k}["{_q(titulo_banda(b))}"]')
            out += [f"    {caja(n)}" for n in g.nodos if n.banda == b]
            out.append("  end")

    estilos = []
    for i, e in enumerate(g.aristas):
        a, b = ids[e.a], ids[e.b]
        if e.fwd and e.back:
            flecha = "<-->"
        else:
            flecha = "-->"
            if e.back:
                a, b = b, a
        svcs = sorted(e.servicios, key=e.servicios.get, reverse=True)
        txt = svcs[0] if svcs else ""
        if len(svcs) > 1:
            txt += f" +{len(svcs) - 1}"
        if e.escrituras:
            txt += " - " + t("{n} escr.", n=e.escrituras)
        if e.rotulo:
            txt = " - ".join(x for x in (e.rotulo, e.rotulo2) if x)
        out.append(f'  {a} {flecha}|"{_q(txt)}"| {b}')
        estilos.append(f"  linkStyle {i} stroke:{CRIT.get(e.crit, '#5b6b7c')},"
                       f"stroke-width:{_ancho_linea(e.bytes):.1f}px")
    return "\n".join(out + estilos) + "\n"
