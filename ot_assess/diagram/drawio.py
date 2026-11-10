"""Exporta un Grafo a draw.io (diagrams.net): XML abierto, sin comprimir, editable por el cliente.

Misma disposicion que el SVG (layout.disponer) y mismos colores (svg.TIPOS, svg.CRIT).
Ids deterministas y ningun dato variable: dos corridas dan los mismos bytes.
"""
from __future__ import annotations

from xml.sax.saxutils import escape

from .graph import Grafo, titulo_banda
from .layout import NODO_H, NODO_W, disponer
from .svg import BORDE, CRIT, PANEL, SUAVE, TIPOS

_ENT = {'"': "&quot;", "'": "&apos;", "\n": "&#10;"}
MAX_SERV = 3


def _a(s) -> str:
    return escape(str(s), _ENT)


def _servicios(servicios: dict) -> str:
    orden = sorted(servicios.items(), key=lambda kv: (-kv[1], kv[0]))
    txt = ", ".join(s for s, _ in orden[:MAX_SERV])
    return txt + (f" +{len(orden) - MAX_SERV}" if len(orden) > MAX_SERV else "")


def render_drawio(g: Grafo, titulo: str, slug: str = "diagrama") -> str:
    d = disponer(g)
    celdas = []
    ids_b = {}
    for i, (b, y0, y1) in enumerate(d.bandas):
        ids_b[b] = f"b{i}"
        estilo = (f"rounded=0;html=0;whiteSpace=wrap;fillColor={PANEL};strokeColor={BORDE};"
                  f"fontColor={SUAVE};fontStyle=1;align=left;verticalAlign=top;spacingLeft=8;spacingTop=4")
        celdas.append(
            f'<mxCell id="b{i}" value="{_a(titulo_banda(b))}" style="{estilo}" vertex="1" parent="1">'
            f'<mxGeometry x="0" y="{y0:g}" width="{d.ancho}" height="{y1 - y0:g}" as="geometry"/></mxCell>')
    ids_n = {}
    for i, n in enumerate(g.nodos):
        ids_n[n.id] = f"n{i}"
        _, relleno, acento, punteado = TIPOS.get(n.tipo, TIPOS["otro"])
        estilo = (f"rounded=1;html=0;whiteSpace=wrap;fillColor={relleno};strokeColor={acento};"
                  f"fontColor=#15202b" + (";dashed=1" if punteado else ""))
        valor = n.etiqueta + (f"\n{n.sub}" if n.sub else "")
        x, y = d.pos[n.id]
        celdas.append(
            f'<mxCell id="n{i}" value="{_a(valor)}" style="{estilo}" vertex="1" parent="1">'
            f'<mxGeometry x="{x - NODO_W / 2:g}" y="{y - NODO_H / 2:g}" width="{NODO_W}" '
            f'height="{NODO_H}" as="geometry"/></mxCell>')
    for i, e in enumerate(g.aristas):
        estilo = (f"edgeStyle=orthogonalEdgeStyle;rounded=0;html=0;strokeColor={CRIT.get(e.crit, SUAVE)};"
                  f"strokeWidth=2;endArrow={'classic' if e.fwd else 'none'};"
                  f"startArrow={'classic' if e.back else 'none'}")
        celdas.append(
            f'<mxCell id="e{i}" value="{_a(e.rotulo + " - " + e.rotulo2 if e.rotulo else _servicios(e.servicios))}" style="{estilo}" edge="1" '
            f'parent="1" source="{ids_n[e.a]}" target="{ids_n[e.b]}">'
            f'<mxGeometry relative="1" as="geometry"/></mxCell>')
    return (
        '<mxfile host="ot_assess">'
        f'<diagram id="{_a(slug)}" name="{_a(titulo)}">'
        f'<mxGraphModel grid="1" gridSize="10" page="1" pageWidth="{d.ancho}" pageHeight="{d.alto}">'
        '<root><mxCell id="0"/><mxCell id="1" parent="0"/>'
        + "".join(celdas) + "</root></mxGraphModel></diagram></mxfile>\n")
