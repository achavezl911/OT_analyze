"""Posicionamiento de nodos por bandas (una banda por nivel Purdue).

Dentro de cada banda los nodos se ordenan con la heuristica del baricentro
(posicion media de sus vecinos en otras bandas) para reducir cruces.
"""
from __future__ import annotations

import math
from dataclasses import dataclass

from .graph import Grafo

ANCHO_ETIQUETA = 164  # columna con el titulo de cada banda
MARGEN_IZQ = 184      # donde empiezan los nodos
MARGEN_DER = 24
NODO_W = 184
NODO_H = 60
SEP_X = 16
SEP_Y = 62
PAD_ARRIBA = 54       # aire para los arcos de aristas dentro de una misma fila
PAD_ABAJO = 22
TOPE = 10


@dataclass
class Disposicion:
    pos: dict            # id -> (x, y) del centro del nodo
    bandas: list         # (banda, y0, y1)
    ancho: int
    alto: int            # alto de las bandas; la leyenda se agrega aparte
    filas: list = None   # una por fila de nodos, de arriba a abajo: (y_arriba, y_abajo, [(x0, x1), ...])
    fila_de: dict = None  # id -> indice en `filas`


def _ordenar(g: Grafo) -> dict:
    orden = {b: sorted((n for n in g.nodos if n.banda == b), key=lambda n: (-n.pkts, n.id))
             for b in g.bandas}
    orden = {b: [n.id for n in ns] for b, ns in orden.items()}
    vecinos: dict = {n.id: [] for n in g.nodos}
    banda_de = {n.id: n.banda for n in g.nodos}
    for e in g.aristas:
        if banda_de[e.a] != banda_de[e.b]:
            vecinos[e.a].append(e.b)
            vecinos[e.b].append(e.a)

    for it in range(4):
        for b in (g.bandas if it % 2 == 0 else reversed(g.bandas)):
            rel = {i: (k + 0.5) / len(ids) for ids in orden.values() for k, i in enumerate(ids)}

            def baricentro(i):
                v = vecinos[i]
                return sum(rel[x] for x in v) / len(v) if v else rel[i]

            orden[b].sort(key=baricentro)
    return orden


def disponer(g: Grafo, ancho: int = 1280) -> Disposicion:
    orden = _ordenar(g)
    util = ancho - MARGEN_IZQ - MARGEN_DER
    por_fila = max(1, min(TOPE, util // (NODO_W + SEP_X)))
    pos, bandas, filas_y, fila_de = {}, [], [], {}
    y = 8
    for b in g.bandas:
        ids = orden[b]
        filas = [ids[i:i + por_fila] for i in range(0, len(ids), por_fila)]
        y0 = y
        top = y + PAD_ARRIBA
        for r, fila in enumerate(filas):
            cy = top + NODO_H / 2 + r * (NODO_H + SEP_Y)
            ocupado = []
            for k, nid in enumerate(fila):
                pos[nid] = (MARGEN_IZQ + (k + 0.5) * util / len(fila), cy)
                fila_de[nid] = len(filas_y)
                ocupado.append((pos[nid][0] - NODO_W / 2 - 6, pos[nid][0] + NODO_W / 2 + 6))
            filas_y.append((cy - NODO_H / 2, cy + NODO_H / 2, ocupado))
        y = top + len(filas) * NODO_H + (len(filas) - 1) * SEP_Y + PAD_ABAJO
        bandas.append((b, y0, y))
    return Disposicion(pos, bandas, ancho, int(math.ceil(y)) + 6, filas_y, fila_de)
