"""Renderizado SVG de los diagramas. Solo texto: sin dependencias ni binarios externos."""
from __future__ import annotations

import collections
import math
from html import escape

from ..i18n import t as _tr
from .graph import Arista, Grafo, titulo_banda
from .layout import (
    ANCHO_ETIQUETA,
    MARGEN_DER,
    MARGEN_IZQ,
    NODO_H,
    NODO_W,
    Disposicion,
    disponer,
)

# Misma paleta que la hoja de estilo del reporte HTML.
TINTA, SUAVE, LINEA, PANEL, ACENTO = "#15202b", "#5b6b7c", "#dde3ea", "#f6f8fa", "#17486b"
BORDE = "#c5d0db"
CLARO = "#cfe0ee"           # texto secundario sobre ACENTO
CRIT = {"Critica": "#8b1a1a", "Alta": "#b4530a", "Media": "#8a6d00", "Baja": "#4a6b52"}
CRIT_TEXTO = {"Critica": "Critica (con escrituras)", "Alta": "Alta", "Media": "Media", "Baja": "Baja"}
FUENTE = "-apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif"
MONO = "ui-monospace, Consolas, Menlo, monospace"
# Al pasar el cursor sobre un conducto, los demas se atenuan y ese se resalta.
ESTILO = ("<style>svg.ot-dg .ot-e{transition:opacity .12s}"
          "svg.ot-dg:has(.ot-e:hover) .ot-e:not(:hover){opacity:.1}"
          "svg.ot-dg .ot-e:hover .v{stroke-width:5;stroke-opacity:1}</style>")
ENC_H = 76                   # alto del encabezado del archivo SVG autonomo

# tipo -> (nombre, relleno del icono, color de acento, punteado)
TIPOS = {
    "controlador": ("PLC / RTU / IED", "#e3eef7", "#17486b", False),
    "supervision": ("HMI / SCADA", "#e3f1ec", "#1f6b57", False),
    "ingenieria": ("Estacion de ingenieria", "#e8eefc", "#2f4f9e", False),
    "servidor": ("Servidor / historiador", "#f3ecdf", "#7a5a1e", False),
    "host": ("Host Windows", "#efe9f5", "#5e3f7a", False),
    "red": ("Equipo de red", "#eceff3", "#46566a", False),
    "firewall": ("Firewall / seguridad", "#fbe9e4", "#9b3b22", False),
    "ot": ("Dispositivo OT", "#e9f1f8", "#2d6f9e", False),
    "externo": ("Externo", "#fdecea", "#8b1a1a", True),
    "otro": ("Sin rol inferido", "#ffffff", "#5b6b7c", True),
    "zona": ("Zona", PANEL, ACENTO, False),
}

# Iconos de trazo en una rejilla de 24x24.
ICONOS = {
    "controlador": '<rect x="3" y="5" width="18" height="12" rx="2"/><path d="M7 17v3M12 17v3M17 17v3"/>'
                   '<circle cx="8" cy="11" r="1.3"/><path d="M12 11h5"/>',
    "supervision": '<rect x="3" y="4" width="18" height="12" rx="1.5"/><path d="M9 20h6M12 16v4"/>'
                   '<path d="M6 12.5l3-3.2 3 2 4-4.3"/>',
    "ingenieria": '<rect x="5" y="5" width="14" height="10" rx="1.2"/><path d="M3 19h18l-2-4H5z"/>'
                  '<path d="M10 8.5l-1.5 1.5 1.5 1.5M14 8.5l1.5 1.5-1.5 1.5"/>',
    "servidor": '<rect x="4" y="4" width="16" height="6" rx="1.3"/><rect x="4" y="13" width="16" height="6" rx="1.3"/>'
                '<path d="M7.5 7h.01M7.5 16h.01M12 7h5M12 16h5"/>',
    "host": '<rect x="4" y="4" width="16" height="11" rx="1.3"/><path d="M9 20h6M12 15v5"/>',
    "red": '<rect x="3" y="9" width="18" height="7" rx="1.5"/><path d="M7 12.5h.01M11 12.5h.01M15 12.5h.01"/>'
           '<path d="M12 3.5v5M10 5.5l2-2 2 2M12 20.5v-4M10 18.5l2 2 2-2"/>',
    "firewall": '<path d="M12 3l8 3v6c0 4.5-3.2 7.8-8 9-4.8-1.2-8-4.5-8-9V6z"/><path d="M9 12l2.2 2.2L15.5 10"/>',
    "ot": '<circle cx="12" cy="12" r="3"/><path d="M12 3v3M12 18v3M3 12h3M18 12h3M5.6 5.6l2.1 2.1M16.3 16.3l2.1 2.1'
          'M18.4 5.6l-2.1 2.1M7.7 16.3l-2.1 2.1"/>',
    "externo": '<path d="M6.5 18a4.5 4.5 0 0 1-.4-8.98A6 6 0 0 1 17.6 8.3 4.7 4.7 0 0 1 17.5 18z"/>',
    "otro": '<circle cx="12" cy="12" r="8"/><path d="M9.6 9.6a2.5 2.5 0 1 1 3.5 2.3c-.7.4-1.1.9-1.1 1.7M12 17h.01"/>',
    "zona": '<path d="M12 3l9 5-9 5-9-5z"/><path d="M3 12.5l9 5 9-5"/>',
}


def _e(s) -> str:
    return escape(str(s), quote=True)


def _trunc(s: str, n: int) -> str:
    return s if len(s) <= n else s[: n - 1] + "…"


def _lineas(s: str, n: int, maximo: int = 2) -> list:
    """Parte un texto en hasta `maximo` lineas de n caracteres, cortando en espacios."""
    out, actual = [], ""
    for palabra in s.split():
        if len(actual) + len(palabra) + (1 if actual else 0) <= n:
            actual = f"{actual} {palabra}".strip()
        else:
            if actual:
                out.append(actual)
            actual = palabra
    if actual:
        out.append(actual)
    if len(out) > maximo:
        out = out[:maximo]
        out[-1] = _trunc(out[-1] + "…", n)
    return [_trunc(x, n) for x in out] or [""]


def _pl(n: int, sing: str, plur: str) -> str:
    return sing if n == 1 else plur


def _ancho_linea(nbytes: int) -> float:
    return max(1.4, min(5.0, 0.8 + 0.45 * math.log10(nbytes + 10)))


def _volumen(n: float) -> str:
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.0f} {u}" if u == "B" else f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} PB"


def _icono(tipo: str, x: float, y: float, color: str, escala: float = 1.0) -> str:
    return (f'<g transform="translate({x:.1f},{y:.1f}) scale({escala})" fill="none" stroke="{color}" '
            f'stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">{ICONOS[tipo]}</g>')


def _defs(p: str) -> str:
    marcas = "".join(
        f'<marker id="{p}-m-{k}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="11" '
        f'markerHeight="11" markerUnits="userSpaceOnUse" orient="auto-start-reverse">'
        f'<path d="M0,0 L10,5 L0,10 z" fill="{c}"/></marker>'
        for k, c in CRIT.items())
    return f"<defs>{marcas}</defs>"


def _marcas(p: str, e: Arista) -> str:
    m = f"url(#{p}-m-{e.crit})"
    return (f' marker-end="{m}"' if e.fwd else "") + (f' marker-start="{m}"' if e.back else "")


def _estilo_linea(e: Arista) -> str:
    baja = e.crit == "Baja"
    dash = ' stroke-dasharray="6 4"' if (baja if e.discontinua is None else e.discontinua) else ""
    ancho = min(_ancho_linea(e.bytes), 2.2) if baja else _ancho_linea(e.bytes)
    return (f'fill="none" stroke="{CRIT.get(e.crit, SUAVE)}" '
            f'stroke-width="{ancho:.1f}" stroke-opacity="{0.55 if baja else 0.9}"{dash}')


def _trazo(d: str, e: Arista, p: str, na: str, nb: str) -> str:
    """Un conducto: area sensible ancha (para el cursor), trazo visible y tooltip."""
    return (f'<g class="ot-e"><path d="{d}" fill="none" stroke="transparent" stroke-width="14" '
            f'pointer-events="stroke"/><path class="v" d="{d}" {_estilo_linea(e)}{_marcas(p, e)}/>'
            f'{_tooltip(e, na, nb)}</g>')


def _tooltip(e: Arista, na: str, nb: str) -> str:
    if e.detalle:
        return "<title>" + "\n".join(_e(x) for x in [f"{na} - {nb}", *e.detalle.split("\n")]) + "</title>"
    svcs = ", ".join(s for s, _ in sorted(e.servicios.items(), key=lambda t: -t[1])[:6])
    resumen = _tr("{c} conductos, {p} paquetes, {v}", c=e.conductos, p=f"{e.pkts:,}", v=_volumen(e.bytes))
    lineas = [f"{na} - {nb}", _tr("Servicios: {s}", s=svcs), resumen,
              _tr("Escrituras: {n}", n=e.escrituras), _tr("Criticidad: {c}", c=_tr(e.crit))]
    return "<title>" + "\n".join(_e(x) for x in lineas) + "</title>"


def _etiqueta(x: float, y: float, linea1: str, linea2: str = "", ancla: str = "middle") -> str:
    halo = 'stroke="#ffffff" stroke-width="4" stroke-linejoin="round" paint-order="stroke"'
    out = (f'<text x="{x:.1f}" y="{y:.1f}" text-anchor="{ancla}" font-size="11" '
           f'font-weight="600" fill="{TINTA}" {halo}>{_e(linea1)}</text>')
    if linea2:
        out += (f'<text x="{x:.1f}" y="{y + 13:.1f}" text-anchor="{ancla}" font-size="10" '
                f'fill="{SUAVE}" {halo}>{_e(linea2)}</text>')
    return out


def _pildora(x: float, y: float, texto: str, color: str) -> str:
    """Rotulo en capsula centrado en (x, y)."""
    w = 6.0 * len(texto) + 22
    return (f'<g><rect x="{x - w / 2:.1f}" y="{y - 10:.1f}" width="{w:.1f}" height="20" rx="10" '
            f'fill="#ffffff" stroke="{BORDE}"/><circle cx="{x - w / 2 + 10:.1f}" cy="{y:.1f}" r="3.2" '
            f'fill="{color}"/><text x="{x + 4:.1f}" y="{y + 3.8:.1f}" text-anchor="middle" font-size="10.5" '
            f'font-weight="600" fill="{TINTA}">{_e(texto)}</text></g>')


def _leyenda_zcr(y: float, ancho: int) -> tuple[str, int]:
    """Leyenda de la vista ZCR: linea continua = conducto con brechas marcadas; punteada = sin brechas."""
    ty = y + 26
    o = [f'<rect x="0" y="{y:.0f}" width="{ancho}" height="1" fill="{LINEA}"/>',
         (f'<text x="14" y="{ty:.0f}" font-size="11" font-weight="700" fill="{ACENTO}">'
          f'{_e(_tr("CONDUCTO ENTRE ZONAS"))}</text>')]
    x = 196
    for k, texto in (("Alta", _tr("Con brechas marcadas (revisar)")), ("Baja", _tr("Sin brechas marcadas"))):
        dash = ' stroke-dasharray="6 4"' if k == "Baja" else ""
        o.append(f'<line x1="{x}" y1="{ty - 4:.0f}" x2="{x + 30}" y2="{ty - 4:.0f}" '
                 f'stroke="{CRIT[k]}" stroke-width="3"{dash}/>')
        o.append(f'<text x="{x + 36}" y="{ty:.0f}" font-size="11" fill="{TINTA}">{_e(texto)}</text>')
        x += 36 + 6.4 * len(texto) + 26
    nota = _tr("Etiqueta: id del conducto y numero de servicios. Las brechas son marcas para revisar, "
               "no juicios de cumplimiento.")
    o.append(f'<text x="14" y="{ty + 26:.0f}" font-size="10.5" fill="{SUAVE}">{_e(nota)}</text>')
    return "".join(o), 62


def _leyenda_tobe(y: float, ancho: int, texto: str) -> tuple[str, int]:
    """Leyenda de la vista TO-BE (T1a): continua = permitir; discontinua = por DMZ; el resto, en el texto."""
    ty = y + 26
    o = [f'<rect x="0" y="{y:.0f}" width="{ancho}" height="1" fill="{LINEA}"/>',
         (f'<text x="14" y="{ty:.0f}" font-size="11" font-weight="700" fill="{ACENTO}">'
          f'{_e(_tr("COMUNICACION PROPUESTA"))}</text>')]
    x = 196
    for k, dash, rotulo in (("Baja", "", _tr("Permitir (pares observados)")),
                            ("Media", ' stroke-dasharray="6 4"', _tr("Por DMZ (origen - DMZ - destino)"))):
        o.append(f'<line x1="{x}" y1="{ty - 4:.0f}" x2="{x + 30}" y2="{ty - 4:.0f}" '
                 f'stroke="{CRIT[k]}" stroke-width="3"{dash}/>')
        o.append(f'<text x="{x + 36}" y="{ty:.0f}" font-size="11" fill="{TINTA}">{_e(rotulo)}</text>')
        x += 36 + 6.4 * len(rotulo) + 26
    lineas = texto.split("\n")
    for n, linea in enumerate(lineas):
        o.append(f'<text x="14" y="{ty + 26 + 15 * n:.0f}" font-size="10.5" fill="{SUAVE}">{_e(linea)}</text>')
    return "".join(o), 50 + 15 * len(lineas)


def _leyenda(y: float, ancho: int, tipos: list, zonas: bool) -> tuple[str, int]:
    o = [f'<rect x="0" y="{y:.0f}" width="{ancho}" height="1" fill="{LINEA}"/>']
    ty = y + 26
    o.append(f'<text x="14" y="{ty:.0f}" font-size="11" font-weight="700" fill="{ACENTO}">'
             f'{_e(_tr("CRITICIDAD DEL CONDUCTO"))}</text>')
    x = 196
    for k in ("Critica", "Alta", "Media", "Baja"):
        dash = ' stroke-dasharray="6 4"' if k == "Baja" else ""
        o.append(f'<line x1="{x}" y1="{ty - 4:.0f}" x2="{x + 30}" y2="{ty - 4:.0f}" '
                 f'stroke="{CRIT[k]}" stroke-width="3"{dash}/>')
        o.append(f'<text x="{x + 36}" y="{ty:.0f}" font-size="11" fill="{TINTA}">{_e(_tr(CRIT_TEXTO[k]))}</text>')
        x += 36 + 6.4 * len(_tr(CRIT_TEXTO[k])) + 26
    alto = 40
    if not zonas and tipos:
        ty += 30
        o.append(f'<text x="14" y="{ty:.0f}" font-size="11" font-weight="700" fill="{ACENTO}">'
                 f'{_e(_tr("TIPO DE EQUIPO"))}</text>')
        x = 196
        for t in tipos:
            nombre, _, color, _ = TIPOS[t]
            nombre = _tr(nombre)
            ancho_item = 24 + 6.4 * len(nombre) + 24
            if x + ancho_item > ancho - 16:          # no cabe: sigue en otra linea
                x, ty, alto = 196, ty + 24, alto + 24
            o.append(_icono(t, x, ty - 16, color, 0.8))
            o.append(f'<text x="{x + 24}" y="{ty:.0f}" font-size="11" fill="{TINTA}">{_e(nombre)}</text>')
            x += ancho_item
        alto += 30
    ty += 26
    nota = _tr("Grosor proporcional al volumen. Flecha: sentido observado (dos puntas: bidireccional). "
               "Linea punteada: criticidad baja.")
    if not zonas:
        nota += " " + _tr("Marca W: el equipo recibe escrituras al proceso.")
    o.append(f'<text x="14" y="{ty:.0f}" font-size="10.5" fill="{SUAVE}">{_e(nota)}</text>')
    return "".join(o), alto + 22


def _envolver(p: str, ancho: int, alto: int, titulo: str, cuerpo: str, enc: dict | None) -> str:
    if enc:
        sub = _e(enc.get("subtitulo", ""))
        cabecera = (f'<rect width="{ancho}" height="{ENC_H}" fill="{ACENTO}"/>'
                    f'<text x="24" y="34" font-size="19" font-weight="700" fill="#ffffff">'
                    f'{_e(enc.get("titulo", titulo))}</text>'
                    f'<text x="24" y="57" font-size="11.5" fill="{CLARO}">{sub}</text>')
        cuerpo = f'{cabecera}<g transform="translate(0,{ENC_H})">{cuerpo}</g>'
        alto += ENC_H
    return (f'<svg xmlns="http://www.w3.org/2000/svg" class="ot-dg" width="{ancho}" height="{alto}" '
            f'viewBox="0 0 {ancho} {alto}" role="img" aria-labelledby="{p}-t" '
            f'font-family="{FUENTE}">'
            f'<title id="{p}-t">{_e(titulo)}</title>{ESTILO}'
            f'<rect width="{ancho}" height="{alto}" fill="#ffffff"/>{_defs(p)}{cuerpo}'
            f'<rect x="0.5" y="0.5" width="{ancho - 1}" height="{alto - 1}" fill="none" stroke="{BORDE}"/></svg>')


# --------------------------------------------------------------------------- #
# Vista por activo
# --------------------------------------------------------------------------- #


def _anclas(g: Grafo, lay: Disposicion) -> dict:
    """Reparte los puntos de entrada y salida en cada nodo para que las flechas no se encimen."""
    ext = collections.defaultdict(lambda: {"abajo": [], "arriba": []})
    for i, e in enumerate(g.aristas):
        (ax, ay), (bx, by) = lay.pos[e.a], lay.pos[e.b]
        if by > ay:
            la, lb = "abajo", "arriba"
        elif by < ay:
            la, lb = "arriba", "abajo"
        else:
            la = lb = "arriba"          # misma fila: arco por arriba
        ext[e.a][la].append((bx, i))
        ext[e.b][lb].append((ax, i))
    anclas = {}
    for nid, lados in ext.items():
        x, y = lay.pos[nid]
        for lado, lst in lados.items():
            lst.sort()
            k = len(lst)
            paso = min(22.0, (NODO_W - 40) / max(k - 1, 1))
            for r, (_, i) in enumerate(lst):
                dy = NODO_H / 2 if lado == "abajo" else -NODO_H / 2
                anclas[(i, nid)] = (x + (r - (k - 1) / 2) * paso, y + dy)
    return anclas


def _libre(x: float, ocupado: list, xmin: float, xmax: float) -> float:
    """Posicion x libre mas cercana a la pedida: la propia si queda holgura; si no, el centro
    del pasillo entre tarjetas mas cercano. Los pasillos exteriores solo cuentan si son anchos
    (uno estrecho pegado al borde se ve como un trazo que se dobla sobre si mismo)."""
    iv = sorted(ocupado)
    cand = [x] if all(x < a - 4 or x > b + 4 for a, b in iv) else []
    bordes = [xmin] + [v for a, b in iv for v in (a, b)] + [xmax]
    for k, (lo, hi) in enumerate(zip(bordes[0::2], bordes[1::2])):   # [xmin,a0] [b0,a1] ... [bn,xmax]
        exterior = k == 0 or k == len(iv)
        if hi - lo >= (60 if exterior else 12):
            cand.append((lo + hi) / 2)
    return min(cand, key=lambda c: abs(c - x)) if cand else x


def _punto_s(p1, p2, t: float) -> tuple:
    """Punto de la curva en S (tangentes verticales) entre dos anclas, con t en [0, 1]."""
    my = (p1[1] + p2[1]) / 2
    u = 1 - t
    x = p1[0] * (u ** 3 + 3 * u * u * t) + p2[0] * (3 * u * t * t + t ** 3)
    y = p1[1] * u ** 3 + my * 3 * u * t * (u + t) + p2[1] * t ** 3
    return x, y


def _choca(p1, p2, fila) -> bool:
    """True si la curva directa atraviesa alguna tarjeta de esa fila."""
    y_arriba, y_abajo, ocupado = fila
    for i in range(61):
        x, y = _punto_s(p1, p2, i / 60)
        if y_arriba - 4 <= y <= y_abajo + 4 and any(a <= x <= b for a, b in ocupado):
            return True
    return False


def _ruta(p1, p2, fa, fb, lay, ancho, usos):
    """Trazo entre dos anclas. Solo si la curva directa atraviesa una tarjeta de una fila
    intermedia, baja recto por un pasillo entre tarjetas de esa fila (asi no parece que
    conecta con un equipo ajeno). `usos` reparte en carriles paralelos los trazos que
    comparten pasillo."""
    pts = [p1]
    paso = 1 if fb > fa else -1
    for k in range(fa + paso, fb, paso):
        if not _choca(p1, p2, lay.filas[k]):
            continue
        y_arriba, y_abajo, ocupado = lay.filas[k]
        ym = (y_arriba + y_abajo) / 2
        t = (ym - p1[1]) / (p2[1] - p1[1])
        xw = _libre(p1[0] + (p2[0] - p1[0]) * t, ocupado, MARGEN_IZQ, ancho - MARGEN_DER)
        n = usos[(k, round(xw / 20))]
        usos[(k, round(xw / 20))] += 1
        xw += (n % 5 - 2) * 4.5                       # carriles de 4.5 px dentro del pasillo
        pts += [(xw, y_arriba - 8), (xw, y_abajo + 8)]
    pts.append(p2)
    d = f"M{p1[0]:.1f},{p1[1]:.1f}"
    for (xa, ya), (xb, yb) in zip(pts, pts[1:]):
        my = (ya + yb) / 2
        d += f" C{xa:.1f},{my:.1f} {xb:.1f},{my:.1f} {xb:.1f},{yb:.1f}"
    medio = pts[len(pts) // 2] if len(pts) > 2 else _punto_s(p1, p2, 0.5)
    return d, medio


def _tarjeta(n, x: float, y: float) -> str:
    x0, y0 = x - NODO_W / 2, y - NODO_H / 2
    nombre, tinte, color, punteado = TIPOS[n.tipo]
    nombre = _tr(nombre)
    recibe = n.escrituras_recibidas > 0
    trazo = CRIT["Critica"] if recibe else BORDE
    dash = ' stroke-dasharray="5 3"' if punteado else ""
    linea3 = _trunc(n.modelo, 25) if n.modelo else nombre
    det = f"\n{n.detalle}" if n.detalle else ""
    wr = _tr(", escrituras recibidas: {n}", n=n.escrituras_recibidas) if recibe else ""
    paq = _tr("Paquetes: {n}", n=f"{n.pkts:,}")
    tx = x0 + 50
    return (
        f'<g><title>{_e(n.etiqueta)}\n{_e(nombre)}{_e(det)}\n{_e(paq)}{_e(wr)}</title>'
        f'<rect x="{x0:.1f}" y="{y0:.1f}" width="{NODO_W}" height="{NODO_H}" rx="8" fill="#ffffff" '
        f'stroke="{trazo}" stroke-width="{2.4 if recibe else 1.2}"{dash}/>'
        f'<path d="M{x0 + 8:.1f},{y0:.1f} H{x0 + 3:.1f} a3,3 0 0 0 -3,3 V{y0 + NODO_H - 3:.1f} a3,3 0 0 0 3,3 H{x0 + 8:.1f} z" '
        f'fill="{color}"/>'
        f'<circle cx="{x0 + 29:.1f}" cy="{y:.1f}" r="16" fill="{tinte}"/>'
        + _icono(n.tipo, x0 + 17, y - 12, color)
        + f'<text x="{tx:.1f}" y="{y0 + 20:.1f}" font-size="12" font-weight="700" fill="{TINTA}">'
          f'{_e(_trunc(n.etiqueta, 17))}</text>'
        + (f'<text x="{tx:.1f}" y="{y0 + 34:.1f}" font-size="10.5" font-family="{MONO}" fill="{SUAVE}">'
           f'{_e(_trunc(n.sub, 20))}</text>' if n.sub else "")
        + f'<text x="{tx:.1f}" y="{y0 + 49:.1f}" font-size="9.5" fill="{color}">{_e(linea3)}</text>'
        + (f'<circle cx="{x0 + NODO_W:.1f}" cy="{y0:.1f}" r="9" fill="{CRIT["Critica"]}"/>'
           f'<text x="{x0 + NODO_W:.1f}" y="{y0 + 3.6:.1f}" text-anchor="middle" font-size="10" '
           f'font-weight="700" fill="#ffffff">W</text>' if recibe else "")
        + "</g>")


def render_topologia(g: Grafo, prefijo: str = "t", ancho: int = 1280, encabezado: dict | None = None) -> str:
    lay = disponer(g, ancho)
    nodos = {n.id: n for n in g.nodos}
    por_banda = collections.Counter(n.banda for n in g.nodos)
    anclas = _anclas(g, lay)
    fondo, aristas, caja, rotulos = [], [], [], []
    mids = {}
    usos = collections.Counter()

    for i, (b, y0, y1) in enumerate(lay.bandas):
        fondo.append(f'<rect x="{ANCHO_ETIQUETA}" y="{y0}" width="{ancho - ANCHO_ETIQUETA}" height="{y1 - y0}" '
                     f'fill="{PANEL if i % 2 == 0 else "#ffffff"}"/>')
        fondo.append(f'<rect x="0" y="{y0 + 1}" width="{ANCHO_ETIQUETA}" height="{y1 - y0 - 2}" fill="{ACENTO}"/>')
        t1, _, t2 = titulo_banda(b).partition(" - ")
        y = y0 + 28
        for linea in _lineas(t1, 19):
            fondo.append(f'<text x="14" y="{y}" font-size="12.5" font-weight="700" fill="#ffffff">{_e(linea)}</text>')
            y += 15
        if t2:
            for linea in _lineas(t2, 24):
                fondo.append(f'<text x="14" y="{y}" font-size="10.5" fill="{CLARO}">{_e(linea)}</text>')
                y += 13
        k = por_banda[b]
        fondo.append(f'<text x="14" y="{y + 6}" font-size="10" fill="#9fbad0">{k} {_pl(k, _tr("equipo"), _tr("equipos"))}</text>')

    # Las criticas se dibujan al final para que queden por encima.
    orden = sorted(range(len(g.aristas)), key=lambda i: _peso(g.aristas[i].crit))
    for i in orden:
        e = g.aristas[i]
        (x1, y1), (x2, y2) = anclas[(i, e.a)], anclas[(i, e.b)]
        if lay.pos[e.a][1] == lay.pos[e.b][1]:
            h = min(44.0, 18 + abs(x2 - x1) * 0.08)
            d = f"M{x1:.1f},{y1:.1f} C{x1:.1f},{y1 - h:.1f} {x2:.1f},{y2 - h:.1f} {x2:.1f},{y2:.1f}"
            mids[i] = ((x1 + x2) / 2, y1 - 0.75 * h)
        else:
            d, mids[i] = _ruta((x1, y1), (x2, y2), lay.fila_de[e.a], lay.fila_de[e.b], lay, ancho, usos)
        aristas.append(_trazo(d, e, prefijo, nodos[e.a].etiqueta, nodos[e.b].etiqueta))

    for n in g.nodos:
        caja.append(_tarjeta(n, *lay.pos[n.id]))

    # Rotulos solo en los conductos con escritura; el resto queda en el tooltip.
    con_w = sorted((i for i, e in enumerate(g.aristas) if e.escrituras),
                   key=lambda i: -g.aristas[i].escrituras)[:8]
    for i in con_w:
        e = g.aristas[i]
        svc = max(e.servicios, key=e.servicios.get)
        mx, my = mids[i]
        escr = _tr("{n} escr.", n=e.escrituras)
        rotulos.append(_pildora(mx, my, f"{_trunc(svc, 22)} - {escr}", CRIT["Critica"]))

    tipos = [t for t in TIPOS if t != "zona" and any(n.tipo == t for n in g.nodos)]
    leyenda, alto_ley = _leyenda(lay.alto + 6, ancho, tipos, zonas=False)
    return _envolver(prefijo, ancho, lay.alto + 6 + alto_ley,
                     _tr("Diagrama de comunicaciones por activo"),
                     "".join(fondo + aristas + caja + rotulos) + leyenda, encabezado)


def _peso(crit: str) -> int:
    return {"Critica": 3, "Alta": 2, "Media": 1}.get(crit, 0)


# --------------------------------------------------------------------------- #
# Vista por zona
# --------------------------------------------------------------------------- #


def render_zonas(g: Grafo, prefijo: str = "z", encabezado: dict | None = None) -> str:
    X0, W, H, GAP = 56, 420, 72, 92
    y_de = {n.id: 18 + i * (H + GAP) for i, n in enumerate(g.nodos)}
    idx = {n.id: i for i, n in enumerate(g.nodos)}
    titulos = {n.id: n.etiqueta for n in g.nodos}
    cx = X0 + W / 2
    cuerpo, rotulos = [], []

    salidas = collections.Counter()      # arcos que salen del lado derecho de cada caja
    arcos = [(e, abs(idx[e.b] - idx[e.a])) for e in g.aristas]
    max_span = max([s for _, s in arcos if s > 1] or [1])
    ancho = max(760, X0 + W + 60 + 38 * max_span + 340)

    for e, span in sorted(arcos, key=lambda t: _peso(t[0].crit)):
        ya, yb = y_de[e.a], y_de[e.b]
        txt1 = f"{e.conductos} {_pl(e.conductos, _tr('conducto'), _tr('conductos'))}" + (
            " - " + _tr("{n} con escritura", n=e.escrituras) if e.escrituras else "")
        svcs = [s for s, _ in sorted(e.servicios.items(), key=lambda t: -t[1])]
        txt2 = ", ".join(_trunc(s, 16) for s in svcs[:2]) + (f" +{len(svcs) - 2}" if len(svcs) > 2 else "")
        if e.rotulo:
            txt1, txt2 = e.rotulo, e.rotulo2
        if span == 1:
            d = f"M{cx:.1f},{ya + H} L{cx:.1f},{yb}"
            lx, ly, ancla = cx + 14, (ya + H + yb) / 2 - 2, "start"
        else:
            k_a, k_b = salidas[e.a], salidas[e.b]
            salidas[e.a] += 1
            salidas[e.b] += 1
            xr = X0 + W
            xo = xr + 46 + 38 * (span - 1)
            y1, y2 = ya + 24 + 14 * k_a, yb + 24 + 14 * k_b
            d = f"M{xr},{y1} C{xo},{y1} {xo},{y2} {xr},{y2}"
            lx, ly, ancla = xo + 10, (y1 + y2) / 2 - 2, "start"
        cuerpo.append(_trazo(d, e, prefijo, titulos[e.a], titulos[e.b]))
        rotulos.append(_etiqueta(lx, ly, txt1, txt2, ancla))

    cajas = []
    for n in g.nodos:
        y = y_de[n.id]
        _, tinte, color, punteado = TIPOS[n.tipo]
        dash = ' stroke-dasharray="5 3"' if punteado else ""
        interno = g.internos.get(n.id, 0)
        sub = n.sub + (f" - {interno} {_pl(interno, _tr('conducto interno'), _tr('conductos internos'))}"
                       if interno else "")
        cajas.append(
            f'<g><title>{_e(n.etiqueta)}\n{_e(sub)}</title>'
            f'<rect x="{X0}" y="{y}" width="{W}" height="{H}" rx="9" fill="#ffffff" stroke="{BORDE}" '
            f'stroke-width="1.3"{dash}/>'
            f'<path d="M{X0 + 9},{y} H{X0 + 4} a4,4 0 0 0 -4,4 V{y + H - 4} a4,4 0 0 0 4,4 H{X0 + 9} z" fill="{color}"/>'
            f'<circle cx="{X0 + 38}" cy="{y + H / 2}" r="19" fill="{tinte}"/>'
            + _icono("externo" if n.tipo == "externo" else "zona", X0 + 26, y + H / 2 - 12, color)
            + f'<text x="{X0 + 68}" y="{y + 30}" font-size="13.5" font-weight="700" fill="{TINTA}">'
              f'{_e(_trunc(n.etiqueta, 40))}</text>'
              f'<text x="{X0 + 68}" y="{y + 50}" font-size="11" fill="{SUAVE}">{_e(sub)}</text></g>')

    alto = 18 + len(g.nodos) * (H + GAP) - GAP + 24
    if g.tobe:
        leyenda, alto_ley = _leyenda_tobe(alto, ancho, g.tobe)
    else:
        leyenda, alto_ley = _leyenda_zcr(alto, ancho) if g.zcr else _leyenda(alto, ancho, [], zonas=True)
    return _envolver(prefijo, ancho, alto + alto_ley,
                     _tr("Segmentacion propuesta (TO-BE)") if g.tobe else _tr("Diagrama de zonas y conductos"),
                     "".join(cuerpo + cajas + rotulos) + leyenda, encabezado)
