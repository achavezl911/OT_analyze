"""Modelo de grafo de los diagramas: nodos, aristas y bandas (zonas Purdue).

Dos vistas salen del mismo grafo base:
  - por activo: un nodo por equipo, acotado a los de mayor riesgo y volumen;
  - por zona: un nodo por nivel Purdue, con los conductos agregados entre zonas.
"""
from __future__ import annotations

import collections
from dataclasses import dataclass, field

from ..catalog import CRIT_ORDER
from ..i18n import t
from ..roles import mostrar as mostrar_rol
from ..util import is_private

# De arriba hacia abajo en el diagrama. Una banda con otro nombre (por ejemplo una zona de
# seguridad definida en una plataforma OT) va despues de estas y antes de "Sin clasificar".
BANDAS = ["Externo", "Nivel 5", "Nivel 4", "Nivel 3.5", "Nivel 3", "Nivel 2-3", "Nivel 2",
          "Nivel 1-2", "Nivel 1", "Nivel 0", "Infraestructura", "Sin clasificar"]

TITULOS = {
    "Externo": "Externo - Fuera del inventario",
    "Nivel 5": "Nivel 5 - Red corporativa",
    "Nivel 4": "Nivel 4 - Sistemas de negocio",
    "Nivel 3.5": "Nivel 3.5 - DMZ industrial",
    "Nivel 3": "Nivel 3 - Operaciones",
    "Nivel 2-3": "Nivel 2-3 - Supervision y servidores",
    "Nivel 2": "Nivel 2 - Supervision y HMI",
    "Nivel 1-2": "Nivel 1-2 - Control / supervision",
    "Nivel 1": "Nivel 1 - Control y campo",
    "Nivel 0": "Nivel 0 - Proceso fisico",
    "Infraestructura": "Infraestructura - Equipos de red",
    "Sin clasificar": "Sin clasificar",
}


def titulo_banda(b: str) -> str:
    return t(TITULOS[b]) if b in TITULOS else b


def orden_banda(b: str) -> tuple:
    if b in BANDAS:
        return (BANDAS.index(b), "")
    return (len(BANDAS) - 1.5, b.lower())


@dataclass
class Nodo:
    id: str
    etiqueta: str
    sub: str
    banda: str
    tipo: str
    pkts: int = 0
    escrituras_recibidas: int = 0
    detalle: str = ""
    modelo: str = ""             # fabricante y modelo, si se conocen


@dataclass
class Arista:
    a: str                       # extremo de referencia; fwd = trafico a -> b
    b: str
    fwd: bool = False
    back: bool = False
    crit: str = "Baja"
    servicios: dict = field(default_factory=dict)   # servicio -> paquetes
    pkts: int = 0
    bytes: int = 0
    escrituras: int = 0
    conductos: int = 0
    rotulo: str = ""             # texto propio del trazo (vista ZCR: id del conducto); vacio = el de siempre
    rotulo2: str = ""
    detalle: str = ""            # tooltip propio (vista ZCR)
    discontinua: object = None   # vista TO-BE (T1a): True = linea discontinua; None = la del criterio de siempre


@dataclass
class Grafo:
    nodos: list
    aristas: list
    bandas: list                 # bandas con al menos un nodo, en orden de arriba a abajo
    zonas: bool = False          # True: cada nodo es una zona, no un equipo
    omitidos: int = 0            # activos que no caben en el diagrama
    aristas_omitidas: int = 0    # trazos que no se dibujan (extremo omitido o recortados)
    aristas_recortadas: int = 0  # de ellos, los que unen equipos visibles pero superan el tope
    internos: dict = field(default_factory=dict)    # zona -> conductos dentro de la zona
    zcr: bool = False            # vista de conductos ZCR (Z1b): leyenda y tooltips propios
    tobe: str = ""               # vista TO-BE (T1a): texto de la leyenda (lineas separadas por salto); vacio = otra vista


def tipo_de(rol: str) -> str:
    r = (rol or "").lower()
    if "equipo de red" in r:
        return "red"
    if "controlador" in r or "cip" in r:
        return "controlador"
    if "hmi" in r or "scada" in r or "cliente de control" in r:
        return "supervision"
    if "windows" in r:
        return "host"
    if "dispositivo ot" in r or "ethernet/ip" in r:
        return "ot"
    return "otro"


def _banda(a: dict, agrupar: str) -> str:
    """Banda de un activo: su nivel Purdue o, con agrupar="zona", la zona de la plataforma
    o, con agrupar="interfaz", la interfaz del firewall (con su zona si la tiene)."""
    if agrupar == "interfaz":
        return a.get("grupo_firewall") or "Sin clasificar"
    if agrupar == "zona":
        return a.get("zona") or "Sin clasificar"
    p = a.get("purdue", "")
    return p if p in BANDAS else "Sin clasificar"


def _base(assets: dict, conduits: list, agrupar: str = "nivel") -> tuple[dict, dict]:
    """Grafo completo: (nodos por id, aristas por par). Sin recortar."""
    ip_activo: dict = {}
    for a in assets.values():
        # "alias": otros nombres con que los conductos pueden referirse al activo (id, MAC, nombre)
        for ip in set(a["ips"]) | set(a.get("alias", ())):
            if ip not in ip_activo or a["pkts"] > ip_activo[ip]["pkts"]:
                ip_activo[ip] = a

    nodos: dict[str, Nodo] = {}

    def nodo_de(ip: str) -> Nodo:
        a = ip_activo.get(ip)
        if a is not None:
            n = nodos.get(a["mac"])
            if n is None:
                ips = sorted(a["ips"])
                nombre = a.get("nombre") or ip
                sub = ", ".join(ips[:2]) if nombre not in ips else ""
                detalle = " | ".join(x for x in (
                    a.get("vendor"), a.get("modelo"), a.get("firmware"),
                    mostrar_rol(a.get("tipo_texto") or a.get("role") or "")) if x)
                n = Nodo(a["mac"], nombre, sub, _banda(a, agrupar),
                         a.get("tipo") or tipo_de(a.get("role", "")), a["pkts"], 0, detalle,
                         " ".join(x for x in (a.get("vendor"), a.get("modelo")) if x))
                nodos[a["mac"]] = n
            return n
        n = nodos.get(ip)
        if n is None:
            externo = not is_private(ip)
            n = Nodo(ip, ip, "", "Externo" if externo else "Sin clasificar",
                     "externo" if externo else "otro")
            nodos[ip] = n
        return n

    aristas: dict[tuple, Arista] = {}
    for k in conduits:
        if k["multicast"]:
            continue
        # ponytail: broadcast dirigido por heuristica /24; un host real .255 queda fuera
        if k["dst"] not in ip_activo and k["dst"].endswith(".255"):
            continue
        na, nb = nodo_de(k["src"]), nodo_de(k["dst"])
        if na.id == nb.id:
            continue
        par = tuple(sorted((na.id, nb.id)))
        e = aristas.get(par)
        if e is None:
            e = aristas[par] = Arista(par[0], par[1])
        if na.id == e.a:
            e.fwd = True
        else:
            e.back = True
        if e.conductos == 0 or CRIT_ORDER.get(k["criticidad"], 9) < CRIT_ORDER.get(e.crit, 9):
            e.crit = k["criticidad"]
        e.servicios[k["servicio"]] = e.servicios.get(k["servicio"], 0) + k["pkts"]
        e.pkts += k["pkts"]
        e.bytes += k["bytes"]
        e.escrituras += k["escrituras"]
        e.conductos += 1
        nb.escrituras_recibidas += k["escrituras"]
    return nodos, aristas


def construir_activos(assets: dict, conduits: list, max_nodos: int = 40,
                      max_aristas: int = 60, agrupar: str = "nivel") -> Grafo:
    nodos, aristas = _base(assets, conduits, agrupar)

    # Prioridad al recortar: quien recibe escrituras o toca un conducto critico,
    # luego conductos de criticidad alta, luego el resto por volumen.
    tier = {n: 2 for n in nodos}
    for e in aristas.values():
        t = 0 if e.crit == "Critica" else 1 if e.crit == "Alta" else 2
        for n in (e.a, e.b):
            tier[n] = min(tier[n], t)
    for n in nodos.values():
        if n.escrituras_recibidas:
            tier[n.id] = 0
    elegidos = sorted(nodos.values(), key=lambda n: (tier[n.id], -n.pkts, n.id))[:max_nodos]
    ids = {n.id for n in elegidos}
    entre = [e for e in aristas.values() if e.a in ids and e.b in ids]
    # Tope de trazos: un diagrama denso deja de leerse. Quedan los de mayor criticidad y volumen.
    visibles = sorted(entre, key=lambda e: (CRIT_ORDER.get(e.crit, 9), -e.bytes, e.a, e.b))[:max_aristas]
    bandas = sorted({n.banda for n in elegidos}, key=orden_banda)
    return Grafo(elegidos, visibles, bandas, omitidos=len(nodos) - len(elegidos),
                 aristas_omitidas=len(aristas) - len(visibles),
                 aristas_recortadas=len(entre) - len(visibles))


def construir_zonas(assets: dict, conduits: list, agrupar: str = "nivel") -> Grafo:
    nodos, aristas = _base(assets, conduits, agrupar)
    por_banda = collections.Counter(n.banda for n in nodos.values())
    bandas = sorted(por_banda, key=orden_banda)
    indice = {b: i for i, b in enumerate(bandas)}

    zonas: dict[tuple, Arista] = {}
    internos: collections.Counter = collections.Counter()
    for e in aristas.values():
        ba, bb = nodos[e.a].banda, nodos[e.b].banda
        if ba == bb:
            internos[ba] += e.conductos
            continue
        fwd, back = e.fwd, e.back
        if indice[ba] > indice[bb]:
            ba, bb, fwd, back = bb, ba, back, fwd
        z = zonas.get((ba, bb))
        if z is None:
            z = zonas[(ba, bb)] = Arista(ba, bb)
        z.fwd, z.back = z.fwd or fwd, z.back or back
        if z.conductos == 0 or CRIT_ORDER.get(e.crit, 9) < CRIT_ORDER.get(z.crit, 9):
            z.crit = e.crit
        for s, p in e.servicios.items():
            z.servicios[s] = z.servicios.get(s, 0) + p
        z.pkts += e.pkts
        z.bytes += e.bytes
        z.escrituras += e.escrituras
        z.conductos += e.conductos

    nodos_z = [Nodo(b, titulo_banda(b), f"{por_banda[b]} " + t("activo" if por_banda[b] == 1 else "activos"), b,
                    "externo" if b == "Externo" else "zona") for b in bandas]
    return Grafo(nodos_z, list(zonas.values()), bandas, zonas=True, internos=dict(internos))
