"""D70: NAT estatico de Cisco FTD/ASA en el contraste (traduccion inversa de lo observado a lo real).

Las reglas de acceso de FTD/ASA (8.3+) se evaluan con las IP REALES; un conducto visto en una captura del lado
mapeado trae las IP traducidas. Aqui se invierte esa traduccion, solo para NAT ESTATICO activo:
- twice NAT: `source static REAL MAPEADO [destination static MAPEADO_DST REAL_DST]`; con destino, AMBOS extremos
  deben casar con el par de la regla (no se traduce un conducto ajeno que comparte una IP).
- object NAT: el real es el propio objeto; no tiene destino.
- Un conducto casa en cuatro formas: visto del lado mapeado (MAPEADO, REAL_DST), visto del lado real
  (REAL, MAPEADO_DST) y los dos sentidos inversos (`unidirectional` quita los inversos).
- Subredes y rangos se traducen uno a uno por desplazamiento (mismo tamano); si no, la regla no es modelable.
- NAT dinamico o PAT no se puede invertir (muchos a uno): el conducto se marca y la IP no cambia.
- Orden: el de la configuracion (twice NAT, object NAT, twice NAT after-auto); la primera que casa gana. El
  orden real de object NAT en el firewall (estaticas antes que dinamicas, por tamano) no se reconstruye.
- `service` (traduccion de puertos) no se modela: la regla se aplica solo a las IP.
Es evidencia pasiva sobre lo observado, no un motor de decision.
"""
from __future__ import annotations

import ipaddress

from ..i18n import t, unir

LADO_MAPEADO = "lado mapeado"
LADO_REAL = "lado real"
INVERSO = " (inverso)"
PAT = "PAT: origen real desconocido"
COL_NAT = ["linea", "interfaces", "tipo", "origen_real", "origen_mapeado", "destino_mapeado", "destino_real",
           "descripcion", "conductos_traducidos", "estado",
           "origen_real_red", "origen_mapeado_red", "destino_mapeado_red", "destino_real_red"]
COL_CONTADORES = ["translate_hits", "untranslate_hits"]      # F6b: solo con show nat detail
COL_TOMAS = ["tomas_nat", "translate_hits_por_toma", "untranslate_hits_por_toma",
             "reinicio_contadores"]                           # F6c: solo con dos o mas tomas
ESTADO_CON_ACIERTOS = "sin trafico en la ventana, con aciertos en el contador"
ESTADO_SIN_ACIERTOS = "sin aciertos en el contador"
HOJA_NAT = "NAT del firewall"
MARCA_ACTIVO = "IP traducida por el NAT del firewall (real: {real})"


def _iv(redes):
    return None if redes is None else [(int(r.network_address), int(r.broadcast_address)) for r in redes]


def _en(iv, ip: int) -> bool:
    return iv is None or any(a <= ip <= b for a, b in iv)


def _traslada(desde, hacia, ip: int):
    off = 0
    for a, b in desde:
        if a <= ip <= b:
            off += ip - a
            break
        off += b - a + 1
    else:
        return None
    for a, b in hacia:
        n = b - a + 1
        if off < n:
            return a + off
        off -= n
    return None


class _Par:
    """Un operando de la regla: el objeto real y el mapeado (None = cualquiera)."""

    def __init__(self, real, mapeado):
        self.real, self.mapeado = _iv(real), _iv(mapeado)

    def en_real(self, ip):
        return _en(self.real, ip)

    def en_mapeado(self, ip):
        return _en(self.mapeado, ip)

    def a_real(self, ip):
        return ip if self.real is None else _traslada(self.mapeado, self.real, ip)

    def a_mapeado(self, ip):
        return ip if self.real is None else _traslada(self.real, self.mapeado, ip)


class _Regla:
    def __init__(self, n):
        self.nat = n
        self.estatica = n.modo == "static"
        self.src = _Par(n.red_origen_real, n.red_origen_mapeado)
        self.dst = _Par(n.red_destino_real, n.red_destino_mapeado) if n.destino else None


def _directo(r, x: int, y: int):
    """(origen real, destino real, lado) si el conducto x -> y (x inicia) casa con la regla; si no, None."""
    s, d = r.src, r.dst
    if not r.estatica:
        return (x, y, LADO_MAPEADO) if s.en_mapeado(x) else None
    if s.en_mapeado(x) and (d is None or d.en_real(y)):
        return s.a_real(x), y, LADO_MAPEADO
    if d is not None and s.en_real(x) and d.en_mapeado(y):
        return x, d.a_real(y), LADO_REAL
    return None


def _aplicar(r, x: int, y: int):
    h = _directo(r, x, y)
    if h is not None:
        return h
    if r.nat.unidireccional:
        return None
    h = _directo(r, y, x)
    return None if h is None else (h[1], h[0], h[2] + INVERSO)


def _ip4(txt):
    try:
        ip = ipaddress.ip_address(str(txt).strip())
    except ValueError:
        return None
    return int(ip) if ip.version == 4 else None


class Traductor:
    """Aplica las reglas nat de un Firewall a los extremos de un conducto y cuenta cuantas veces casa cada una."""

    def __init__(self, nats):
        self.nats = list(nats)
        self.reglas = [_Regla(n) for n in self.nats
                       if n.modelable and not n.inactiva and n.modo in ("static", "dynamic", "pat")]
        self.usos = {id(n): 0 for n in self.nats}
        self._cache: dict = {}

    def __bool__(self):
        return bool(self.reglas)

    def _calcular(self, x: int, y: int, bidireccional: bool):
        for r in self.reglas:
            h = _aplicar(r, x, y)
            if h is None and bidireccional:         # no se sabe quien inicio: se prueba el otro extremo
                h = _aplicar(r, y, x)
                if h is not None:
                    h = (h[1], h[0], h[2])
            if h is not None:
                return r, h
        return None

    def traducir(self, s, d, bidireccional: bool = False):
        """{'s', 'd' (IP reales), 'regla' (Nat), 'lado', 'pat', 'cambio'} o None si ninguna regla casa."""
        x, y = _ip4(s), _ip4(d)
        if x is None or y is None:
            return None
        k = (x, y, bool(bidireccional))
        if k not in self._cache:
            self._cache[k] = self._calcular(x, y, bool(bidireccional))
        hit = self._cache[k]
        if hit is None:
            return None
        r, (rs, rd, lado) = hit
        self.usos[id(r.nat)] += 1
        if not r.estatica:
            return {"s": str(s), "d": str(d), "regla": r.nat, "lado": PAT, "pat": True, "cambio": False}
        return {"s": str(ipaddress.IPv4Address(rs)), "d": str(ipaddress.IPv4Address(rd)), "regla": r.nat,
                "lado": lado, "pat": False, "cambio": (rs, rd) != (x, y)}

    def real_de(self, ip):
        """IP real si `ip` es un MAPEADO de NAT estatico (traduccion del origen); None si no."""
        x = _ip4(ip)
        if x is None:
            return None
        for r in self.reglas:
            if r.estatica and r.src.real is not None and r.src.en_mapeado(x):
                real = r.src.a_real(x)
                return None if real is None or real == x else str(ipaddress.IPv4Address(real))
        return None


def nombre_regla(n) -> str:
    """Como se cita la regla en las salidas: 'linea N' o 'linea N: descripcion'."""
    return f"linea {n.linea}" + (": " + n.descripcion if n.descripcion else "")


def _estado(n, usos: int) -> str:
    if n.inactiva:
        return "inactiva"
    if not n.modelable:
        return "no modelable: " + n.motivo
    if usos:
        return "usada"
    if n.hits_traducidos is None:
        return "sin uso en la ventana"
    # F6b: los contadores desde el ultimo clear cubren mas tiempo que la ventana observada
    return ESTADO_CON_ACIERTOS if n.hits_traducidos + (n.hits_inversos or 0) > 0 else ESTADO_SIN_ACIERTOS


def _txt_redes(redes) -> str:
    return "any" if redes is None else ",".join(str(r) for r in redes)


def _tomas(n) -> dict:
    """F6c: columnas por toma; el valor de una toma en que la regla no se emparejo queda vacio."""
    def lista(i):
        return "; ".join("" if h is None or h[i] is None else str(h[i]) for h in n.hits_por_toma)
    return {"tomas_nat": sum(1 for h in n.hits_por_toma if h), "translate_hits_por_toma": lista(0),
            "untranslate_hits_por_toma": lista(1), "reinicio_contadores": "si" if n.bajadas() else ""}


def filas(nats, traductor) -> list:
    """Filas (dicts con COL_NAT y, con show nat detail, COL_CONTADORES) de firewall_nat.csv, en el orden de
    evaluacion. Las redes salen de los objetos de la configuracion o, si faltan, de show nat detail."""
    out = []
    for n in nats:
        f = {"linea": n.linea, "interfaces": ",".join(n.interfaces),
             "tipo": n.modo,
             "origen_real": n.origen_real, "origen_mapeado": n.origen_mapeado,
             "destino_mapeado": n.destino_mapeado, "destino_real": n.destino_real,
             "descripcion": n.descripcion, "conductos_traducidos": traductor.usos.get(id(n), 0),
             "estado": _estado(n, traductor.usos.get(id(n), 0)),
             "origen_real_red": _txt_redes(n.red_origen_real),
             "origen_mapeado_red": _txt_redes(n.red_origen_mapeado),
             "destino_mapeado_red": _txt_redes(n.red_destino_mapeado) if n.destino else "",
             "destino_real_red": _txt_redes(n.red_destino_real) if n.destino else "",
             "translate_hits": "" if n.hits_traducidos is None else n.hits_traducidos,
             "untranslate_hits": "" if n.hits_inversos is None else n.hits_inversos}
        if len(n.hits_por_toma) > 1:
            f.update(_tomas(n))
        out.append(f)
    return out


def nota(fw) -> str:
    """Nota de la tabla cuando la sesion trae show nat detail ('' si no)."""
    d = getattr(fw, "nat_detalle", None)
    if not d:
        return ""
    piezas = [t("show nat detail: {leidas} reglas leidas, {sin} sin emparejar con la configuracion, {falta} reglas "
                "de la configuracion sin contadores", leidas=d["reglas_detalle"], sin=d["sin_emparejar"],
                falta=d["config_sin_contador"])]
    if d.get("modeladas_con_detalle"):
        piezas.append(t("{n} modeladas con las redes de show nat detail (falta un objeto)",
                        n=d["modeladas_con_detalle"]))
    if d.get("tomas", 1) > 1:
        piezas.append(t("{n} tomas de show nat detail; se usa el maximo por regla", n=d["tomas"]))
        nombres = [f"{i}={x}" for i, x in enumerate(d.get("nombres") or [], 1) if x]
        if nombres:
            piezas.append(t("tomas: {lista}", lista=", ".join(nombres)))
        for a, b in d.get("reinicios") or []:
            piezas.append(t("contadores reiniciados entre la toma {a} y la {b} (clear, despliegue o reinicio del "
                            "equipo): los aciertos entre esas tomas no se ven", a=a, b=b))
    return unir("; ", piezas)


def columnas(nat: dict) -> list:
    return (["firewall"] if nat.get("multiple") else []) + COL_NAT + (COL_CONTADORES if nat.get("con_contadores") else []) \
        + (COL_TOMAS if any("tomas_nat" in x for x in nat["filas"]) else [])


def filas_tabla(nat: dict) -> list:
    cols = columnas(nat)
    return [[x.get(c, "") for c in cols] for x in nat["filas"]]


def hay(fw: dict) -> bool:
    return bool(((fw or {}).get("nat") or {}).get("filas"))
