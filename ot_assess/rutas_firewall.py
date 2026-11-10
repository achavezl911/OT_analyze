"""XD-b: zonas desde las rutas de un firewall (--rutas-firewall).

Lee la tabla de rutas de un firewall (tabla CSV/XLSX, comandos `route` de Cisco ASA o salida de
`show route`), asigna a cada IP la interfaz por la que el firewall la alcanza (prefijo mas largo) y
marca los conductos que cruzan el firewall. Funciones puras salvo cargar(), que toca el disco.
Es inferencia desde la tabla de rutas, no desde la politica: no dice que el trafico este permitido.
"""
from __future__ import annotations

import collections
import ipaddress
import re
import unicodedata
from pathlib import Path

from .i18n import t
from .importers.lector import leer_tabla

SIN_RUTA = "sin ruta"
SUFIJO_DEFECTO = " (ruta por defecto)"
AVISO_SIN_C = ("sin rutas conectadas: las redes de transito del firewall caen en la ruta mas larga "
               "que las contiene; usa la salida de show route")

COL_INTERFACES = ["interfaz", "zona", "redes", "rutas", "activos", "siguientes_saltos"]
COL_MATRIZ = ["interfaz_origen", "interfaz_destino", "conductos", "servicios", "bytes",
              "origenes", "destinos"]

_IFACE = ("interfaz", "interface", "nameif", "iface")
_CIDR = ("red_cidr", "cidr")
_RED = ("red", "network", "destination", "red_destino")
_MASCARA = ("mascara", "mask", "netmask", "subnet_mask")
_PREFIJO = ("prefijo", "prefix", "prefix_length")
_ZONA = ("zona", "zone", "etiqueta")
_SALTO = ("siguiente_salto", "next_hop", "gateway")
_TIPO = ("tipo", "type")

_IP = r"\d+\.\d+\.\d+\.\d+"
_COD = r"[A-Za-z]{1,2}\*?(?:\s+[A-Za-z]{1,2}\d?)?"
_RED_TXT = rf"(?P<red>{_IP})(?:/(?P<pref>\d+)|\s+(?P<mask>{_IP}))"
_RE_CMD = re.compile(r"^\s*route\s+(?P<nif>\S+)\s+(?P<red>\S+)\s+(?P<mask>\S+)\s+(?P<gw>\S+)"
                     r"(?:\s+\d+)?(?:\s+\S+)*\s*$", re.IGNORECASE)
_RE_LINEA = re.compile(rf"^\s*(?P<cod>{_COD})\s+\d+\.\d+\.\d+\.\d+")
_RE_SHOW = re.compile(rf"^\s*(?P<cod>{_COD})\s+{_RED_TXT}\s+(?:\[\d+/\d+\]\s+via\s+(?P<gw>[^\s,]+),"
                      rf"\s*(?:[^\s,]+,\s*)?(?P<nif>\S+)|is directly connected,\s*(?P<nifc>\S+))\s*$")
_RE_CONT = re.compile(r"^\s+\[\d+/\d+\]\s+via\s+(?P<gw>[^\s,]+),\s*(?:[^\s,]+,\s*)?(?P<nif>\S+)\s*$")
_RE_FW = re.compile(r"^el firewall \((.*)\)$")


def _norm(s) -> str:
    s = unicodedata.normalize("NFD", str(s or ""))
    s = "".join(c for c in s if not unicodedata.combining(c)).strip().lower()
    return re.sub(r"[^a-z0-9]+", "_", s).strip("_")


def _prefijo(mask: str, donde: str) -> int:
    try:
        m = int(ipaddress.IPv4Address(mask))
    except ValueError:
        raise SystemExit(f"[!] {donde}: mascara invalida '{mask}'")
    inv = ~m & 0xFFFFFFFF
    if inv & (inv + 1):
        raise SystemExit(f"[!] {donde}: mascara no contigua '{mask}'")
    return bin(m).count("1")


def _red(texto: str, mask, pref, donde: str):
    """Red (strict=False) desde 'a.b.c.d/n', o desde red + mascara o red + prefijo."""
    texto = str(texto or "").strip()
    if texto == "0":
        texto = "0.0.0.0"  # nosec B104: es la red de la ruta por defecto, no una direccion de escucha
    try:
        if "/" in texto:
            return ipaddress.ip_network(texto, strict=False)
        mask, pref = str(mask or "").strip(), str(pref or "").strip().lstrip("/")
        if mask and mask != "0":
            n = _prefijo(mask, donde)
        elif mask == "0":
            n = 0
        else:
            n = int(pref) if pref else (128 if ":" in texto else 32)
        return ipaddress.ip_network(f"{texto}/{n}", strict=False)
    except ValueError:
        raise SystemExit(f"[!] {donde}: red invalida '{texto}'")


def _ruta(red, interfaz, zona, salto, tipo, origen) -> dict:
    return {"red": red, "interfaz": interfaz, "zona": zona, "siguiente_salto": salto,
            "tipo": tipo, "origen": origen}


def _desde_texto(texto: str, nombre: str):
    """Rutas de comandos `route` y de `show route`; None si el texto no trae ninguno."""
    rutas, previa, visto = [], None, False
    for n, linea in enumerate(texto.splitlines(), 1):
        donde = f"'{nombre}': linea {n}"
        if not linea.strip():
            continue
        m = _RE_CMD.match(linea)
        if m:
            visto = True
            rutas.append(_ruta(_red(m["red"], m["mask"], None, donde), m["nif"], "", m["gw"], "S", donde))
            continue
        c = _RE_CONT.match(linea)
        if c and previa is not None:
            visto = True
            rutas.append(_ruta(previa["red"], c["nif"], "", c["gw"], previa["tipo"], donde))
            continue
        if not _RE_LINEA.match(linea):
            continue
        s = _RE_SHOW.match(linea)
        if not s:
            raise SystemExit(f"[!] {donde}: linea de ruta no reconocida '{linea.strip()}'")
        visto = True
        red = _red(s["red"] + (f"/{s['pref']}" if s["pref"] else ""), s["mask"], None, donde)
        cod = s["cod"].split()[0]
        previa = _ruta(red, s["nif"] or s["nifc"], "", s["gw"] or "", cod, donde)
        rutas.append(previa)
    return rutas if visto else None


def _celda(fila: dict, alias: tuple) -> str:
    for k, v in fila.items():
        if _norm(k) in alias:
            return str(v or "").strip()
    return ""


def _desde_tabla(filas: list, nombre: str) -> list:
    """Busca la primera fila con columna de interfaz y de red; lee hasta que acaba la seccion."""
    if not filas:
        raise SystemExit(f"[!] '{nombre}': tabla vacia")
    # leer_tabla toma como encabezado la primera fila con 2+ celdas; si hay un titulo, el
    # encabezado real quedo entre los registros.
    todas = [list(filas[0].keys())] + [list(f.values()) for f in filas]
    for i, fila in enumerate(todas):
        cab = [_norm(c) for c in fila]
        if any(c in _IFACE for c in cab) and any(c in _CIDR + _RED for c in cab):
            break
    else:
        raise SystemExit(f"[!] '{nombre}': no encuentro una fila de encabezado con columna de "
                         f"interfaz (interfaz, interface, nameif) y de red (red_cidr, cidr, red, ...)")
    cab = [_norm(c) for c in todas[i]]
    rutas = []
    for n, valores in enumerate(todas[i + 1:], i + 2):
        f = dict(zip(cab, [str(v or "").strip() for v in valores]))
        donde = f"'{nombre}': fila {n}"
        cidr, red = _celda(f, _CIDR), _celda(f, _RED)
        texto = cidr or red
        if not (texto[:1].isdigit() and ("." in texto or ":" in texto)):
            break  # vacia o no es una red (p. ej. una seccion de resumen): fin de la tabla
        iface = _celda(f, _IFACE)
        if not iface:
            raise SystemExit(f"[!] {donde}: interfaz vacia")
        net = _red(texto, _celda(f, _MASCARA), _celda(f, _PREFIJO), donde)
        rutas.append(_ruta(net, iface, _celda(f, _ZONA), _celda(f, _SALTO), _celda(f, _TIPO), donde))
    if not rutas:
        raise SystemExit(f"[!] '{nombre}': el encabezado no va seguido de ninguna ruta")
    return rutas


def _sin_repetidas(rutas: list) -> list:
    vistas, out = set(), []
    for r in rutas:
        k = (r["red"], r["interfaz"])
        if k not in vistas:
            vistas.add(k)
            out.append(r)
    return out


def cargar(path):
    """(rutas, avisos) desde el archivo; el formato se detecta por contenido."""
    p = Path(path)
    try:
        raw = p.read_bytes()
    except OSError as e:
        raise SystemExit(f"[!] No pude leer '{path}': {e}")
    rutas = None
    if raw[:2] != b"PK":
        from .importers.lector import _texto
        rutas = _desde_texto(_texto(raw), p.name)
    if rutas is None:
        rutas = _desde_tabla(leer_tabla(p), p.name)
    rutas = _sin_repetidas(rutas)
    avisos = []
    if not any(r["tipo"] == "C" for r in rutas):
        avisos.append(t(AVISO_SIN_C))
    return rutas, avisos


def ubicar(ip, rutas: list, avisos=None):
    """(interfaz o None, es_el_firewall) de la ruta de prefijo mas largo que contiene la IP.
    Empate de la misma red entre interfaces distintas: gana la primera del archivo y se avisa."""
    try:
        a = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return None, False
    mejor = None
    for r in rutas:
        if a in r["red"] and (mejor is None or r["red"].prefixlen > mejor["red"].prefixlen):
            mejor = r
    if mejor is None:
        return None, False
    if avisos is not None:
        otras = {r["interfaz"] for r in rutas if r["red"] == mejor["red"]}
        if len(otras) > 1:
            msg = t("la red {red} sale por {n} interfaces ({lista}): se usa {usada}, la primera del archivo",
                    red=mejor["red"], n=len(otras), lista=", ".join(sorted(otras)), usada=mejor["interfaz"])
            if msg not in avisos:
                avisos.append(msg)
    return mejor["interfaz"], mejor["tipo"] == "L"


def _solo_defecto(ip, rutas: list) -> bool:
    """True si la unica ruta que contiene la IP es la ruta por defecto (0.0.0.0/0 o ::/0)."""
    try:
        a = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return False
    cont = [r for r in rutas if a in r["red"]]
    return bool(cont) and all(r["red"].prefixlen == 0 for r in cont)


def interfaz_de(ip, rutas: list, avisos=None) -> str:
    iface, fw = ubicar(ip, rutas, avisos)
    if iface is None:
        return SIN_RUTA
    if fw:
        return f"el firewall ({iface})"
    return iface + SUFIJO_DEFECTO if _solo_defecto(ip, rutas) else iface


def mostrar_iface(texto: str) -> str:
    """Interfaz con sus marcas (sin ruta, ruta por defecto, el firewall) en el idioma del reporte."""
    if texto == SIN_RUTA:
        return t(SIN_RUTA)
    m = _RE_FW.match(texto or "")
    if m:
        return t("el firewall ({iface})", iface=mostrar_iface(m.group(1)))
    if texto and texto.endswith(SUFIJO_DEFECTO):
        return texto[:-len(SUFIJO_DEFECTO)] + t(SUFIJO_DEFECTO)
    return texto


def _servicios_t(texto: str) -> str:
    """Lista 'servicio n; servicio n' con la marca 'sin puerto' en el idioma del reporte."""
    return "; ".join(t("sin puerto") + p[len("sin puerto"):] if p.startswith("sin puerto") else p
                     for p in texto.split("; "))


def _base(texto: str) -> str:
    m = _RE_FW.match(texto or "")
    return m.group(1) if m else (texto or "")


def _cruza(a: str, b: str) -> bool:
    if SIN_RUTA in (a, b) or not a or not b or _RE_FW.match(a) or _RE_FW.match(b):
        return False
    # Internet (ruta por defecto) y la red interna de la misma interfaz no pasan por el firewall
    return a.replace(SUFIJO_DEFECTO, "") != b.replace(SUFIJO_DEFECTO, "")


def _servicio(k: dict) -> str:
    """'443/tcp TLS', '443 TLS' (sin L4), '8080' (sin protocolo) o 'sin puerto'."""
    puerto = str(k.get("port") if k.get("port") is not None else "").strip()
    if puerto in ("", "0", "-"):
        return "sin puerto"
    l4 = str(k.get("l4") or "").strip()
    sv = str(k.get("servicio") or "").strip()
    return " ".join(x for x in (f"{puerto}/{l4}" if l4 else puerto, "" if sv in ("", "-") else sv) if x)


def aplicar(path, assets: dict, conductos: list) -> dict:
    """Carga las rutas, anota conductos y activos y devuelve el dict de Assessment.rutas."""
    rutas, avisos = cargar(path)
    return aplicar_rutas(rutas, avisos, assets, conductos, Path(path).name)


def aplicar_rutas(rutas: list, avisos: list, assets: dict, conductos: list, archivo: str = "",
                  ip_de=lambda x: x) -> dict:
    """Como aplicar() pero con las rutas ya cargadas (dicts de _ruta). `ip_de` traduce el extremo de
    un conducto a IP (en las exportaciones el extremo puede ser el id del activo)."""
    cache: dict = {}

    def de(ip):
        if ip not in cache:
            cache[ip] = interfaz_de(ip, rutas, avisos)
        return cache[ip]

    for k in conductos:
        k["if_origen"], k["if_destino"] = de(ip_de(k["src"])), de(ip_de(k["dst"]))
        k["cruza_firewall"] = _cruza(k["if_origen"], k["if_destino"])
    por_activo: collections.Counter = collections.Counter()
    for a in assets.values():
        ips = sorted(a["ips"])
        a["interfaz_firewall"] = next((de(i) for i in ips if de(i) != SIN_RUTA), de(ips[0]) if ips else "")
        if not _RE_FW.match(a["interfaz_firewall"]):  # el propio firewall no cuenta como activo
            por_activo[a["interfaz_firewall"]] += 1
    def _grupo(r):
        return r["interfaz"] + (SUFIJO_DEFECTO if r["red"].prefixlen == 0 else "")

    orden = list(dict.fromkeys(_grupo(r) for r in rutas))
    interfaces = []
    for nombre in orden:
        rs = [r for r in rutas if _grupo(r) == nombre]
        interfaces.append({
            "interfaz": nombre,
            "zona": ";".join(dict.fromkeys(r["zona"] for r in rs if r["zona"])),
            "redes": ";".join(str(r["red"]) for r in rs),
            "rutas": len(rs), "activos": por_activo.get(nombre, 0),
            "siguientes_saltos": ";".join(dict.fromkeys(r["siguiente_salto"] for r in rs if r["siguiente_salto"]))})
    zonas = {i["interfaz"]: i["zona"] for i in interfaces}
    for a in assets.values():  # nombre de la banda en el diagrama agrupado por interfaz
        z = zonas.get(a["interfaz_firewall"], "")
        base = mostrar_iface(a["interfaz_firewall"])
        a["grupo_firewall"] = f"{base} ({z})" if z else base
    grupos: dict = {}
    for k in conductos:
        if k["cruza_firewall"]:
            grupos.setdefault((k["if_origen"], k["if_destino"]), []).append(k)
    matriz = []
    for (o, d), ks in grupos.items():
        sv = collections.Counter(_servicio(k) for k in ks)
        top = sorted(sv.items(), key=lambda x: (-x[1], x[0]))[:10]
        matriz.append({"interfaz_origen": o, "interfaz_destino": d, "conductos": len(ks),
                       "servicios": "; ".join(f"{s} {n}" for s, n in top),
                       "bytes": sum(k.get("bytes", 0) for k in ks),
                       "origenes": len({k["src"] for k in ks}), "destinos": len({k["dst"] for k in ks})})
    matriz.sort(key=lambda m: (-m["conductos"], m["interfaz_origen"], m["interfaz_destino"]))
    return {"archivo": archivo, "rutas": len(rutas), "interfaces": interfaces,
            "asignacion": dict(sorted(cache.items())), "matriz": matriz, "avisos": avisos}


def filas_interfaces(rutas: dict) -> list:
    return [[i[c] for c in COL_INTERFACES] for i in rutas["interfaces"]]


def filas_matriz(rutas: dict) -> list:
    return [[m[c] for c in COL_MATRIZ] for m in rutas["matriz"]]


MAX_PARES = 20
MAX_TEXTO = 80
NOTA = ("Inferido de la tabla de rutas del firewall, no de su politica: indica por que interfaz se "
        "alcanza cada IP, no que el trafico este permitido.")


def _corto(texto: str) -> str:
    return texto if len(texto) <= MAX_TEXTO else texto[:MAX_TEXTO - 3] + "..."


def seccion(rutas: dict, conductos: list) -> dict:
    """Datos de la seccion 'Flujos entre interfaces del firewall' para HTML, Markdown y Word."""
    from .util import human
    cruzan = sum(1 for k in conductos if k.get("cruza_firewall"))
    total = len(rutas["matriz"])
    resumen = t("{ni} interfaces y {nr} rutas leidas de {archivo}; {cruzan} de {total} conductos cruzan el firewall.",
                ni=len(rutas["interfaces"]), nr=rutas["rutas"], archivo=rutas["archivo"],
                cruzan=cruzan, total=len(conductos))
    mas = ""
    if total > MAX_PARES:
        mas = t("Se muestran {n} de {total} pares; la matriz completa esta en firewall_matriz.csv.",
                n=MAX_PARES, total=total)
    return {
        "resumen": resumen,
        "avisos": list(rutas["avisos"]),
        "cab_matriz": [t(c) for c in ("Origen", "Destino", "Conductos", "Servicios", "Bytes")],
        "matriz": [[mostrar_iface(m["interfaz_origen"]), mostrar_iface(m["interfaz_destino"]), m["conductos"],
                    _corto(_servicios_t(m["servicios"])), human(m["bytes"])] for m in rutas["matriz"][:MAX_PARES]],
        "mas": mas,
        "cab_interfaces": [t(c) for c in ("Interfaz", "Zona", "Redes", "Activos")],
        "interfaces": [[mostrar_iface(i["interfaz"]), i["zona"], _corto(i["redes"]), i["activos"]]
                       for i in rutas["interfaces"]],
    }
