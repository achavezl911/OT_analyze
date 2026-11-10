"""E3a: contraste de reglas de firewall/ACL (CSV generico) contra conductos observados.

Funciones puras: no usan tshark. Solo cargar() toca el disco. La primera regla que casa decide
(ACL ordenada). "sin_regla" = ninguna casa: denegacion implicita, pero el trafico se observo.
El numero de fila en los mensajes y en el id por defecto ("fila N") es el N-esimo registro
despues del encabezado.
"""
from __future__ import annotations

import ipaddress
import unicodedata
from pathlib import Path

from .importers.lector import leer_csv

MAX_REGLAS = 100000

_ALIAS = {
    "origen": "origen", "source": "origen", "src": "origen",
    "destino": "destino", "destination": "destino", "dst": "destino",
    "puerto": "puerto", "port": "puerto", "dport": "puerto",
    "protocolo": "protocolo", "protocol": "protocolo", "proto": "protocolo",
    "accion": "accion", "action": "accion",
    "id": "id", "nombre": "id", "name": "id",
}
_REQUERIDAS = ("origen", "destino", "puerto", "protocolo", "accion")
_CUALQUIERA = ("", "any", "*")
_ACCION = {"permitir": "permitir", "allow": "permitir", "permit": "permitir", "accept": "permitir",
           "denegar": "denegar", "deny": "denegar", "drop": "denegar", "reject": "denegar",
           "block": "denegar"}


def _norm(s: str) -> str:
    s = unicodedata.normalize("NFD", str(s or ""))
    return "".join(c for c in s if not unicodedata.combining(c)).strip().lower()


def _redes(valor: str, nombre: str, fila: int):
    """None = cualquiera; si no, lista de redes."""
    partes = valor.split()
    if not partes or (len(partes) == 1 and partes[0].lower() in _CUALQUIERA):
        return None
    redes = []
    for p in partes:
        try:
            redes.append(ipaddress.ip_network(p, strict=False))
        except ValueError:
            raise SystemExit(f"[!] '{nombre}': fila {fila}: direccion o CIDR invalido '{p}'")
    return redes


def _puertos(valor: str, nombre: str, fila: int):
    """None = cualquiera; si no, lista de (min, max)."""
    partes = valor.split()
    if not partes or (len(partes) == 1 and partes[0].lower() in _CUALQUIERA):
        return None
    rangos = []
    for p in partes:
        a, sep, b = p.partition("-")
        try:
            lo = int(a)
            hi = int(b) if sep else lo
        except ValueError:
            lo = hi = -1
        if not (0 <= lo <= hi <= 65535) or not a.isdigit() or (sep and not b.isdigit()):
            raise SystemExit(f"[!] '{nombre}': fila {fila}: puerto invalido '{p}'")
        rangos.append((lo, hi))
    return rangos


def _proto(valor: str, nombre: str, fila: int):
    v = valor.strip().lower()
    if v in _CUALQUIERA or v == "ip":
        return None
    if v in ("tcp", "udp"):
        return v
    raise SystemExit(f"[!] '{nombre}': fila {fila}: protocolo invalido '{valor}'")


def reglas_de_filas(filas: list, nombre: str) -> list:
    """Convierte los registros de leer_csv en reglas (dicts). 'nombre' es el archivo, sin ruta."""
    if not filas:
        raise SystemExit(f"[!] '{nombre}': sin reglas o sin encabezado")
    if len(filas) > MAX_REGLAS:
        raise SystemExit(f"[!] '{nombre}': mas de {MAX_REGLAS} reglas")
    mapa = {}
    # leer_csv omite las celdas ausentes de filas cortas: el encabezado es la union de claves.
    encabezados = dict.fromkeys(h for f in filas for h in f)
    for h in encabezados:
        campo = _ALIAS.get(_norm(h))
        if campo is None:
            raise SystemExit(f"[!] '{nombre}': encabezado desconocido '{h}'")
        mapa[h] = campo
    faltan = [c for c in _REQUERIDAS if c not in mapa.values()]
    if faltan:
        raise SystemExit(f"[!] '{nombre}': falta la columna requerida '{faltan[0]}'")
    reglas = []
    for n, fila in enumerate(filas, 1):
        v = {campo: (fila.get(h) or "").strip() for h, campo in mapa.items()}
        accion = _ACCION.get(v["accion"].lower())
        if accion is None:
            raise SystemExit(f"[!] '{nombre}': fila {n}: accion invalida '{v['accion']}'")
        reglas.append({
            "id": v.get("id") or f"fila {n}",
            "accion": accion,
            "origen": _redes(v["origen"], nombre, n),
            "destino": _redes(v["destino"], nombre, n),
            "puertos": _puertos(v["puerto"], nombre, n),
            "proto": _proto(v["protocolo"], nombre, n),
            "texto": {k: v[k] for k in ("origen", "destino", "puerto", "protocolo")},
        })
    return reglas


def contrastar(path, conductos: list) -> dict:
    """Carga el CSV y arma el dict que guarda Assessment.firewall."""
    p = Path(path)
    reglas = cargar(p)
    resultados, sin_trafico = evaluar(reglas, conductos)
    por_id = {r["id"]: r for r in reglas}
    cuenta = {"permitido": 0, "denegado_observado": 0, "sin_regla": 0}
    for r in resultados:
        cuenta[r["resultado"]] += 1
    cuenta["reglas_sin_trafico"] = len(sin_trafico)
    return {"archivo": p.name, "resultados": resultados, "resumen": cuenta,
            "sin_trafico": [dict(regla=i, **por_id[i]["texto"]) for i in sin_trafico]}


NOTA = ("Una regla sin trafico en la ventana de captura no es necesariamente innecesaria: puede "
        "cubrir operaciones poco frecuentes. Trafico sin regla o denegado que se observo indica "
        "una regla ausente, un control no aplicado o un punto de captura distinto del firewall.")
_ORDEN = {"sin_regla": 0, "denegado_observado": 1, "respuesta": 2, "permitido": 3, "no_cruza": 4}


def filas_contraste(conductos: list, fw: dict) -> list:
    """[(conducto, {"resultado", "regla"})] ordenado: sin_regla, denegado_observado, permitido, no_cruza."""
    pares = list(zip(conductos, fw["resultados"]))
    return sorted(pares, key=lambda p: _ORDEN[p[1]["resultado"]])  # estable: orden de conductos


def cargar(path) -> list:
    p = Path(path)
    return reglas_de_filas(leer_csv(p.read_bytes()), p.name)


def _ip(valor):
    try:
        return ipaddress.ip_address(str(valor).strip())
    except ValueError:
        return None


def _casa(regla: dict, ip_s, ip_d, c: dict) -> bool:
    for campo, ip in (("origen", ip_s), ("destino", ip_d)):
        redes = regla[campo]
        if redes is not None and (ip is None or not any(ip in r for r in redes)):
            return False
    if regla["proto"] is not None and regla["proto"] != c.get("l4"):
        return False
    if regla["puertos"] is not None:
        port = c.get("port")  # los conductos reales traen texto ("502") o "" sin L4
        port = int(port) if str(port).isdigit() else None
        if port is None or not any(lo <= port <= hi for lo, hi in regla["puertos"]):
            return False
    return True


def evaluar(reglas: list, conductos: list):
    """-> (resultados, reglas_sin_trafico).

    resultados: uno por conducto, en el mismo orden: {"resultado": "permitido" |
    "denegado_observado" | "sin_regla", "regla": id o ""}.
    reglas_sin_trafico: ids de reglas "permitir" que no fueron la primera coincidencia de ningun
    conducto, en el orden del archivo.
    """
    usadas = set()
    resultados = []
    for c in conductos:
        ip_s, ip_d = _ip(c.get("src")), _ip(c.get("dst"))
        for i, r in enumerate(reglas):
            if _casa(r, ip_s, ip_d, c):
                usadas.add(i)
                resultados.append({"resultado": "permitido" if r["accion"] == "permitir"
                                   else "denegado_observado", "regla": r["id"]})
                break
        else:
            resultados.append({"resultado": "sin_regla", "regla": ""})
    sin_trafico = [r["id"] for i, r in enumerate(reglas)
                   if r["accion"] == "permitir" and i not in usadas]
    return resultados, sin_trafico
