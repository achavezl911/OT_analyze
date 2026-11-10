"""M5: valida la politica propuesta (M3a, revisada por el analista) contra el trafico de OTRA ventana (D67).

Responde "que romperia esta propuesta": cada cruce observado en la ventana nueva (firewall_cruces_detalle.csv de otra
corrida hecha con --firewall del mismo equipo) se evalua contra las reglas de politica_propuesta.csv en orden, la
primera que coincide gana (como el firewall), y se compara con lo que el firewall hace hoy. No se conecta a nada ni
modifica la propuesta. La ventana nueva tambien es parcial: no prueba que no falte nada.
"""
from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path

from ..i18n import DIR_CATALOGOS
from ..report.common import escritor_csv
from . import cruces as _cr
from . import fmc
from .politica import ANY_INTERNET, nombre_valido

MAX_PROF = 10
TOP = 20
ARCHIVO_CRUCES = "firewall_cruces_detalle.csv"

SIGUE_PERMITIDO = "sigue_permitido"
SE_ROMPERIA = "se_romperia"
BLOQUEO_DECIDIDO = "bloqueo_decidido"
SIGUE_BLOQUEADO = "sigue_bloqueado"
SE_ABRIRIA = "se_abriria"
PROBABLE_RESPUESTA = "probable_respuesta"
PUERTO_DINAMICO_MIN = 49152     # inicio del rango dinamico/efimero de IANA
CATEGORIAS = [SE_ROMPERIA, SE_ABRIRIA, PROBABLE_RESPUESTA, BLOQUEO_DECIDIDO, SIGUE_BLOQUEADO, SIGUE_PERMITIDO]

COL_ENTRADA = ["interfaz_origen", "interfaz_destino", "ip_origen", "ip_destino", "nombre_origen", "nombre_destino",
               "ambito_destino", "protocolo_l4", "puerto", "protocolo_aplicacion", "conductos", "bytes",
               "regla_actual", "resultado"]
COL_CRUCES = ["interfaz_origen", "interfaz_destino", "ip_origen", "ip_destino", "nombre_origen", "nombre_destino",
              "ambito_destino", "protocolo_l4", "puerto", "protocolo_aplicacion", "conductos", "bytes",
              "l4_inferido", "etiquetas", "resultado_hoy", "regla_actual", "decision", "regla_propuesta",
              "categoria", "casi_regla", "sugerencia", "fuentes"]
COL_REGLAS = ["orden", "nombre", "decision", "cruces", "conductos", "bytes", "sin_uso"]
NOTA = ("La ventana nueva tambien es parcial: este resultado no prueba que no falte nada. Un 'se_romperia' es trafico "
        "que hoy cruza y la propuesta no permite; puede ser trafico legitimo que falta o trafico que conviene cerrar: "
        "lo decide el analista. Una regla sin uso es un dato, no una orden de borrarla.")

_RES = {"permitido": "permitido", "allowed": "permitido", "denegado_observado": "denegado_observado",
        "denied but observed": "denegado_observado", "sin_regla": "sin_regla", "no rule": "sin_regla",
        "respuesta": "respuesta", "session reply": "respuesta"}
_ET_ENTRANTE, _ET_DNS = "desde Internet", "DNS externo"


class ErrorValidar(Exception):
    """Entrada que no se puede evaluar; el mensaje es para el analista (sin rutas absolutas)."""


def _reverso() -> dict:
    """Texto traducido (ingles) -> clave en espanol, para leer salidas hechas con --idioma en."""
    rev = {k: k for k in (_ET_ENTRANTE, _ET_DNS)}
    try:
        cat = json.loads((DIR_CATALOGOS / "en.json").read_text(encoding="utf-8"))["en"]
    except (OSError, ValueError, KeyError):
        return rev
    for k in (_ET_ENTRANTE, _ET_DNS):
        if k in cat:
            rev[cat[k]] = k
    return rev


_REV = _reverso()


# ---------- propuesta ----------

class _Lado:
    __slots__ = ("inet", "ips", "nets")

    def __init__(self):
        self.ips: set = set()
        self.nets: list = []
        self.inet = False

    def unir(self, o: _Lado) -> None:
        self.ips |= o.ips
        self.nets += o.nets
        self.inet = self.inet or o.inet


class _Srv:
    __slots__ = ("items", "todo")

    def __init__(self):
        self.items: list = []        # (protocolo en minusculas, desde, hasta); desde None = sin puerto
        self.todo = False

    def unir(self, o: _Srv) -> None:
        self.items += o.items
        self.todo = self.todo or o.todo


def _leer(ruta, columnas: tuple) -> list:
    try:
        return fmc._leer(ruta, columnas)
    except fmc.ErrorFmc as e:
        raise ErrorValidar(str(e).replace(str(ruta), Path(str(ruta)).name))


def _servicio(valor: str):
    """'tcp/502', 'udp/1000-2000', 'icmp' -> (protocolo, desde, hasta); 'ip'/'any'/'' -> 'todo'; None si no sirve."""
    v = valor.strip().lower()
    if v in fmc.SERVICIO_CUALQUIERA:
        return "todo"
    m = re.match(r"^([a-z0-9_\-]{1,20})(?:/(\d{1,5})(?:-(\d{1,5}))?)?$", v)
    if not m:
        return None
    if m.group(2) is None:
        return (m.group(1), None, None)
    a = int(m.group(2))
    b = int(m.group(3)) if m.group(3) else a
    if not (0 <= a <= 65535 and 0 <= b <= 65535 and a <= b):
        return None
    return (m.group(1), a, b)


class Propuesta:
    def __init__(self, filas_prop: list, filas_obj: list, zonas=None, alias=()):
        self.errores: list = []
        self.zonas = zonas or {}
        self.alias = [a.lower() for a in alias]
        self.objs: dict = {}
        self.fila_obj: dict = {}
        for i, f in enumerate(filas_obj, 2):
            n = f["nombre"]
            if not n:
                continue
            if n in self.objs:
                self._err("objetos", i, f"objeto repetido: {n}")
            self.objs[n] = f
            self.fila_obj[n] = i
        self._lados: dict = {}
        self._srvs: dict = {}
        for n in self.objs:
            self._compilar(n)
        self.reglas = self._reglas(filas_prop)
        if self.errores:
            raise ErrorValidar("\n".join(dict.fromkeys(self.errores)))

    def _err(self, archivo: str, fila: int, texto: str) -> None:
        self.errores.append(f"{archivo} fila {fila}: {texto}")

    def _tipo(self, n: str):
        return fmc._TIPO.get(self.objs[n]["tipo"].lower())

    def _compilar(self, nombre: str, pila=()):
        """Objeto -> _Lado (host/red/grupo) o _Srv (servicio/grupo_servicio); errores con el numero de fila."""
        tipo = self._tipo(nombre)
        fila = self.fila_obj[nombre]
        cache = self._srvs if tipo in ("servicio", "grupo_servicio") else self._lados
        if nombre in cache:
            return cache[nombre]
        o = self.objs[nombre]
        if nombre in pila or len(pila) >= MAX_PROF:
            self._err("objetos", fila, f"grupo '{nombre}' circular o con mas de {MAX_PROF} niveles")
            return None
        res = None
        if tipo in ("host", "red"):
            res = _Lado()
            if nombre == ANY_INTERNET and tipo == "red":
                res.inet = True
            elif tipo == "host":
                try:
                    res.ips.add(str(ipaddress.ip_address(o["valor"])))
                except ValueError:
                    self._err("objetos", fila, f"objeto {nombre}: IP no valida '{o['valor']}'")
            else:
                try:
                    res.nets.append(ipaddress.ip_network(o["valor"], strict=True))
                except ValueError:
                    self._err("objetos", fila, f"objeto {nombre}: red no valida '{o['valor']}'")
        elif tipo == "servicio":
            res = _Srv()
            sv = _servicio(o["valor"])
            if sv is None:
                self._err("objetos", fila, f"objeto {nombre}: servicio no valido '{o['valor']}'")
            elif sv == "todo":
                res.todo = True
            else:
                res.items.append(sv)
        elif tipo in ("grupo", "grupo_servicio"):
            res = _Lado() if tipo == "grupo" else _Srv()
            miembros = fmc._lista(o["miembros"])
            if not miembros:
                self._err("objetos", fila, f"objeto {nombre}: grupo sin miembros")
            for m in miembros:
                if m not in self.objs:
                    self._err("objetos", fila, f"objeto {nombre}: el miembro '{m}' no esta en el archivo de objetos")
                    continue
                mt = self._tipo(m)
                ok = (mt in ("host", "red", "grupo")) if tipo == "grupo" else (mt in ("servicio", "grupo_servicio"))
                if not ok:
                    self._err("objetos", fila, f"objeto {nombre}: el miembro '{m}' no cabe en un {o['tipo']}")
                    continue
                sub = self._compilar(m, pila + (nombre,))
                if sub is not None:
                    res.unir(sub)
        else:
            self._err("objetos", fila, f"objeto {nombre}: tipo desconocido '{o['tipo']}'")
        if res is not None:
            cache[nombre] = res
        return res

    def _lista(self, f: dict, campo: str, fila: int, clases: tuple, quien: str) -> list:
        nombres = fmc._lista(f[campo])
        if not nombres:
            self._err("propuesta", fila, f"regla {quien}: columna {campo} vacia")
        for n in nombres:
            if n not in self.objs:
                self._err("propuesta", fila, f"regla {quien}: el objeto '{n}' no esta en el archivo de objetos")
            elif self._tipo(n) not in clases:
                self._err("propuesta", fila, f"regla {quien}: '{n}' ({self.objs[n]['tipo']}) no sirve en {campo}")
        return nombres

    def _reglas(self, filas: list) -> list:
        reglas, ordenes, nombres = [], set(), set()
        for i, f in enumerate(filas, 2):
            quien = f["nombre"] or f["orden"] or f"(fila {i})"
            try:
                orden = int(f["orden"])
            except ValueError:
                self._err("propuesta", i, f"regla {quien}: orden no numerico '{f['orden']}'")
                continue
            if orden in ordenes:
                self._err("propuesta", i, f"regla {quien}: orden repetido ({orden})")
            ordenes.add(orden)
            if f["nombre"] in nombres:
                self._err("propuesta", i, f"regla repetida: {f['nombre']}")
            nombres.add(f["nombre"])
            dec = fmc._DECISION.get(f["decision"].lower())
            if dec is None:
                self._err("propuesta", i, f"regla {quien}: decision desconocida '{f['decision']}'")
                continue
            lados = ("host", "red", "grupo")
            srv = ("servicio", "grupo_servicio")
            nom_o = self._lista(f, "origen", i, lados, quien)
            nom_d = self._lista(f, "destino", i, lados, quien)
            nom_s = self._lista(f, "servicios", i, srv, quien)
            ifs = None
            if f.get("interfaces", ""):
                partes = [p.strip() for p in f["interfaces"].split("->")]
                if len(partes) == 2 and all(partes):
                    ifs = (partes[0].lower(), partes[1].lower())
                else:
                    self._err("propuesta", i, f"regla {quien}: interfaces no valida '{f['interfaces']}' "
                                              "(se espera ENTRADA -> SALIDA)")
            elif not (f["zona_entrada"] and f["zona_salida"]):
                self._err("propuesta", i, f"regla {quien}: sin interfaces ni zonas")
            lo, ld, ss = _Lado(), _Lado(), _Srv()
            for nombres_l, dest in ((nom_o, lo), (nom_d, ld)):
                for n in nombres_l:
                    if n in self._lados:
                        dest.unir(self._lados[n])
            for n in nom_s:
                if n in self._srvs:
                    ss.unir(self._srvs[n])
            reglas.append({"orden": orden, "nombre": f["nombre"] or str(orden), "decision": dec, "fila": i,
                           "ifs": ifs, "zonas": (f["zona_entrada"].lower(), f["zona_salida"].lower()),
                           "nom_o": nom_o, "nom_d": nom_d, "nom_s": nom_s, "o": lo, "d": ld, "s": ss})
        reglas.sort(key=lambda r: r["orden"])
        return reglas

    def zona_de(self, ifc: str) -> str:
        for al in self.alias:
            z = self.zonas.get((al, ifc.lower()))
            if z:
                return z.lower()
        return ("SZ_" + nombre_valido(ifc)).lower()


# ---------- cruces ----------

def _res(texto: str) -> str:
    return _RES.get(texto.strip().lower(), _RES.get(texto.strip(), texto.strip()))


def _etiquetas(texto: str) -> set:
    return {_REV.get(x.strip(), x.strip()) for x in texto.split(";") if x.strip()}


def _si(v: str) -> bool:
    return v.strip().lower() in ("si", "yes", "true", "1")


def _entero(v, defecto=0) -> int:
    try:
        return int(str(v).strip())
    except ValueError:
        return defecto


def _archivo_cruces(ruta: str) -> Path:
    p = Path(ruta).expanduser()
    if p.is_dir():
        p = p / ARCHIVO_CRUCES
    if not p.is_file():
        raise ErrorValidar(f"--cruces: no encuentro {ARCHIVO_CRUCES} en '{Path(ruta).name}' "
                           "(use la carpeta de salida de una corrida con --firewall o el archivo mismo)")
    return p


def leer_cruces(rutas: list) -> list:
    """Cruces agregados de una o varias rutas: lista de dicts ordenada de forma determinista."""
    acum: dict = {}
    prioridad = {"permitido": 0, "sin_regla": 1, "denegado_observado": 2, "respuesta": 3}
    for ruta in rutas:
        p = _archivo_cruces(ruta)
        etiqueta = p.parent.name or p.name
        filas = _leer(p, tuple(COL_ENTRADA))
        for f in filas:
            if f.get("ip_origen_real") or f.get("ip_destino_real"):
                # D70: las reglas se evaluan con las IP reales; la observada (traducida por NAT) no cuenta
                f["ip_origen"] = f.get("ip_origen_real") or f["ip_origen"]
                f["ip_destino"] = f.get("ip_destino_real") or f["ip_destino"]
                f["ambito_destino"] = "Internet" if _cr._global(f["ip_destino"]) else "interna"
            res = _res(f["resultado"])
            k = (f["interfaz_origen"], f["interfaz_destino"], f["ip_origen"], f["ip_destino"],
                 f["protocolo_l4"].lower(), f["puerto"], f["protocolo_aplicacion"])
            a = acum.get(k)
            if a is None:
                a = acum[k] = dict(f, resultado=res, conductos=0, bytes=0, hay_bytes=False, fuentes=set())
            elif prioridad.get(res, 1) < prioridad.get(a["resultado"], 1):
                a["resultado"] = res
            for c in ("nombre_origen", "nombre_destino", "regla_actual", "etiquetas"):
                if not a[c] and f[c]:
                    a[c] = f[c]
            a["conductos"] += _entero(f["conductos"])
            if f["bytes"].strip():
                a["bytes"] += _entero(f["bytes"])
                a["hay_bytes"] = True
            a["l4_inferido"] = f.get("l4_inferido", "")
            fu = [x.strip() for x in f.get("fuentes", "").split(";") if x.strip()]
            a["fuentes"].update(fu or [etiqueta])
    return [acum[k] for k in sorted(acum, key=lambda k: (k[0], k[1], _orden_ip(k[2]), _orden_ip(k[3]), k[4],
                                                         _entero(k[5], -1), k[6]))]


def _orden_ip(x: str):
    try:
        ip = ipaddress.ip_address(x)
        return (0, ip.version, int(ip), "")
    except ValueError:
        return (1, 0, 0, x)


def _ip(x: str):
    try:
        return ipaddress.ip_address(x)
    except ValueError:
        return None


class _Cruce:
    """Un cruce preparado para evaluarlo (IP ya interpretadas, servicio normalizado)."""

    def __init__(self, c: dict):
        self.c = c
        self.s, self.d = c["ip_origen"], c["ip_destino"]
        self.so, self.do = _ip(self.s), _ip(self.d)
        self.s_pub = self.so is not None and _cr._global(self.s)
        self.d_pub = self.do is not None and _cr._global(self.d)
        self.l4 = c["protocolo_l4"].strip().lower()
        self.puerto = int(c["puerto"]) if c["puerto"].strip().isdigit() else None
        if self.l4 == "" and self.puerto is not None:
            self.protos = ("tcp", "udp")          # transporte desconocido o inferido: casa con ambos (M2c)
        else:
            self.protos = (self.l4,) if self.l4 else ()
        self.ifo, self.ifd = c["interfaz_origen"].lower(), c["interfaz_destino"].lower()
        self.hoy = _res(c["resultado"])


def _en_lado(lado: _Lado, ip: str, obj, publica: bool) -> bool:
    if ip in lado.ips or (lado.inet and publica):
        return True
    return obj is not None and any(obj in n for n in lado.nets)


def _en_srv(srv: _Srv, x: _Cruce) -> bool:
    if srv.todo:
        return True
    for proto, a, b in srv.items:
        if proto not in x.protos:
            continue
        if a is None:
            if x.puerto is None:
                return True
        elif x.puerto is not None and a <= x.puerto <= b:
            return True
    return False


def _en_interfaces(r: dict, x: _Cruce, p: Propuesta) -> bool:
    if r["ifs"] is not None:
        return r["ifs"] == (x.ifo, x.ifd)
    return r["zonas"] == (p.zona_de(x.ifo), p.zona_de(x.ifd))


def _tipo_lado(p: Propuesta, nombre: str) -> str:
    return "grupo" if p._tipo(nombre) in ("grupo", "grupo_servicio") else "objeto"


def _nombre_servicio(x: _Cruce) -> str:
    if x.puerto is None:
        return (x.l4 or "ip").upper()
    return ("/".join(t.upper() for t in x.protos) if len(x.protos) != 1 else x.protos[0].upper()) + f"/{x.puerto}"


def _sugerencia(p: Propuesta, r: dict, x: _Cruce, dim: str) -> str:
    if dim == "origen" or dim == "destino":
        nombres = r["nom_o"] if dim == "origen" else r["nom_d"]
        ip = x.s if dim == "origen" else x.d
        elegido = next((n for n in nombres if n != ANY_INTERNET), nombres[0])
        return f"agregar {ip} al {_tipo_lado(p, elegido)} {elegido} de la regla {r['nombre']}"
    sv = _nombre_servicio(x)
    if len(r["nom_s"]) == 1 and p._tipo(r["nom_s"][0]) == "servicio":
        return f"agregar {sv} a los servicios de la regla {r['nombre']} (hoy {r['nom_s'][0]})"
    return f"agregar {sv} al grupo {r['nom_s'][0]} de la regla {r['nombre']}"


def _bloqueo_herramienta(x: _Cruce):
    """Razon por la que M3a ya decidio bloquear este cruce aunque hoy pase (politica_bloqueados)."""
    et = _etiquetas(x.c.get("etiquetas", ""))
    if _ET_ENTRANTE in et and not x.d_pub:
        return "origen en Internet hacia la red interna"
    if _ET_DNS in et and not x.s_pub:
        return "DNS externo (usar el DNS interno)"
    return None


def evaluar(p: Propuesta, cruces: list, incluir_revisar: bool = False) -> dict:
    """-> {"cruces": filas de validacion_cruces, "reglas": filas de validacion_reglas, "omitidos": respuestas}."""
    activas = [r for r in p.reglas if r["decision"] != "revisar" or incluir_revisar]
    uso = {r["orden"]: [0, 0, 0] for r in p.reglas}
    filas, omitidos = [], 0
    for c in cruces:
        x = _Cruce(c)
        if x.hoy == "respuesta":
            omitidos += 1
            continue
        ganadora = None
        for r in activas:
            if (_en_interfaces(r, x, p) and _en_lado(r["o"], x.s, x.so, x.s_pub)
                    and _en_lado(r["d"], x.d, x.do, x.d_pub) and _en_srv(r["s"], x)):
                ganadora = r
                break
        hoy_permite = x.hoy != "denegado_observado"
        casi, sug, decision, regla = "", "", "defecto", ""
        if ganadora is not None:
            decision, regla = ganadora["decision"], ganadora["nombre"]
            u = uso[ganadora["orden"]]
            u[0] += 1
            u[1] += _entero(c["conductos"])
            u[2] += c["bytes"]
        if ganadora is not None and ganadora["decision"] != "bloquear":
            cat = SIGUE_PERMITIDO if hoy_permite else SE_ABRIRIA
        elif ganadora is not None:
            cat = BLOQUEO_DECIDIDO if hoy_permite else SIGUE_BLOQUEADO
        else:
            razon = _bloqueo_herramienta(x)
            if razon:
                cat = BLOQUEO_DECIDIDO if hoy_permite else SIGUE_BLOQUEADO
                sug = f"la propuesta lo bloquea a proposito: {razon} (ver politica_bloqueados.csv)"
            elif hoy_permite:
                cat = SE_ROMPERIA
                casi, sug = _casi(p, x)
            else:
                cat = SIGUE_BLOQUEADO
        filas.append({"c": c, "x": x, "hoy": x.hoy, "decision": decision, "regla": regla, "cat": cat,
                      "casi": casi, "sug": sug})
    _marcar_respuestas(filas, [_Cruce(c) for c in cruces])
    reglas = []
    for r in p.reglas:
        n, con, by = uso[r["orden"]]
        excl = r["decision"] == "revisar" and not incluir_revisar
        reglas.append({"orden": r["orden"], "nombre": r["nombre"], "decision": r["decision"], "cruces": n,
                       "conductos": con, "bytes": by or "",
                       "sin_uso": "no evaluada (revisar)" if excl else ("si" if n == 0 else "")})
    return {"cruces": filas, "reglas": reglas, "omitidos": omitidos}


def _marcar_respuestas(filas: list, todos: list) -> None:
    """Un se_romperia/se_abriria a puerto dinamico con cruce inverso a puerto bajo en la entrada es casi seguro la
    respuesta de una conexion permitida: el firewall la deja pasar por estado."""
    bajos = {}
    for y in todos:
        if y.puerto is not None and y.puerto < PUERTO_DINAMICO_MIN:
            bajos.setdefault((y.s, y.d), []).append(y)
    for e in filas:
        x = e["x"]
        if e["cat"] not in (SE_ROMPERIA, SE_ABRIRIA) or x.puerto is None or x.puerto < PUERTO_DINAMICO_MIN:
            continue
        ida = [y.puerto for y in bajos.get((x.d, x.s), []) if set(y.protos) & set(x.protos)]
        if ida:
            e["cat"], e["casi"] = PROBABLE_RESPUESTA, ""
            e["sug"] = (f"respuesta probable de {x.d}:{min(ida)} (el firewall la deja pasar por estado; "
                        "verificar si es otra conexion)")


def _casi(p: Propuesta, x: _Cruce) -> tuple:
    """(regla, sugerencia) de la regla permitir/revisar que casa en todo salvo una dimension; menor orden."""
    for r in p.reglas:
        if r["decision"] == "bloquear" or not _en_interfaces(r, x, p):
            continue
        falta = [dim for dim, ok in (("origen", _en_lado(r["o"], x.s, x.so, x.s_pub)),
                                     ("destino", _en_lado(r["d"], x.d, x.do, x.d_pub)),
                                     ("servicio", _en_srv(r["s"], x))) if not ok]
        if not falta:       # solo una revisar excluida casa del todo
            return r["nombre"], (f"la regla {r['nombre']} es revisar y no se evaluo: use --incluir-revisar o "
                                 "cambiela a permitir")
        if len(falta) == 1:
            return r["nombre"], _sugerencia(p, r, x, falta[0])
    return "", ""


# ---------- salidas ----------

def _fila_cruce(e: dict) -> list:
    c = e["c"]
    return [c["interfaz_origen"], c["interfaz_destino"], c["ip_origen"], c["ip_destino"], c["nombre_origen"],
            c["nombre_destino"], c["ambito_destino"], c["protocolo_l4"], c["puerto"], c["protocolo_aplicacion"],
            c["conductos"], c["bytes"] if c["hay_bytes"] else "", c.get("l4_inferido", ""), c.get("etiquetas", ""),
            e["hoy"], c["regla_actual"], e["decision"], e["regla"], e["cat"], e["casi"], e["sug"],
            "; ".join(sorted(c["fuentes"]))]


def _peso(e: dict):
    c = e["c"]
    return (CATEGORIAS.index(e["cat"]), -(c["bytes"] if c["hay_bytes"] else 0), -_entero(c["conductos"]))


def resumen(res: dict) -> dict:
    """{categoria: [cruces, conductos]} en el orden de CATEGORIAS."""
    out = {k: [0, 0] for k in CATEGORIAS}
    for e in res["cruces"]:
        out[e["cat"]][0] += 1
        out[e["cat"]][1] += _entero(e["c"]["conductos"])
    return out


def _linea(x) -> str:
    return " ".join(str(x).split())


def texto_md(res: dict, incluir_revisar: bool, fuentes: list) -> str:
    cuenta = resumen(res)
    out = ["# Validacion de la politica propuesta contra otra ventana", "",
           "Ventana nueva: " + ", ".join(_linea(Path(f).name or f) for f in fuentes) + ".",
           "Reglas `revisar`: " + ("evaluadas como permitir (--incluir-revisar)." if incluir_revisar
                                   else "no evaluadas (sin --incluir-revisar)."), "", "## Resultado por categoria", ""]
    for k in CATEGORIAS:
        out.append(f"- {k}: {cuenta[k][0]} cruces ({cuenta[k][1]} conductos)")
    if cuenta[PROBABLE_RESPUESTA][0]:
        out.append(f"  ({PROBABLE_RESPUESTA}: puerto destino dinamico y cruce inverso a puerto bajo en la misma entrada; "
                   "el firewall las deja pasar por estado, no se listan abajo; verificar si es otra conexion)")
    if res["omitidos"]:
        out.append(f"- Respuestas de sesion omitidas (no se evaluan, las cubre la regla de ida): {res['omitidos']}")
    rotos = sorted((e for e in res["cruces"] if e["cat"] == SE_ROMPERIA), key=_peso)[:TOP]
    out += ["", f"## Lo que se romperia (los {TOP} de mas bytes)", ""]
    if not rotos:
        out.append("Ninguno.")
    for e in rotos:
        c = e["c"]
        srv = (c["protocolo_l4"] or "ip") + ("/" + c["puerto"] if c["puerto"] else "")
        out.append(f"- {c['interfaz_origen']} -> {c['interfaz_destino']}: {c['ip_origen']} -> {c['ip_destino']} "
                   f"{srv}, {c['conductos']} conductos"
                   + (f", {c['bytes']} bytes" if c["hay_bytes"] else "") + ". "
                   + (_linea(e["sug"]) if e["sug"] else "Sin regla cercana: falta una regla nueva o se cierra a proposito."))
    sin = [r for r in res["reglas"] if r["sin_uso"] == "si"]
    out += ["", "## Reglas de la propuesta sin uso en la ventana nueva", ""]
    if not sin:
        out.append("Ninguna.")
    for r in sin:
        out.append(f"- {r['orden']} {_linea(r['nombre'])} ({r['decision']})")
    nr = [r for r in res["reglas"] if r["sin_uso"].startswith("no evaluada")]
    if nr:
        out += ["", f"{len(nr)} reglas `revisar` no se evaluaron."]
    out += ["", "## Nota", "", NOTA, ""]
    return "\n".join(out)


def escribir(res: dict, carpeta: Path, incluir_revisar: bool, fuentes: list) -> list:
    carpeta.mkdir(parents=True, exist_ok=True)
    with open(carpeta / "validacion_cruces.csv", "w", newline="", encoding="utf-8-sig") as fh:
        w = escritor_csv(fh)
        w.writerow(COL_CRUCES)
        for e in sorted(res["cruces"], key=_peso):
            w.writerow(_fila_cruce(e))
    with open(carpeta / "validacion_reglas.csv", "w", newline="", encoding="utf-8-sig") as fh:
        w = escritor_csv(fh)
        w.writerow(COL_REGLAS)
        for r in res["reglas"]:
            w.writerow([r[c] for c in COL_REGLAS])
    (carpeta / "validacion.md").write_text(texto_md(res, incluir_revisar, fuentes), encoding="utf-8")
    return ["validacion_cruces.csv", "validacion_reglas.csv", "validacion.md"]


def validar(ruta_prop: str, ruta_obj: str, rutas_cruces: list, incluir_revisar=False, zonas=None, alias=()) -> dict:
    prop = _leer(ruta_prop, fmc.COL_PROPUESTA)
    objs = _leer(ruta_obj, fmc.COL_OBJETOS)
    p = Propuesta(prop, objs, zonas, alias)
    return evaluar(p, leer_cruces(rutas_cruces), incluir_revisar)


__all__ = ["CATEGORIAS", "ErrorValidar", "escribir", "resumen", "validar"]
