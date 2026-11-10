"""M3a: politica propuesta por firewall a partir de lo observado (D47).

Por cada firewall toma los conductos que lo cruzan (resultado de integracion.contrastar) y propone reglas
puntuales (equipo o grupo + servicio exacto + interfaces) clasificadas en permitir / revisar / bloquear, mas la
comparacion contra las reglas actuales. La clasificacion es fija (tabla en este modulo); el analista la ajusta
despues. Es evidencia pasiva sobre lo observado en la ventana de las fuentes, no un motor de decision ni una
afirmacion de cumplimiento. Funciones puras salvo cargar_zonas (lee un CSV).
"""
from __future__ import annotations

import collections
import csv
import ipaddress
import re

from ..catalog import OT_PORTS
from ..i18n import Traducido, t
from . import cruces as _cr
from . import esperados as _es
from . import higiene as _hg
from . import topologia as _tp

D_PERMITIR = "permitir"
D_REVISAR = "revisar"
D_BLOQUEAR = "bloquear"
DECISIONES = [D_PERMITIR, D_REVISAR, D_BLOQUEAR]

E_REEMPLAZADA = "reemplazada"
E_ACOTAR = "acotar"
E_ELIMINAR = "eliminar candidata"
E_VALIDAR = "validar antes de eliminar"
E_BLOQUEO = "bloqueo"
E_MANTENER = "mantener bloqueo explicito"
ESTADOS = [E_REEMPLAZADA, E_ACOTAR, E_ELIMINAR, E_VALIDAR, E_BLOQUEO, E_MANTENER]

R_ENTRANTE = "origen en Internet hacia la red interna"
R_DNS = "DNS externo (usar el DNS interno)"
R_DENEGADO = "denegado hoy por el firewall"
R_RETORNO = "solo lo permite una regla de retorno"
R_UN_DIA = "visto un solo dia"
R_SIN_PUERTO = "sin puerto (cualquier protocolo IP)"
R_OT = _cr.OT

ANY_INTERNET = "ANY_INTERNET"
MAX_HOSTS = 10
COBERTURA_24 = 0.8
MIN_EN_24 = 4           # miembros minimos en una /24 para sustituirlos por la red
MAX_NOMBRE = 64
MAX_REGLA = 60          # deja sitio al prefijo SG_ del grupo de servicios
MAX_LISTA = 5

NIVELES_OT = frozenset({"Nivel 0", "Nivel 1", "Nivel 1-2", "Nivel 2", "Nivel 2-3", "Nivel 3"})
_UDP_TIPICO = frozenset({53, 67, 68, 69, 123, 161, 162, 500, 514, 1900, 5353})
_NO_NOMBRE = re.compile(r"[^A-Za-z0-9_.\-]+")

NOTA = ("La propuesta solo cubre lo observado en la ventana de las fuentes; operaciones poco frecuentes "
        "(mantenimiento, contingencia, respaldo mensual) pueden no aparecer. Desplegar primero con registro y "
        "revisar antes de bloquear. Es evidencia tecnica relacionada, no una afirmacion de cumplimiento.")
TITULO = "Politica propuesta"
HOJAS = {"propuesta": "Politica propuesta", "objetos": "Politica objetos", "comparacion": "Politica comparacion",
         "bloqueados": "Politica bloqueados", "esperados": _es.HOJA}
COL_PROPUESTA = ["orden", "nombre", "decision", "razones", "zona_entrada", "zona_salida", "interfaces", "origen",
                 "destino", "servicios", "conductos", "origenes", "destinos", "bytes", "dias", "fuentes",
                 "reglas_actuales", "justificacion"]
COL_OBJETOS = ["nombre", "tipo", "valor", "miembros"]
COL_COMPARACION = ["regla_actual", "nombre", "accion", "aciertos", "conductos_observados", "estado",
                   "reglas_propuestas", "marcas", "comentario"]
COL_BLOQUEADOS = ["interfaz_entrada", "interfaz_salida", "servicio", "origenes", "destinos", "ejemplos_origen",
                  "ejemplos_destino", "conductos", "bytes", "razon", "regla_actual"]
ACCION_DEFECTO = "bloquear con registro (accion por defecto de la politica; no es una regla)"


def nombre_valido(x: str) -> str:
    """Caracteres validos para FMC: letras, digitos, _ - y punto."""
    return _NO_NOMBRE.sub("_", str(x)).strip("_")


def cargar_zonas(ruta: str) -> dict:
    """CSV `firewall,interfaz,zona` -> {(firewall, interfaz) en minusculas: zona}. ValueError si no sirve."""
    try:
        with open(ruta, newline="", encoding="utf-8-sig") as fh:
            lector = csv.DictReader(fh)
            campos = [(c or "").strip().lower() for c in (lector.fieldnames or [])]
            falta = [c for c in ("firewall", "interfaz", "zona") if c not in campos]
            if falta:
                raise ValueError(f"{ruta}: faltan las columnas {', '.join(falta)} (firewall,interfaz,zona)")
            out = {}
            for fila in lector:
                f = {(k or "").strip().lower(): (v or "").strip() for k, v in fila.items()}
                if f["firewall"] and f["interfaz"] and f["zona"]:
                    out[(f["firewall"].lower(), f["interfaz"].lower())] = f["zona"]
            return out
    except OSError as e:
        raise ValueError(f"no pude leer {ruta}: {e}")


def _orden_ip(x):
    try:
        ip = ipaddress.ip_address(x)
        return (0, ip.version, int(ip), "")
    except ValueError:
        return (1, 0, 0, str(x))


def _v4(x):
    try:
        return ipaddress.IPv4Address(x)
    except ValueError:
        return None


def _l4_servicio(l4: str, puerto):
    """(transporte en mayusculas, inferido). Sin transporte (xDome) se infiere por el puerto."""
    if l4 in ("tcp", "udp"):
        return l4.upper(), False
    if puerto is None:
        return (l4.upper() if l4 else "IP"), False
    if (puerto, "udp") in OT_PORTS and (puerto, "tcp") not in OT_PORTS:
        return "UDP", True
    return ("UDP" if puerto in _UDP_TIPICO else "TCP"), True


def _nombre_servicio(sv) -> str:
    return "S_" + sv[0] + ("_" + str(sv[1]) if sv[1] is not None else "")


class _Objetos:
    """Objetos de la politica de un firewall, sin colisiones de nombre y sin duplicados por valor."""

    def __init__(self):
        self.filas: dict = {}
        self.cache: dict = {}
        self.n_grupos = 0

    def _unico(self, base: str) -> str:
        base = base[:MAX_NOMBRE]
        n = 2
        cand = base
        while cand in self.filas:
            suf = f"_{n}"
            cand = base[:MAX_NOMBRE - len(suf)] + suf
            n += 1
        return cand

    def _alta(self, clave, base, tipo, valor, miembros=""):
        if clave not in self.cache:
            nombre = self._unico(base)
            self.filas[nombre] = {"nombre": nombre, "tipo": tipo, "valor": valor, "miembros": miembros}
            self.cache[clave] = nombre
        return self.cache[clave]

    def host(self, ip, nombre):
        return self._alta(("h", ip), "H_" + nombre_valido(nombre or ip.replace(".", "_")), "host", ip)

    def red(self, cidr):
        return self._alta(("n", cidr), "N_" + nombre_valido(cidr.replace(".", "_")), "red", cidr)

    def servicio(self, sv):
        valor = sv[0].lower() + ("/" + str(sv[1]) if sv[1] is not None else "")
        return self._alta(("s", sv), _nombre_servicio(sv), "servicio", valor)

    def internet(self):
        return self._alta(("i",), ANY_INTERNET, "red", "0.0.0.0/0")

    def grupo(self, miembros, ifc, tipo):
        clave = ("g", frozenset(miembros))
        if clave not in self.cache:
            self.n_grupos += 1
            base = f"G_{nombre_valido(ifc)}_{nombre_valido(tipo) or 'hosts'}_{self.n_grupos}"
        else:
            base = ""
        return self._alta(clave, base, "grupo", "", ";".join(miembros))

    def grupo_servicios(self, nombre_regla, servicios):
        return self._alta(("sg", nombre_regla), "SG_" + nombre_regla, "grupo_servicio", "",
                          ";".join(servicios))


def _indice(assets: dict):
    """(ip -> activo, /24 -> IPs inventariadas)."""
    por_ip: dict = {}
    inv24: dict = collections.defaultdict(set)
    for a in (assets or {}).values():
        for ip in a.get("ips") or ():
            por_ip.setdefault(ip, a)
            v = _v4(ip)
            if v is not None:
                inv24[str(ipaddress.IPv4Network((int(v) & 0xFFFFFF00, 24)))].add(ip)
    return por_ip, inv24


def _nombre_activo(a) -> str:
    if not a:
        return ""
    return a.get("nombre") or (sorted(a.get("hostnames") or ())[:1] or [""])[0]


def _tipo_activo(a) -> str:
    if not a:
        return ""
    for k in ("tipo_texto", "role", "tipo"):
        v = a.get(k)
        if v and str(v).lower() not in ("otro", "indeterminado"):
            return str(v)
    return ""


def interfaces_ot(fw, assets: dict) -> tuple:
    """(interfaces de OT, se_sabe): una interfaz es de OT si la mayoria de sus activos con nivel Purdue
    clasificado esta en los niveles 0 a 3. Sin ningun activo clasificado no se sabe cuales son."""
    cuenta: dict = collections.defaultdict(lambda: [0, 0])
    for a in (assets or {}).values():
        nivel = a.get("purdue")
        if not nivel or not str(nivel).startswith("Nivel"):
            continue
        for ip in sorted(a.get("ips") or ()):
            ifc = fw.interfaz_de(ip)
            if ifc:
                cuenta[ifc][0] += 1
                cuenta[ifc][1] += nivel in NIVELES_OT
                break
    return {i for i, (n, o) in cuenta.items() if o * 2 > n}, bool(cuenta)


def _razones(it: dict, ot: set, ot_sabido: bool, espejo=frozenset()) -> tuple:
    """(decision, razones) de un conducto; ver D47."""
    et = it["et"]
    if it["res"] == "denegado_observado":
        return D_BLOQUEAR, [R_DENEGADO]
    if _cr.DESDE_NET in et and not it["dest_global"]:
        return D_BLOQUEAR, [R_ENTRANTE]
    if _cr.DNS_EXT in et and not it["orig_global"]:
        return D_BLOQUEAR, [R_DNS]
    rz = []
    for e in (_cr.ACCESO_REMOTO, _cr.ARCHIVOS):
        if e in et:
            rz.append(e)
    if _cr.CLARO in et and _cr.OT not in et:     # los protocolos OT van en claro por diseno: los cubre `protocolo OT`
        rz.append(_cr.CLARO)
    if _cr.ADMIN in et:
        rz.append(_cr.ADMIN)
    if _cr.OT in et and (not ot_sabido or it["ifo"] not in ot or it["ifd"] not in ot):
        rz.append(R_OT)
    for e in (_cr.HACIA_NET, _cr.DESDE_NET, _cr.ALTO):
        if e in et:
            rz.append(e)
    if it["res"] == "permitido" and it.get("regla") in espejo:
        rz.append(R_RETORNO)
    if it["dias"] == 1:
        rz.append(R_UN_DIA)
    if it["puerto"] is None or it["puerto"] == "":
        # sin puerto la regla abriria cualquier protocolo y puerto entre esos equipos: nunca permitir directo
        rz.append(R_SIN_PUERTO)
    for e in (_cr.MUCHOS_O, _cr.MUCHOS_D):
        if e in it["et_grupo"]:
            rz.append(e)
    return (D_REVISAR if rz else D_PERMITIR), rz


def _preparar(d: dict, conductos: list, ip_de, idx: dict, ot: set, ot_sabido: bool, incompleto) -> tuple:
    """(items de los conductos que cruzan, respuestas)."""
    espejo = frozenset(r["id"] for r in d["reglas"] if r.get("activa", True) and _hg._tiene(r, _hg.M_ESPEJO))
    items, grupos, glob = [], collections.defaultdict(lambda: (set(), set())), {}
    respuestas = 0

    def es_global(ip):
        v = glob.get(ip)
        if v is None:
            v = glob[ip] = _cr._global(ip)
        return v

    for i, c in enumerate(conductos):
        r = d["resultados"][i]
        res = r["resultado"]
        if res == "no_cruza":
            continue
        s, dd = str(ip_de(c.get("src"))), str(ip_de(c.get("dst")))
        ns, nd = c.get("src_nombre"), c.get("dst_nombre")
        nat = r.get("nat")     # D70: la propuesta usa las IP reales; la observada queda en la justificacion
        obs = None
        if nat:
            obs = (s, dd, nat["regla"])
            s0, d0 = s, dd
            s, dd = nat["s"], nat["d"]
            ns, nd = (ns if s == s0 else ""), (nd if dd == d0 else "")
        if r.get("sentido") == "invertido":
            s, dd, ns, nd = dd, s, nd, ns
            if obs:
                obs = (obs[1], obs[0], obs[2])
        l4 = str(c.get("l4") or "").strip().lower()
        puerto = _cr._puerto(c)
        servicio = str(c.get("servicio") or "")
        app = "" if servicio == "-" else servicio
        et = set(_cr.etiquetas_de(puerto, l4, app, dd, s, (idx.get(dd) or {}).get("tipo", ""),
                                  res == "denegado_observado"))
        it = {"i": i, "s": s, "d": dd, "ns": ns if ns and ns != s else "", "nd": nd if nd and nd != dd else "",
              "ifo": r["if_origen"], "ifd": r["if_destino"], "l4": l4, "puerto": puerto, "app": app,
              "res": res, "regla": r.get("regla", ""), "regla_nombre": r.get("regla_nombre", ""),
              "et": et, "bytes": int(c.get("bytes") or 0), "dias": c.get("dias"),
              "primera": c.get("primera") or "", "ultima": c.get("ultima") or "",
              "fuentes": c.get("fuentes") or (), "orig_global": es_global(s), "dest_global": es_global(dd),
              "incompleto": incompleto[i] if incompleto else (), "nat": obs}
        if res == "respuesta":
            respuestas += 1
            it["decision"], it["razones"] = "respuesta", []
        else:
            g = grupos[(it["ifo"], it["ifd"], l4, puerto, app)]
            g[0].add(s)
            g[1].add(dd)
        items.append(it)
    muchos = {k: ({_cr.MUCHOS_O} if len(o) >= _cr.UMBRAL_MUCHOS else set())
              | ({_cr.MUCHOS_D} if len(dd) >= _cr.UMBRAL_MUCHOS else set()) for k, (o, dd) in grupos.items()}
    for it in items:
        if it["res"] == "respuesta":
            continue
        it["et_grupo"] = muchos[(it["ifo"], it["ifd"], it["l4"], it["puerto"], it["app"])]
        it["decision"], it["razones"] = _razones(it, ot, ot_sabido, espejo)
        it["sv"], it["l4_inferido"] = _l4_servicio(it["l4"], it["puerto"])
        it["sv"] = (it["sv"], it["puerto"])
    return items, respuestas


def _rango_dias(its: list) -> str:
    dias = [x["dias"] for x in its if x["dias"]]
    pri = [x["primera"] for x in its if x["primera"]]
    ult = [x["ultima"] for x in its if x["ultima"]]
    if not dias and not pri:
        return ""
    txt = str(max(dias)) + " " + t("dias") if dias else ""
    if pri:
        txt += " (" + min(pri) + " " + t("a") + " " + max(ult or pri) + ")"
    return txt.strip()


def _bicliques(its: list) -> list:
    """[(origenes, destinos, [servicios])]: por servicio, los origenes con el mismo conjunto de destinos van
    juntos (sin permitir pares que no se vieron); servicios con los mismos conjuntos comparten regla."""
    por_sv: dict = collections.defaultdict(lambda: collections.defaultdict(set))
    for x in its:
        o = ANY_INTERNET if x["orig_global"] else x["s"]
        dd = ANY_INTERNET if x["dest_global"] else x["d"]
        por_sv[x["sv"]][o].add(dd)
    pares: dict = collections.defaultdict(list)
    for sv, mapa in por_sv.items():
        por_dest: dict = collections.defaultdict(set)
        for o, dests in mapa.items():
            por_dest[frozenset(dests)].add(o)
        for dests, orig in por_dest.items():
            pares[(frozenset(orig), dests)].append(sv)
    return [(o, dd, sorted(svs, key=lambda s: (s[0], -1 if s[1] is None else s[1])))
            for (o, dd), svs in sorted(pares.items(), key=lambda kv: (
                sorted(map(_orden_ip, kv[0][0])), sorted(map(_orden_ip, kv[0][1])), sorted(kv[1], key=str)))]


class _Lado:
    __slots__ = ("just", "nombres", "tam")

    def __init__(self):
        self.nombres, self.tam, self.just = [], 0, []


def _lado(ips, ifc, objs, nombres_ip, info, inv24, internas) -> _Lado:
    out = _Lado()
    reales = sorted((x for x in ips if x != ANY_INTERNET), key=_orden_ip)
    if ANY_INTERNET in ips:
        out.nombres.append(objs.internet())
        out.tam += 2 ** 32
    if len(reales) <= MAX_HOSTS:
        for ip in reales:
            out.nombres.append(objs.host(ip, nombres_ip.get(ip, "")))
        out.tam += len(reales)
        return out
    miembros, redes = [], []
    por24: dict = collections.defaultdict(list)
    for ip in reales:
        v = _v4(ip)
        if v is None:
            por24[None].append(ip)
        else:
            por24[str(ipaddress.IPv4Network((int(v) & 0xFFFFFF00, 24)))].append(ip)
    for red in sorted(k for k in por24 if k is not None):
        mi = por24[red]
        inv = inv24.get(red) or set()
        cub = len(inv & set(mi))
        if len(mi) >= MIN_EN_24 and inv and cub / len(inv) >= COBERTURA_24:
            redes.append(red)
            out.just.append(("red {red} (/24): las IP del grupo cubren {c} de {n} activos inventariados",
                             {"red": red, "c": cub, "n": len(inv)}))
        else:
            miembros += mi
    miembros += por24.get(None, [])
    nombres = [objs.red(r) for r in redes] + [objs.host(ip, nombres_ip.get(ip, "")) for ip in miembros]
    out.tam += 256 * len(redes) + len(miembros)
    if len(nombres) == 1:
        out.nombres += nombres
        return out
    tipos = collections.Counter(info(ip) for ip in reales if info(ip))
    tipo = tipos.most_common(1)[0][0] if tipos else "hosts"
    g = objs.grupo(nombres, ifc, tipo)
    out.nombres.append(g)
    out.just.append(("objeto grupo {g} con {n} IP", {"g": g, "n": len(reales)}))
    return out


def _zona(fw, aliases, ifc, zonas, sin_zona):
    for al in aliases:
        z = zonas.get((al, ifc.lower()))
        if z:
            return z
    z = fw.zona_de(ifc)
    if z and z.lower() != ifc.lower():      # sin show zone el adaptador pone el nameif como zona: no es una zona real
        return z
    sin_zona.add(ifc)
    return "SZ_" + nombre_valido(ifc)


def _ancha(regla) -> bool:
    """Regla mas amplia que cualquier trafico concreto: cualquier origen o destino, o sin puertos en tcp/udp/ip."""
    if regla is None:
        return False
    subs = regla.subreglas or [regla]
    for s in subs:
        o = s.origen if hasattr(s, "origen") else []
        dd = s.destino if hasattr(s, "destino") else []
        if any(n.prefixlen == 0 for n in o) or any(n.prefixlen == 0 for n in dd):
            return True
        protos = s.protocolos if hasattr(s, "protocolos") else []
        pt = s.puertos_destino if hasattr(s, "puertos_destino") else getattr(s, "puertos", [])
        if (not protos or any(p in ("ip", "tcp", "udp") for p in protos)) and not pt:
            return True
    return False


def construir(fw, d: dict, ident: str, aliases: list, conductos: list, ip_de, idx: dict, inv24: dict,
              assets: dict, zonas: dict, incompleto=None) -> dict:
    """Politica propuesta de un firewall (`d` = integracion.contrastar de ese firewall)."""
    ot, ot_sabido = interfaces_ot(fw, assets)
    items, respuestas = _preparar(d, conductos, ip_de, idx, ot, ot_sabido, incompleto)
    internas = sorted({str(r.red) for r in fw.rutas if r.tipo != "defecto" and r.red.prefixlen > 0},
                      key=lambda x: _orden_ip(x.split("/")[0]))
    nombres_ip: dict = {}
    for ip, a in idx.items():
        n = _nombre_activo(a)
        if n and n != ip:
            nombres_ip[ip] = n
    for it in items:
        if it["ns"]:
            nombres_ip[it["s"]] = it["ns"]
        if it["nd"]:
            nombres_ip[it["d"]] = it["nd"]

    def info(ip):
        return _tipo_activo(idx.get(ip))

    objs = _Objetos()
    sin_zona: set = set()
    # reglas candidatas, en orden determinista
    reglas = []
    clave: dict = collections.defaultdict(list)
    for it in items:
        if it["decision"] in (D_PERMITIR, D_REVISAR):
            clave[(it["ifo"], it["ifd"], it["decision"])].append(it)
    for k in sorted(clave):
        its = clave[k]
        dueno = {}
        bic = _bicliques(its)
        for n, (o, dd, svs) in enumerate(bic):
            for sv in svs:
                for ip in o:
                    dueno[(sv, ip)] = n
        por_regla: dict = collections.defaultdict(list)
        for x in its:
            por_regla[dueno[(x["sv"], ANY_INTERNET if x["orig_global"] else x["s"])]].append(x)
        for n, (o, dd, svs) in enumerate(bic):
            xs = por_regla[n]
            lo = _lado(o, k[0], objs, nombres_ip, info, inv24, internas)
            ld = _lado(dd, k[1], objs, nombres_ip, info, inv24, internas)
            razones = [r for r in dict.fromkeys(r for x in xs for r in x["razones"])]
            reglas.append({"ifo": k[0], "ifd": k[1], "decision": k[2], "razones": razones, "svs": svs,
                           "origen": lo, "destino": ld, "items": xs, "tam": max(lo.tam, 1) * max(ld.tam, 1),
                           "zo": _zona(fw, aliases, k[0], zonas, sin_zona),
                           "zd": _zona(fw, aliases, k[1], zonas, sin_zona)})
    reglas.sort(key=lambda r: (r["zo"], r["zd"], r["tam"], DECISIONES.index(r["decision"]), r["ifo"], r["ifd"]))
    usados: set = set()
    for orden, r in enumerate(reglas, 1):
        cuenta = collections.Counter()
        for x in r["items"]:
            cuenta[x["sv"]] += 1
        principal = max(r["svs"], key=lambda s: (cuenta[s], str(s)))
        base = nombre_valido(f"{orden}_{r['ifo']}_a_{r['ifd']}_{_nombre_servicio(principal)}")[:MAX_REGLA]
        nombre, n = base, 2
        while nombre in usados:
            suf = f"_{n}"
            nombre, n = base[:MAX_REGLA - len(suf)] + suf, n + 1
        usados.add(nombre)
        r["orden"], r["nombre"] = orden, nombre
        sn = [objs.servicio(sv) for sv in r["svs"]]
        r["servicios"] = sn[0] if len(sn) == 1 else objs.grupo_servicios(nombre, sn)
    # bloqueados: agregado por par de interfaces, servicio y razon
    bl: dict = collections.defaultdict(list)
    for it in items:
        if it["decision"] == D_BLOQUEAR:
            sv = (it["l4"] or "ip") + ("/" + str(it["puerto"]) if it["puerto"] is not None else "")
            if it["app"]:
                sv += " (" + it["app"] + ")"
            bl[(it["ifo"], it["ifd"], sv, it["razones"][0])].append(it)
    bloqueados = []
    for k in sorted(bl):
        xs = bl[k]
        o = {x["s"]: x["ns"] for x in xs}
        dd = {x["d"]: x["nd"] for x in xs}
        by = sum(x["bytes"] for x in xs)
        bloqueados.append({"interfaz_entrada": k[0], "interfaz_salida": k[1], "servicio": k[2], "origenes": len(o),
                           "destinos": len(dd), "ejemplos_origen": _cr._ejemplos(o), "ejemplos_destino": _cr._ejemplos(dd),
                           "conductos": len(xs), "bytes": by or "", "razon": k[3],
                           "indices": [x["i"] for x in xs],
                           "regla_actual": "; ".join(sorted({(x["regla"] + " " + x["regla_nombre"]).strip()
                                                             for x in xs if x["regla"]})[:MAX_LISTA])})
    # justificacion y reglas actuales por regla propuesta
    for r in reglas:
        xs = r["items"]
        r["conductos"] = len(xs)
        r["bytes"] = sum(x["bytes"] for x in xs)
        r["dias"] = _rango_dias(xs)
        r["fuentes"] = sorted({f for x in xs for f in x["fuentes"]})
        r["actuales"] = sorted({(x["regla"] + " " + x["regla_nombre"]).strip() for x in xs if x["regla"]})
        j = [("observado: {c} conductos, {o} origenes, {d} destinos", {
            "c": len(xs), "o": len({x["s"] for x in xs}), "d": len({x["d"] for x in xs})})]
        if r["actuales"]:
            j.append(("permitido hoy por {r}", {"r": "; ".join(r["actuales"][:MAX_LISTA])}))
        elif any(x["res"] == "sin_regla" for x in xs):
            j.append(("hoy sin regla que lo permita", {}))
        if any(x["l4_inferido"] for x in xs):
            j.append(("transporte inferido por el puerto", {}))
        for x in [x for x in xs if x["nat"]][:MAX_LISTA]:
            j.append(("observado como {o} (NAT {r})", {"o": x["nat"][0] + " -> " + x["nat"][1], "r": x["nat"][2]}))
        j += r["origen"].just + r["destino"].just
        falt = sorted({f for x in xs for f in x["incompleto"]})
        if falt:
            j.append(("camino incompleto: sin interfaz conocida en {f}", {"f": ", ".join(falt)}))
        r["just"] = j
    return _comparar(fw, d, ident, reglas, bloqueados, items, respuestas, objs, sin_zona, internas)


def _comparar(fw, d, ident, reglas, bloqueados, items, respuestas, objs, sin_zona, internas) -> dict:
    por_id = {r.id: r for r in fw.reglas}
    cubre: dict = collections.defaultdict(lambda: [0, 0, set(), 0])    # id -> total, cubiertos, propuestas, bloq
    propia = {}
    for r in reglas:
        for x in r["items"]:
            propia[x["i"]] = r
    for x in items:
        if not x["regla"]:
            continue
        c = cubre[x["regla"]]
        c[0] += 1
        if x["res"] == "respuesta":
            c[1] += 1
        elif x["i"] in propia:
            c[1] += 1
            c[2].add(propia[x["i"]]["nombre"])
        else:
            c[3] += 1
    filas = []
    for rd in d["reglas"]:
        if not rd["activa"]:
            continue
        c = cubre.get(rd["id"], [0, 0, set(), 0])
        total, cubiertos, props, bloq = c
        regla = por_id.get(rd["id"])
        marcas = rd["marcas"]
        com: list = []
        if rd["accion"] == "bloquear":
            if total and rd["aciertos"]:
                estado = E_MANTENER
                com.append(("tiene conductos observados y aciertos", {}))
            else:
                estado = E_BLOQUEO
                com.append(("la sustituye la accion por defecto", {}))
        elif total == 0:
            if d["resumen"]["con_contadores"] and not rd["aciertos"]:
                estado = E_ELIMINAR
                com.append(("sin aciertos en el firewall y sin conductos observados", {}))
            elif rd["aciertos"]:
                estado = E_VALIDAR
                com.append(("tiene {a} aciertos y el sensor no vio su trafico: no eliminar sin validar",
                            {"a": rd["aciertos"]}))
            else:
                estado = E_VALIDAR
                com.append(("sin contadores de aciertos: no se sabe si se usa", {}))
        elif _hg.M_ANY in marcas or _ancha(regla):
            estado = E_ACOTAR
            com.append(("mas amplia que lo observado ({n} conductos)", {"n": total}))
        elif cubiertos == total:
            estado = E_REEMPLAZADA
        else:
            estado = E_ACOTAR
            com.append(("{n} de sus conductos se proponen para bloquear", {"n": bloq}))
        filas.append({"regla_actual": rd["id"], "nombre": rd["nombre"], "accion": rd["accion"],
                      "aciertos": rd["aciertos"], "conductos_observados": total, "estado": estado,
                      "reglas_propuestas": "; ".join(sorted(props)[:MAX_LISTA])
                      + ("; ..." if len(props) > MAX_LISTA else ""),
                      "marcas": marcas, "comentario": com})
    cd = collections.Counter(x["decision"] for x in items)
    resumen = {"conductos": len(items), "respuestas": respuestas,
               "conductos_por_decision": {k: cd.get(k, 0) for k in DECISIONES},
               "reglas_por_decision": {k: sum(1 for r in reglas if r["decision"] == k) for k in DECISIONES},
               "bloqueados": len(bloqueados),
               "estados": {e: sum(1 for f in filas if f["estado"] == e) for e in ESTADOS},
               "caminos_incompletos": sum(1 for r in reglas if any(x["incompleto"] for x in r["items"])),
               "pares_zonas": _pares_zonas(reglas)}
    avisos = [("sin zona de seguridad para la interfaz {i}: se propone SZ_{n} (usar --zonas-fw)",
               {"i": i, "n": nombre_valido(i)}) for i in sorted(sin_zona)]
    return {"id": ident, "prefijo": _tp.prefijo_archivo(ident), "reglas": reglas, "internas": internas,
            "objetos": list(objs.filas.values()), "comparacion": filas, "bloqueados": bloqueados, "resumen": resumen, "avisos": avisos}


def _pares_zonas(reglas: list) -> list:
    acum: dict = {}
    for r in reglas:
        a = acum.setdefault((r["zo"], r["zd"]), {D_PERMITIR: 0, D_REVISAR: 0})
        a[r["decision"]] += 1
    return [{"zona_entrada": k[0], "zona_salida": k[1], "permitir": v[D_PERMITIR], "revisar": v[D_REVISAR]}
            for k, v in sorted(acum.items())]


def construir_todo(ids: list, nombres: list, fws: list, dicts: list, conductos: list, assets: dict, ip_de,
                   zonas=None) -> dict:
    """{'firewalls': [politica por firewall], 'multiple': bool, 'avisos': [...]}."""
    zonas = zonas or {}
    idx, inv24 = _indice(assets)
    incompleto = None
    if len(fws) > 1:
        incompleto = [[] for _ in conductos]
        cache: dict = {}

        def conoce(k, ip):
            if (k, ip) not in cache:
                cache[(k, ip)] = fws[k].interfaz_de(ip) is not None
            return cache[(k, ip)]
        for i, c in enumerate(conductos):
            cruzan = [k for k, d in enumerate(dicts) if d["resultados"][i]["resultado"] != "no_cruza"]
            if not cruzan:
                continue
            s, dd = str(ip_de(c.get("src"))), str(ip_de(c.get("dst")))
            for k in range(len(fws)):
                if k not in cruzan and conoce(k, s) != conoce(k, dd):
                    incompleto[i].append(ids[k])
    out = []
    for k, fw in enumerate(fws):
        stem = nombres[k].rsplit(".", 1)[0] if "." in nombres[k] else nombres[k]
        aliases = [x.lower() for x in dict.fromkeys([ids[k], fw.hostname, nombres[k], stem]) if x]
        pk = construir(fw, dicts[k], ids[k], aliases, conductos, ip_de, idx, inv24, assets, zonas, incompleto)
        pk["esperados"] = _es.calcular(fw, dicts[k], conductos, assets, ip_de,
                                       lambda ifc, fw=fw, al=aliases: _zona(fw, al, ifc, zonas, set()))   # M6
        out.append(pk)
    return {"firewalls": out, "multiple": len(fws) > 1,
            "avisos": [(x["id"], a) for x in out for a in x["avisos"]]}


def texto_aviso(ident: str, aviso, multiple: bool) -> str:
    clave, kw = aviso
    return (ident + ": " if multiple else "") + t(clave, **kw)


def _j(partes: list) -> str:
    return "; ".join(t(c, **kw) for c, kw in partes)


def _nombre_archivo(base: str, p: dict, multiple: bool) -> str:
    return (p["prefijo"] + "_" + base) if multiple else base


def _hoja(nombre: str, p: dict, multiple: bool):
    return Traducido(p["id"] + " " + t(nombre)) if multiple else nombre


def filas_propuesta(p: dict) -> list:
    return [[r["orden"], r["nombre"], t(r["decision"]), "; ".join(t(x) for x in r["razones"]), r["zo"], r["zd"],
             r["ifo"] + " -> " + r["ifd"], ";".join(r["origen"].nombres), ";".join(r["destino"].nombres),
             r["servicios"], r["conductos"], len({x["s"] for x in r["items"]}),
             len({x["d"] for x in r["items"]}), r["bytes"] or "", r["dias"], "; ".join(r["fuentes"]),
             "; ".join(r["actuales"]), _j(r["just"])] for r in p["reglas"]]


def _miembros(o: dict, p: dict) -> str:
    if o["nombre"] != ANY_INTERNET:
        return o["miembros"]
    ints = p["internas"]
    return t("excepto las redes internas del firewall") + (
        ": " + "; ".join(ints[:MAX_LISTA]) + ("; ..." if len(ints) > MAX_LISTA else "") if ints else "")


def filas_objetos(p: dict) -> list:
    return [[o["nombre"], t(o["tipo"]), o["valor"], _miembros(o, p)] for o in p["objetos"]]


def filas_comparacion(p: dict) -> list:
    return [[f["regla_actual"], f["nombre"], t(f["accion"]), f["aciertos"], f["conductos_observados"],
             t(f["estado"]), f["reglas_propuestas"], f["marcas"], _j(f["comentario"])] for f in p["comparacion"]]


def filas_bloqueados(p: dict) -> list:
    return [[b[c] if c != "razon" else t(b[c]) for c in COL_BLOQUEADOS] for b in p["bloqueados"]]


def filas_esperados(p: dict) -> list:
    return _es.filas(p["esperados"])


def hay(fw: dict) -> bool:
    pol = (fw or {}).get("politica")
    return bool(pol and pol["firewalls"])


def tablas(pol: dict) -> list:
    """[(archivo, hoja, cabecera, filas)] de la politica propuesta de cada firewall."""
    out = []
    mult = pol["multiple"]
    for p in pol["firewalls"]:
        for clave, base, cab, f in (("propuesta", "politica_propuesta.csv", COL_PROPUESTA, filas_propuesta),
                                    ("objetos", "politica_objetos.csv", COL_OBJETOS, filas_objetos),
                                    ("comparacion", "politica_comparacion.csv", COL_COMPARACION,
                                     filas_comparacion),
                                    ("bloqueados", "politica_bloqueados.csv", COL_BLOQUEADOS, filas_bloqueados),
                                    ("esperados", _es.ARCHIVO, _es.COLUMNAS, filas_esperados)):
            out.append((_nombre_archivo(base, p, mult), _hoja(HOJAS[clave], p, mult), cab, f(p)))
    if pol["firewalls"]:     # vista agrupada para el cliente: un solo archivo con todos los firewalls
        out.append((_es.ARCHIVO_CLIENTE, _es.HOJA_CLIENTE, _es.COLUMNAS_CLIENTE, _es.filas_cliente(pol)))
    return out


def resumen_texto(pol: dict) -> str:
    c = sum(p["resumen"]["conductos"] for p in pol["firewalls"])
    r = sum(p["resumen"]["respuestas"] for p in pol["firewalls"])
    n = sum(len(p["reglas"]) for p in pol["firewalls"])
    b = sum(p["resumen"]["bloqueados"] for p in pol["firewalls"])
    txt = t("{n} reglas propuestas a partir de {c} conductos que cruzan ({r} respuestas de sesion no generan "
            "regla); {b} agregados para bloquear o ya negados. Detalle en politica_propuesta.csv, "
            "politica_objetos.csv, politica_comparacion.csv y politica_bloqueados.csv.", n=n, c=c, r=r, b=b)
    return (txt + " " + _es.texto_resumen(pol)).strip()


def tablas_reporte(pol: dict) -> list:
    """[(titulo, cabecera, filas)] para HTML, Markdown y Word."""
    mult = pol["multiple"]

    def pre(cab, filas, p):
        return ([t("Firewall")] + cab, [[p["id"]] + f for f in filas]) if mult else (cab, filas)
    dec, zon, est = ([], []), ([], []), ([], [])
    for p in pol["firewalls"]:
        rs = p["resumen"]
        c, f = pre([t("Decision"), t("Reglas"), t("Conductos")],
                   [[t(k), rs["reglas_por_decision"][k], rs["conductos_por_decision"][k]] for k in DECISIONES], p)
        dec = (c, dec[1] + f)
        c, f = pre([t("Zona de entrada"), t("Zona de salida"), t("permitir"), t("revisar")],
                   [[z["zona_entrada"], z["zona_salida"], z["permitir"], z["revisar"]] for z in rs["pares_zonas"]], p)
        zon = (c, zon[1] + f)
        c, f = pre([t("Estado de la regla actual"), t("Reglas")],
                   [[t(e), rs["estados"][e]] for e in ESTADOS if rs["estados"][e]], p)
        est = (c, est[1] + f)
    return [(t("Politica propuesta por decision"),) + dec, (t("Politica propuesta por par de zonas"),) + zon,
            (t("Reglas actuales contra la propuesta"),) + est]
