"""F1c: higiene de reglas de firewall (marcas por regla) y hallazgos derivados de la configuracion.

Marcas (columna `marcas` de firewall_reglas.csv; varias separadas por "; "): ver DECISIONES D43.
Es evidencia pasiva sobre el modelo (aproximacion), no un motor de decision del firewall.
Funciones puras: no tocan el disco.
"""
from __future__ import annotations

import collections
import ipaddress

from ..i18n import t
from .modelo import Subregla

M_ANY = "any-any"
M_CONFIA = "confia sin inspeccion"
M_SOMBRA = "sombreada por "
M_DISTINTA = " (accion distinta)"
M_SIN_ACIERTOS = "sin aciertos"
M_SIN_CONDUCTOS = "sin conductos observados"
M_SIN_ARP = "salto sin ARP"
M_SIN_TRAFICO = "sin trafico observado"
M_CUBIERTA = "cubierta por "
M_DOS_SALTOS = "mismo prefijo en dos saltos"
M_ESPEJO = "espejo de "
M_RETORNO = " (retorno)"
PISTA_RETORNO = ("regreso", "retorno", "return", "vuelta", "back")
AVISO_RETORNO = "el nombre sugiere una regla de retorno pero no es espejo de ninguna regla (revisar a mano)"
PREFIJO_RECORTE = 24    # mismo prefijo en dos saltos: solo si la red mas amplia es /24 o mas larga
SIN_DATO = "sin dato"
MAX_IDS = 20
_DEFECTO = ("DEFAULT ACTION RULE", "DEFAULT TUNNEL ACTION RULE")
_ACL_FTD = "CSM_FW_ACL_"

TIT_ANY = "Reglas de firewall que permiten cualquier origen hacia cualquier destino (segun la configuracion del firewall)"
TIT_CONFIA = "Reglas de firewall que confian trafico sin inspeccion (segun la configuracion del firewall)"
TIT_SOMBRA = "Reglas de firewall sombreadas o sin uso (segun la configuracion del firewall)"
TIT_RUTAS = ("Rutas estaticas hacia saltos que no responden o sin trafico observado "
             "(segun la configuracion del firewall)")
TIT_RETORNO = ("Reglas de retorno que abren conexiones entrantes en un firewall con estado "
               "(segun la configuracion del firewall)")
TIT_DENEGADO ="Trafico observado que el firewall denegaria (segun la configuracion del firewall)"


def _permite(r) -> bool:
    return r.accion in ("permitir", "confiar")


def _subs_de(r) -> list:
    return r.subreglas or [Subregla(list(r.protocolos), list(r.origen), list(r.destino), [],
                                    list(r.puertos), list(r.zonas_origen), list(r.zonas_destino))]


def _redes(redes):
    """None = cualquiera; () = sin resolver; si no, tuplas (red, mascara) enteras."""
    if any(r.prefixlen == 0 for r in redes):
        return None
    return tuple((int(r.network_address), int(r.netmask)) for r in redes)


def _cubre_redes(a, b) -> bool:
    """La lista a (None = todo) contiene toda red de b. Sin resolver (()) nunca se da por cubierto."""
    if a is None:
        return True
    if b is None or not a or not b:
        return False
    return all(any(ma & mb == ma and nb & ma == na for na, ma in a) for nb, mb in b)


def _cubre_puertos(a, b) -> bool:
    if a is None:
        return True
    if b is None:
        return False
    return all(any(x <= lo and hi <= y for x, y in a) for lo, hi in b)


class _H:
    """Subregla preparada para el analisis de sombreado."""
    __slots__ = ("accion", "d", "idx", "o", "pd", "po", "protos", "zd", "zo")

    def __init__(self, idx, permite, s):
        self.idx, self.accion = idx, permite
        self.protos = None if not s.protocolos or "ip" in s.protocolos else frozenset(s.protocolos)
        self.zo = frozenset(x.lower() for x in s.zonas_origen) or None
        self.zd = frozenset(x.lower() for x in s.zonas_destino) or None
        self.o, self.d = _redes(s.origen), _redes(s.destino)
        self.po = tuple(s.puertos_origen) or None
        self.pd = tuple(s.puertos_destino) or None


def _cubre(a, b) -> bool:
    """La subregla a (anterior) casa todo lo que casa b."""
    if a.protos is not None and (b.protos is None or not b.protos <= a.protos):
        return False
    if a.zo is not None and (b.zo is None or not b.zo <= a.zo):
        return False
    if a.zd is not None and (b.zd is None or not b.zd <= a.zd):
        return False
    return (_cubre_puertos(a.pd, b.pd) and _cubre_puertos(a.po, b.po)
            and _cubre_redes(a.o, b.o) and _cubre_redes(a.d, b.d))


def _es_defecto(r, ultima_ftd) -> bool:
    return r.nombre.strip().upper() in _DEFECTO or r is ultima_ftd


def _sombras(evaluadas) -> dict:
    """{indice de regla: texto de la marca}: reglas con todas sus subreglas cubiertas por reglas anteriores."""
    previas: list = []
    out = {}
    for i, r in enumerate(evaluadas):
        propias = [_H(i, _permite(r), s) for s in _subs_de(r)]
        ids, distinta, todas = [], False, bool(propias)
        for b in propias:
            hallada = next((a for a in previas if _cubre(a, b)), None)
            if hallada is None:
                todas = False
                break
            if evaluadas[hallada.idx].id not in ids:
                ids.append(evaluadas[hallada.idx].id)
            distinta = distinta or hallada.accion != b.accion
        if todas:
            out[i] = M_SOMBRA + ",".join(ids) + (M_DISTINTA if distinta else "")
        previas.extend(propias)
    return out


def _compatibles(x, y) -> bool:
    """Conjuntos de interfaces o protocolos (None = cualquiera) que pueden coincidir."""
    return x is None or y is None or bool(x & y)


def _espejos(evaluadas) -> dict:
    """{indice de regla B: [indices de reglas A]}: B es el retorno de A en un firewall con estado (D43).

    Alguna subregla de B tiene las interfaces de A intercambiadas (sin interfaz = cualquiera), origen contenido
    en el destino de A, destino contenido en el origen de A (B cabe en el reflejo de A: deja volver desde los
    destinos de A hacia sus origenes) y un puerto de destino que es uno de A
    (mismo rango). Sin puerto de destino en alguna de las dos no se compara. Si A y B se reflejan entre si,
    solo se marca la posterior."""
    por_puerto: dict = collections.defaultdict(list)
    for i, r in enumerate(evaluadas):
        if _permite(r):
            for s in _subs_de(r):
                h = _H(i, True, s)
                for pr in h.pd or ():
                    por_puerto[pr].append(h)
    pares: dict = {}
    for j, r in enumerate(evaluadas):
        if not _permite(r):
            continue
        for s in _subs_de(r):
            b = _H(j, True, s)
            for pr in b.pd or ():
                for a in por_puerto.get(pr, ()):
                    if (a.idx != j and _compatibles(a.protos, b.protos) and _compatibles(a.zd, b.zo)
                            and _compatibles(a.zo, b.zd) and _cubre_redes(a.d, b.o) and _cubre_redes(a.o, b.d)):
                        pares.setdefault(j, set()).add(a.idx)
    def amplitud(k):    # 1 si el origen de la regla es mas amplio que su destino (any -> equipos: abre entrada)
        rg = evaluadas[k]
        o = sum(n.num_addresses for n in rg.origen) if rg.origen else 2 ** 32
        d = sum(n.num_addresses for n in rg.destino) if rg.destino else 2 ** 32
        return 1 if o > d else 0

    def pref(k):    # reflejo mutuo: es el retorno la que tiene nombre de retorno; si no, la que abre entrada
        return (any(p in evaluadas[k].nombre.lower() for p in PISTA_RETORNO), amplitud(k), k)

    # un retorno abre entrada (origen mas amplio que el destino) o lo dice su nombre; una regla de ida
    # "equipos -> any" refleja cualquier regla de entrada hacia esos equipos y no es un retorno
    return {j: sorted(i for i in ids if not (j in pares.get(i, ()) and pref(i) > pref(j)))
            for j, ids in pares.items() if pref(j)[0] or amplitud(j)}


def avisos_retorno(evaluadas, marcas: dict) -> dict:
    """{id(regla): aviso}: el nombre sugiere retorno pero la regla no esta marcada como espejo."""
    return {id(r): AVISO_RETORNO for r in evaluadas
            if _permite(r) and any(p in r.nombre.lower() for p in PISTA_RETORNO)
            and not any(m.startswith(M_ESPEJO) for m in marcas.get(id(r), ()))}


def marcar(evaluadas: list, usos: dict, con_contadores: bool) -> dict:
    """{id(regla): [marcas]} para las reglas evaluadas. `usos` = {id(regla): conductos que cruzan}."""
    ftd = [r for r in evaluadas if r.acl.startswith(_ACL_FTD)]
    ultima = ftd[-1] if ftd else None
    sombras = _sombras(evaluadas)
    espejos = _espejos(evaluadas)
    out = {}
    for i, r in enumerate(evaluadas):
        m = []
        if _permite(r) and not _es_defecto(r, ultima) and any(
                any(n.prefixlen == 0 for n in s.origen) and any(n.prefixlen == 0 for n in s.destino)
                and not s.puertos_destino for s in _subs_de(r)):
            m.append(M_ANY)
        if r.accion == "confiar":
            m.append(M_CONFIA)
        if i in sombras and not _es_defecto(r, ultima):
            # la regla por defecto no la escribio nadie: que otra la sombree ya sale como any-any
            m.append(sombras[i])
        if espejos.get(i):
            m.append(M_ESPEJO + ",".join(evaluadas[k].id for k in espejos[i]) + M_RETORNO)
        if con_contadores and r.aciertos == 0:
            m.append(M_SIN_ACIERTOS)
        if _permite(r) and not usos.get(id(r), 0):
            m.append(M_SIN_CONDUCTOS)
        out[id(r)] = m
    return out


def estado_rutas(fw, destinos: list) -> list:
    """Una fila por ruta: red, interfaz, siguiente_salto, tipo, salto_en_arp, conductos, marcas.
    `destinos` = IP de destino (entero) de los conductos que cruzan el firewall."""
    cuenta = collections.Counter()
    ips_de = collections.defaultdict(set)
    for d in destinos:
        r = fw.ruta_de(ipaddress.IPv4Address(d)) if d is not None else None
        if r is not None:
            cuenta[id(r)] += 1
            ips_de[id(r)].add(str(ipaddress.IPv4Address(d)))
    arp = {a.ip for a in fw.arp}
    # estaticas con salto, para cubierta / mismo prefijo (las por defecto solo entran en salto sin ARP)
    est = [r for r in fw.rutas if r.tipo == "estatica" and r.salto]
    out = []
    for r in fw.rutas:
        n = cuenta[id(r)]
        marcas = []
        if not r.salto:
            en = ""
        elif not arp:
            en = SIN_DATO
        else:
            en = "si" if r.salto in arp else "no"
        if r.tipo in ("estatica", "defecto"):
            if en == "no":
                marcas.append(M_SIN_ARP)
            if r.tipo == "estatica" and not n:
                marcas.append(M_SIN_TRAFICO)
        if r.tipo == "estatica" and r.salto:
            cub = next((o for o in est if o is not r and o.salto == r.salto and o.interfaz == r.interfaz
                        and o.red != r.red and r.red.subnet_of(o.red)), None)
            if cub is not None:
                marcas.append(M_CUBIERTA + str(cub.red))
            # Un resumen (/8, /12, /16) con rutas especificas por otros saltos es diseno normal (prefijo mas
            # largo). Se marca solo cuando una subred pequena (/24 o mas larga) se recorta con rutas mas
            # especificas por otro salto, o es recortada asi (caso real: /25 por un salto y /32 de ella por otro).
            if any(o is not r and o.salto != r.salto and o.red.overlaps(r.red)
                   and min(o.red.prefixlen, r.red.prefixlen) >= PREFIJO_RECORTE for o in est):
                marcas.append(M_DOS_SALTOS)
        out.append({"red": str(r.red), "interfaz": r.interfaz, "siguiente_salto": r.salto, "tipo": r.tipo,
                    "salto_en_arp": en, "conductos": n, "marcas": "; ".join(marcas),
                    "ips": sorted(ips_de[id(r)])})
    return out


def resumen_rutas(filas: list) -> dict:
    return {"rutas": len(filas),
            "sin_arp": sum(1 for f in filas if M_SIN_ARP in f["marcas"]),
            "sin_trafico": sum(1 for f in filas if M_SIN_TRAFICO in f["marcas"]),
            "sin_dato": bool(filas) and all(f["salto_en_arp"] in ("", SIN_DATO) for f in filas)}


def _hallazgo_rutas(cap, filas: list) -> None:
    from ..rules.base import finding

    malas = [f for f in filas if M_SIN_ARP in f["marcas"] or M_SIN_TRAFICO in f["marcas"]]
    if not malas:
        return
    con_trafico = any(M_SIN_ARP in f["marcas"] and f["conductos"] for f in malas)
    lista = "; ".join(f"{f['red']} -> {f['siguiente_salto']} ({f['interfaz']}): {f['marcas']}"
                      for f in malas[:MAX_IDS])
    if len(malas) > MAX_IDS:
        lista += "; " + t("y {n} mas", n=len(malas) - MAX_IDS)
    finding(cap, "Media" if con_trafico else "Baja", TIT_RUTAS,
            t("Rutas: {n}. Con salto sin ARP: {a}. Sin trafico observado: {s}. {lista}", n=len(malas),
              a=sum(1 for f in malas if M_SIN_ARP in f["marcas"]),
              s=sum(1 for f in malas if M_SIN_TRAFICO in f["marcas"]), lista=lista),
            "Una ruta estatica hacia un salto que no responde, o que ningun trafico observado usa, es "
            "configuracion heredada que amplia la superficie y puede desviar o perder trafico.",
            "Confirmar con el dueno de la red y retirar las rutas sin uso; el ARP envejece, asi que una "
            "ruta de uso poco frecuente puede no tener ARP en el momento de la captura.", "Higiene",
            activos=_ips(malas))


def _tiene(r: dict, marca: str) -> bool:
    return any(m.startswith(marca) for m in r["marcas"].split("; ") if m)


def _nom(r: dict) -> str:
    return f"{r['id']} ({r['nombre']})" if r["nombre"] else str(r["id"])


def _hallazgo_retorno(cap, reglas: list) -> None:
    from ..rules.base import finding

    por_id = {(r.get("fw", ""), r.get("id0", r["id"])): r for r in reglas}
    pares, alta = [], False
    for b in reglas:
        marca = next((m for m in b["marcas"].split("; ") if m.startswith(M_ESPEJO)), None)
        if marca is None:
            continue
        origen_any = "any" in b["origen"].split(";")
        alta = alta or (origen_any and b["conductos_observados"] > 0)
        for ida in marca[len(M_ESPEJO):-len(M_RETORNO)].split(","):
            a = por_id.get((b.get("fw", ""), ida))
            pares.append(f"{_nom(a) if a else ida} -> {_nom(b)}")
    if not pares:
        return
    lista = "; ".join(pares[:MAX_IDS])
    if len(pares) > MAX_IDS:
        lista += "; " + t("y {n} mas", n=len(pares) - MAX_IDS)
    finding(cap, "Alta" if alta else "Media", TIT_RETORNO,
            t("Pares regla de ida -> regla de retorno: {n}. {lista}", n=len(pares), lista=lista),
            "En un firewall con estado la respuesta de una regla ya esta permitida por la sesion; la regla de "
            "retorno solo agrega conexiones entrantes nuevas hacia ese puerto, con origen amplio si es any.",
            "En un firewall con estado la respuesta ya esta permitida: retirar la regla espejo salvo que el "
            "servicio realmente reciba conexiones entrantes y, en ese caso, acotar el origen.", "Segmentacion",
            activos=_ips([b for b in reglas if any(m.startswith(M_ESPEJO) for m in b["marcas"].split("; "))]))


def _ips(reglas: list) -> list:
    """IP de los extremos de los conductos observados que pasan por esas reglas."""
    return [ip for r in reglas for ip in r.get("ips", ())]


def _lista(reglas: list) -> str:
    txt = "; ".join(f"{r['id']} ({r['nombre']})" if r["nombre"] else str(r["id"]) for r in reglas[:MAX_IDS])
    if len(reglas) > MAX_IDS:
        txt += "; " + t("y {n} mas", n=len(reglas) - MAX_IDS)
    return txt


def unir_firewalls(fw: dict) -> dict:
    """Varios firewalls (M1): reglas, rutas y denegados de todos en un solo dict, con el id del firewall
    por delante en la evidencia, para que salga un hallazgo por tipo."""
    reglas, rutas, resultados = [], [], []
    for x in fw["firewalls"]:
        d, i = x["datos"], x["id"]
        reglas += [dict(r, id=f"{i}:{r['id']}", fw=i, id0=r["id"]) for r in d["reglas"]]
        rutas += [dict(r, red=f"{i} {r['red']}") for r in d["rutas_estado"]]
        resultados += [dict(r, regla=f"{i}:{r['regla']}") for r in d["resultados"]
                       if r["resultado"] == "denegado_observado"]
    return {"reglas": reglas, "rutas_estado": rutas, "resultados": resultados}


def agregar_hallazgos(cap, fw: dict) -> None:
    """Hallazgos de la configuracion del firewall en 'cap' (un Capture de extras)."""
    from ..rules.base import finding

    if fw.get("firewalls"):
        fw = unir_firewalls(fw)

    reglas = [r for r in fw.get("reglas", ()) if r.get("activa", True)]
    anys = [r for r in reglas if _tiene(r, M_ANY)]
    if anys:
        usadas = any(r["aciertos"] or r["conductos_observados"] for r in anys)
        finding(cap, "Alta" if usadas else "Media", TIT_ANY,
                t("Reglas: {n}. Con aciertos o conductos observados: {u}. {lista}", n=len(anys),
                  u=sum(1 for r in anys if r["aciertos"] or r["conductos_observados"]), lista=_lista(anys)),
                "Una regla que permite cualquier origen hacia cualquier destino anula la segmentacion que el "
                "firewall debe imponer entre zonas.",
                "Acotar origen, destino y servicios a lo observado y necesario.", "Segmentacion",
                activos=_ips(anys))
    confia = [r for r in reglas if _tiene(r, M_CONFIA)]
    if confia:
        finding(cap, "Media", TIT_CONFIA, t("Reglas: {n}. {lista}", n=len(confia), lista=_lista(confia)),
                "El trafico confiado (trust) no pasa por la inspeccion de intrusiones del firewall: un "
                "ataque dentro de ese trafico no se detecta ni se bloquea.",
                "Pasar a permitir con inspeccion salvo justificacion de rendimiento documentada.",
                "Segmentacion", activos=_ips(confia))
    sombreadas = [r for r in reglas if _tiene(r, M_SOMBRA)]
    distintas = [r for r in sombreadas if M_DISTINTA in r["marcas"]]
    sin_uso = [r for r in reglas if _tiene(r, M_SIN_ACIERTOS) or _tiene(r, M_SIN_CONDUCTOS)]
    if sombreadas or sin_uso:
        finding(cap, "Media" if distintas else "Baja", TIT_SOMBRA,
                t("Sombreadas: {s} (con accion distinta: {d}). Sin aciertos o sin conductos observados: {u}. "
                  "Sombreadas: {ls}. Sin uso: {lu}", s=len(sombreadas), d=len(distintas), u=len(sin_uso),
                  ls=_lista(sombreadas) or "-", lu=_lista(sin_uso) or "-"),
                "Las reglas sombreadas nunca se aplican y las que no tienen uso amplian la superficie y la "
                "carga de revision sin aportar control.",
                "Revisar con el dueno de la regla antes de retirar: una regla sin uso puede cubrir una "
                "operacion poco frecuente.", "Higiene", activos=_ips(sombreadas + sin_uso))
    _hallazgo_retorno(cap, reglas)
    _hallazgo_rutas(cap, fw.get("rutas_estado", ()))
    den = [x for x in fw.get("resultados", ()) if x["resultado"] == "denegado_observado"]
    if den:
        por_regla = collections.Counter((x["regla"], x.get("regla_nombre", "")) for x in den)
        top = sorted(por_regla.items(), key=lambda kv: (-kv[1], kv[0]))
        lista = "; ".join(f"{i} ({n}): {c}" if n else f"{i}: {c}" for (i, n), c in top[:MAX_IDS])
        finding(cap, "Media", TIT_DENEGADO,
                t("Conductos que cruzan el firewall y caen en una regla de denegar: {n}. Reglas: {lista}",
                  n=len(den), lista=lista),
                "El sensor observo trafico que, segun la configuracion cargada, el firewall deberia denegar.",
                "Confirmar el camino real del trafico y si hay otro punto de paso; la causa puede ser otro "
                "camino que no pasa por este firewall, una regla o NAT no modelados, o intentos bloqueados "
                "que el sensor ve antes del firewall.", "Segmentacion",
                activos=[ip for x in den for ip in x.get("ips", ())])
