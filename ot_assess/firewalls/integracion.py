"""F1b: integra el modelo comun de firewall (F1a) al analisis.

- rutas: Firewall.rutas + interfaces/zonas -> dicts de rutas_firewall._ruta -> aplicar_rutas.
- contraste: reglas del modelo (en orden de la ACL) -> dicts de firewall.reglas_de_filas; la regla con
  interfaces (`ifc`) solo casa si las interfaces de entrada y salida del conducto coinciden.
  Resultado en el formato de firewall.contrastar (+ regla_nombre y la tabla de reglas con su uso).
Solo se escribe lo que viene del modelo; el adaptador ya descarta secretos.
Es evidencia pasiva (aproximacion del modelo), no un motor de decision del firewall.
"""
from __future__ import annotations

from pathlib import Path

from .. import firewall as _fw
from .. import rutas_firewall as _rf
from ..catalog import OT_PORTS
from ..i18n import t
from . import checkpoint as _cp
from . import cisco
from . import cruces as _cr
from . import fortigate as _fg
from . import higiene as _hg
from . import nat as _nt
from . import paloalto as _pa
from . import politica as _po
from . import rutas_propuestas as _rp
from . import topologia as _tp
from .modelo import Subregla

COL_REGLAS = ["id", "nombre", "politica", "seccion", "accion", "interfaces_origen", "interfaces_destino",
              "origen", "destino", "servicios", "aciertos", "primer_acierto", "ultimo_acierto",
              "conductos_observados", "avisos", "activa", "marcas"]
COL_RUTAS = ["red", "interfaz", "siguiente_salto", "tipo", "salto_en_arp", "conductos", "marcas"]
MAX_REDES = 10
_ACL_FTD = "CSM_FW_ACL_"
_CODIGO = {"estatica": "S", "dinamica": "O", "defecto": "S*"}




def rutas_de(fw) -> list:
    """Rutas del modelo como dicts de rutas_firewall._ruta."""
    out = []
    for r in fw.rutas:
        if r.tipo == "conectada":
            cod = "C"
        elif r.tipo == "local":
            cod = "L"
        else:
            cod = (r.codigo.split() or [""])[0] or _CODIGO.get(r.tipo, "S")
        out.append(_rf._ruta(r.red, r.interfaz, fw.zona_de(r.interfaz), r.salto, cod, "firewall"))
    return out


def _reglas_politica(fw, avisos) -> list:
    activas = [r for r in fw.reglas if r.activa]
    ftd = [r for r in activas if r.acl.startswith(_ACL_FTD)]
    if ftd:
        return ftd
    if len({r.acl for r in activas}) > 1:
        avisos.append(t("no se sabe que ACL se aplica (no se lee access-group): se usan todas, en el orden del archivo"))
    return activas


def _permite(r) -> bool:
    return r.accion in ("permitir", "confiar")


def _subs_de(r) -> list:
    """Subreglas de una regla; si el adaptador no las dio, una sola con los campos de union."""
    return r.subreglas or [Subregla(list(r.protocolos), list(r.origen), list(r.destino), [],
                                    list(r.puertos), list(r.zonas_origen), list(r.zonas_destino))]


def _enteros(redes):
    """None = cualquier IP (hay 0.0.0.0/0); si no, tuplas (red, mascara) como enteros ([] = sin resolver)."""
    if any(r.prefixlen == 0 for r in redes):
        return None
    return tuple((int(r.network_address), int(r.netmask)) for r in redes)


class _Sub:
    """Subregla preparada para comparar rapido (redes como enteros, protocolos y zonas como conjuntos)."""
    __slots__ = ("d", "o", "protos", "puertos", "regla", "zd", "zo")

    def __init__(self, regla, s):
        self.regla = regla
        self.o, self.d = _enteros(s.origen), _enteros(s.destino)
        self.zo = frozenset(x.lower() for x in s.zonas_origen) or None
        self.zd = frozenset(x.lower() for x in s.zonas_destino) or None
        self.protos = None if not s.protocolos or "ip" in s.protocolos else frozenset(s.protocolos)
        self.puertos = tuple(s.puertos_destino) or None


def _en_redes(redes, ip: int) -> bool:
    return redes is None or any(ip & m == n for n, m in redes)


def _puerto_de(c):
    p = str(c.get("port") if c.get("port") is not None else "")   # los conductos traen texto ("502") o ""
    return int(p) if p.isdigit() else None


def _proto_puerto(s, l4: str, puerto):
    """(casa, l4_inferido) de la parte protocolo + puerto de destino de una subregla."""
    inferido = False
    if s.protos is not None:
        if l4:
            if l4 not in s.protos:
                return False, False
        elif "tcp" in s.protos or "udp" in s.protos:
            # sin transporte en el conducto (xDome trae solo el protocolo de aplicacion): se compara por
            # puerto sin exigir tcp/udp y el resultado se marca como l4 inferido
            inferido = True
        else:
            return False, False     # gre, ipinip, icmp...: solo casan con un conducto de ese transporte
        if not inferido and l4 not in ("tcp", "udp"):
            return True, False      # sin puertos que comparar
    if s.puertos is not None and (puerto is None or not any(a <= puerto <= b for a, b in s.puertos)):
        return False, False
    return True, inferido


def _redes(redes) -> str:
    if not redes:
        return ""
    txt = ["any" if r.prefixlen == 0 else str(r) for r in redes]
    if len(txt) > MAX_REDES:
        return ";".join(txt[:MAX_REDES]) + ";" + t("y {n} mas", n=len(txt) - MAX_REDES)
    return ";".join(txt)


def _servicios(r) -> str:
    proto = "/".join(r.protocolos) or "ip"
    if not r.puertos:
        return proto
    return proto + "/" + ",".join(str(a) if a == b else f"{a}-{b}" for a, b in r.puertos)


def _ip_de(assets: dict):
    """Extremo de conducto -> IP: en capturas ya es la IP; en exportaciones puede ser el id del activo."""
    def de(x):
        if _fw._ip(x) is not None or x not in assets:
            return x
        return next(iter(sorted(assets[x]["ips"])), x)
    return de


_PUERTOS_OT = frozenset(p for (p, _l) in OT_PORTS)


def _es_servicio(puerto) -> bool:
    """Puerto de servicio conocido: bien conocido (< 1024) o del catalogo OT."""
    return puerto is not None and (puerto < 1024 or puerto in _PUERTOS_OT)


def elegir_sentido(original: str, invertido: str) -> str:
    """D43: el primero que resulte permitido; si ninguno, el original (con el mismo puerto en los dos
    sentidos no hay otro dato para decidir cual es el servidor)."""
    return "invertido" if original != "permitido" and invertido == "permitido" else "original"


def contrastar(fw, conductos: list, archivo: str, avisos: list, assets=None, forzar=None) -> dict:
    """Dict de Assessment.firewall (formato de firewall.contrastar + 'reglas' y 'avisos').

    `forzar`: sentido ('original' | 'invertido' | None) por conducto; M1 lo fija para todo el camino."""
    ip_de = _ip_de(assets or {})
    trad = _nt.Traductor(fw.nat)      # D70: las reglas de acceso se evaluan con las IP reales
    if trad:                          # un activo cuya IP es un MAPEADO: se marca, no se fusiona con el real
        for a in (assets or {}).values():
            reales = sorted({r for r in (trad.real_de(ip) for ip in a.get("ips") or ()) if r})
            if reales:
                a["nat_nota"] = _nt.MARCA_ACTIVO.format(real=";".join(reales))
    evaluadas = _reglas_politica(fw, avisos)
    usos = {id(r): 0 for r in evaluadas}
    # subreglas en el orden de la ACL; las de puerto de origen restringido no casan (el conducto solo
    # trae el puerto del servidor) y se cuentan una vez
    subs, con_origen = [], 0
    for r in evaluadas:
        for sr in _subs_de(r):
            if sr.puertos_origen:
                con_origen += 1
            else:
                subs.append(_Sub(r, sr))
    cand_s: dict = {}                 # (ip, interfaz) -> indices de subreglas cuyo origen casa
    cand_d: dict = {}
    pares: dict = {}                  # (ip_s, ip_d, if_s, if_d) -> indices que casan en redes e interfaces
    decididos: dict = {}              # (par, l4, puerto) -> (indice | None, l4_inferido)

    def candidatas(cache, ip, ifc, lado):
        k = (ip, ifc)
        if k not in cache:
            cache[k] = frozenset(
                i for i, x in enumerate(subs)
                if ip is not None and _en_redes(x.o if lado == 0 else x.d, ip)
                and ((x.zo if lado == 0 else x.zd) is None
                     or (ifc is not None and ifc.lower() in (x.zo if lado == 0 else x.zd))))
        return cache[k]

    def evaluar(n_s, n_d, if_s, if_d, l4, puerto):
        """(indice de subregla | None, l4_inferido) de un sentido concreto."""
        par = (n_s, n_d, if_s, if_d)
        if par not in pares:
            pares[par] = sorted(candidatas(cand_s, n_s, if_s, 0) & candidatas(cand_d, n_d, if_d, 1))
        k = (par, l4, puerto)
        if k not in decididos:
            decididos[k] = (None, False)
            for i in pares[par]:
                ok, inf = _proto_puerto(subs[i], l4, puerto)
                if ok:
                    decididos[k] = (i, inf)
                    break
        return decididos[k]

    def armar(ev, if_s, if_d):
        i, inf = ev
        if i is None:
            return {"resultado": "sin_regla", "regla": "", "regla_nombre": "", "if_origen": if_s,
                    "if_destino": if_d}, None
        r = subs[i].regla
        return {"resultado": "permitido" if _permite(r) else "denegado_observado", "regla": r.id,
                "regla_nombre": r.nombre, "l4_inferido": inf, "if_origen": if_s, "if_destino": if_d}, r

    resultados, reglas_de, ida = [], [], {}
    destinos = []                     # destino (entero) de los conductos que cruzan, para las rutas
    for pos, c in enumerate(conductos):
        s, d_ = ip_de(c.get("src")), ip_de(c.get("dst"))
        hit = trad.traducir(s, d_, bool(c.get("bidireccional"))) if trad else None
        nat = None
        s_ev, d_ev = s, d_
        if hit is not None:
            s_ev, d_ev = hit["s"], hit["d"]
            if hit["cambio"] or hit["pat"]:
                nat = {"s": s_ev, "d": d_ev, "regla": _nt.nombre_regla(hit["regla"]), "lado": hit["lado"]}
        ip_s, ip_d = _fw._ip(s_ev), _fw._ip(d_ev)
        n_s = int(ip_s) if ip_s is not None and ip_s.version == 4 else None
        n_d = int(ip_d) if ip_d is not None and ip_d.version == 4 else None
        if_s, if_d = fw.interfaz_de(s_ev), fw.interfaz_de(d_ev)
        if if_s is None or if_d is None or if_s == if_d:
            # las dos puntas detras de la misma interfaz (o sin interfaz conocida): no atraviesa este firewall
            resultados.append({"resultado": "no_cruza", "regla": "", "regla_nombre": ""})
            reglas_de.append(None)
            continue
        l4 = str(c.get("l4") or "").strip().lower()
        puerto = _puerto_de(c)
        r, regla = armar(evaluar(n_s, n_d, if_s, if_d, l4, puerto), if_s, if_d)
        r["sentido"] = "original"
        n_dest = n_d
        if c.get("bidireccional"):
            # la clave del importador ordena por IP: no dice quien inicio. Se prueban los dos sentidos.
            r2, regla2 = armar(evaluar(n_d, n_s, if_d, if_s, l4, puerto), if_d, if_s)
            r2["sentido"] = "invertido"
            ambos = {"original": (r, regla), "invertido": (r2, regla2)}
            elegido = forzar[pos] if forzar else None
            if elegido is None:
                elegido = elegir_sentido(r["resultado"], r2["resultado"])
            r, regla = ambos[elegido]
            r = dict(r, sentidos={"original": ambos["original"][0], "invertido": ambos["invertido"][0]})
            if elegido == "invertido":
                n_dest = n_s
        destinos.append(n_dest)
        r = dict(r, ips=[str(s), str(d_)])      # extremos del conducto, para la criticidad de los hallazgos
        if nat is not None:
            r["nat"] = nat
        resultados.append(r)
        reglas_de.append(regla)
        if r["resultado"] == "permitido" and _es_servicio(puerto):
            # clave en el sentido REAL de la sesion (cliente, servidor): si se eligio el invertido, el cliente es d_
            cli, srv = (d_, s) if r.get("sentido") == "invertido" else (s, d_)
            ida.setdefault((str(cli), str(srv)), (r, regla))
    # respuestas de sesion: puerto alto cuyo conducto inverso esta permitido por un puerto de servicio
    for pos, c in enumerate(conductos):
        r = resultados[pos]
        if r["resultado"] not in ("denegado_observado", "sin_regla") or c.get("bidireccional"):
            continue
        puerto = _puerto_de(c)
        if puerto is None or puerto < 1024 or _es_servicio(puerto):
            continue
        # la respuesta va del servidor al cliente: este conducto (srv -> cli:puerto alto) es la vuelta de la
        # sesion cli -> srv:servicio permitida
        hit = ida.get((str(ip_de(c.get("dst"))), str(ip_de(c.get("src")))))
        if hit is not None:
            r_ida, regla_ida = hit
            resultados[pos] = dict(r, resultado="respuesta", regla=r_ida["regla"],
                                   regla_nombre=r_ida["regla_nombre"], l4_inferido=r_ida.get("l4_inferido", False))
            reglas_de[pos] = regla_ida
    ips_regla: dict = {}
    for pos, regla in enumerate(reglas_de):
        if regla is not None:
            usos[id(regla)] += 1
            ips_regla.setdefault(id(regla), set()).update(resultados[pos].get("ips", ()))
    cuenta = {"permitido": 0, "denegado_observado": 0, "respuesta": 0, "sin_regla": 0, "no_cruza": 0}
    for x in resultados:
        cuenta[x["resultado"]] += 1
    cuenta["invertidos"] = sum(1 for x in resultados if x.get("sentido") == "invertido")
    sin_trafico = [r for r in evaluadas if _permite(r) and not usos[id(r)]]
    cuenta["reglas_sin_trafico"] = len(sin_trafico)
    permitir = [r for r in evaluadas if _permite(r)]
    cuenta["con_contadores"] = any(r.aciertos for r in fw.reglas)
    cuenta["permitir_con_aciertos_sin_conductos"] = sum(1 for r in permitir if r.aciertos > 0 and not usos[id(r)])
    cuenta["permitir_con_conductos_sin_aciertos"] = sum(1 for r in permitir if r.aciertos == 0 and usos[id(r)])
    cuenta["reglas"] = len(fw.reglas)
    cuenta["subreglas_con_puerto_origen"] = con_origen
    cuenta["l4_inferido"] = sum(1 for x in resultados if x.get("l4_inferido"))
    marcas = _hg.marcar(evaluadas, usos, cuenta["con_contadores"])
    pistas = _hg.avisos_retorno(evaluadas, marcas)
    rutas_estado = _hg.estado_rutas(fw, destinos)
    ftd = [r for r in evaluadas if r.acl.startswith(_ACL_FTD)]
    ultima = ftd[-1] if ftd else None
    reglas = [{
        "registro": r.registro, "defecto": _hg._es_defecto(r, ultima),     # FWLOG (D137); no van a resultado.json
        "id": r.id, "nombre": r.nombre, "politica": r.politica, "seccion": r.seccion, "accion": r.accion,
        "interfaces_origen": ";".join(r.zonas_origen), "interfaces_destino": ";".join(r.zonas_destino),
        "origen": _redes(r.origen), "destino": _redes(r.destino), "servicios": _servicios(r),
        "aciertos": r.aciertos, "primer_acierto": r.primer_acierto, "ultimo_acierto": r.ultimo_acierto,
        "conductos_observados": usos.get(id(r), 0), "avisos": "; ".join(r.no_resuelto + ([pistas[id(r)]] if id(r) in pistas else [])),
        "activa": r.activa, "marcas": "; ".join(marcas.get(id(r), ())) if r.activa else "",
        "ips": sorted(ips_regla.get(id(r), ()))}
        for r in fw.reglas]
    extra = {"nat": {"filas": _nt.filas(fw.nat, trad), "con_contadores": bool(fw.nat_detalle),
                     "nota": _nt.nota(fw)}} if fw.nat else {}
    return {**extra, "archivo": archivo, "fabricante": fw.fabricante, "hostname": fw.hostname,
            "resultados": resultados, "resumen": cuenta, "reglas": reglas, "avisos": avisos,
            "rutas_estado": rutas_estado,
            "rutas_propuestas": _rp.construir(fw, rutas_estado, destinos),
            "cruces": _cr.construir(conductos, resultados, assets, ip_de),
            "sin_trafico": [{"regla": r.id, "origen": _redes(r.origen), "destino": _redes(r.destino),
                             "puerto": ",".join(str(a) if a == b else f"{a}-{b}" for a, b in r.puertos),
                             "protocolo": "/".join(r.protocolos)} for r in sin_trafico]}


def _rutas(fw, nombre: str, assets: dict, conductos: list) -> dict:
    rutas_av: list = []
    rutas = _rf.aplicar_rutas(_rf._sin_repetidas(rutas_de(fw)), rutas_av, assets, conductos, nombre,
                              _ip_de(assets))
    if not any(r.tipo == "conectada" for r in fw.rutas):
        rutas_av.append(t(_rf.AVISO_SIN_C))
    rutas["avisos"] = rutas_av
    return rutas


def _con_politica(res: dict, nombres: list, fws: list, dicts: list, conductos: list, assets: dict,
                  zonas) -> dict:
    """M3a: agrega res['politica'] (politica propuesta por firewall) y sus avisos."""
    ids = _tp.identificadores(fws, nombres)
    pol = _po.construir_todo(ids, nombres, fws, dicts, conductos, assets, _ip_de(assets), zonas)
    res["politica"] = pol
    res["rutas_propuestas"] = _rp.combinar(ids, dicts)
    res["avisos"] = list(res["avisos"]) + [_po.texto_aviso(i, a, pol["multiple"]) for i, a in pol["avisos"]]
    return res


def cargar_todos(archivos, contadores=None) -> tuple:
    """([Firewall], [nombre]) detectando el fabricante por el contenido (D57): FortiGate si hay
    `config firewall policy` / `config system interface` (un Firewall por VDOM), si no Cisco."""
    fws, nombres = [], []
    for a in archivos:
        cp = _cp.detectar(a)
        if cp is not None:
            fws.append(_cp.analizar(*cp))
            nombres.append(Path(a).name)
            continue
        texto_pa = _pa.detectar(a)
        if texto_pa is not None:
            lote = _pa.analizar_texto(texto_pa)
            if contadores:
                _pa.aplicar_contadores(lote, contadores)
            fws.extend(lote)
            multi = len(lote) > 1
            nombres.extend(Path(a).name + (":" + f.hostname.rpartition(":")[2] if multi else "") for f in lote)
            continue
        texto = _fg.detectar(a)
        if texto is None:
            fws.append(cisco.cargar(a))
            nombres.append(Path(a).name)
            continue
        lote = _fg.analizar_texto(texto)
        if contadores:
            _fg.aplicar_contadores(lote, contadores)
        fws.extend(lote)
        multi = len(lote) > 1
        nombres.extend(Path(a).name + (":" + f.hostname.rpartition(":")[2] if multi else "") for f in lote)
    if contadores and not any(f.fabricante in (_fg.FABRICANTE, _pa.FABRICANTE) for f in fws):
        for f in fws:
            f.avisos.append("--firewall-contadores solo aplica a FortiGate y Palo Alto: ignorado")
    return fws, nombres


def integrar(archivos, assets: dict, conductos: list, zonas=None, contadores=None) -> tuple:
    """(res.rutas, res.firewall) desde la salida de la CLI de uno o varios firewalls (M1, D45).

    Con uno solo, la salida es la de siempre. Con varios, res.rutas es la del primero (las marcas de
    interfaz de activos y conductos) y res.firewall trae ademas 'firewalls' y 'topologia'."""
    fws, nombres = cargar_todos(list(archivos), contadores)
    if len(fws) == 1:
        rutas = _rutas(fws[0], nombres[0], assets, conductos)
        d = contrastar(fws[0], conductos, nombres[0], list(fws[0].avisos), assets)
        return rutas, _con_politica(d, nombres, fws, [d], conductos, assets, zonas)
    return integrar_modelos(fws, nombres, assets, conductos, zonas)


def integrar_modelos(fws: list, nombres: list, assets: dict, conductos: list, zonas=None) -> tuple:
    """Varios Firewall ya cargados -> (res.rutas del primero, res.firewall con la topologia)."""
    ids = _tp.identificadores(fws, nombres)
    ip_de = _ip_de(assets)
    rutas_i = []
    for k, fw in enumerate(fws):
        if k == 0:
            rutas_i.append(_rutas(fw, nombres[k], assets, conductos))
        else:       # copias: aplicar_rutas escribe interfaz y cruce en los activos y los conductos
            rutas_i.append(_rutas(fw, nombres[k], {a: dict(v) for a, v in assets.items()},
                                  [dict(c) for c in conductos]))
    dicts = [contrastar(fw, conductos, nombres[k], list(fw.avisos), assets) for k, fw in enumerate(fws)]
    sentidos = _tp.elegir_sentidos(dicts, len(conductos))
    if any(x is not None and r["resultados"][i].get("sentido") != x
           for r in dicts for i, x in enumerate(sentidos)):      # un firewall eligio distinto: se unifica
        dicts = [contrastar(fw, conductos, nombres[k], list(fw.avisos), assets, sentidos)
                 for k, fw in enumerate(fws)]
    for d, r in zip(dicts, rutas_i):
        d["rutas_info"] = r
    res = _tp.combinar(ids, fws, dicts, conductos, assets, ip_de)
    _con_politica(res, nombres, fws, dicts, conductos, assets, zonas)
    for c, r in zip(conductos, res["resultados"]):    # cruza el firewall = cruza alguno de la cadena
        c["cruza_firewall"] = c.get("cruza_firewall") or r["resultado"] != "no_cruza"
    return rutas_i[0], res


def filas_reglas(fw: dict) -> list:
    return [[{True: t("si"), False: t("no")}[x[c]] if c == "activa" else x[c] for c in COL_REGLAS]
            for x in fw["reglas"]]


def filas_rutas(fw: dict) -> list:
    return [[t(x[c]) if c == "salto_en_arp" and x[c] else x[c] for c in COL_RUTAS] for x in fw["rutas_estado"]]


def resumen_rutas_texto(fw: dict) -> str:
    """Una linea de resumen de rutas para las secciones de firewall ('' si no hay rutas)."""
    filas = fw.get("rutas_estado")
    if not filas:
        return ""
    r = _hg.resumen_rutas(filas)
    txt = t("{n} rutas del firewall; con salto sin ARP: {a}; estaticas sin trafico observado: {s}; "
            "detalle en firewall_rutas.csv.", n=r["rutas"], a=r["sin_arp"], s=r["sin_trafico"])
    if r["sin_dato"]:
        txt += " " + t("sin show arp: no se valida el salto")
    return txt


def resumen_texto(fw: dict) -> str:
    """Parrafo de resumen de la tabla de reglas para las secciones de firewall."""
    r = fw["resumen"]
    txt = t("{n} reglas leidas de {archivo} ({fabricante}); tabla completa en firewall_reglas.csv.",
            n=r["reglas"], archivo=fw["archivo"], fabricante=fw["fabricante"])
    if r["con_contadores"]:
        txt += " " + t("Reglas de permitir con aciertos en el firewall y sin conductos observados: {a}; "
                       "con conductos observados y sin aciertos: {b}.",
                       a=r["permitir_con_aciertos_sin_conductos"], b=r["permitir_con_conductos_sin_aciertos"])
    return txt

