"""Evidencia observable de IEC 62351 por protocolo (D117): que se vio en la captura, no un dictamen.

La tabla marcos/iec62351_protocolos.json es propia y sin revisar; no contiene texto de la norma. Por
cada protocolo cubierto por alguna parte de 62351 dice si se vio, en que puerto y si hay senales de la
proteccion que esa parte describe (TLS en el puerto seguro, autenticacion segura de DNP3). "Conductos
al puerto seguro" (de cap.flows) y "TLS confirmado" (ServerHello visto desde ese puerto) van separados:
Wireshark puede no decodificar TLS en un puerto que no reconoce. Los protocolos OT que la tabla no
cubre salen como "no aplica" solo si se vieron. GOOSE, SV y el control de acceso por roles (-8) no se
evaluan de forma pasiva.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
from functools import lru_cache
from pathlib import Path

from .catalog import OT_PORTS
from .i18n import t
from .roles import mostrar as mostrar_rol

RUTA = Path(__file__).parent / "marcos" / "iec62351_protocolos.json"
HOJA = "IEC 62351 evidencia"
ARCHIVO = "iec62351_evidencia.csv"
COLUMNAS = ["protocolo", "partes_62351", "observado", "conductos_en_claro", "conductos_puerto_seguro",
            "tls_confirmado", "autenticacion_segura", "evidencia", "nota"]

OBSERVADA = "proteccion observada"
NO_OBSERVADA = "proteccion no observada"
NO_EVALUABLE = "no evaluable de forma pasiva"
NO_APLICA = "no aplica"
NO_VISTO = "protocolo no observado"
FIJA = "Evidencia observable con mapeo propio sin revisar; no es un dictamen."


@lru_cache(maxsize=1)
def cargar() -> dict:
    return json.loads(RUTA.read_text(encoding="utf-8"))


def _eventos(caps, tipo: str) -> list:
    return [e for c in caps for e in c.protocolo_eventos if e.get("tipo") == tipo]


def _pares_flujos(caps, puertos) -> set:
    """Pares (origen, destino) con flujos hacia alguno de los (puerto, transporte)."""
    want = {(str(p), l4) for l4, p in puertos}
    return {(f["src"], f["dst"]) for c in caps for f in c.flows.values() if (f["dport"], f["l4"]) in want}


def _pares_l2(caps, prefijo: str) -> set:
    """Pares (MAC origen, MAC destino) de cap.l2_flows con destino en el rango multicast `prefijo`."""
    return {(s, d) for c in caps for (s, d) in c.l2_flows if (d or "").lower().startswith(prefijo)}


def _pares_vistos(caps, proto: str) -> set:
    return {(e["origen"], e["destino"]) for e in _eventos(caps, "p62351_visto") if e["proto"] == proto}


def _en(pares: set, otros: set) -> set:
    """Pares de `pares` cuyo sentido o el contrario esta en `otros`."""
    return {p for p in pares if p in otros or (p[1], p[0]) in otros}


def _si_no(x: bool) -> str:
    return t("si") if x else t("no")


def _fila(proto, partes, vio, claro, seguro, tls, auth, evidencia, piezas) -> list:
    nota = " ".join([*piezas, t(FIJA)])
    return [proto, partes, _si_no(vio), claro, seguro, tls, auth, t(evidencia), nota]


def _cubierto(caps, p: dict) -> list:
    partes = "; ".join(p["partes"])
    piezas = []
    seguros = [x[1] for x in p["seguro"]]
    tls = sum(e["n"] for e in _eventos(caps, "p62351_tls") if e["puerto"] in seguros)
    seguro = len(_pares_flujos(caps, p["seguro"]))
    dec = p["decodificado"]
    if p["proteccion"] == "capa2":
        multicast = p.get("mac_destino_multicast")
        pares = _pares_l2(caps, multicast) if multicast else _pares_vistos(caps, dec)
        vio = bool(pares) or any(c.ethertypes.get(dec) for c in caps)
        if not vio:
            return _fila(p["protocolo"], partes, False, 0, 0, 0, "", NO_VISTO, [t("Protocolo no visto en la captura.")])
        piezas.append(t("{proto} visto; la extension de seguridad de IEC 62351-6 no se decodifica en esta version.",
                        proto=dec))
        if multicast:
            piezas.append(t("Pares contados por MAC de destino multicast {prefijo}xx:xx; un flujo unicast no se cuenta.",
                            prefijo=multicast))
        return _fila(p["protocolo"], partes, True, len(pares), 0, 0, "", NO_EVALUABLE, piezas)
    claro = _pares_flujos(caps, p["claro"])
    sin_decodificar = 0
    if dec:      # 102/tcp lo comparten MMS y S7comm: se separa por el protocolo decodificado
        mms = _en(claro, _pares_vistos(caps, dec))
        sin_decodificar = len(claro - mms - _en(claro, _pares_vistos(caps, "S7comm")))
        claro = mms
    auth = sum(e["n"] for e in _eventos(caps, "p62351_dnp3_auth")) if p["proteccion"] == "tls_y_autenticacion" else ""
    protegido = tls > 0 or (auth or 0) > 0
    vio = bool(claro) or seguro > 0 or tls > 0 or bool(auth)
    if not vio:
        piezas = [t("Protocolo no visto en la captura.")]
        if sin_decodificar:
            piezas.append(t("{n} conductos a 102/tcp sin decodificar: no se asignan a MMS ni a S7comm.",
                            n=sin_decodificar))
        return _fila(p["protocolo"], partes, False, 0, 0, 0, auth, NO_VISTO, piezas)
    if tls:
        piezas.append(t("TLS confirmado: ServerHello visto desde el puerto seguro."))
    elif seguro:
        piezas.append(t("Hay conductos al puerto seguro sin ServerHello visto: Wireshark puede no decodificar TLS"
                        " en ese puerto o el handshake no esta en la captura; TLS no confirmado."))
    if auth:
        piezas.append(t("Se vieron funciones de autenticacion segura de DNP3 (32, 33 o 131)."))
    if claro:
        piezas.append(t("Tambien hay conductos en el puerto en claro.") if protegido
                      else t("Trafico en el puerto en claro sin proteccion observada en esta captura."))
    if sin_decodificar:
        piezas.append(t("{n} conductos a 102/tcp sin decodificar: no se asignan a MMS ni a S7comm.", n=sin_decodificar))
    return _fila(p["protocolo"], partes, vio, len(claro), seguro, tls, auth,
                 OBSERVADA if protegido else NO_OBSERVADA, piezas)


def _no_cubiertos(caps) -> list:
    """Protocolos OT del catalogo que la tabla no cubre y que se vieron; S7comm por protocolo decodificado."""
    cat = cargar()
    excluidos = {(p, l4) for l4, p in cat["excluidos_no_cubiertos"]}
    grupos: dict = {}
    for (puerto, l4), (nombre, categoria) in OT_PORTS.items():
        if categoria == "ot" and (puerto, l4) not in excluidos:
            grupos.setdefault(nombre, []).append((l4, puerto))
    filas = [(nombre, _pares_flujos(caps, pts)) for nombre, pts in grupos.items()]
    filas.append(("S7comm", _en(_pares_flujos(caps, [("tcp", 102)]), _pares_vistos(caps, "S7comm"))))
    return [_fila(n, t(NO_APLICA), True, len(p), "", "", "", NO_APLICA,
                  [t("No esta entre los protocolos que cubren las partes de IEC 62351 consideradas"
                     " (mapeo propio sin revisar).")])
            for n, p in sorted(filas) if p]


def filas(caps) -> list:
    cat = cargar()
    out = [_cubierto(caps, p) for p in cat["protocolos"]]
    r = cat["roles"]
    out.append(_fila(t(r["protocolo"]), "; ".join(r["partes"]), False, "", "", "", "", NO_EVALUABLE,
                     [t("El control de acceso por roles no se puede evaluar de forma pasiva.")]))
    return out + _no_cubiertos(caps)


def tablas(caps) -> list:
    """Una hoja por corrida con capturas; sin capturas no hay nada que observar."""
    if not caps:
        return []
    return [(ARCHIVO, HOJA, COLUMNAS, filas(caps))]


# ---------------------------------------------------------------------------------------------------------
# E62351F (D125): evidencia por flujo con estado y nota del equipo, activada por perfil u opcion.
# ---------------------------------------------------------------------------------------------------------
ARCHIVO_FLUJOS = "iec62351_flujos.csv"
HOJA_FLUJOS = "IEC 62351 flujos"
ATRIBUTO = "iec62351_flujos"          # resultado de preparar(), colgado de args
COLUMNAS_FLUJOS = ["id_flujo", "protocolo", "partes_62351", "origen", "origen_nombre", "origen_zona",
                   "origen_nivel", "destino", "destino_nombre", "destino_zona", "destino_nivel", "transporte",
                   "puerto", "canal", "tls_confirmado", "autenticacion_segura", "evidencia", "fuente",
                   "estado_equipo", "nota_equipo", "nota"]
ESTADOS_DEFECTO = ["por revisar", "confirmado", "no aplica", "excepcion documentada"]
PROTO_SIN_DECODIFICAR = "MMS o S7comm (sin decodificar)"
CLARO, SEGURO, CAPA2 = "en claro", "puerto seguro", "capa 2"
MAX_BYTES_ESTADOS = 20 * 1024 * 1024
MAX_FILAS_ESTADOS = 100000
# Un archivo escrito con --idioma en lleva las cabeceras traducidas: se aceptan ambas.
ALIAS = {"id_flujo": ("id_flujo", "flow_id"), "estado_equipo": ("estado_equipo", "team_status"),
         "nota_equipo": ("nota_equipo", "team_note")}
_C = {c: i for i, c in enumerate(COLUMNAS_FLUJOS)}


def estados_validos(v, fallo):
    """Normaliza la clave de perfil iec62351_flujos: None (apagada) o {'estados': [...], 'inicial': x}."""
    if v is False:
        return None
    if v is True:
        return {"estados": list(ESTADOS_DEFECTO), "inicial": ESTADOS_DEFECTO[0]}
    if not isinstance(v, dict):
        fallo("'iec62351_flujos' debe ser true, false o un objeto con 'estados' e 'inicial'.")
    for k in v:
        if k not in ("estados", "inicial"):
            fallo("clave desconocida '" + str(k) + "' en 'iec62351_flujos'.")
    est = v.get("estados", ESTADOS_DEFECTO)
    if not isinstance(est, list) or not 2 <= len(est) <= 10:
        fallo("'iec62351_flujos.estados' debe ser una lista de 2 a 10 textos.")
    for x in est:
        if (not isinstance(x, str) or not 1 <= len(x) <= 40 or x != x.strip()
                or "\n" in x or "\r" in x):
            fallo("'iec62351_flujos.estados': cada estado es un texto de 1 a 40 caracteres, sin saltos de "
                  "linea ni espacios en los extremos.")
    if len(set(est)) != len(est):
        fallo("'iec62351_flujos.estados' tiene estados repetidos.")
    ini = v.get("inicial", est[0])
    if not isinstance(ini, str) or ini not in est:
        fallo("'iec62351_flujos.inicial' debe ser uno de los estados.")
    return {"estados": list(est), "inicial": ini}


class _Activos:
    """Busca el activo de un extremo por id, MAC o IP."""

    def __init__(self, assets):
        self.por_clave = {}
        for k, a in (assets or {}).items():
            self.por_clave[str(k).lower()] = a
            if a.get("mac"):
                self.por_clave[str(a["mac"]).lower()] = a
        for a in (assets or {}).values():
            for ip in a.get("ips") or ():
                self.por_clave.setdefault(str(ip).lower(), a)

    def de(self, clave) -> dict:
        return self.por_clave.get(str(clave).lower(), {})


def _extremo(activos, k, lado) -> list:
    clave = k[lado]
    a = activos.de(clave)
    nombre = k.get(lado + "_nombre") or a.get("nombre") or clave
    nivel = k.get(lado + "_zona") or a.get("purdue") or ""
    return [clave, nombre, a.get("zona_asignada") or "", mostrar_rol(nivel)]


def _id_flujo(proto, origen, destino, l4, puerto) -> str:
    base = "|".join([proto, origen, destino, l4, str(puerto)])
    return "F62-" + hashlib.sha256(base.encode("utf-8")).hexdigest()[:10]


def _flujo(activos, k, proto, partes, canal, l4, puerto, tls, auth, evidencia, fuente, piezas, ini) -> dict:
    fila = [_id_flujo(proto, k["src"], k["dst"], l4, puerto), proto, partes, *_extremo(activos, k, "src"),
            *_extremo(activos, k, "dst"), l4, puerto, t(canal), tls, auth, t(evidencia), t(fuente), ini, "",
            " ".join([*piezas, t(FIJA)])]
    return {"clave": evidencia, "fila": fila}


def _pares_en(par, otros) -> bool:
    return par in otros or (par[1], par[0]) in otros


def _filas_captura(caps, conduits, activos, ini) -> list:
    out = []
    tls_vistos = {(e["servidor"], e["cliente"], e["puerto"]) for e in _eventos(caps, "p62351_tls")}
    auth_vistos = {(e["maestro"], e["outstation"]) for e in _eventos(caps, "p62351_dnp3_auth")}
    for p in cargar()["protocolos"]:
        partes = "; ".join(p["partes"])
        dec = p["decodificado"]
        if p["proteccion"] == "capa2":
            multicast = p.get("mac_destino_multicast")
            pares = _pares_l2(caps, multicast) if multicast else _pares_vistos(caps, dec)
            for s, d in pares:
                pieza = t("{proto} visto; la extension de seguridad de IEC 62351-6 no se decodifica en esta "
                          "version.", proto=dec)
                out.append(_flujo(activos, {"src": s, "dst": d}, p["protocolo"], partes, CAPA2, "", "", "", "",
                                  NO_EVALUABLE, "captura", [pieza], ini))
            continue
        claro = {(l4, str(pt)) for l4, pt in p["claro"]}
        seguro = {(l4, str(pt)) for l4, pt in p["seguro"]}
        mms = _pares_vistos(caps, dec) if dec else set()
        s7 = _pares_vistos(caps, "S7comm") if dec else set()
        con_auth = p["proteccion"] == "tls_y_autenticacion"
        for k in conduits:
            clave = (k["l4"], str(k["port"]))
            if clave not in claro and clave not in seguro:
                continue
            par = (k["src"], k["dst"])
            a_ok = con_auth and _pares_en(par, auth_vistos)
            auth = _si_no(a_ok) if con_auth else ""
            piezas = []
            if con_auth:
                piezas.append(t("Autenticacion segura de DNP3 vista en el par maestro/outstation.") if a_ok
                              else t("Sin autenticacion segura de DNP3 vista en el par maestro/outstation."))
            if clave in seguro:
                tls = (k["dst"], k["src"], int(k["port"])) in tls_vistos
                piezas.insert(0, t("Flujo al puerto seguro con ServerHello visto del servidor al cliente: TLS "
                                   "confirmado.") if tls else
                              t("Flujo al puerto seguro sin ServerHello visto de ese servidor a ese cliente: TLS no "
                                "confirmado (Wireshark puede no decodificar TLS en ese puerto o el handshake no "
                                "esta en la captura)."))
                out.append(_flujo(activos, k, p["protocolo"], partes, SEGURO, k["l4"], k["port"], _si_no(tls),
                                  auth, OBSERVADA if tls or a_ok else NO_OBSERVADA, "captura", piezas, ini))
                continue
            proto, ev = p["protocolo"], (OBSERVADA if a_ok else NO_OBSERVADA)
            if dec:      # 102/tcp lo comparten MMS y S7comm: se separa por el protocolo decodificado
                if _pares_en(par, s7) and not _pares_en(par, mms):
                    continue
                if not _pares_en(par, mms):
                    proto, ev = PROTO_SIN_DECODIFICAR, NO_EVALUABLE
                    piezas.append(t("Flujo a 102/tcp sin decodificar: no se asigna a MMS ni a S7comm."))
            if ev == NO_OBSERVADA:
                piezas.append(t("Flujo en el puerto en claro sin proteccion observada para este par."))
            out.append(_flujo(activos, k, proto, partes, CLARO, k["l4"], k["port"], "", auth, ev, "captura",
                              piezas, ini))
    return out


def _filas_exportacion(conduits, activos, ini) -> list:
    out = []
    for p in cargar()["protocolos"]:
        if p["proteccion"] == "capa2":
            continue
        partes = "; ".join(p["partes"])
        for k in conduits:
            l4, port = k.get("l4") or "", str(k.get("port") or "")
            en = [canal for canal, lista in ((CLARO, p["claro"]), (SEGURO, p["seguro"]))
                  for pl4, pt in lista if str(pt) == port and l4 in ("", pl4)]
            if not en:
                continue
            canal, proto, ev = en[0], p["protocolo"], NO_EVALUABLE
            piezas = [t("exportacion: sin paquetes para confirmar TLS")]
            if canal == CLARO:
                ev = NO_OBSERVADA
                piezas.append(t("Conducto importado en el puerto en claro; la exportacion no permite comprobar "
                                "otra proteccion."))
                if p["decodificado"]:
                    serv = str(k.get("servicio") or "").lower()
                    if "mms" not in serv and "s7" in serv:
                        continue
                    if "mms" not in serv:
                        proto, ev = PROTO_SIN_DECODIFICAR, NO_EVALUABLE
                        piezas.append(t("Flujo a 102/tcp sin decodificar: no se asigna a MMS ni a S7comm."))
            out.append(_flujo(activos, k, proto, partes, canal, l4, port, "", "", ev, "exportacion", piezas, ini))
    return out


def construir(caps, conduits, assets, inicial: str) -> list:
    """Filas por flujo como [{'clave': evidencia, 'fila': [...]}], sin repetidos y en orden fijo."""
    activos = _Activos(assets)
    crudas = (_filas_captura(caps, conduits, activos, inicial) if caps
              else _filas_exportacion(conduits, activos, inicial))
    unicas: dict = {}
    for x in crudas:
        unicas.setdefault(x["fila"][0], x)

    def orden(x):
        f = x["fila"]
        pt = str(f[_C["puerto"]])
        return (f[_C["protocolo"]], f[_C["origen"]], f[_C["destino"]], int(pt) if pt.isdigit() else -1,
                f[_C["transporte"]])
    return sorted(unicas.values(), key=orden)


def leer_estados(ruta) -> dict:
    """{id_flujo: (estado, nota)} de un iec62351_flujos.csv llenado por el equipo. ValueError si no sirve."""
    p = Path(ruta)
    try:
        if p.stat().st_size > MAX_BYTES_ESTADOS:
            raise ValueError("'" + p.name + "' pesa mas de 20 MB.")
        texto = p.read_bytes().decode("utf-8-sig")
    except (OSError, UnicodeDecodeError) as e:
        raise ValueError("No pude leer '" + p.name + "': " + str(e))
    cab = texto.split("\n", 1)[0]
    sep = ";" if cab.count(";") > cab.count(",") else ","
    out: dict = {}
    try:
        lector = csv.reader(io.StringIO(texto), delimiter=sep)
        cols = [c.strip() for c in (next(lector, None) or [])]
        idx = {}
        for k, alias in ALIAS.items():
            hay = [cols.index(a) for a in alias if a in cols]
            if not hay:
                raise ValueError("'" + p.name + "' no tiene la columna " + k + ".")
            idx[k] = hay[0]
        n = 0
        for fila in lector:
            if not any(c.strip() for c in fila):
                continue
            n += 1
            if n > MAX_FILAS_ESTADOS:
                raise ValueError("'" + p.name + "' tiene mas de " + str(MAX_FILAS_ESTADOS) + " filas.")
            cel = [fila[idx[k]] if idx[k] < len(fila) else "" for k in ("id_flujo", "estado_equipo", "nota_equipo")]
            ident, estado, nota = cel[0].strip(), cel[1].strip(), cel[2]
            if not ident:
                continue
            if ident in out and out[ident] != (estado, nota):
                raise ValueError("id_flujo repetido con valores distintos: " + ident + ".")
            out[ident] = (estado, nota)
    except csv.Error as e:
        raise ValueError("'" + p.name + "' no es un CSV valido: " + str(e))
    return out


def preparar(ap, args, perfil, caps, conduits, assets):
    """Arma la tabla por flujo si el perfil o --iec62351-estados la piden y la guarda en args.
    Un estado importado vacio conserva el inicial. Los errores del archivo terminan con codigo 2
    (ap.error) antes de escribir salidas."""
    cfg = (perfil or {}).get("iec62351_flujos")
    ruta = getattr(args, "iec62351_estados", None)
    if not cfg and not ruta:
        return None
    cfg = cfg or {"estados": list(ESTADOS_DEFECTO), "inicial": ESTADOS_DEFECTO[0]}
    filas = construir(caps, conduits, assets, cfg["inicial"])
    ids = {x["fila"][0] for x in filas}
    importados = no_encontrados = 0
    if ruta:
        try:
            previos = leer_estados(ruta)
        except ValueError as e:
            ap.error(str(e))
        malos = sorted(i for i, (est, _n) in previos.items() if i in ids and est and est not in cfg["estados"])
        if malos:
            ap.error("estado no permitido en " + str(len(malos)) + " flujos (ids: " + ", ".join(malos[:10])
                     + "). Permitidos: " + ", ".join(cfg["estados"]) + ".")
        for x in filas:
            previo = previos.get(x["fila"][0])
            if previo:
                if previo[0]:
                    x["fila"][_C["estado_equipo"]] = previo[0]
                x["fila"][_C["nota_equipo"]] = previo[1]
                importados += 1
        no_encontrados = len(set(previos) - ids)
        if no_encontrados:
            print("[!] --iec62351-estados: " + str(no_encontrados) + " id_flujo del archivo ya no existen en esta "
                  "corrida; no se trasladan.")
    por_estado = {e: 0 for e in cfg["estados"]}
    por_ev: dict = {}
    for x in filas:
        est = x["fila"][_C["estado_equipo"]]
        por_estado[est] = por_estado.get(est, 0) + 1
        por_ev[x["clave"]] = por_ev.get(x["clave"], 0) + 1
    res = {"filas": [x["fila"] for x in filas],
           "json": {"filas": len(filas), "estados": list(cfg["estados"]), "por_estado": por_estado,
                    "por_evidencia": dict(sorted(por_ev.items())), "estados_importados": importados,
                    "ids_no_encontrados": no_encontrados}}
    setattr(args, ATRIBUTO, res)
    return res


def tablas_flujos(args) -> list:
    d = getattr(args, ATRIBUTO, None)
    if not isinstance(d, dict):
        return []
    return [(ARCHIVO_FLUJOS, HOJA_FLUJOS, COLUMNAS_FLUJOS, d["filas"])]


def para_json(args):
    d = getattr(args, ATRIBUTO, None)
    return d["json"] if isinstance(d, dict) else None
