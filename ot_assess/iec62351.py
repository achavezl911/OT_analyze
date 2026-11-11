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

import json
from functools import lru_cache
from pathlib import Path

from .catalog import OT_PORTS
from .i18n import t

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
    if not vio and not sin_decodificar:
        return _fila(p["protocolo"], partes, False, 0, 0, 0, auth, NO_VISTO, [t("Protocolo no visto en la captura.")])
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
