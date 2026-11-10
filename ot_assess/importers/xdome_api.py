"""Cliente de la API de Claroty xDome (solo lectura) y conversion a los CSV que ya importamos (E1e, D42).

El cliente no conoce el disco ni la consola: recibe la funcion de peticion (se sustituye en las
pruebas) y la de espera. El token vive solo en la cabecera Authorization; ningun mensaje lo incluye.
"""
from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request

from .. import json_entrada

BASE = "https://api.claroty.com"
PAGINA = 1000
MAX_REINTENTOS_429 = 6
ESPERA_429_DEFECTO = 5.0
ESPERA_429_MAX = 120.0
MAX_DEPURACIONES = 80
SONDEO = "campo_invalido_sondeo"

# Conjuntos: nombre -> (ruta, clave de la respuesta, campos de orden). Rutas bajo /api/v1/ con barra final.
CONJUNTOS = {
    "dispositivos": ("devices/", "devices", ["uid"]),
    "relaciones_vulnerabilidades": ("device_vulnerability_relations/", "devices_vulnerabilities",
                                    ["device_uid", "vulnerability_id"]),
    "alertas": ("alerts/", "alerts", ["id"]),
    "relaciones_alertas": ("device_alert_relations/", "devices_alerts", ["alert_id", "device_uid"]),
    "eventos": ("events/", "events", ["id"]),
    "vulnerabilidades": ("vulnerabilities/", "vulnerabilities", ["name"]),
}

# device_* que se toman de las relaciones (el resto del dispositivo viene de devices/).
DEVICE_EN_RELACIONES = [
    "device_uid", "device_name", "device_ip_list", "device_mac_list", "device_category", "device_subcategory",
    "device_type", "device_manufacturer", "device_model", "device_site_name", "device_purdue_level",
    "device_retired", "device_asset_id", "device_software_or_firmware_version", "device_os_name"]
DEVICE_BASE = ["uid", "asset_id", "device_name", "ip_list", "mac_list", "site_name", "purdue_level", "retired"]
# Candidatos extra de devices/: los que la API no acepte se descartan en depurar.
DEVICE_EXTRA = ["network_list", "networks", "network", "vlan_list", "vlans", "vlan", "risk_score", "risk_level",
                "risk_score_level", "os_version"]
EVENTOS_EXCLUIDOS = {"login_password_length"}


class ErrorApi(Exception):
    """Falla de la API. El mensaje nunca lleva el token."""


def peticion_http(base: str, ruta: str, token: str, cuerpo: dict, timeout: float = 180.0) -> tuple:
    """POST JSON. -> (codigo HTTP, cuerpo JSON o {}, cabeceras en minusculas). Solo urllib."""
    if not base.lower().startswith("https://"):
        raise ErrorApi("La base de la API debe ser https://")
    req = urllib.request.Request(
        base.rstrip("/") + "/api/v1/" + ruta, data=json.dumps(cuerpo).encode(), method="POST",
        headers={"Authorization": "Bearer " + token, "Content-Type": "application/json",
                 "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:  # nosec B310 - esquema https comprobado arriba
            codigo, raw, cab = r.status, r.read(), r.headers
    except urllib.error.HTTPError as e:
        codigo, raw, cab = e.code, e.read(), e.headers
    except (urllib.error.URLError, OSError) as e:
        raise ErrorApi("sin conexion con la API (" + type(e).__name__ + ")")
    try:
        datos = json_entrada.cargar(raw.decode("utf-8", "replace")) if raw else {}
    except ValueError:
        datos = {}
    return codigo, datos if isinstance(datos, dict) else {}, {k.lower(): v for k, v in dict(cab).items()}


def _comillas(texto: str) -> list:
    return re.findall(r"'([^']+)'", texto)


def _detalle(datos: dict) -> str:
    d = datos.get("detail") if isinstance(datos, dict) else None
    if isinstance(d, list):
        d = "; ".join(str(x.get("msg", x)) if isinstance(x, dict) else str(x) for x in d)
    return str(d if d is not None else "")[:300]


def _esperados(datos: dict):
    """Lista de campos validos del 422 (detail[0].ctx.expected), o None."""
    try:
        exp = datos["detail"][0]["ctx"]["expected"]
    except (KeyError, IndexError, TypeError):
        return None
    return _comillas(exp) if isinstance(exp, str) else None


def _indices(datos: dict) -> list:
    """Indices de campos invalidos (loc = ["body","fields",<indice>]) del 422 de devices/."""
    out = []
    det = datos.get("detail") if isinstance(datos, dict) else None
    for x in det if isinstance(det, list) else []:
        loc = x.get("loc") if isinstance(x, dict) else None
        if isinstance(loc, list) and len(loc) >= 3 and loc[1] == "fields" and isinstance(loc[-1], int):
            out.append(loc[-1])
    return out


def _prohibidos(datos: dict) -> set:
    d = datos.get("detail") if isinstance(datos, dict) else None
    texto = json.dumps(d) if not isinstance(d, str) else d
    pos = texto.lower().find("forbidden fields")
    return set(_comillas(texto[pos:])) if pos >= 0 else set()


class Cliente:
    def __init__(self, base: str, token: str, peticion=None, dormir=None):
        self.base, self._token = base, token
        self._peticion = peticion or peticion_http
        self._dormir = dormir or time.sleep

    def _limpio(self, texto: str) -> str:
        return texto.replace(self._token, "***") if self._token else texto

    def _post(self, ruta: str, cuerpo: dict) -> tuple:
        """-> (codigo, datos). Reintenta 429 esperando Retry-After (maximo 6 veces)."""
        for intento in range(MAX_REINTENTOS_429 + 1):
            codigo, datos, cab = self._peticion(self.base, ruta, self._token, cuerpo)
            if codigo != 429 or intento == MAX_REINTENTOS_429:
                return codigo, datos
            try:
                espera = float(cab.get("retry-after", ESPERA_429_DEFECTO))
            except (TypeError, ValueError):
                espera = ESPERA_429_DEFECTO
            self._dormir(min(max(espera, 0.0), ESPERA_429_MAX))
        return 429, {}

    @staticmethod
    def _cuerpo(campos: list, orden: list, offset: int, limit: int) -> dict:
        c = {"fields": campos, "offset": offset, "limit": limit}
        orden_ok = [{"field": f, "order": "asc"} for f in orden if f in campos]
        if orden_ok:        # la API rechaza sort_by vacio (422 "at least 1 item"; events: 400 "must sort")
            c["sort_by"] = orden_ok
        return c

    def campos_validos(self, ruta: str):
        """Campos validos de un conjunto (lista `expected` del 422), o None si la API no los lista."""
        codigo, datos = self._post(ruta, self._cuerpo([SONDEO], [], 0, 1))
        return _esperados(datos) if codigo == 422 else None

    def depurar(self, ruta: str, candidatos: list) -> list:
        """Quita los campos invalidos (422) y los prohibidos por la licencia (403) hasta obtener 200."""
        campos = list(dict.fromkeys(candidatos))
        for _ in range(MAX_DEPURACIONES):
            if not campos:
                return []
            codigo, datos = self._post(ruta, self._cuerpo(campos, [], 0, 1))
            if codigo == 200:
                return campos
            if codigo == 403:
                malos = _prohibidos(datos)
                nuevos = [c for c in campos if c not in malos]
            elif codigo == 422:
                esperados = _esperados(datos)
                if esperados is not None:          # la lista de validos manda sobre los indices
                    nuevos = [c for c in campos if c in esperados]
                else:
                    idx = set(_indices(datos))
                    nuevos = [c for i, c in enumerate(campos) if i not in idx]
            else:
                raise ErrorApi("HTTP " + str(codigo) + " en " + ruta + ": " + self._limpio(_detalle(datos)))
            if len(nuevos) == len(campos):
                raise ErrorApi("no pude depurar los campos de " + ruta + " (HTTP " + str(codigo) + "): "
                               + self._limpio(_detalle(datos)))
            campos = nuevos
        raise ErrorApi("demasiados reintentos al depurar los campos de " + ruta)

    def descargar(self, ruta: str, clave: str, campos: list, orden: list) -> list:
        """Todas las paginas de 1000; termina con la primera pagina de menos de `limit`."""
        out: list = []
        offset = 0
        while True:
            codigo, datos = self._post(ruta, self._cuerpo(campos, orden, offset, PAGINA))
            if codigo != 200:
                raise ErrorApi("HTTP " + str(codigo) + " en " + ruta + ": " + self._limpio(_detalle(datos)))
            pagina = datos.get(clave)
            if not isinstance(pagina, list):
                raise ErrorApi("respuesta sin la clave '" + clave + "' en " + ruta)
            out.extend(pagina)
            if len(pagina) < PAGINA:
                return out
            offset += PAGINA


def _seleccion(nombre: str, validos: list) -> list:
    """De los campos validos de un conjunto, los que se piden."""
    if nombre == "relaciones_vulnerabilidades":
        return [c for c in validos if c.startswith(("vulnerability_", "device_vulnerability_"))
                or c in DEVICE_EN_RELACIONES]
    if nombre == "relaciones_alertas":
        return [c for c in validos if c.startswith(("alert_", "device_alert_")) or c in DEVICE_EN_RELACIONES]
    if nombre == "eventos":
        return [c for c in validos if c not in EVENTOS_EXCLUIDOS]
    return list(validos)


def _candidatos_devices(validos_rel) -> list:
    cands = list(DEVICE_BASE)
    devs = [c for c in (validos_rel or DEVICE_EN_RELACIONES)
            if c.startswith("device_") and not c.startswith(("device_vulnerability_", "device_alert_"))]
    for c in devs:
        cands += [c, c[len("device_"):]]
    return list(dict.fromkeys(cands + DEVICE_EXTRA))


def descargar_conjuntos(cli: Cliente, aviso) -> dict:
    """-> {conjunto: (registros, campos usados)}. Un conjunto que falla avisa y queda vacio."""
    res: dict = {}
    validos_rel = None
    orden = ["relaciones_vulnerabilidades", "dispositivos", "alertas", "relaciones_alertas", "eventos",
             "vulnerabilidades"]
    for nombre in orden:
        ruta, clave, ord_ = CONJUNTOS[nombre]
        try:
            if nombre == "dispositivos":
                cands = _candidatos_devices(validos_rel)
            else:
                validos = cli.campos_validos(ruta)
                if validos is None:
                    raise ErrorApi("la API no listo los campos validos de " + ruta)
                if nombre == "relaciones_vulnerabilidades":
                    validos_rel = validos
                cands = _seleccion(nombre, validos)
            campos = cli.depurar(ruta, cands)
            if not campos:
                raise ErrorApi("ningun campo aceptado en " + ruta)
            regs = cli.descargar(ruta, clave, campos, ord_)
        except ErrorApi as e:
            aviso("[!] " + nombre + ": " + str(e))
            res[nombre] = ([], [])
            continue
        res[nombre] = (regs, campos)
        aviso(nombre + ": " + str(len(regs)) + " registros, " + str(len(campos)) + " campos")
    return res


# ---------------------------------------------------------------- conversion a CSV

CAB_ACTIVOS = ["DEVICE NAME", "IP", "MAC", "MAC OUI", "NETWORK", "VLAN", "CATEGORY", "SUB CATEGORY",
               "TYPE", "MANUFACTURER", "MODEL", "OS", "FIRMWARE VERSION", "PURDUE LEVEL", "SITE NAME",
               "RISK SCORE"]       # sin UID: la clave del activo debe ser la MAC, como en la interfaz
CAB_VULNS = ["activo", "ip", "mac", "cve", "severidad", "cvss", "estado", "producto", "version", "fuente"]
CAB_ALERTAS = ["fecha", "origen", "destino", "puerto", "protocolo", "firma", "severidad", "categoria"]
SEVERIDADES = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"}
SEVERIDAD_ALERTA_DEFECTO = "Medium"       # no es dato de xDome: se cuenta y se avisa


def _txt(v) -> str:
    if v is None:
        return ""
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (list, tuple)):
        return ", ".join(_txt(x) for x in v if _txt(x))
    if isinstance(v, dict):
        return _txt(v.get("name") or v.get("value") or "")
    return str(v).strip()


def _lista(v) -> list:
    if isinstance(v, (list, tuple)):
        return [s for s in (_txt(x) for x in v) if s]
    return [s.strip() for s in _txt(v).split(",") if s.strip()]


def _obt(*fuentes, claves: tuple) -> str:
    """Primer valor no vacio de `claves` en las fuentes, en orden."""
    for f in fuentes:
        for k in claves:
            v = _txt((f or {}).get(k))
            if v:
                return v
    return ""


def _dispositivos(res: dict) -> dict:
    """{uid: registro de dispositivo}; los que solo aparecen en relaciones se arman sin el prefijo device_."""
    devs: dict = {}
    for r in res.get("dispositivos", ([], []))[0]:
        uid = _obt(r, claves=("uid", "device_uid"))
        if uid:
            devs[uid] = r
    for nombre in ("relaciones_vulnerabilidades", "relaciones_alertas"):
        for r in res.get(nombre, ([], []))[0]:
            uid = _obt(r, claves=("device_uid",))
            if uid and uid not in devs:
                devs[uid] = {k[len("device_"):]: v for k, v in r.items() if k.startswith("device_")}
    return devs


def _dato(dev: dict, *claves) -> str:
    return _obt(dev, claves=tuple(claves) + tuple("device_" + c for c in claves))


def filas_activos(res: dict) -> list:
    out = []
    for _uid, d in sorted(_dispositivos(res).items()):
        if _txt(d.get("retired")).lower() == "true":
            continue
        ips, macs = _lista(_dato(d, "ip_list")), _lista(_dato(d, "mac_list"))
        out.append([
            _dato(d, "name"), ", ".join(ips), ", ".join(macs), "",
            _dato(d, "network_list", "networks", "network"), _dato(d, "vlan_list", "vlans", "vlan"),
            _dato(d, "category"), _dato(d, "subcategory"), _dato(d, "type"), _dato(d, "manufacturer"),
            _dato(d, "model"), _dato(d, "os_name", "os"), _dato(d, "software_or_firmware_version"),
            _dato(d, "purdue_level"), _dato(d, "site_name"),
            _dato(d, "risk_score", "risk_level", "risk_score_level")])
    return out


def filas_vulnerabilidades(res: dict) -> tuple:
    """-> (filas, omitidas sin CVE)."""
    devs = _dispositivos(res)
    filas, sin_cve = [], 0
    for r in res.get("relaciones_vulnerabilidades", ([], []))[0]:
        cves = [c.upper() for c in _lista(r.get("vulnerability_cve_ids"))]
        if not cves:
            sin_cve += 1
            continue
        dev = devs.get(_obt(r, claves=("device_uid",)), {})
        ips, macs = _lista(_obt(r, dev, claves=("device_ip_list", "ip_list"))), \
            _lista(_obt(r, dev, claves=("device_mac_list", "mac_list")))
        sev = SEVERIDADES.get(_txt(r.get("vulnerability_adjusted_vulnerability_score_level")).lower(), "")
        rel = _txt(r.get("vulnerability_relevance"))
        estado = "fixed" if rel.lower() == "fixed" else "open"
        fuente = "xDome; relevancia " + rel
        if _txt(r.get("vulnerability_is_known_exploited")).lower() == "true":
            fuente += "; explotada activamente"
        for cve in dict.fromkeys(cves):
            filas.append([_obt(r, dev, claves=("device_name", "name")), ips[0] if ips else "",
                          macs[0] if macs else "", cve, sev, _txt(r.get("vulnerability_cvss_v3_score")),
                          estado, _obt(r, dev, claves=("device_model", "model")),
                          _obt(r, dev, claves=("device_software_or_firmware_version",
                                               "software_or_firmware_version")), fuente])
    return filas, sin_cve


def _puerto(v) -> str:
    s = _txt(v)
    return s if s.isdigit() and int(s) <= 65535 else ""


def _sev_alerta(a: dict) -> tuple:
    """-> (severidad en ingles, fue_dato_de_xdome)."""
    for k in ("severity", "alert_severity", "risk_level", "priority"):
        s = SEVERIDADES.get(_txt((a or {}).get(k)).lower())
        if s:
            return s, True
    return SEVERIDAD_ALERTA_DEFECTO, False


def filas_alertas(res: dict) -> tuple:
    """-> (filas, omitidas {motivo: n}, filas con severidad por defecto)."""
    devs = _dispositivos(res)
    alertas = {}
    for a in res.get("alertas", ([], []))[0]:
        alertas[_txt(a.get("id"))] = a
    filas, omit, defecto = [], {"evento sin firma": 0, "relacion sin firma": 0, "relacion sin IP": 0}, 0
    con_evento = set()
    for e in res.get("eventos", ([], []))[0]:
        aid = _txt(e.get("alert_id"))
        a = alertas.get(aid, {})
        firma = _obt(a, claves=("alert_name", "name")) or _txt(e.get("event_type"))
        if not firma:
            omit["evento sin firma"] += 1
            continue
        if aid:
            con_evento.add(aid)
        sev, real = _sev_alerta(a or e)
        defecto += 0 if real else 1
        filas.append([_txt(e.get("timestamp")), _txt(e.get("side_a_ip")), _txt(e.get("side_b_ip")),
                      _puerto(e.get("side_b_port")), _txt(e.get("protocol")), firma, sev,
                      _obt(a, claves=("category",))])
    for r in res.get("relaciones_alertas", ([], []))[0]:
        aid = _txt(r.get("alert_id"))
        if aid in con_evento:
            continue
        a = alertas.get(aid, {})
        firma = _obt(a, r, claves=("alert_name", "name"))
        if not firma:
            omit["relacion sin firma"] += 1
            continue
        ips = _lista(_dato(devs.get(_txt(r.get("device_uid")), {}), "ip_list")) or \
            _lista(r.get("device_ip_list"))
        if not ips:
            omit["relacion sin IP"] += 1
            continue
        sev, real = _sev_alerta(a or r)
        defecto += 0 if real else 1
        filas.append([_obt(a, claves=("update_time", "timestamp", "created_time")), ips[0], "", "", "", firma,
                      sev, _obt(a, r, claves=("category", "alert_category"))])
    return filas, {k: v for k, v in omit.items() if v}, defecto
