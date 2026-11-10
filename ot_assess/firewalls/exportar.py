"""Exportacion de la politica propuesta (M3a, revisada) a FortiOS, Check Point y PAN-OS como archivos de comandos (M4, D58).

Reutiliza la lectura y la validacion de M3b (`fmc.construir`): mismas reglas de inclusion, mismos objetos usados,
mismos errores. La herramienta no se conecta a ningun equipo: el analista revisa y aplica los archivos. La sintaxis es
la publica de cada fabricante y NO se probo contra equipos reales: validarla en la version del cliente.
"""
from __future__ import annotations

import ipaddress
import re
import shlex
from datetime import datetime
from pathlib import Path

from .fmc import ErrorFmc
from .politica import NOTA

FORMATOS = ("fmc", "fortios", "checkpoint", "panos")
# limite de caracteres de nombre por fabricante (M3a usa 64 como maximo)
LIMITE = {"fortios": 79, "checkpoint": 63, "panos": 63}
ARCHIVO = {"fortios": "fortios_politica.conf", "checkpoint": "checkpoint_mgmt_cli.txt", "panos": "panos_set.txt"}
LEEME_ARCHIVO = {"fortios": "LEEME_FORTIOS.txt", "checkpoint": "LEEME_CHECKPOINT.txt", "panos": "LEEME_PANOS.txt"}
NOMBRE_FAB = {"fortios": "Fortinet FortiOS", "checkpoint": "Check Point (mgmt_cli)", "panos": "Palo Alto PAN-OS"}
MAX_COMENTARIO_FAB = 250
_CTRL = re.compile(r"[\x00-\x1f\x7f]+")


def _limpio(texto: str) -> str:
    """Una sola linea: los saltos y caracteres de control no pueden inyectar comandos."""
    return _CTRL.sub(" ", texto or "").strip()


def _q(texto: str) -> str:
    """Cadena entre comillas dobles con \\ y \" escapadas (FortiOS y PAN-OS)."""
    return '"' + _limpio(texto).replace("\\", "\\\\").replace('"', '\\"') + '"'


def _sh(texto: str) -> str:
    """Argumento de shell (Check Point: mgmt_cli se ejecuta desde un shell)."""
    return shlex.quote(_limpio(texto))


def _nombres_cortos(res: dict, formato: str, avisos: list) -> dict:
    """nombre -> nombre que cabe en el fabricante. Aviso si se recorta; ErrorFmc si dos nombres chocan."""
    lim = LIMITE[formato]
    mapa: dict = {}
    for espacio, nombres in (("objeto", [o["name"] for k in ("hosts", "redes", "grupos_red", "servicios",
                                                              "grupos_servicio") for o in res["objetos"][k]]),
                             ("regla", [r["name"] for r in res["reglas"]])):
        destino: dict = {}
        for n in nombres:
            corto = n[:lim]
            if corto != n:
                avisos.append(f"{espacio} {n}: el nombre pasa de {lim} caracteres ({NOMBRE_FAB[formato]}); "
                              f"se recorta a {corto}")
            if corto in destino and destino[corto] != n:
                raise ErrorFmc(f"{espacio}s '{destino[corto]}' y '{n}' chocan al recortar a {lim} caracteres "
                               f"({NOMBRE_FAB[formato]}); renombre uno en el CSV")
            destino[corto] = n
            mapa[n] = corto
    return mapa


def _ipv4(valor: str, que: str, formato: str):
    red = ipaddress.ip_network(valor, strict=False)
    if red.version != 4:
        raise ErrorFmc(f"{que} {valor}: IPv6 no se exporta a {NOMBRE_FAB[formato]} (solo IPv4)")
    return red


def _comentario(r: dict) -> str:
    c = r["newComments"][0] if r["newComments"] else ""
    return _limpio(c)[:MAX_COMENTARIO_FAB]


def _cabecera(formato: str, res: dict, fecha: str, marca: str) -> list:
    lineas = [f"{marca} Propuesta de politica para {NOMBRE_FAB[formato]} - generada el {fecha}",
              f"{marca} Politica: {res['politica']}",
              f"{marca} NOTA: {NOTA}",
              f"{marca} Sintaxis NO probada contra equipos reales: validar en la version del cliente antes de aplicar.",
              f"{marca} Las reglas 'revisar' van deshabilitadas. No se borra ni modifica nada existente."]
    return lineas


def _miembros(o: dict) -> list:
    return [x["name"] for x in o["objects"]]


# ----------------------------------------------------------------------------------------------------- FortiOS
def _fortios(res: dict, ren: dict, fecha: str, opc: dict) -> str:
    ob = res["objetos"]
    s = ren.get
    out = _cabecera("fortios", res, fecha, "#")
    out += ["# Aplicar por CLI (o pegar en la consola) en una ventana de cambio; en VDOM, entrar antes con 'config vdom'.", ""]

    def bloque(titulo, filas):
        if filas:
            out.append("config " + titulo)
            for f in filas:
                out.append("    edit " + _q(f[0]))
                out.extend("        " + x for x in f[1])
                out.append("    next")
            out.append("end")
            out.append("")

    def _subnet(o):
        red = _ipv4(o["value"], "objeto " + o["name"], "fortios")
        return f"set subnet {red.network_address} {red.netmask}"

    bloque("firewall address", [(s(o["name"], o["name"]), [_subnet(o)]) for o in ob["hosts"] + ob["redes"]])
    bloque("firewall addrgrp", [(s(o["name"], o["name"]), ["set member " + " ".join(
        _q(s(m, m)) for m in _miembros(o))]) for o in ob["grupos_red"]])
    bloque("firewall service custom", [(s(o["name"], o["name"]), [f"set {o['protocol'].lower()}-portrange {o['port']}"]) for o in ob["servicios"]])
    bloque("firewall service group", [(s(o["name"], o["name"]), ["set member " + " ".join(
        _q(s(m, m)) for m in _miembros(o))]) for o in ob["grupos_servicio"]])
    filas = []
    for r in res["reglas"]:
        c = ["set name " + _q(s(r["name"], r["name"])),
             "set srcintf " + _q(r["sourceZones"][0]), "set dstintf " + _q(r["destinationZones"][0]),
             "set srcaddr " + " ".join(_q(s(x, x)) for x in r["sourceNetworks"]),
             "set dstaddr " + " ".join(_q(s(x, x)) for x in r["destinationNetworks"]),
             "set action accept", "set schedule " + _q("always"),
             "set service " + (" ".join(_q(s(x, x)) for x in r["destinationPorts"]) or _q("ALL")),
             "set logtraffic all"]
        if not r["enabled"]:
            c.append("set status disable")
        if _comentario(r):
            c.append("set comments " + _q(_comentario(r)))
        filas.append(("0", c))
    if filas:
        out.append("config firewall policy")
        for _i, c in filas:
            out.append("    edit 0")        # FortiOS asigna el id
            out.extend("        " + x for x in c)
            out.append("    next")
        out.append("end")
        out.append("")
    out.append("# La denegacion por defecto de FortiOS es implicita: no se genera.")
    return "\n".join(out) + "\n"


# ------------------------------------------------------------------------------------------------ Check Point
def _checkpoint(res: dict, ren: dict, fecha: str, opc: dict) -> str:
    ob = res["objetos"]
    capa = opc.get("capa") or "Network"
    s = ren.get
    pre = "mgmt_cli -s session.txt "
    out = _cabecera("checkpoint", res, fecha, "#")
    out += ["# Cada linea es un comando completo: bash checkpoint_mgmt_cli.txt (tras iniciar sesion).",
            "# mgmt_cli login user USUARIO > session.txt          (use -s session.txt en cada comando; ya viene abajo)",
            "# Check Point no tiene zonas en la regla: la zona de la propuesta va en el comentario.", ""]

    def lista(campo, nombres):
        return " ".join(f"{campo}.{i} {_sh(s(n, n))}" for i, n in enumerate(nombres, 1))

    for o in ob["hosts"]:
        _ipv4(o["value"], "objeto " + o["name"], "checkpoint")
        out.append(pre + f"add host name {_sh(s(o['name'], o['name']))} ip-address {_sh(o['value'])}")
    for o in ob["redes"]:
        red = _ipv4(o["value"], "objeto " + o["name"], "checkpoint")
        out.append(pre + f"add network name {_sh(s(o['name'], o['name']))} subnet {red.network_address} "
                   f"mask-length {red.prefixlen}")
    for o in ob["grupos_red"]:
        out.append(pre + f"add group name {_sh(s(o['name'], o['name']))} {lista('members', _miembros(o))}")
    for o in ob["servicios"]:
        out.append(pre + "add service-%s name %s port %s" % (o["protocol"].lower(), _sh(s(o["name"], o["name"])),
                                                             _sh(o["port"])))
    for o in ob["grupos_servicio"]:
        out.append(pre + "add service-group name %s %s" % (_sh(s(o["name"], o["name"])),
                                                          lista("members", _miembros(o))))
    for r in res["reglas"]:
        coment = "zonas %s -> %s" % (r["sourceZones"][0], r["destinationZones"][0])
        if _comentario(r):
            coment += " | " + _comentario(r)
        srv = lista("service", r["destinationPorts"]) if r["destinationPorts"] else "service Any"
        out.append(pre + "add access-rule layer %s position bottom name %s %s %s %s action Accept "
                   "track.type Log enabled %s comments %s" % (
                       _sh(capa), _sh(s(r["name"], r["name"])), lista("source", r["sourceNetworks"]),
                       lista("destination", r["destinationNetworks"]), srv,
                       "true" if r["enabled"] else "false", _sh(coment[:MAX_COMENTARIO_FAB + 40])))
    out += ["", "# Publicar solo despues de revisar en SmartConsole (el analista decide):",
            "# " + pre + "publish"]
    return "\n".join(out) + "\n"


# ------------------------------------------------------------------------------------------------------ PAN-OS
def _panos(res: dict, ren: dict, fecha: str, opc: dict) -> str:
    ob = res["objetos"]
    s = ren.get
    pre = "set vsys %s " % opc["vsys"] if opc.get("vsys") else "set "
    out = _cabecera("panos", res, fecha, "#")
    out += ["# Pegar en modo configuracion (configure). Con --vsys los comandos llevan 'set vsys <nombre>'.", ""]

    def lst(nombres):
        return "[ " + " ".join(_q(s(n, n)) if re.search(r"\s", s(n, n)) else s(n, n) for n in nombres) + " ]"

    for o in ob["hosts"]:
        ip = ipaddress.ip_address(o["value"])
        out.append(pre + "address %s ip-netmask %s/%d" % (s(o["name"], o["name"]), ip, ip.max_prefixlen))
    for o in ob["redes"]:
        out.append(pre + "address %s ip-netmask %s" % (s(o["name"], o["name"]), ipaddress.ip_network(o["value"])))
    for o in ob["grupos_red"]:
        out.append(pre + "address-group %s static %s" % (s(o["name"], o["name"]), lst(_miembros(o))))
    for o in ob["servicios"]:
        out.append(pre + "service %s protocol %s port %s" % (s(o["name"], o["name"]), o["protocol"].lower(), o["port"]))
    for o in ob["grupos_servicio"]:
        out.append(pre + "service-group %s members %s" % (s(o["name"], o["name"]), lst(_miembros(o))))
    for r in res["reglas"]:
        linea = pre + "rulebase security rules %s from %s to %s source %s destination %s service %s " \
            "application any action allow log-end yes" % (
                s(r["name"], r["name"]), r["sourceZones"][0], r["destinationZones"][0], lst(r["sourceNetworks"]),
                lst(r["destinationNetworks"]), lst(r["destinationPorts"]) if r["destinationPorts"] else "any")
        if not r["enabled"]:
            linea += " disabled yes"
        if _comentario(r):
            linea += " description " + _q(_comentario(r))
        out.append(linea)
    out += ["", "# Confirmar solo despues de revisar con 'show' y 'validate full' (el analista decide):", "# commit"]
    return "\n".join(out) + "\n"


_GENERADORES = {"fortios": _fortios, "checkpoint": _checkpoint, "panos": _panos}

_PASOS = {
    "fortios": ("Pegar el archivo en la CLI de FortiOS (SSH o consola), en el VDOM correcto.",
                "Revisar con 'show firewall policy' que las reglas nuevas quedaron al final y deshabilitadas las de revisar.",
                "Las interfaces o zonas de las reglas (srcintf/dstintf) deben existir; si no, FortiOS rechaza la regla.",
                "Si ya existe un objeto con el mismo nombre, 'edit' lo modifica en vez de crearlo: comparar antes.",
                "Quitar lo agregado: 'config firewall policy' y 'delete <id>' por cada regla (los ids se ven con "
                "'show firewall policy'); luego 'delete' de los servicios, grupos y direcciones listados abajo."),
    "checkpoint": ("Iniciar sesion: mgmt_cli login user USUARIO > session.txt (o con la API de la consola).",
                   "Ejecutar: bash checkpoint_mgmt_cli.txt (cada linea es un comando mgmt_cli completo).",
                   "Revisar los cambios en SmartConsole (sesion sin publicar). La capa es '{capa}' (opcion --capa).",
                   "Publicar con 'mgmt_cli -s session.txt publish' solo tras revisar; para descartar, "
                   "'mgmt_cli -s session.txt discard'.",
                   "Quitar lo agregado ya publicado: 'delete access-rule', 'delete group', 'delete host', "
                   "'delete network', 'delete service-tcp/udp' por nombre, en una sesion nueva."),
    "panos": ("Entrar a modo configuracion y pegar el archivo (o cargarlo con 'load config partial' si lo prefiere).",
              "Revisar con 'show' y 'validate full'.",
              "Las zonas de las reglas (from/to) deben existir en el vsys; si no, 'commit' falla.",
              "Confirmar con 'commit' solo tras revisar (en una ventana de cambio).",
              "Quitar lo agregado: antes del 'commit', 'revert config'; despues, 'delete rulebase security rules "
              "<regla>' y 'delete address|address-group|service|service-group <nombre>' por cada nombre listado."),
}


def _leeme(formato: str, res: dict, fecha: str, opc: dict) -> str:
    ob = res["objetos"]
    n_rev = sum(1 for r in res["reglas"] if not r["enabled"])
    nombres = [o["name"] for k in ("hosts", "redes", "grupos_red", "servicios", "grupos_servicio") for o in ob[k]]
    pasos = "\n".join("  %d. %s" % (i, p.format(capa=opc.get("capa") or "Network"))
                      for i, p in enumerate(_PASOS[formato], 1))
    return (f"Carga de la politica propuesta a {NOMBRE_FAB[formato]}\n" + "=" * 60 + "\n"
            f"Generado el {fecha}. Politica: {res['politica']}\n"
            f"Reglas exportadas: {len(res['reglas'])} ({n_rev} deshabilitadas por ser \"revisar\"). "
            f"Omitidas: {res['omitidas']['bloquear']} bloquear, {res['omitidas']['revisar']} revisar.\n\n"
            f"NOTA: {NOTA}\n\n"
            f"Archivo: {ARCHIVO[formato]}. La herramienta no se conecta a ningun equipo; no probo esta sintaxis contra\n"
            "equipos reales: validarla en simulacion o laboratorio con la version del cliente antes de aplicar.\n\n"
            "Pasos\n  0. Revisar el archivo completo (objetos, reglas, comentarios) y compararlo con la politica vigente.\n"
            f"{pasos}\n"
            "  Despues de aplicar: validar con el dueno del proceso, mantener el registro y revisar los aciertos antes de\n"
            "  endurecer. El archivo no borra ni modifica objetos ni reglas existentes.\n\n"
            f"Objetos creados ({len(nombres)}):\n" + "".join(f"  {n}\n" for n in nombres) +
            f"Reglas creadas ({len(res['reglas'])}):\n" + "".join(
                f"  {r['name']}{'' if r['enabled'] else ' (deshabilitada)'}\n" for r in res["reglas"]))


def generar(formato: str, res: dict, fecha: str = None, capa: str = None, vsys: str = None) -> dict:
    """res de `fmc.construir` -> {"archivos": {nombre: texto}, "avisos": [...]}. ErrorFmc si no cabe o choca."""
    if formato not in LIMITE:
        raise ErrorFmc(f"formato desconocido: {formato}")
    fecha = fecha or datetime.now().strftime("%Y-%m-%d")
    avisos = list(res["avisos"])
    ren = _nombres_cortos(res, formato, avisos)
    opc = {"capa": capa, "vsys": vsys}
    texto = _GENERADORES[formato](res, ren, fecha, opc)
    return {"archivos": {ARCHIVO[formato]: texto, LEEME_ARCHIVO[formato]: _leeme(formato, res, fecha, opc)},
            "avisos": avisos}


def escribir(archivos: dict, carpeta: Path) -> list:
    carpeta.mkdir(parents=True, exist_ok=True)
    for n, t in archivos.items():
        (carpeta / n).write_text(t, encoding="utf-8")
    return list(archivos)
