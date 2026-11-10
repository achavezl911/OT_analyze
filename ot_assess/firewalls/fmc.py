"""Exportacion de la politica propuesta (M3a, ya revisada por el analista) a Cisco FMC 7.6 por API REST (M3b, D48).

La herramienta no se conecta a ningun FMC: genera JSON de objetos y reglas y un script autonomo que por defecto solo
simula. Las rutas y nombres de la API salen de la documentacion publica de la API REST de FMC y deben validarse contra
la version del cliente (7.6.4) en modo simular antes de aplicar.
"""
from __future__ import annotations

import csv
import ipaddress
import json
import re
from pathlib import Path

from .politica import ACCION_DEFECTO, MAX_NOMBRE, NOTA  # noqa: F401  (ACCION_DEFECTO: documentacion)

PLANTILLA = Path(__file__).with_name("aplicar_fmc.py.tmpl")
MAX_OBJ_LADO = 50
MAX_COMENTARIO = 250
NOMBRE_FMC = re.compile(r"^[A-Za-z0-9_.\-]{1," + str(MAX_NOMBRE) + r"}$")
# servicio "cualquiera" de M3a (conducto sin puerto: cualquier protocolo IP). En FMC es una regla sin puertos de
# destino; no se exporta como objeto.
SERVICIO_CUALQUIERA = ("ip", "any", "")

# Decision y tipo tal como los escribe politica.py (es) o su traduccion (en).
_DECISION = {"permitir": "permitir", "allow": "permitir", "revisar": "revisar", "review": "revisar",
             "bloquear": "bloquear", "block": "bloquear"}
_TIPO = {"host": "host", "red": "red", "network": "red", "grupo": "grupo", "group": "grupo",
         "servicio": "servicio", "service": "servicio", "grupo_servicio": "grupo_servicio",
         "service group": "grupo_servicio"}
COL_PROPUESTA = ("orden", "nombre", "decision", "razones", "zona_entrada", "zona_salida", "origen", "destino",
                 "servicios", "justificacion")
COL_OBJETOS = ("nombre", "tipo", "valor", "miembros")


class ErrorFmc(Exception):
    """Entrada que no se puede exportar; el mensaje es para el analista."""


def _leer(ruta, columnas: tuple) -> list:
    try:
        with open(ruta, newline="", encoding="utf-8-sig") as fh:
            lector = csv.DictReader(fh)
            campos = [(c or "").strip().lower() for c in (lector.fieldnames or [])]
            falta = [c for c in columnas if c not in campos]
            if falta:
                raise ErrorFmc(f"{ruta}: faltan las columnas {', '.join(falta)}")
            return [{(k or "").strip().lower(): (v or "").strip() for k, v in f.items()} for f in lector]
    except (OSError, UnicodeDecodeError) as e:
        raise ErrorFmc(f"no pude leer {ruta}: {type(e).__name__}")


def _lista(x: str) -> list:
    return [p.strip() for p in (x or "").split(";") if p.strip()]


def _valor_host(v: str):
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def _valor_red(v: str):
    try:
        ipaddress.ip_network(v, strict=True)
        return "/" in v
    except ValueError:
        return False


def _servicio(v: str):
    """'tcp/443' o 'udp/1000-2000' -> (PROTOCOLO, puerto) o None."""
    m = re.match(r"^(tcp|udp)/(\d{1,5})(?:-(\d{1,5}))?$", v.lower())
    if not m:
        return None
    a = int(m.group(2))
    b = int(m.group(3)) if m.group(3) else a
    if not (1 <= a <= 65535 and 1 <= b <= 65535 and a <= b):
        return None
    return m.group(1).upper(), m.group(2) + ("-" + m.group(3) if m.group(3) else "")


def _es_cualquiera(nombre: str, objs: dict, vistos=None) -> bool:
    """Servicio con valor ip/any/vacio, o grupo de servicios que contiene alguno (cualquier puerto)."""
    o = objs.get(nombre)
    if o is None:
        return False
    tipo = _TIPO.get(o["tipo"].lower())
    if tipo == "servicio":
        return o["valor"].strip().lower() in SERVICIO_CUALQUIERA
    if tipo == "grupo_servicio":
        vistos = vistos or set()
        if nombre in vistos:
            return False
        vistos.add(nombre)
        return any(_es_cualquiera(m, objs, vistos) for m in _lista(o["miembros"]))
    return False


def construir(filas_prop: list, filas_obj: list, politica: str, incluir_revisar: bool = False) -> dict:
    """-> {"objetos", "reglas", "avisos", "politica", "omitidas"}. ErrorFmc si algo no es exportable."""
    errores: list = []
    objs: dict = {}
    for f in filas_obj:
        n = f["nombre"]
        if not n:
            continue
        if n in objs:
            errores.append(f"objeto repetido: {n}")
        objs[n] = f
    if not NOMBRE_FMC.match(politica or ""):
        errores.append(f"nombre de politica no valido para FMC: '{politica}'")

    reglas_csv, omitidas, vistos = [], {"bloquear": 0, "revisar": 0}, set()
    for f in filas_prop:
        d = _DECISION.get(f["decision"].lower())
        if d is None:
            errores.append(f"regla {f['nombre'] or f['orden']}: decision desconocida '{f['decision']}'")
        elif d == "bloquear":
            omitidas["bloquear"] += 1
        elif d == "revisar" and not incluir_revisar:
            omitidas["revisar"] += 1
        else:
            reglas_csv.append((d, f))

    usados: set = set()

    def pedir(nombre, regla):
        if nombre not in objs:
            errores.append(f"regla {regla}: el objeto '{nombre}' no esta en el archivo de objetos")
            return False
        if nombre not in usados:
            usados.add(nombre)
            pila.append(nombre)
        return True

    pila: list = []
    reglas, avisos = [], []
    for d, f in reglas_csv:
        nom = f["nombre"]
        if not NOMBRE_FMC.match(nom):
            errores.append(f"nombre de regla no valido para FMC: '{nom}' (letras, digitos, _ - . y maximo {MAX_NOMBRE})")
        if nom in vistos:
            errores.append(f"regla repetida: {nom}")
        vistos.add(nom)
        zo, zd = f["zona_entrada"], f["zona_salida"]
        if not zo or not zd:
            errores.append(f"regla {nom}: zona de seguridad vacia")
        lados = {"origen": _lista(f["origen"]), "destino": _lista(f["destino"]), "servicios": _lista(f["servicios"])}
        cualquiera = [x for x in lados["servicios"] if _es_cualquiera(x, objs)]
        if cualquiera:
            # un servicio "cualquiera" abre todos los puertos: la regla va sin destinationPorts (y se avisa)
            avisos.append(f"regla {nom}: servicio cualquiera ({', '.join(cualquiera)}): sin restriccion de puertos")
            lados["servicios"] = []
            pedir_srv = False
        else:
            pedir_srv = True
        for k, v in lados.items():
            if not v and (k != "servicios" or pedir_srv):
                errores.append(f"regla {nom}: columna {k} vacia")
            for x in v:
                pedir(x, nom)
        for k in ("origen", "destino"):
            if len(lados[k]) > MAX_OBJ_LADO:
                avisos.append(f"regla {nom}: {len(lados[k])} objetos en {k} (mas de {MAX_OBJ_LADO}); conviene agrupar")
        if any(objs.get(x, {}).get("valor") in ("0.0.0.0/0", "::/0") for k in ("origen", "destino")
               for x in lados[k]):
            avisos.append(f"regla {nom}: usa 0.0.0.0/0 (cualquier direccion) en origen o destino")
        coment = f["justificacion"]
        if d == "revisar":
            coment = "revisar: " + (f["razones"] or "sin razones") + (" | " + coment if coment else "")
        reglas.append({"name": nom, "action": "ALLOW", "enabled": d == "permitir",
                       "sourceZones": [zo], "destinationZones": [zd],
                       "sourceNetworks": lados["origen"], "destinationNetworks": lados["destino"],
                       "destinationPorts": lados["servicios"], "logBegin": False, "logEnd": True,
                       "sendEventsToFMC": True, "newComments": [coment[:MAX_COMENTARIO]] if coment else []})

    # objetos usados (con sus miembros), validados por tipo
    salida = {"hosts": [], "redes": [], "grupos_red": [], "servicios": [], "grupos_servicio": []}
    while pila:
        n = pila.pop(0)
        o = objs[n]
        tipo = _TIPO.get(o["tipo"].lower())
        if not NOMBRE_FMC.match(n):
            errores.append(f"nombre de objeto no valido para FMC: '{n}' (letras, digitos, _ - . y maximo {MAX_NOMBRE})")
        if tipo == "host":
            if not _valor_host(o["valor"]):
                errores.append(f"objeto {n}: valor de host no valido '{o['valor']}'")
            salida["hosts"].append({"name": n, "type": "Host", "value": o["valor"], "description": ""})
        elif tipo == "red":
            if not _valor_red(o["valor"]):
                errores.append(f"objeto {n}: valor de red no valido '{o['valor']}' (a.b.c.d/n sin bits de host)")
            salida["redes"].append({"name": n, "type": "Network", "value": o["valor"], "description": ""})
        elif tipo == "servicio" and o["valor"].strip().lower() in SERVICIO_CUALQUIERA:
            continue        # "cualquiera": no es un objeto de FMC (la regla va sin puertos)
        elif tipo == "grupo_servicio" and _es_cualquiera(n, objs):
            continue        # grupo con un miembro "cualquiera" = cualquier puerto
        elif tipo == "servicio":
            sv = _servicio(o["valor"])
            if sv is None:
                errores.append(f"objeto {n}: servicio no exportable '{o['valor']}' (se espera tcp/PUERTO o udp/PUERTO)")
                sv = ("TCP", "0")
            salida["servicios"].append({"name": n, "type": "ProtocolPortObject", "protocol": sv[0], "port": sv[1],
                                        "description": ""})
        elif tipo in ("grupo", "grupo_servicio"):
            miembros = _lista(o["miembros"])
            if not miembros:
                errores.append(f"objeto {n}: grupo sin miembros")
            refs = []
            for m in miembros:
                if pedir(m, "grupo " + n):
                    mt = _TIPO.get(objs[m]["tipo"].lower())
                    ok = (mt in ("host", "red")) if tipo == "grupo" else (mt == "servicio")
                    if not ok:
                        errores.append(f"objeto {n}: el miembro '{m}' ({objs[m]['tipo']}) no cabe en un {o['tipo']}")
                    refs.append({"name": m, "type": {"host": "Host", "red": "Network", "grupo": "NetworkGroup",
                                                     "servicio": "ProtocolPortObject",
                                                     "grupo_servicio": "PortObjectGroup"}.get(mt, "")})
            if tipo == "grupo":
                salida["grupos_red"].append({"name": n, "type": "NetworkGroup", "objects": refs})
            else:
                salida["grupos_servicio"].append({"name": n, "type": "PortObjectGroup", "objects": refs})
        else:
            errores.append(f"objeto {n}: tipo desconocido '{o['tipo']}'")
    # los lados de las reglas deben ser de la clase correcta
    for r in reglas:
        for campo, validos in (("sourceNetworks", ("host", "red", "grupo")), ("destinationNetworks", ("host", "red", "grupo")),
                               ("destinationPorts", ("servicio", "grupo_servicio"))):
            for x in r[campo]:
                if x in objs and _TIPO.get(objs[x]["tipo"].lower()) not in validos:
                    errores.append(f"regla {r['name']}: '{x}' ({objs[x]['tipo']}) no sirve en {campo}")
    if not reglas and not errores:
        errores.append("no queda ninguna regla que exportar (¿todas son bloquear o revisar?)")
    if errores:
        raise ErrorFmc("\n".join(dict.fromkeys(errores)))
    return {"politica": politica, "objetos": salida, "reglas": reglas, "avisos": avisos, "omitidas": omitidas}


def nombre_politica_defecto(ruta_propuesta: str, fecha: str) -> str:
    """PROPUESTA_<firewall>_<AAAAMMDD>; el firewall es el prefijo de <fw>_politica_propuesta.csv (FW si no hay)."""
    stem = Path(ruta_propuesta).stem
    fw = stem[:-len("_politica_propuesta")] if stem.endswith("_politica_propuesta") else "FW"
    fw = re.sub(r"[^A-Za-z0-9_.\-]+", "_", fw).strip("_") or "FW"
    return (f"PROPUESTA_{fw}_{fecha}")[:MAX_NOMBRE]


def leer_entradas(prop: str, obj: str) -> tuple:
    return _leer(prop, COL_PROPUESTA), _leer(obj, COL_OBJETOS)


def _escribir_json(ruta: Path, dato) -> None:
    ruta.write_text(json.dumps(dato, indent=2, ensure_ascii=True, sort_keys=False) + "\n", encoding="utf-8")


LEEME = """\
Carga de la politica propuesta a Cisco FMC 7.6 (API REST)
==========================================================
Politica nueva: {politica}
Reglas exportadas: {n_reglas} ({n_rev} deshabilitadas por ser "revisar"). Omitidas: {n_bloq} bloquear, {n_omrev} revisar.

NOTA: {nota}

Archivos
  fmc_objetos.json   objetos por tipo (hosts, redes, grupos de red, servicios, grupos de servicio)
  fmc_reglas.json    reglas en el orden de la propuesta (accion ALLOW; nombres en vez de id)
  aplicar_fmc.py     script autonomo (solo biblioteca estandar de Python 3.9+)
  aplicar_fmc.log    lo crea el script: metodo, ruta y codigo de cada llamada (sin credenciales)

Pasos
  1. Revisar fmc_reglas.json y fmc_objetos.json. Las rutas y los nombres de la API vienen de la documentacion
     publica de FMC y NO estan validados contra el equipo del cliente: validarlos con la version instalada (7.6.4)
     en modo simular antes de aplicar.
  2. Simular (por defecto; solo hace GET, mas el POST del token):
       python3 aplicar_fmc.py
     Pide URL del FMC, usuario y contrasena (no se guardan ni se imprimen). Verifica TLS; para una CA propia use
     --ca ARCHIVO. --inseguro desactiva la verificacion y no debe usarse en un cliente.
  3. Revisar lo que mostro: objetos que se crearian, zonas faltantes, politica nueva.
     Las zonas de seguridad deben existir en FMC (dependen de las interfaces del equipo; el script no las crea).
  4. Aplicar: python3 aplicar_fmc.py --aplicar   (pide escribir SI). Crea solo lo que falta y una politica de
     acceso NUEVA con accion por defecto BLOCK y registro al inicio de la conexion; si ya existe una con ese nombre,
     se detiene. Nunca borra ni modifica objetos ni politicas existentes.
  5. Revisar la politica en la interfaz de FMC (orden, reglas deshabilitadas, registro de la accion por defecto).
  6. Asignar la politica al equipo en una ventana de cambio (el script no la asigna ni despliega) y desplegar
     primero con registro, antes de endurecer.
"""


def escribir(res: dict, carpeta: Path) -> list:
    carpeta.mkdir(parents=True, exist_ok=True)
    _escribir_json(carpeta / "fmc_objetos.json", res["objetos"])
    _escribir_json(carpeta / "fmc_reglas.json", res["reglas"])
    plantilla = PLANTILLA.read_text(encoding="utf-8")
    script = plantilla.replace("__POLITICA__", json.dumps(res["politica"]))
    (carpeta / "aplicar_fmc.py").write_text(script, encoding="utf-8")
    n_rev = sum(1 for r in res["reglas"] if not r["enabled"])
    (carpeta / "LEEME_FMC.txt").write_text(LEEME.format(
        politica=res["politica"], n_reglas=len(res["reglas"]), n_rev=n_rev, n_bloq=res["omitidas"]["bloquear"],
        n_omrev=res["omitidas"]["revisar"], nota=NOTA), encoding="utf-8")
    return ["fmc_objetos.json", "fmc_reglas.json", "aplicar_fmc.py", "LEEME_FMC.txt"]
