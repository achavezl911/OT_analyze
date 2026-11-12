"""AVK1 (D124): paquete verificado de avisos ICS de CISA (CSAF) y KEV para sitios sin red.

El analista lo arma en un equipo con red (la herramienta no descarga nada), lo lleva en un medio y en la planta se
verifica por SHA-256 antes de usarlo. Es evidencia de integridad del medio, no una firma ni una prueba de origen.
Reutiliza los hashes y las rutas seguras del paquete de entrega (entrega.py) y la lectura de avisos_cisa.
"""
from __future__ import annotations

import hashlib
import json
import sys
import zipfile
from pathlib import Path

from . import __version__, json_entrada
from . import avisos_cisa as ac
from . import entrega as ent
from .entorno import commit_corto
from .i18n import t

FORMATO = "ot_assess.avisos/1"
MANIFIESTO = "manifiesto_avisos.json"
SUMAS = "manifiesto_avisos.sha256"
MAX_PROBLEMAS = 20


def construir(avisos, kev, fecha: str):
    """-> (contenidos {ruta: bytes}, manifiesto dict). SystemExit si una fuente no se puede leer."""
    contenidos: dict = {}
    man: dict = {"formato": FORMATO, "ot_assess": __version__, "commit": commit_corto(), "creado": fecha,
                 "kev": None, "csaf": None, "archivos": []}
    if kev:
        k = ac.cargar_kev(kev)
        nombre = Path(kev).name
        if not ent._ruta_segura(nombre):
            raise SystemExit(f"[!] {t('nombre de archivo KEV no permitido')}: {nombre!r}")
        contenidos["kev/" + nombre] = Path(kev).read_bytes()
        man["kev"] = {"archivo": nombre, "catalogVersion": k["version"], "dateReleased": k["fecha"],
                      "registros": k["total"]}
    if avisos:
        r = {"leidos": 0, "saltados": 0, "sobre_tamano": 0, "sobrantes": 0}
        validos, ultimo = 0, None
        for rel, raw in ac.archivos_json(avisos, r):
            if not ent._ruta_segura(rel):
                raise SystemExit(f"[!] {t('ruta de aviso no permitida')}: {rel!r}")
            contenidos["csaf/" + rel] = raw
            try:
                res = ac._aviso_csaf(json_entrada.cargar(raw.decode("utf-8-sig")), set())
            except (ValueError, UnicodeDecodeError, RecursionError):
                res = None
            if res is None:
                continue
            validos += 1
            if res[2] and (ultimo is None or res[2] > ultimo):
                ultimo = res[2]
        if not r["leidos"]:
            raise SystemExit(f"[!] {t('no se leyo ningun JSON de los avisos')}: {Path(avisos).name}")
        man["csaf"] = {"archivos": r["leidos"], "avisos_csaf": validos,
                       "saltados": r["leidos"] - validos + r["saltados"] + r["sobre_tamano"] + r["sobrantes"],
                       "aviso_mas_reciente": ultimo.isoformat() if ultimo else ""}
    man["archivos"] = [{"ruta": ruta, "bytes": len(b), "sha256": hashlib.sha256(b).hexdigest()}
                       for ruta, b in sorted(contenidos.items())]
    texto = json.dumps(man, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
    contenidos[MANIFIESTO] = texto.encode("utf-8")
    filas = [(ruta, hashlib.sha256(b).hexdigest()) for ruta, b in contenidos.items()]
    contenidos[SUMAS] = ent.lineas_sha256(filas).encode("utf-8")
    return contenidos, man


def _leer(ruta: Path):
    """-> (hashes reales {ruta: sha256}, funcion para leer un miembro). ErrorEntrega si no es legible."""
    if ruta.is_file():
        try:
            reales = ent._hashes_zip(ruta)
        except zipfile.BadZipFile:
            raise ent.ErrorEntrega(t("no es un ZIP valido"))

        def leer(nombre):
            with zipfile.ZipFile(ruta) as z:
                return z.read(nombre)
    elif ruta.is_dir():
        reales = ent._hashes_carpeta(ruta)

        def leer(nombre):
            return (ruta / nombre).read_bytes()
    else:
        raise ent.ErrorEntrega(t("no existe"))
    return reales, leer


def verificar(ruta) -> dict:
    """-> {"problemas": [...], "archivos": n, "manifiesto": dict, "sha256_manifiesto": str}.

    ErrorEntrega si no es un paquete legible (sin manifiestos, manifiesto mal formado, rutas inseguras)."""
    ruta = Path(ruta).expanduser()
    reales, leer = _leer(ruta)
    if SUMAS not in reales or MANIFIESTO not in reales:
        raise ent.ErrorEntrega(t("falta {a} o {b}: no es un paquete de avisos", a=SUMAS, b=MANIFIESTO))
    sumas = ent._leer_sumas(leer(SUMAS).decode("utf-8", "replace"))
    for r in sumas:
        if not ent._ruta_segura(r):
            raise ent.ErrorEntrega(t("{a} trae una ruta no permitida", a=SUMAS) + f": {r!r}")
    raw_man = leer(MANIFIESTO)
    try:
        man = json_entrada.cargar(raw_man.decode("utf-8"))
        if man["formato"] != FORMATO:
            raise KeyError("formato")
        decl = {a["ruta"]: a["sha256"] for a in man["archivos"]}
        if not isinstance(man.get("kev"), (dict, type(None))) or not isinstance(man.get("csaf"), (dict, type(None))):
            raise TypeError("fuentes")
    except (ValueError, KeyError, TypeError, UnicodeDecodeError):
        raise ent.ErrorEntrega(t("{m} no se puede leer o no tiene el formato {f}", m=MANIFIESTO, f=FORMATO))
    for r in decl:
        if not ent._ruta_segura(r):
            raise ent.ErrorEntrega(t("{a} trae una ruta no permitida", a=MANIFIESTO) + f": {r!r}")
    problemas = []
    for r in sorted(sumas):
        if r not in reales:
            problemas.append(f"{t('FALTANTE')}: {r}")
        elif reales[r] != sumas[r]:
            problemas.append(f"{t('MODIFICADO')}: {r}")
    for r in sorted(reales):
        if r not in sumas and r != SUMAS:
            problemas.append(f"{t('SOBRANTE')}: {r}")
    for r in sorted(decl):
        if sumas.get(r) != decl[r] and f"{t('MODIFICADO')}: {r}" not in problemas:
            problemas.append(f"{t('MODIFICADO')}: {r} ({MANIFIESTO})")
    if MANIFIESTO not in sumas:
        problemas.append(f"{t('FALTANTE')}: {MANIFIESTO} ({SUMAS})")
    return {"problemas": problemas, "archivos": len(sumas), "manifiesto": man,
            "sha256_manifiesto": hashlib.sha256(raw_man).hexdigest()}


def usar(ruta) -> dict:
    """Verifica la carpeta del paquete y devuelve {"avisos": ruta|None, "kev": ruta|None, "info": dict para el entorno}.

    SystemExit(2) con el motivo en stderr si no verifica o no es una carpeta."""
    p = Path(ruta).expanduser()
    if p.is_file():
        _fallar(t("--paquete-avisos espera una carpeta; descomprima el ZIP antes"))
    try:
        r = verificar(p)
    except ent.ErrorEntrega as e:
        _fallar(t("no se pudo verificar el paquete de avisos") + f": {e}")
    except OSError as e:
        _fallar(t("no se pudo leer el paquete de avisos") + f": {e}")
    if r["problemas"]:
        _fallar(t("el paquete de avisos no verifica") + ": " + "; ".join(r["problemas"][:MAX_PROBLEMAS]))
    man = r["manifiesto"]
    kev = man.get("kev")
    csaf = man.get("csaf")
    info = {"sha256": r["sha256_manifiesto"], "creado": str(man.get("creado") or ""),
            "version_kev": str(kev.get("catalogVersion") or "") if kev else "",
            "avisos_csaf": int(csaf.get("avisos_csaf") or 0) if csaf else 0, "verificado": True}
    return {"avisos": str(p / "csaf") if csaf else None,
            "kev": str(p / "kev" / kev["archivo"]) if kev else None, "info": info}


def _fallar(msg: str):
    print(f"[!] {msg}", file=sys.stderr)
    raise SystemExit(2)


def resolver(ap, args, perfil) -> None:
    """Valida --paquete-avisos y la clave de perfil avisos_solo_paquete; deja args.avisos_ics y args.kev listos.

    Se llama justo despues de aplicar el perfil, antes de leer o escribir nada. Sin la opcion ni la clave no hace nada."""
    pq = getattr(args, "paquete_avisos", None)
    directo = getattr(args, "avisos_ics", None) or getattr(args, "kev", None)
    if pq and directo:
        ap.error(t("--paquete-avisos no se combina con --avisos-ics ni --kev"))
    if directo and (perfil or {}).get("avisos_solo_paquete") is True:
        _fallar(t("el perfil exige un paquete verificado: use --paquete-avisos"))
    if not pq:
        return
    u = usar(pq)
    args.avisos_ics, args.kev = u["avisos"], u["kev"]
    args.paquete_avisos_info = u["info"]
