"""Paquete de entrega con manifiesto y verificacion (B6, D64).

Arma la carpeta (o ZIP) que se entrega al cliente desde una o mas carpetas de salida de la herramienta, con
`manifiesto.json` (version, entradas por hash, salidas por hash) y `manifiesto.sha256` (formato sha256sum).
Evidencia tecnica de integridad: no firma ni cifra, y no es dictamen de cumplimiento.
"""
from __future__ import annotations

import datetime
import fnmatch
import gzip
import hashlib
import json
import os
import re
import zipfile
from pathlib import Path, PurePosixPath

from . import __version__, json_entrada
from .entorno import commit_corto

FORMATO = "ot_assess.entrega/1"
MANIFIESTO = "manifiesto.json"
SUMAS = "manifiesto.sha256"
LEEME = "LEEME_ENTREGA.txt"
RESERVADOS = {MANIFIESTO, SUMAS, LEEME}
EXTENSIONES_TEXTO = {".json", ".md", ".csv", ".html", ".txt", ".xml", ".drawio", ".svg", ".yaml", ".yml"}
LIMITE_TEXTO = 64 << 20
FECHA_ZIP_MIN = (1980, 1, 1, 0, 0, 0)

TEXTO_LEEME = """Paquete de entrega (ot_assess)

Que es: salidas de un analisis tecnico pasivo, con un manifiesto (manifiesto.json) que registra la version de
la herramienta que las produjo, los archivos de entrada (solo nombre, tamano y SHA-256; las entradas originales
no se incluyen) y el SHA-256 de cada archivo de este paquete.

Como verificar que nada cambio:
  sha256sum -c manifiesto.sha256          (dentro de esta carpeta)
  python ot_pcap_assess.py empaquetar --verificar RUTA_DE_ESTE_PAQUETE

Nota: es evidencia tecnica de integridad y procedencia. No firma el contenido (quien modifique archivos y
manifiesto a la vez no se detecta sin una firma o un hash guardado aparte) y no es dictamen de cumplimiento.
"""


class ErrorEntrega(Exception):
    pass


# ---- exclusiones --------------------------------------------------------------------------------------

def _inicio_gzip(ruta: Path, n: int = 96) -> bytes:
    try:
        with gzip.open(ruta, "rb") as fh:
            return fh.read(n)
    except (OSError, EOFError, ValueError):
        return b""


def _es_cache(ruta: Path) -> bool:
    """Archivo de la cache de E6: .json.gz cuyo contenido empieza con la cabecera de cache_capturas."""
    if not ruta.name.endswith(".json.gz"):
        return False
    return re.match(rb'\{\s*"formato"\s*:\s*\d+\s*,\s*"clave"\s*:', _inicio_gzip(ruta)) is not None


def _es_mapa_anonimizacion(ruta: Path) -> bool:
    """Mapa de anonimizar.py: objeto JSON con clave hex y los campos de correspondencia real -> seudonimo."""
    try:
        if ruta.stat().st_size > LIMITE_TEXTO:
            return False
        d = json_entrada.cargar(ruta.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        return False
    if not isinstance(d, dict):
        return False
    campos = ("ips", "macs", "nombres", "terminos", "carga")
    return sum(1 for c in campos if isinstance(d.get(c), dict)) >= 3 and isinstance(d.get("clave"), str)


def _es_lista_terminos(ruta: Path, coinciden: set) -> bool:
    """Lista de --terminos (un termino por linea): se reconoce porque el mapa de la misma carpeta la contiene,
    o por nombre con 'termino'. Se compara contra los terminos reales de los mapas hallados."""
    if "termino" in ruta.name.lower() and ruta.suffix.lower() in ("", ".txt", ".lst", ".list"):
        return True
    if ruta.suffix.lower() not in ("", ".txt", ".lst", ".list") or not coinciden:
        return False
    try:
        if ruta.stat().st_size > (1 << 20):
            return False
        lineas = {ln.strip().lower() for ln in ruta.read_text(encoding="utf-8-sig").splitlines()
                  if ln.strip() and not ln.strip().startswith("#")}
    except (OSError, ValueError):
        return False
    return bool(lineas) and lineas <= coinciden


def _terminos_de_mapas(carpeta: Path) -> set:
    out: set = set()
    for dirpath, dirnames, nombres in os.walk(carpeta):
        dirnames[:] = [d for d in dirnames if not os.path.islink(os.path.join(dirpath, d))]
        for n in nombres:
            p = Path(dirpath) / n
            if p.suffix.lower() == ".json" and not p.is_symlink() and _es_mapa_anonimizacion(p):
                d = json_entrada.cargar(p.read_text(encoding="utf-8-sig"))
                out.update(str(k).lower() for k in d.get("terminos", {}))
    return out


# ---- recorrido ----------------------------------------------------------------------------------------

def recopilar(carpeta: Path, excluir: list, cache_dir: Path | None = None):
    """-> (archivos [(ruta, relativa posix)], omitidos [(relativa, motivo)])."""
    carpeta = Path(carpeta)
    terminos = _terminos_de_mapas(carpeta)
    cache_abs = cache_dir.resolve() if cache_dir else None
    archivos: list = []
    omitidos: list = []
    for dirpath, dirnames, nombres in os.walk(carpeta):
        base = Path(dirpath)
        rel_dir = base.relative_to(carpeta)
        quedan = []
        for d in sorted(dirnames):
            p = base / d
            rel = (rel_dir / d).as_posix()
            if p.is_symlink():
                omitidos.append((rel, "enlace simbolico (no se sigue)"))
            elif d.startswith("."):
                omitidos.append((rel + "/", "carpeta oculta"))
            elif d == "crudo":
                omitidos.append((rel + "/", "volcados crudos de API"))
            elif cache_abs is not None and p.resolve() == cache_abs:
                omitidos.append((rel + "/", "carpeta de cache (--cache)"))
            else:
                quedan.append(d)
        dirnames[:] = quedan
        for n in sorted(nombres):
            p = base / n
            rel = (rel_dir / n).as_posix() if str(rel_dir) != "." else n
            motivo = None
            if p.is_symlink():
                motivo = "enlace simbolico (no se sigue)"
            elif not p.is_file():
                motivo = "no es un archivo regular"
            elif n.startswith("."):
                motivo = "archivo oculto"
            elif n.lower().endswith(".log"):
                motivo = "registro (.log)"
            elif _es_cache(p):
                motivo = "cache de lectura de capturas (E6)"
            elif p.suffix.lower() == ".json" and _es_mapa_anonimizacion(p):
                motivo = "mapa de anonimizacion (permite revertirla)"
            elif _es_lista_terminos(p, terminos):
                motivo = "lista de terminos de anonimizacion"
            elif any(fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(n, pat) for pat in excluir):
                motivo = "--excluir"
            if motivo:
                omitidos.append((rel, motivo))
            else:
                archivos.append((p, rel))
    return archivos, omitidos


# ---- hash, limpieza de rutas ---------------------------------------------------------------------------

def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def sha256_flujo(fh) -> tuple:
    h = hashlib.sha256()
    n = 0
    for bloque in iter(lambda: fh.read(1 << 20), b""):
        h.update(bloque)
        n += len(bloque)
    return h.hexdigest(), n


def _variantes_ruta(carpeta: Path) -> list:
    """Rutas absolutas de la carpeta de origen (tal cual, resuelta, con barras de Windows), la mas larga primero."""
    vs = {str(carpeta), str(carpeta.resolve()), str(carpeta.absolute())}
    vs |= {v.replace("\\", "/") for v in vs} | {v.replace("/", "\\") for v in vs}
    return sorted((v for v in vs if len(v) > 1), key=len, reverse=True)


def _limpiar_json_comparacion(texto: str, extra: list) -> str:
    try:
        d = json_entrada.cargar(texto)
    except ValueError:
        return texto
    if isinstance(d, dict) and {"antes", "despues", "umbral_volumen"} <= set(d):
        for k in ("antes", "despues"):
            if isinstance(d.get(k), str):
                d[k] = Path(d[k]).name
                extra.append(d[k])
        return json.dumps(d, indent=2, ensure_ascii=False)
    return texto


def _limpiar_json_resultado(texto: str) -> str:
    """resultado.json guarda la ruta absoluta de cada pcap en 'archivo': se reduce al nombre."""
    try:
        d = json_entrada.cargar(texto)
    except ValueError:
        return texto
    cambio = []

    def visita(x):
        if isinstance(x, dict):
            for clave in ("archivo", "File name"):      # 'File name' es la salida de capinfos
                a = x.get(clave)
                if isinstance(a, str) and (a.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:", a)):
                    x[clave] = Path(a.replace("\\", "/")).name
                    cambio.append(1)
            for v in x.values():
                visita(v)
        elif isinstance(x, list):
            for v in x:
                visita(v)
    visita(d)
    return json.dumps(d, indent=2, ensure_ascii=False) if cambio else texto


def contenido_limpio(ruta: Path, carpeta: Path, avisos: list, rel: str) -> bytes:
    """Bytes a copiar. Los textos pierden la ruta absoluta de la carpeta de origen (sustituida por su nombre)."""
    datos = ruta.read_bytes()
    if ruta.suffix.lower() not in EXTENSIONES_TEXTO or len(datos) > LIMITE_TEXTO:
        return datos
    try:
        texto = datos.decode("utf-8")
    except UnicodeDecodeError:
        return datos
    original = texto
    if ruta.name == "comparacion.json":
        texto = _limpiar_json_comparacion(texto, [])
    elif ruta.name == "resultado.json":
        texto = _limpiar_json_resultado(texto)
    for v in _variantes_ruta(carpeta):
        if v in texto:
            texto = texto.replace(v, carpeta.name)
    if texto != original:
        avisos.append(f"{rel}: se quito la ruta absoluta del equipo")
        return texto.encode("utf-8")
    return datos


def _texto_con_ruta(datos: bytes, rutas: list) -> bool:
    try:
        t = datos.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return any(v in t for v in rutas)


# ---- manifiesto ---------------------------------------------------------------------------------------

def _lee_json(p: Path) -> dict:
    try:
        d = json_entrada.cargar(p.read_text(encoding="utf-8"))
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _entradas(entorno: dict) -> list:
    """Archivos de entrada que registro entorno.py: solo nombre, tamano (si se conocia) y sha256."""
    out = []
    vistos = set()

    def agregar(e, rol):
        if not isinstance(e, dict) or not e.get("archivo"):
            return
        nombre = Path(str(e["archivo"]).replace("\\", "/")).name
        fila = {"rol": rol, "archivo": nombre, "sha256": str(e.get("sha256") or "")}
        if isinstance(e.get("tamano"), int):
            fila["tamano"] = e["tamano"]
        clave = (rol, nombre, fila["sha256"])
        if clave not in vistos:
            vistos.add(clave)
            out.append(fila)
    for rol in ("perfil", "reglas_firewall", "vulnerabilidades", "alertas", "kev", "tor_relays", "avisos_ics",
                "catalogo_vulnerabilidades"):
        agregar(entorno.get(rol), rol)
    for e in entorno.get("capturas") or []:
        agregar(e, "captura")
    for e in entorno.get("entradas") or []:
        agregar(e, "exportacion")
    return out


def _meta_carpeta(carpeta: Path) -> dict:
    res = _lee_json(carpeta / "resultado.json")
    cmpj = _lee_json(carpeta / "comparacion.json")
    entorno = res.get("entorno") if isinstance(res.get("entorno"), dict) else {}
    perfil = res.get("perfil") if isinstance(res.get("perfil"), dict) else {}
    if cmpj:
        tipo = "comparacion"
        meta = (cmpj.get("meta") or {}).get("despues") or {}
        version = str(meta.get("version") or "")
        cliente, sitio = str(meta.get("cliente") or ""), str(meta.get("sitio") or "")
    elif res:
        tipo = "diagrama" if entorno.get("modo") == "exportacion" else "capturas"
        version = str(entorno.get("ot_assess") or "")
        cliente, sitio = str(perfil.get("cliente") or ""), str(perfil.get("sitio") or "")
    elif (carpeta / "solicitud_cambio.md").is_file() or any(carpeta.glob("solicitud_cambio*")):
        tipo, version, cliente, sitio = "solicitud-cambio", "", "", ""
    elif (carpeta / "politica_propuesta.csv").is_file():
        tipo, version, cliente, sitio = "politica", "", "", ""
    else:
        tipo, version, cliente, sitio = "desconocido", "", "", ""
    return {"tipo": tipo, "version": version, "cliente": cliente, "sitio": sitio,
            "entradas": _entradas(entorno)}


def nombre_unico(nombre: str, usados: set) -> str:
    base = nombre or "salida"
    cand, n = base, 2
    while cand in usados:
        cand = f"{base}_{n}"
        n += 1
    usados.add(cand)
    return cand


def ahora_utc() -> str:
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def lineas_sha256(filas: list) -> str:
    """filas = [(ruta, sha256)] -> texto de sha256sum, ordenado por ruta."""
    return "".join(f"{h}  {r}\n" for r, h in sorted(filas))


def construir(carpetas: list, excluir: list, titulo: str, fecha: str, cache_dir: Path | None = None):
    """-> (contenidos {ruta: bytes}, manifiesto dict, omitidos [(carpeta, relativa, motivo)], avisos).

    Todo se arma en memoria con rutas relativas; escribir() lo baja a disco o a ZIP."""
    contenidos: dict = {}
    carp_man: list = []
    omitidos: list = []
    avisos: list = []
    usados: set = set()
    rutas_origen: list = []
    clientes: set = set()
    for c in carpetas:
        c = Path(c).expanduser()
        if not c.is_dir():
            raise ErrorEntrega(f"'{c}' no es una carpeta de salida.")
        sub = nombre_unico(c.name, usados)
        archivos, omit = recopilar(c, excluir, cache_dir)
        omitidos.extend((sub, r, m) for r, m in omit)
        for r, m in omit:
            if "enlace simbolico" in m:
                avisos.append(f"{sub}/{r}: {m}")
        rutas_origen.extend(_variantes_ruta(c))
        salidas = []
        for ruta, rel in archivos:
            destino = f"{sub}/{rel}"
            if destino in RESERVADOS:
                continue
            datos = contenido_limpio(ruta, c, avisos, destino)
            contenidos[destino] = datos
            salidas.append({"ruta": destino, "tamano": len(datos), "sha256": sha256_bytes(datos)})
        meta = _meta_carpeta(c)
        if meta["cliente"] or meta["sitio"]:
            clientes.add((meta["cliente"], meta["sitio"]))
        carp_man.append({"carpeta": sub, "tipo": meta["tipo"], "version_herramienta": meta["version"],
                         "entradas": meta["entradas"], "salidas": sorted(salidas, key=lambda s: s["ruta"])})
    for dest, datos in contenidos.items():
        if _texto_con_ruta(datos, rutas_origen):
            raise ErrorEntrega(f"{dest}: contiene una ruta absoluta del equipo y no se pudo limpiar.")
    cl = sorted(clientes)
    manifiesto = {
        "formato": FORMATO,
        "herramienta": {"nombre": "ot_assess", "version": __version__, "commit": commit_corto()},
        "empaquetado_utc": fecha,
        "titulo": titulo,
        "cliente": cl[0][0] if len(cl) == 1 else "",
        "sitio": cl[0][1] if len(cl) == 1 else "",
        "carpetas": carp_man,
    }
    if len(cl) > 1:
        avisos.append("las carpetas traen clientes o sitios distintos: el manifiesto no declara uno")
    mj = (json.dumps(manifiesto, indent=2, ensure_ascii=False, sort_keys=False) + "\n").encode("utf-8")
    contenidos[LEEME] = TEXTO_LEEME.encode("utf-8")
    contenidos[MANIFIESTO] = mj
    contenidos[SUMAS] = lineas_sha256([(r, sha256_bytes(d)) for r, d in contenidos.items()
                                       if r != SUMAS]).encode("utf-8")
    return contenidos, manifiesto, omitidos, avisos


# ---- escritura -----------------------------------------------------------------------------------------

def _fecha_zip(fecha: str) -> tuple:
    try:
        d = datetime.datetime.strptime(fecha, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return FECHA_ZIP_MIN
    t = (d.year, d.month, d.day, d.hour, d.minute, d.second - d.second % 2)
    return t + (0,) if t[0] >= 1980 else FECHA_ZIP_MIN


def escribir_carpeta(destino: Path, contenidos: dict) -> None:
    destino = Path(destino)
    if destino.exists() and (not destino.is_dir() or any(destino.iterdir())):
        raise ErrorEntrega(f"'{destino}' ya existe y no esta vacia: elige otra carpeta de entrega.")
    destino.mkdir(parents=True, exist_ok=True)
    for ruta in sorted(contenidos):
        p = destino / ruta
        p.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o666)
        with os.fdopen(fd, "wb") as fh:
            fh.write(contenidos[ruta])


def escribir_zip(destino: Path, contenidos: dict, fecha: str) -> None:
    destino = Path(destino)
    if destino.exists():
        raise ErrorEntrega(f"'{destino}' ya existe: elige otro nombre de ZIP.")
    destino.parent.mkdir(parents=True, exist_ok=True)
    fz = _fecha_zip(fecha)
    fd = os.open(str(destino), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o666)
    with os.fdopen(fd, "wb") as fh, zipfile.ZipFile(fh, "w", zipfile.ZIP_DEFLATED) as z:
        for ruta in sorted(contenidos):
            zi = zipfile.ZipInfo(ruta, date_time=fz)
            zi.compress_type = zipfile.ZIP_DEFLATED
            zi.external_attr = 0o600 << 16
            zi.create_system = 3
            z.writestr(zi, contenidos[ruta])


# ---- verificacion --------------------------------------------------------------------------------------

def _ruta_segura(nombre: str) -> bool:
    if not nombre or nombre.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:", nombre) or "\\" in nombre:
        return False
    return ".." not in PurePosixPath(nombre).parts


def _hashes_zip(ruta: Path) -> dict:
    out: dict = {}
    with zipfile.ZipFile(ruta) as z:
        for zi in z.infolist():
            if not _ruta_segura(zi.filename):
                raise ErrorEntrega(f"el ZIP trae un miembro con ruta no permitida: {zi.filename!r}")
        for zi in z.infolist():
            if zi.is_dir():
                continue
            if zi.filename in out:
                raise ErrorEntrega(f"el ZIP repite el miembro {zi.filename!r}")
            with z.open(zi) as fh:
                out[zi.filename] = sha256_flujo(fh)[0]
    return out


def _hashes_carpeta(ruta: Path) -> dict:
    out: dict = {}
    for dirpath, dirnames, nombres in os.walk(ruta):
        for n in nombres:
            p = Path(dirpath) / n
            rel = p.relative_to(ruta).as_posix()
            if p.is_symlink() or not p.is_file():
                out[rel] = "(no es un archivo regular)"
                continue
            with open(p, "rb") as fh:
                out[rel] = sha256_flujo(fh)[0]
    return out


def _leer_sumas(texto: str) -> dict:
    out: dict = {}
    for ln in texto.splitlines():
        if not ln.strip():
            continue
        m = re.match(r"^([0-9a-f]{64})  (.+)$", ln)
        if not m:
            raise ErrorEntrega(f"{SUMAS}: linea mal formada: {ln[:60]!r}")
        out[m.group(2)] = m.group(1)
    return out


def verificar(ruta) -> dict:
    """-> {"modificados": [...], "faltantes": [...], "sobrantes": [...]}. Lanza ErrorEntrega si no es verificable."""
    ruta = Path(ruta).expanduser()
    if ruta.is_file():
        try:
            reales = _hashes_zip(ruta)
        except zipfile.BadZipFile:
            raise ErrorEntrega(f"'{ruta}' no es un ZIP valido.")
    elif ruta.is_dir():
        reales = _hashes_carpeta(ruta)
    else:
        raise ErrorEntrega(f"'{ruta}' no existe.")
    if SUMAS not in reales or MANIFIESTO not in reales:
        raise ErrorEntrega(f"falta {SUMAS} o {MANIFIESTO}: no es un paquete de entrega.")
    if ruta.is_file():
        with zipfile.ZipFile(ruta) as z:
            sumas_txt = z.read(SUMAS).decode("utf-8", "replace")
            man_txt = z.read(MANIFIESTO).decode("utf-8", "replace")
    else:
        sumas_txt = (ruta / SUMAS).read_text(encoding="utf-8", errors="replace")
        man_txt = (ruta / MANIFIESTO).read_text(encoding="utf-8", errors="replace")
    sumas = _leer_sumas(sumas_txt)
    for r in sumas:
        if not _ruta_segura(r):
            raise ErrorEntrega(f"{SUMAS} trae una ruta no permitida: {r!r}")
    esperados = dict(sumas)
    # el manifiesto debe describir los mismos hashes que manifiesto.sha256 (no se pueden editar por separado)
    try:
        man = json_entrada.cargar(man_txt)
        decl = {s["ruta"]: s["sha256"] for c in man["carpetas"] for s in c["salidas"]}
    except (ValueError, KeyError, TypeError):
        raise ErrorEntrega(f"{MANIFIESTO} no se puede leer o no tiene el formato {FORMATO}.")
    modificados = sorted(r for r in esperados if r in reales and reales[r] != esperados[r])
    faltantes = sorted(r for r in esperados if r not in reales)
    sobrantes = sorted(r for r in reales if r not in esperados and r != SUMAS)
    for r, h in decl.items():
        if esperados.get(r) != h and r not in modificados and r in esperados:
            modificados.append(r)
        elif r not in esperados and r not in faltantes:
            faltantes.append(r)
    return {"modificados": sorted(set(modificados)), "faltantes": sorted(set(faltantes)),
            "sobrantes": sobrantes, "archivos": len(esperados)}
