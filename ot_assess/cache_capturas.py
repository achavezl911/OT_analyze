"""Cache de lectura de capturas (E6, D63): guarda el resultado de la extraccion de tshark por captura.

Formato: JSON comprimido con gzip, un archivo por captura. Nunca pickle ni marshal: cargar un archivo
manipulado no ejecuta codigo. El codificador etiqueta lo que JSON no tiene (set, Counter, tuple, Path,
dict con claves que no son str) y el decodificador reconstruye los mismos tipos.
"""
from __future__ import annotations

import collections
import gzip
import hashlib
import io
import json
import os
import sys
from pathlib import Path

from . import __version__, json_entrada
from .entorno import NO_DISPONIBLE, commit_corto, sha256_archivo, version_tshark
from .model import Capture

FORMATO = 1
LIMITE_BYTES = 2 << 30          # tope al descomprimir (un archivo manipulado no agota la memoria)
_ETIQUETA = "__t"
# Fuentes que definen la extraccion: si cambian, lo guardado ya no vale aunque la version sea la misma.
_FUENTES = ("flows.py", "fields.py", "tools.py", "model.py", "util.py", "cache_capturas.py",
           "cobertura_captura.py")


class NoSoportado(TypeError):
    """Un atributo de Capture tiene un tipo que el codificador no sabe guardar."""


def codificar(x):
    t = type(x)
    if x is None or t in (bool, int, float, str):
        return x
    if t is list:
        return [codificar(v) for v in x]
    if t is tuple:
        return {_ETIQUETA: "tuple", "v": [codificar(v) for v in x]}
    if t in (set, frozenset):
        elementos = sorted((codificar(v) for v in x), key=lambda v: json.dumps(v, sort_keys=True))
        return {_ETIQUETA: "set" if t is set else "frozenset", "v": elementos}
    if t is Path or isinstance(x, Path):
        return {_ETIQUETA: "path", "v": str(x)}
    if t is collections.Counter:
        return {_ETIQUETA: "counter", "v": [[codificar(k), codificar(v)] for k, v in x.items()]}
    if t is dict:
        if all(type(k) is str for k in x) and _ETIQUETA not in x:
            return {k: codificar(v) for k, v in x.items()}
        return {_ETIQUETA: "dict", "v": [[codificar(k), codificar(v)] for k, v in x.items()]}
    raise NoSoportado(f"tipo no soportado por la cache: {t.__name__}")


def decodificar(x):
    if isinstance(x, list):
        return [decodificar(v) for v in x]
    if not isinstance(x, dict):
        return x
    if _ETIQUETA not in x:
        return {k: decodificar(v) for k, v in x.items()}
    et, v = x[_ETIQUETA], x["v"]
    if et == "tuple":
        return tuple(decodificar(e) for e in v)
    if et == "set":
        return {decodificar(e) for e in v}
    if et == "frozenset":
        return frozenset(decodificar(e) for e in v)
    if et == "path":
        return Path(v)
    if et == "counter":
        return collections.Counter({decodificar(k): decodificar(n) for k, n in v})
    if et == "dict":
        return {decodificar(k): decodificar(n) for k, n in v}
    raise ValueError(f"etiqueta desconocida: {et}")


def capture_a_dict(cap: Capture) -> dict:
    return {k: codificar(v) for k, v in vars(cap).items()}


def capture_desde_dict(datos: dict, ruta: Path) -> Capture:
    cap = Capture(ruta)
    for k, v in datos.items():
        if k not in ("path", "name"):      # la ruta es la de ahora: la cache se indexa por contenido
            setattr(cap, k, decodificar(v))
    return cap


def huella_codigo() -> str:
    """SHA-256 de las fuentes que definen la extraccion (cubre un arbol de trabajo sin commit)."""
    raiz = Path(__file__).resolve().parent
    archivos = [raiz / n for n in _FUENTES] + sorted((raiz / "detail").glob("*.py"))
    h = hashlib.sha256()
    for p in archivos:
        h.update(p.name.encode())
        try:
            h.update(p.read_bytes())
        except OSError:
            h.update(b"?")
    return h.hexdigest()


def _clave_texto(clave: dict) -> str:
    return json.dumps(clave, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


class CacheCapturas:
    """Carpeta de cache. Los archivos solo se crean dentro de ella, con permisos 600."""

    def __init__(self, carpeta, run, tshark_bin: str, flow_fields, detail_fields, detail_filter,
                 args, renovar: bool = False):
        self.carpeta = Path(carpeta)
        self.renovar = renovar
        self.aciertos = 0
        self.sha: dict = {}                 # captura -> sha256 (lo reutiliza entorno.py)
        self.precargadas: dict = {}
        self.base = {
            "formato": FORMATO,
            "ot_assess": __version__,
            "commit": commit_corto(),
            "codigo": huella_codigo(),
            "tshark": version_tshark(run, tshark_bin),
            "max_packets": int(args.max_packets),
            "no_detail": bool(args.no_detail),
            "flow_fields": list(flow_fields),
            "detail_fields": list(detail_fields),
            "detail_filter": detail_filter,
        }
        self.carpeta.mkdir(parents=True, exist_ok=True)

    def _clave(self, f: Path) -> str:
        if f not in self.sha:
            self.sha[f] = sha256_archivo(f)
        return _clave_texto(dict(self.base, pcap=self.sha[f]))

    def _archivo(self, clave: str) -> Path:
        return self.carpeta / (hashlib.sha256(clave.encode()).hexdigest() + ".json.gz")

    def cargar(self, f: Path):
        """Captura guardada o None (con aviso si el archivo existe pero no sirve). Nunca lanza."""
        if self.renovar:
            return None
        clave = self._clave(f)
        if self.sha[f] == NO_DISPONIBLE:
            return None
        arch = self._archivo(clave)
        if not arch.is_file():
            return None
        try:
            with gzip.open(arch, "rb") as fh:
                crudo = fh.read(LIMITE_BYTES + 1)
            if len(crudo) > LIMITE_BYTES:
                raise ValueError("archivo demasiado grande")
            doc = json_entrada.cargar(crudo.decode("utf-8"))
            if doc.get("formato") != FORMATO:
                raise ValueError(f"version de formato desconocida ({doc.get('formato')})")
            if doc.get("clave") != clave:
                raise ValueError("la clave guardada no coincide")
            cap = capture_desde_dict(doc["captura"], f)
        except Exception as e:  # noqa: BLE001 - cualquier fallo de lectura: se relee la captura
            print(f"[!] cache: {arch.name} no sirve ({type(e).__name__}: {e}); se relee {f.name}",
                  file=sys.stderr)
            return None
        self.precargadas[f] = cap
        return cap

    def tomar(self, f: Path):
        cap = self.precargadas.pop(f, None)
        if cap is not None:
            self.aciertos += 1
        return cap

    def guardar(self, f: Path, cap: Capture) -> None:
        """Escribe la cache de una captura legible. Un fallo se avisa y no detiene el analisis."""
        try:
            clave = self._clave(f)
            if self.sha[f] == NO_DISPONIBLE:
                return
            doc = {"formato": FORMATO, "clave": clave, "captura": capture_a_dict(cap)}
            crudo = json.dumps(doc, ensure_ascii=True, allow_nan=True).encode("ascii")
            buf = io.BytesIO()
            with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
                gz.write(crudo)
            arch = self._archivo(clave)
            tmp = arch.with_name(arch.name + f".{os.getpid()}.tmp")
            fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(buf.getvalue())
            os.chmod(tmp, 0o600)
            os.replace(tmp, arch)
        except Exception as e:  # noqa: BLE001 - la cache es una optimizacion
            print(f"[!] cache: no se guardo {f.name} ({type(e).__name__}: {e})", file=sys.stderr)
