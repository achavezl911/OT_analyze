"""Localiza y envuelve tshark, capinfos y editcap."""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


WIRESHARK_DIRS = [
    # Windows
    r"C:\Program Files\Wireshark",
    r"C:\Program Files (x86)\Wireshark",
    # Linux
    "/usr/bin",
    "/usr/sbin",
    "/usr/local/bin",
    "/snap/bin",
    "/var/lib/flatpak/exports/bin",
    # macOS
    "/opt/homebrew/bin",
    "/usr/local/opt/wireshark/bin",
    "/Applications/Wireshark.app/Contents/MacOS",
]

INSTALL_HINT = {
    "linux": "instala el paquete 'tshark' (Debian/Ubuntu: sudo apt install tshark; "
             "RHEL/Rocky: sudo dnf install wireshark-cli)",
    "darwin": "instala Wireshark (brew install --cask wireshark)",
}.get(sys.platform, "instala Wireshark")


def find_tool(name: str, override: str | None = None) -> str:
    if override:
        p = Path(override)
        if p.is_dir():
            for cand in (p / name, p / f"{name}.exe"):
                if cand.exists():
                    return str(cand)
        elif p.exists():
            return str(p)
        sys.exit(f"[!] No encuentro {name} en {override}")
    found = shutil.which(name)
    if found:
        return found
    for d in WIRESHARK_DIRS:
        for cand in (Path(d) / name, Path(d) / f"{name}.exe"):
            if cand.exists():
                return str(cand)
    sys.exit(
        f"[!] No encuentro '{name}'. {INSTALL_HINT}, o pasa --tshark con la "
        f"ruta de la carpeta que lo contiene."
    )


class CapturaIlegible(Exception):
    """La captura no se pudo leer completa: corrupta, truncada, vacia o tshark termino con error."""


def run(cmd: list[str], timeout: int = 7200) -> tuple[int, str, str]:
    p = subprocess.run(
        cmd, capture_output=True, text=True, errors="replace", timeout=timeout
    )
    return p.returncode, p.stdout, p.stderr


def contar_duplicados(texto: str) -> int | None:
    """Extrae '<n> packets skipped' de la salida de editcap -d."""
    m = re.search(r"(\d+) packets? skipped", texto)
    return int(m.group(1)) if m else None


def _causa(stderr: str, path: Path) -> str:
    """Error de Wireshark en una linea, sin la ruta (puede llevar el nombre del cliente)."""
    lineas = [x.strip() for x in stderr.replace(str(path), path.name).splitlines()
              if x.strip() and "could be dangerous" not in x]
    return " / ".join(lineas)[:300] or "Wireshark termino con error sin mensaje"


class Tshark:
    def __init__(self, tshark: str, capinfos: str, editcap: str, probe_dir: Path):
        self.tshark = tshark
        self.capinfos_bin = capinfos
        self.editcap = editcap
        self.probe_dir = probe_dir
        self.probe: Path | None = None

    def make_probe(self, sample: Path) -> None:
        """Un archivo de 1 paquete para validar filtros rapido."""
        self.probe_dir.mkdir(parents=True, exist_ok=True)
        probe = self.probe_dir / "probe.pcapng"
        rc, _, _ = run(
            [self.editcap, "-r", str(sample), str(probe), "1-1"], timeout=300
        )
        self.probe = probe if rc == 0 and probe.exists() else None

    def valid_fields(self, fields: list[str]) -> list[str]:
        """Quita los campos que este tshark no conoce, leyendo su propio error."""
        if not self.probe:
            return fields
        fields = list(fields)
        for _ in range(12):
            cmd = [self.tshark, "-r", str(self.probe), "-T", "fields"]
            for f in fields:
                cmd += ["-e", f]
            rc, _, err = run(cmd, timeout=120)
            if rc == 0:
                return fields
            bad = re.findall(r"^\s*\t?([\w._-]+)\s*$", err, re.M)
            bad = [b for b in bad if b in fields]
            if not bad:
                # No logramos identificar el campo malo; devolvemos un minimo seguro.
                return [f for f in fields if f.startswith(("frame.", "eth.", "ip."))]
            fields = [f for f in fields if f not in bad]
        return fields

    def valid_filter(self, parts: list[str]) -> str:
        """Arma el filtro con las piezas que compilan en este tshark."""
        if not self.probe:
            return " || ".join(f"({p})" for p in parts)
        ok = []
        for p in parts:
            rc, _, _ = run(
                [self.tshark, "-r", str(self.probe), "-Y", p, "-c", "1", "-q"],
                timeout=60,
            )
            if rc == 0:
                ok.append(p)
        return " || ".join(f"({p})" for p in ok) if ok else "frame"

    def fields_pass(
        self, path: Path, fields: list[str], dfilter: str | None, limit: int
    ):
        cmd = [self.tshark, "-r", str(path), "-n", "-N", "m", "-T", "fields",
               "-E", "separator=\t", "-E", "occurrence=a", "-E", "aggregator=|"]
        for f in fields:
            cmd += ["-e", f]
        if dfilter:
            cmd += ["-Y", dfilter]
        if limit:
            cmd += ["-c", str(limit)]
        with tempfile.TemporaryFile("w+", errors="replace") as err:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=err,
                text=True, errors="replace", bufsize=1 << 20,
            )
            assert proc.stdout is not None
            for line in proc.stdout:
                yield line.rstrip("\n").split("\t")
            if proc.wait() != 0:
                err.seek(0)
                raise CapturaIlegible(_causa(err.read(), path))

    def capinfos(self, path: Path) -> dict:
        """Metadatos de la captura. CapturaIlegible si capinfos falla (corrupta, truncada) o no hay paquetes."""
        rc, out, err = run([self.capinfos_bin, "-M", str(path)], timeout=1800)
        info = {}
        for line in out.splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                info[k.strip()] = v.strip()
        if rc != 0:
            raise CapturaIlegible(_causa(err, path))
        if not re.fullmatch(r"[1-9]\d*", info.get("Number of packets", "")):
            raise CapturaIlegible("la captura no contiene paquetes")
        return info

    def duplicados(self, path: Path) -> int | None:
        """Paquetes duplicados (editcap -d, ventana de 5 paquetes); None si editcap falla. COR-02."""
        rc, out, err = run([self.editcap, "-d", str(path), os.devnull], timeout=1800)
        return contar_duplicados(out + "\n" + err) if rc == 0 else None

    def phs(self, path: Path) -> dict[str, int]:
        rc, out, err = run([self.tshark, "-r", str(path), "-q", "-z", "io,phs"], timeout=7200)
        if rc != 0:
            raise CapturaIlegible(_causa(err, path))
        protos: dict[str, int] = {}
        for line in out.splitlines():
            m = re.match(r"^(\s*)([\w.-]+)\s+frames:(\d+)\s+bytes:(\d+)", line)
            if m:
                protos[m.group(2)] = int(m.group(3))
        return protos
