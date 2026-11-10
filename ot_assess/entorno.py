"""Entorno de analisis: con que se hizo el analisis (custodia y reproducibilidad, COR-03)."""
from __future__ import annotations

import hashlib
from pathlib import Path

from . import __version__
from .i18n import t

NO_DISPONIBLE = "no disponible"


def commit_corto(raiz: Path | None = None) -> str:
    """Commit del repositorio leyendo .git a mano (sin git ni subprocess). Nunca lanza."""
    try:
        git = (raiz or Path(__file__).resolve().parents[1]) / ".git"
        head = (git / "HEAD").read_text(encoding="utf-8").strip()
        if head.startswith("ref:"):
            ref = head[4:].strip()
            suelta = git / ref
            if suelta.is_file():
                head = suelta.read_text(encoding="utf-8").strip()
            else:
                head = ""
                for linea in (git / "packed-refs").read_text(encoding="utf-8").splitlines():
                    partes = linea.split()
                    if len(partes) == 2 and partes[1] == ref:
                        head = partes[0]
        int(head, 16)
        return head[:12] if len(head) >= 12 else NO_DISPONIBLE
    except Exception:  # noqa: BLE001 - el entorno es informativo: cualquier fallo es "no disponible"
        return NO_DISPONIBLE


def sha256_archivo(path: Path) -> str:
    """SHA-256 leyendo por bloques (hay capturas de GB)."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for bloque in iter(lambda: fh.read(1 << 20), b""):
                h.update(bloque)
    except OSError:
        return NO_DISPONIBLE
    return h.hexdigest()


def version_tshark(run, tshark_bin: str) -> str:
    """Primera linea de `tshark --version`; sin la ruta del binario."""
    try:
        rc, out, _ = run([tshark_bin, "--version"], timeout=30)
        lineas = out.strip().splitlines()
        return lineas[0].strip() if rc == 0 and lineas else NO_DISPONIBLE
    except Exception:  # noqa: BLE001 - el entorno es informativo: cualquier fallo es "no disponible"
        return NO_DISPONIBLE


def construir(run, tshark_bin: str, caps: list, args, ignorados: list[str]) -> dict:
    ruta = getattr(args, "perfil", None)
    reglas = getattr(args, "reglas_firewall", None)
    vul = getattr(args, "vulnerabilidades", None)
    ale = getattr(args, "alertas", None)
    cat = getattr(args, "catalogo_vulnerabilidades", None)
    out = {
        "perfil": ({"archivo": Path(ruta).name, "sha256": sha256_archivo(Path(ruta))}
                   if ruta else None),
        "reglas_firewall": ({"archivo": Path(reglas).name, "sha256": sha256_archivo(Path(reglas))}
                            if reglas else None),
        "vulnerabilidades": ({"archivo": Path(vul).name, "sha256": sha256_archivo(Path(vul))}
                             if vul else None),
        "alertas": ({"archivo": Path(ale).name, "sha256": sha256_archivo(Path(ale))}
                    if ale else None),
        "kev": getattr(args, "kev_entrada", None),
        "tor_relays": getattr(args, "tor_entrada", None),
        "avisos_ics": getattr(args, "avisos_entrada", None),
        "catalogo_vulnerabilidades": ({"archivo": Path(cat).name, "sha256": sha256_archivo(Path(cat))}
                                      if cat else None),
        "ot_assess": __version__,
        "commit": commit_corto(),
        "tshark": version_tshark(run, tshark_bin),
        "estandares": str(args.estandar),
        "max_packets": int(args.max_packets),
        "campos_ignorados": sorted(ignorados),
        "capturas": [{"archivo": c.name,
                      "sha256": getattr(args, "sha_capturas", {}).get(c.path) or sha256_archivo(c.path),
                      "legible": not c.error, "muestreada": bool(c.sampled)} for c in caps],
    }
    if getattr(args, "custodia", None):      # sin --custodia la salida no cambia en nada (K1)
        from . import custodia
        out["custodia"] = custodia.estado_capturas(args.custodia, [(c["archivo"], c["sha256"]) for c in out["capturas"]])
    return out


def _linea_custodia(e: dict) -> list[tuple[str, str]]:
    c = e.get("custodia")
    if not c:
        return []
    n = sum(1 for x in c["capturas"] if x["estado"] == "registrada")
    cad = t("integra") if c["cadena"] == "integra" else t("rota (linea {n})", n="".join(d for d in c["cadena"] if d.isdigit()))
    return [(t("Cadena de custodia"),
             t("{n} de {m} capturas registradas (huella {h}; cadena {c})", n=n, m=len(c["capturas"]), h=c["huella"], c=cad))]


def lineas(e: dict) -> list[tuple[str, str]]:
    """(etiqueta, valor) en texto plano, ASCII, para HTML y Markdown."""
    mp = e["max_packets"]
    p = e.get("perfil")
    fw = e.get("reglas_firewall")
    vu = e.get("vulnerabilidades")
    al = e.get("alertas")
    kev, av = e.get("kev"), e.get("avisos_ics")
    tor = e.get("tor_relays")
    cat = e.get("catalogo_vulnerabilidades")
    cisa = [*([(t("Catalogo de vulnerabilidades del analista importado"), f"{cat['archivo']} ({cat['sha256']})")]
              if cat else []),
            *([(t("KEV de CISA importado"), f"{kev['archivo']} ({kev['sha256']})")] if kev else []),
            *([(t("Lista de relays Tor importada"), f"{tor['archivo']} ({tor['sha256']})")] if tor else []),
            *([(t("Avisos ICS de CISA importados"),
                t("{a} ({n} JSON leidos, {h})", a=av["archivo"], n=av["json_leidos"], h=av["sha256"]))]
              if av else [])]
    if e.get("modo") == "exportacion":     # sin tshark ni muestreo: solo lo que aplica a exportaciones
        return [
            (t("Perfil del proyecto"), f"{p['archivo']} ({p['sha256']})" if p else t("ninguno")),
            *([(t("Vulnerabilidades importadas"), f"{vu['archivo']} ({vu['sha256']})")] if vu else []),
            *([(t("Alertas importadas"), f"{al['archivo']} ({al['sha256']})")] if al else []),
            *cisa,
            (t("Version de ot_assess"), t("{v} (commit {c})", v=e["ot_assess"], c=e["commit"])),
            (t("Marcos (--estandar)"), e["estandares"]),
        ]
    return [
        (t("Perfil del proyecto"), f"{p['archivo']} ({p['sha256']})" if p else t("ninguno")),
        (t("Reglas de firewall"), f"{fw['archivo']} ({fw['sha256']})" if fw else t("ninguna")),
        *([(t("Vulnerabilidades importadas"), f"{vu['archivo']} ({vu['sha256']})")] if vu else []),
        *([(t("Alertas importadas"), f"{al['archivo']} ({al['sha256']})")] if al else []),
        *cisa,
        (t("Version de ot_assess"), t("{v} (commit {c})", v=e["ot_assess"], c=e["commit"])),
        (t("Version de tshark"), t(e["tshark"]) if e["tshark"] == NO_DISPONIBLE else e["tshark"]),
        (t("Marcos (--estandar)"), e["estandares"]),
        *_linea_custodia(e),
        (t("Muestreo (--max-packets)"),
         t("{n} paquetes por captura", n=f"{mp:,}") if mp else t("0 (sin muestreo)")),
        (t("Campos ignorados por este tshark"),
         ", ".join(e["campos_ignorados"]) or t("ninguno")),
    ]
