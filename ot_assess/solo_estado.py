"""ESTADO1 (D140): salidas de solo estado y archivo interno de candidatos a hallazgo.

Con la clave de perfil `solo_estado` ({} vale) arma, al final de la corrida y releyendo los CSV ya escritos, una copia
de las tablas de estado (inventario, topologia, flujos, segmentacion) sin las columnas de juicio, en una subcarpeta, y
un archivo interno `candidatos_hallazgo.csv` con una fila por hallazgo de la corrida para la revision del analista.
No quita ni cambia ninguna salida completa. Sin la clave no hace nada.
"""
from __future__ import annotations

import csv
import re
from pathlib import Path

from . import entregables as _en
from . import manifiesto as _mf
from . import secretos as _sec
from .catalog import SEV_ORDER
from .i18n import t
from .report.common import escritor_csv
from .report.xlsx import escribir_xlsx
from .riesgo import id_hallazgo

CLAVE = "solo_estado"
CARPETA = "estado"
ARCHIVO_XLSX = "estado.xlsx"
ARCHIVO_CANDIDATOS = "candidatos_hallazgo.csv"
MAX_SALIDAS = 50
MAX_TEXTO = 100

SALIDAS = tuple(n + ".csv" for n in (
    "inventario", "inventario_normalizado", "inventario_procedencia", "activos", "comunicaciones", "flujos",
    "top_conductos", "top_equipos", "mezcla_protocolos", "linea_base_trafico", "periodicidad", "dns_registros",
    "dns_servidores", "dns_resoluciones", "direccionamiento_ip", "zonas", "conductos_zcr", "cobertura_captura",
    "cobertura_zonas", "switch_puertos", "switch_vlans", "switch_span", "firewall_interfaces", "firewall_rutas",
    "firewall_matriz", "firewall_reglas", "firewall_nat", "registro_red", "manifiesto", "plan_captura", "salud_red",
    "tcp_conductos"))
JUICIO = ("severidad", "riesgo", "recomendacion", "propuesta", "brechas", "sl_t", "origen_sl_t", "marcas",
          "etiquetas", "avisos", "observaciones", "ids_hallazgo", "hallazgos", "playbook", "playbooks", "prioridad",
          "decision", "regla_sugerida", "quick_win")
PREFIJOS_JUICIO = ("criticidad", "riesgo")

COLUMNAS_CAND = ["id_hallazgo", "categoria", "titulo", "severidad", "fuente", "confianza", "evidencia", "activos",
                 "dataset_id", "entregable_destino", "estado_revision", "revisado_por", "fecha", "comentario"]

C_TRAFICO, C_CONFIG = "observado en trafico", "segun configuracion"
C_PLATAFORMA, C_VERSION, C_DERIVADO = "segun plataforma", "inferido por version", "derivado"
CONFIANZAS = (C_TRAFICO, C_CONFIG, C_PLATAFORMA, C_VERSION, C_DERIVADO)

_FUENTES_VERSION = ("vulnerabilidades por firmware", "reporte de obsolescencia")
_FUENTES_CONFIG = ("salud de la red (switches)", "registro en firewalls y switches")
_PREF_CONFIG = ("firewall ", "switches ")
_PREF_PLATAFORMA = ("exportacion ", "vulnerabilidades ", "alertas ")
_RE_CARPETA = re.compile(r"^[A-Za-z0-9_-]{1,40}$")


# --------------------------------------------------------------------------- #
# Perfil
# --------------------------------------------------------------------------- #

def validar(v, fallo, objeto) -> dict:
    """Normaliza la clave de perfil `solo_estado` ({} vale)."""
    v = objeto(v, CLAVE, ("carpeta", "salidas", "entregable_destino"))
    out: dict = {"carpeta": CARPETA}
    if "carpeta" in v:
        c = v["carpeta"]
        if not isinstance(c, str) or not _RE_CARPETA.match(c):
            fallo(f"'{CLAVE}.carpeta' debe ser un texto de 1 a 40 caracteres de A-Z, a-z, 0-9, guion y guion bajo.")
        out["carpeta"] = c
    if "salidas" in v:
        s = v["salidas"]
        if not isinstance(s, list) or not 1 <= len(s) <= MAX_SALIDAS:
            fallo(f"'{CLAVE}.salidas' debe ser una lista de 1 a {MAX_SALIDAS} nombres de archivo.")
        for x in s:
            if not isinstance(x, str) or x not in SALIDAS:
                fallo(f"'{CLAVE}.salidas': '{x}' no esta en la lista de salidas de estado ({', '.join(SALIDAS)}).")
        out["salidas"] = list(dict.fromkeys(s))
    if "entregable_destino" in v:
        e = v["entregable_destino"]
        if not isinstance(e, str) or not 1 <= len(e.strip()) <= MAX_TEXTO:
            fallo(f"'{CLAVE}.entregable_destino' debe ser un texto de 1 a {MAX_TEXTO} caracteres.")
        out["entregable_destino"] = e.strip()
    return out


# --------------------------------------------------------------------------- #
# Copia de solo estado
# --------------------------------------------------------------------------- #

def _nombres_juicio() -> set:
    return {x.lower() for n in JUICIO for x in (n, t(n))}


def es_juicio(cabecera: str, nombres: set) -> bool:
    """La columna es de juicio (por su nombre interno o traducido, o porque empieza por criticidad o riesgo)."""
    h = cabecera.strip().lower()
    if h in nombres:
        return True
    pref = {p for base in PREFIJOS_JUICIO for p in (base, t(base).lower())}
    return any(h.startswith(p) for p in pref)


def _leer(path: Path):
    with open(path, newline="", encoding="utf-8-sig") as fh:
        return list(csv.reader(fh))


def _copiar(outdir: Path, destino: Path, salidas) -> list:
    """Escribe en `destino` las copias filtradas y devuelve [(archivo, cabecera, filas, quitadas)]."""
    nombres = _nombres_juicio()
    out = []
    for archivo in salidas:
        origen = outdir / archivo
        if not origen.is_file():
            continue
        try:
            filas = _leer(origen)
        except (OSError, UnicodeDecodeError, csv.Error):
            continue
        if not filas:
            continue
        cab = filas[0]
        quedan = [i for i, h in enumerate(cab) if not es_juicio(h, nombres)]
        if not quedan:
            continue
        quitadas = [h for h in cab if es_juicio(h, nombres)]
        cuerpo = [[f[i] if i < len(f) else "" for i in quedan] for f in filas[1:]]
        cab2 = [cab[i] for i in quedan]
        destino.mkdir(parents=True, exist_ok=True)
        with open(destino / archivo, "w", newline="", encoding="utf-8-sig") as fh:
            w = csv.writer(fh)
            w.writerow(cab2)
            w.writerows(cuerpo)
        out.append((archivo, cab2, cuerpo, quitadas))
    return out


# --------------------------------------------------------------------------- #
# Candidatos a hallazgo
# --------------------------------------------------------------------------- #

def confianza(fuente: str, capturas) -> str:
    if fuente in capturas:
        return C_TRAFICO
    if fuente in _FUENTES_VERSION:
        return C_VERSION
    if fuente in _FUENTES_CONFIG or fuente.startswith(_PREF_CONFIG):
        return C_CONFIG
    if fuente.startswith(_PREF_PLATAFORMA):
        return C_PLATAFORMA
    return C_DERIVADO


def _datasets(fuente: str, manifiesto, entradas=()) -> str:
    """dataset_id de los datasets cuyos archivos incluyen el de la fuente. Una fuente 'exportacion <plataforma>' sale
    de los archivos de exportes de la corrida (`entradas`)."""
    if not _mf.hay(manifiesto):
        return ""
    plataforma = fuente.startswith("exportacion ")
    ids = []
    for ds in manifiesto["filas"]:
        archivos = [a for a in ds.get("archivos", ()) if a]
        if plataforma:
            casa = any(a in entradas for a in archivos)
        else:
            casa = any(fuente == a or re.search(r"(?:^|[ ,])" + re.escape(a) + r"(?:$|[ ,])", fuente)
                       for a in archivos)
        if casa:
            ids.append(ds["dataset_id"])
    return ";".join(dict.fromkeys(ids))


def _evidencia(f: dict) -> str:
    traducida = t(f["evidencia"])
    tipos = {tipo for texto in (f["evidencia"], traducida) for _n, tipo, _v in _sec.escanear_texto(texto)}
    if tipos:
        return t("[evidencia retenida: posible secreto ({tipos})]", tipos=", ".join(sorted(tipos)))
    return traducida


def filas_candidatos(res, cfg: dict) -> list:
    capturas = {c.name for c in res.caps}
    plan = _en.plan(getattr(res, "perfil", None))
    destino_perfil = cfg.get("entregable_destino", "")
    entradas = {e["archivo"] for e in (getattr(res, "entorno", None) or {}).get("entradas", ())}
    out = []
    for c in [*res.caps, *res.extras]:
        for f in sorted(c.findings, key=lambda x: SEV_ORDER.get(x["severidad"], 9)):
            fuente = f.get("captura") or c.name
            destino = (_en.texto_hallazgo(plan, f) if plan else "") or destino_perfil
            out.append([f.get("id") or id_hallazgo(f["titulo"]), t(f["categoria"]), t(f["titulo"]),
                        t(f["severidad"]), fuente, t(confianza(fuente, capturas)), _evidencia(f),
                        ";".join(sorted(set(f.get("activos") or ()))),
                        _datasets(fuente, getattr(res, "manifiesto", None), entradas),
                        destino, "", "", "", ""])
    return out


# --------------------------------------------------------------------------- #
# Escritura
# --------------------------------------------------------------------------- #

def escribir(res, outdir: Path):
    """Escribe la copia de solo estado y los candidatos. Devuelve el bloque de resultado.json o None sin la clave."""
    cfg = (getattr(res, "perfil", None) or {}).get(CLAVE)
    if cfg is None:
        return None
    carpeta = cfg.get("carpeta", CARPETA)
    copias = _copiar(outdir, outdir / carpeta, cfg.get("salidas") or SALIDAS)
    if copias:
        escribir_xlsx(outdir / carpeta / ARCHIVO_XLSX,
                      [(a[:-len(".csv")][:31], cab, filas) for a, cab, filas, _q in copias])
    filas = filas_candidatos(res, cfg)
    with open(outdir / ARCHIVO_CANDIDATOS, "w", newline="", encoding="utf-8-sig") as fh:
        w = escritor_csv(fh)
        w.writerow([t(c) for c in COLUMNAS_CAND])
        w.writerows(filas)
    bloque = para_json(carpeta, copias, len(filas))
    print(t("[*] solo estado: {n} tablas en {c}/, {m} candidatos a hallazgo", n=len(copias), c=carpeta,
            m=len(filas)))
    return bloque


def para_json(carpeta: str, copias: list, candidatos: int) -> dict:
    return {"carpeta": carpeta,
            "tablas": [{"archivo": a, "filas": len(filas), "columnas_quitadas": q} for a, _c, filas, q in copias],
            "candidatos": candidatos}
