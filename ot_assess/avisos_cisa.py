"""T6: catalogo KEV y avisos ICS (CSAF) de CISA, desde archivos locales, cruzados por CVE exacto (D66).

La herramienta nunca sale a la red (D1): el analista descarga los archivos y los pasa con --kev y
--avisos-ics. Cruce SOLO por CVE; no se compara fabricante, modelo ni firmware con el product_tree.
Memoria acotada: de cada aviso solo se guarda lo de los CVE que ya estan en el archivo de vulnerabilidades.
"""
from __future__ import annotations

import datetime
import hashlib
import os
from pathlib import Path

from . import json_entrada
from .i18n import t
from .importers.lector import leer_csv
from .vulnerabilidades import _CVE

MAX_BYTES_KEV = 50 * 1024 * 1024
MAX_BYTES_AVISO = 20 * 1024 * 1024
MAX_ARCHIVOS = 20000
DIAS_VIEJO = 30
EXTRACTO = 200

TITULO_KEV = "Vulnerabilidades explotadas activamente (catalogo KEV de CISA) en activos"
COLUMNAS_KEV = ["kev", "kev_fecha_agregada", "kev_fecha_limite", "kev_ransomware", "avisos_ics",
                "remediacion_fabricante"]
COLUMNAS_AVISOS = ["aviso", "titulo", "publicado", "actualizado", "url", "cves", "activos", "abiertas",
                   "cvss_max", "remediaciones"]


def _hoy(hoy):
    return hoy or datetime.datetime.now(datetime.timezone.utc).date()


def _fecha(s):
    try:
        return datetime.date.fromisoformat(str(s or "").strip()[:10])
    except ValueError:
        return None


def _clave(h) -> str:
    return "".join(c for c in str(h).lower() if c.isalnum())


# ---------------------------------------------------------------- KEV

def _reg_kev(r: dict):
    cve = str(r.get("cveID") or "").strip().upper()
    if not _CVE.match(cve):
        return None
    return cve, {
        "producto": f"{r.get('vendorProject') or ''} {r.get('product') or ''}".strip(),
        "nombre": str(r.get("vulnerabilityName") or ""),
        "agregada": str(r.get("dateAdded") or "").strip(),
        "limite": str(r.get("dueDate") or "").strip(),
        "ransomware": str(r.get("knownRansomwareCampaignUse") or "").strip(),
        "accion": str(r.get("requiredAction") or ""),
    }


def cargar_kev(path) -> dict:
    """KEV de CISA en JSON o CSV (se detecta por contenido). SystemExit si no se puede leer."""
    p = Path(path)
    try:
        if p.stat().st_size > MAX_BYTES_KEV:
            raise SystemExit(f"[!] '{p.name}': el catalogo KEV pasa de {MAX_BYTES_KEV // (1 << 20)} MB")
        raw = p.read_bytes()
    except OSError as e:
        raise SystemExit(f"[!] No pude leer '{p.name}': {e.strerror or e}")
    cabecera = {"catalogVersion": "", "dateReleased": ""}
    if raw.lstrip(b"\xef\xbb\xbf \r\n\t")[:1] in (b"{", b"["):
        try:
            datos = json_entrada.cargar(raw.decode("utf-8-sig"))
        except (ValueError, UnicodeDecodeError):
            raise SystemExit(f"[!] '{p.name}': JSON invalido")
        lista = datos.get("vulnerabilities") if isinstance(datos, dict) else None
        if not isinstance(lista, list):
            raise SystemExit(f"[!] '{p.name}': no es el catalogo KEV (falta 'vulnerabilities')")
        cabecera = {k: str(datos.get(k) or "") for k in cabecera}
        filas = [r for r in lista if isinstance(r, dict)]
    else:
        filas = [{_alias(k): v for k, v in f.items()} for f in leer_csv(raw)]
        if not filas or "cveID" not in filas[0]:
            raise SystemExit(f"[!] '{p.name}': formato desconocido (se esperaba el KEV de CISA en JSON o CSV)")
    por_cve = {}
    for r in filas:
        reg = _reg_kev(r)
        if reg:
            por_cve.setdefault(reg[0], reg[1])
    if not por_cve:
        raise SystemExit(f"[!] '{p.name}': sin vulnerabilidades KEV reconocibles")
    fecha = cabecera["dateReleased"][:10] or max((v["agregada"] for v in por_cve.values()), default="")
    return {"archivo": p.name, "version": cabecera["catalogVersion"], "fecha": fecha,
            "total": len(por_cve), "por_cve": por_cve,
            "entrada": {"archivo": p.name, "sha256": hashlib.sha256(raw).hexdigest()}}


_NOMBRES_KEV = ("cveID", "vendorProject", "product", "vulnerabilityName", "dateAdded", "shortDescription",
                "requiredAction", "dueDate", "knownRansomwareCampaignUse", "notes")
_POR_CLAVE = {_clave(n): n for n in _NOMBRES_KEV}


def _alias(h):
    return _POR_CLAVE.get(_clave(h), h)


# ---------------------------------------------------------------- avisos CSAF

def detalle_vulnerabilidad(v: dict) -> tuple:
    """(CVSS v3 maximo o None, categorias de remediacion, extracto de la remediacion) de una vulnerabilidad CSAF."""
    cvss = [s["cvss_v3"]["baseScore"] for s in v.get("scores") or ()
            if isinstance(s, dict) and isinstance(s.get("cvss_v3"), dict)
            and isinstance(s["cvss_v3"].get("baseScore"), (int, float))]
    rem = [r for r in v.get("remediations") or () if isinstance(r, dict) and r.get("category")]
    detalle = next((r for r in rem if r.get("details") and r["category"] == "vendor_fix"),
                   next((r for r in rem if r.get("details")), {}))
    return (max(cvss) if cvss else None, sorted({str(r["category"]) for r in rem}),
            " ".join(str(detalle.get("details") or "").split())[:EXTRACTO])


def _aviso_csaf(datos, cves: set):
    """(id, aviso reducido o None, fecha de la ultima revision) o None si no es CSAF."""
    doc = datos.get("document") if isinstance(datos, dict) else None
    if not isinstance(doc, dict) or not isinstance(datos.get("vulnerabilities"), list):
        return None
    seg = doc.get("tracking")
    aviso_id = str(seg.get("id") or "").strip() if isinstance(seg, dict) else ""
    if not aviso_id:
        return None
    refs = [r for r in doc.get("references") or () if isinstance(r, dict) and r.get("url")]
    url = next((r["url"] for r in refs if r.get("category") == "self"), refs[0]["url"] if refs else "")
    aviso = {"id": aviso_id, "titulo": str(doc.get("title") or ""),
             "publicado": str(seg.get("initial_release_date") or "")[:10],
             "actualizado": str(seg.get("current_release_date") or "")[:10],
             "url": str(url), "cves": {}}
    for v in datos["vulnerabilities"]:
        cve = str(v.get("cve") or "").strip().upper() if isinstance(v, dict) else ""
        if cve not in cves:
            continue
        cvss, categorias, extracto = detalle_vulnerabilidad(v)
        aviso["cves"][cve] = {"cvss": cvss, "categorias": categorias, "extracto": extracto}
    return aviso_id, (aviso if aviso["cves"] else None), _fecha(aviso["actualizado"])


def archivos_json(ruta, r: dict):
    """Generador comun de la lectura de avisos: (ruta relativa, bytes) de cada JSON de un archivo o carpeta.

    Carpeta recursiva y sin enlaces simbolicos; respeta MAX_ARCHIVOS y MAX_BYTES_AVISO. Actualiza en `r` los
    contadores leidos, saltados (ilegibles), sobre_tamano y sobrantes, y `_lineas` (sha256 y ruta de cada JSON)."""
    p = Path(ruta)
    if p.is_symlink() or not (p.is_file() or p.is_dir()):
        raise SystemExit(f"[!] No pude leer '{p.name}': no es un archivo ni una carpeta")
    if p.is_file():
        archivos = [(p, p.name)]
    else:
        archivos = []
        for dirpath, dirnames, nombres in os.walk(p, followlinks=False):
            dirnames.sort()
            for n in sorted(nombres):
                f = Path(dirpath) / n
                if n.lower().endswith(".json") and not f.is_symlink():
                    archivos.append((f, f.relative_to(p).as_posix()))
    archivos.sort(key=lambda x: x[1])
    if len(archivos) > MAX_ARCHIVOS:
        r["sobrantes"] = len(archivos) - MAX_ARCHIVOS
        archivos = archivos[:MAX_ARCHIVOS]
    r["_lineas"] = []
    for f, rel in archivos:
        try:
            if f.stat().st_size > MAX_BYTES_AVISO:
                r["sobre_tamano"] += 1
                continue
            raw = f.read_bytes()
        except OSError:
            r["saltados"] += 1
            continue
        r["leidos"] += 1
        r["_lineas"].append(f"{hashlib.sha256(raw).hexdigest()}  {rel}")
        yield rel, raw


def cargar_avisos(ruta, cves: set, visitante=None) -> dict:
    """Una pasada por un JSON o una carpeta (recursiva, sin seguir enlaces simbolicos).

    `visitante(datos, ruta_relativa)` (opcional, V1a) recibe cada aviso CSAF ya leido: la carpeta se lee una vez."""
    p = Path(ruta)
    r = {"archivo": p.name, "leidos": 0, "saltados": 0, "sobre_tamano": 0, "sobrantes": 0,
         "ultimo": None, "avisos": {}, "avisos_csaf": 0}
    for rel, raw in archivos_json(ruta, r):
        try:
            datos = json_entrada.cargar(raw.decode("utf-8-sig"))
            res = _aviso_csaf(datos, cves)
        except (ValueError, UnicodeDecodeError, RecursionError):
            res = None
        if res is None:
            r["saltados"] += 1
            continue
        r["avisos_csaf"] += 1
        aviso_id, aviso, fecha = res
        if fecha and (r["ultimo"] is None or fecha > r["ultimo"]):
            r["ultimo"] = fecha
        if visitante is not None:
            visitante(datos, rel)
        previo = r["avisos"].get(aviso_id)
        if aviso and (previo is None or aviso["actualizado"] >= previo["actualizado"]):
            r["avisos"][aviso_id] = aviso
    if p.is_file() and r["avisos_csaf"] == 0:
        raise SystemExit(f"[!] '{p.name}': no es un aviso ICS en CSAF 2.0")
    r["ultimo"] = r["ultimo"].isoformat() if r["ultimo"] else ""
    lineas = r.pop("_lineas")
    r["entrada"] = {"archivo": p.name, "json_leidos": r["leidos"],
                    "sha256": hashlib.sha256("\n".join(sorted(lineas)).encode()).hexdigest()}
    return r


def avisos_de_carga(av: dict) -> list:
    """Avisos de consola de la lectura (una linea por tema, no por archivo)."""
    out = []
    if av["saltados"]:
        out.append(f"--avisos-ics: {av['saltados']} JSON saltados (no son avisos CSAF o no se pudieron leer)")
    if av["sobre_tamano"]:
        out.append(f"--avisos-ics: {av['sobre_tamano']} archivos ignorados por pasar "
                   f"{MAX_BYTES_AVISO // (1 << 20)} MB")
    if av["sobrantes"]:
        out.append(f"--avisos-ics: {av['sobrantes']} archivos ignorados por pasar el limite de {MAX_ARCHIVOS}")
    if not av["avisos_csaf"]:
        out.append("--avisos-ics: no se leyo ningun aviso CSAF")
    return out


def avisos_de_antiguedad(kev, av, hoy=None) -> list:
    """Avisos de catalogo viejo: fecha del KEV o del aviso CSAF mas reciente a mas de DIAS_VIEJO de la corrida."""
    hoy = _hoy(hoy)
    out = []
    for etiqueta, fecha in (("catalogo KEV", kev and kev["fecha"]), ("aviso CSAF mas reciente", av and av["ultimo"])):
        d = _fecha(fecha)
        if d and (hoy - d).days > DIAS_VIEJO:
            out.append(f"{etiqueta} del {d.isoformat()}; puede estar desactualizado")
    return out


def preparar(args, vulns, hoy=None, visitante=None):
    """(kev, avisos) segun --kev y --avisos-ics; (None, None) sin vulnerabilidades. Imprime los avisos.

    Deja en args.kev_entrada y args.avisos_entrada lo que entorno.py registra (sin rutas absolutas).
    `visitante` (V1a) recibe cada aviso CSAF en la misma pasada: la carpeta se lee una sola vez.
    """
    ruta_kev, ruta_av = getattr(args, "kev", None), getattr(args, "avisos_ics", None)
    if not (ruta_kev or ruta_av):
        return None, None
    if vulns is None:
        print("[!] --kev y --avisos-ics: no hay vulnerabilidades importadas que cruzar por CVE; se ignoran en ese cruce")
        return None, None
    kev = cargar_kev(ruta_kev) if ruta_kev else None
    av = cargar_avisos(ruta_av, cves_de(vulns), visitante) if ruta_av else None
    args.kev_entrada = kev["entrada"] if kev else None
    args.avisos_entrada = av["entrada"] if av else None
    for adv in [*(avisos_de_carga(av) if av else ()), *avisos_de_antiguedad(kev, av, hoy)]:
        print(f"[!] {adv}")
    return kev, av


# ---------------------------------------------------------------- cruce

def cves_de(vulns: list) -> set:
    return {v["cve"] for v in vulns}


def anotar(cruces: list, kev=None, av=None) -> None:
    """Agrega a cada cruce: kev ('si'/'no'/'' si no hubo --kev), kev_info y avisos (lista de avisos)."""
    por_aviso = {}
    if av:
        for a in av["avisos"].values():
            for cve in a["cves"]:
                por_aviso.setdefault(cve, []).append(a)
    for c in cruces:
        cve = c["vuln"]["cve"]
        if kev:
            info = kev["por_cve"].get(cve)
            c["kev"] = "si" if info else "no"
            c["kev_info"] = info
        c["avisos"] = sorted(por_aviso.get(cve, ()), key=lambda a: a["id"])


def kev_efectivo(cruces: list, kev=None):
    """KEV de la propia columna del archivo importado (cve_is_kev de Nozomi, D74), sumado al de --kev.

    Marca como 'si' lo que la columna dice; devuelve `kev` o, si no se dio --kev y la columna marco
    algo, un KEV sintetico (sin version ni fecha) para que el hallazgo y el resumen se generen."""
    hay = [c for c in cruces if "kev_col" in c["vuln"]]
    if not hay:
        return kev
    marcadas = 0
    for c in hay:
        if c["vuln"]["kev_col"]:
            marcadas += 1
            c["kev"] = "si"
            c["kev_info"] = c.get("kev_info") or {"agregada": "", "limite": "", "ransomware": ""}
        elif "kev" not in c:
            c["kev"] = "no"
            c["kev_info"] = None
    if kev is None and marcadas:
        return {"archivo": "columna cve_is_kev", "version": "indicada por la columna cve_is_kev del archivo",
                "fecha": "", "por_cve": {}, "entrada": None}
    return kev


def resumen_cisa(cruces: list, kev=None, av=None) -> dict:
    """Bloques 'kev' y 'avisos_ics' para resultado.json (solo los que se pidieron)."""
    out = {}
    if kev:
        en = [c for c in cruces if c.get("kev") == "si"]
        out["kev"] = {"archivo": kev["archivo"], "version": kev["version"], "fecha": kev["fecha"],
                      "en_kev": len(en),
                      "abiertas_en_kev": sum(1 for c in en if _abierta_asociada(c))}
    if av:
        ids = {a["id"] for c in cruces for a in c.get("avisos") or ()}
        out["avisos_ics"] = {"archivo": av["archivo"], "archivos_leidos": av["leidos"],
                             "saltados": av["saltados"] + av["sobre_tamano"] + av["sobrantes"],
                             "avisos_con_cruce": len(ids)}
    return out


def _abierta_asociada(c) -> bool:
    return c["vuln"]["estado"] == "abierta" and c["activo"] is not None


# ---------------------------------------------------------------- columnas y tabla de avisos

def columnas_kev(c: dict) -> list:
    """Valores de COLUMNAS_KEV para un cruce (vacios si no se dio --kev / sin avisos)."""
    info = c.get("kev_info") or {}
    ransom = info.get("ransomware", "").lower()
    ransom = "si" if ransom == "known" else "no" if ransom == "unknown" else info.get("ransomware", "")
    cats = sorted({k for a in c.get("avisos") or () for k in a["cves"][c["vuln"]["cve"]]["categorias"]})
    return [c.get("kev", ""), info.get("agregada", ""), info.get("limite", ""), ransom,
            ";".join(a["id"] for a in c.get("avisos") or ()), ";".join(cats)]


def filas_avisos(cruces: list, assets: dict) -> list:
    """Una fila por aviso con cruce, por cvss_max descendente y luego aviso."""
    por_aviso = {}
    for c in cruces:
        for a in c.get("avisos") or ():
            por_aviso.setdefault(a["id"], (a, []))[1].append(c)
    filas = []
    for aid, (a, cs) in por_aviso.items():
        cves = sorted({c["vuln"]["cve"] for c in cs})
        activos = sorted({(assets.get(c["activo"]) or {}).get("nombre") or str(c["activo"])
                          for c in cs if c["activo"] is not None})
        cvss = [a["cves"][cv]["cvss"] for cv in cves if a["cves"][cv]["cvss"] is not None]
        cats = sorted({k for cv in cves for k in a["cves"][cv]["categorias"]})
        filas.append([aid, a["titulo"], a["publicado"], a["actualizado"], a["url"], ";".join(cves),
                      ";".join(activos), sum(1 for c in cs if _abierta_asociada(c)),
                      max(cvss) if cvss else "", ";".join(cats)])
    return sorted(filas, key=lambda f: (-(f[8] if f[8] != "" else -1), f[0]))


# ---------------------------------------------------------------- hallazgo

def agregar_hallazgo_kev(cap, cruces: list, assets: dict, kev: dict, hoy=None) -> None:
    """Hallazgo Alta si hay vulnerabilidades abiertas asociadas a un activo y presentes en el KEV."""
    from .rules.base import finding

    en = [c for c in cruces if c.get("kev") == "si" and _abierta_asociada(c)]
    if not en:
        return
    por_activo: dict = {}
    for c in en:
        por_activo.setdefault(c["activo"], {})[c["vuln"]["cve"]] = c["kev_info"]

    def nombre(k):
        return (assets.get(k) or {}).get("nombre") or str(k)
    orden = sorted(por_activo, key=lambda k: (-len(por_activo[k]), nombre(k), str(k)))
    lineas = []
    for k in orden[:10]:
        partes = []
        for cve in sorted(por_activo[k])[:3]:
            i = por_activo[k][cve]
            ransom = {"known": t("si"), "unknown": t("no")}.get(i["ransomware"].lower(), i["ransomware"] or "-")
            partes.append(t("{cve} (agregada al KEV {f}; ransomware: {r})", cve=cve, f=i["agregada"] or "-", r=ransom))
        extra = len(por_activo[k]) - 3
        lineas.append(f"{nombre(k)}: {', '.join(partes)}" + (f" (+{extra})" if extra > 0 else ""))
    viejo = avisos_de_antiguedad(kev, None, hoy)
    ev = t("Catalogo KEV de CISA version {v}, publicado {f}. Vulnerabilidades abiertas asociadas a un activo "
           "y presentes en el KEV: {n}, en {a} activos. {lineas}{mas}. La fecha limite del KEV (columna "
           "kev_fecha_limite de vulnerabilidades.csv) la fija CISA para agencias federales de EE. UU. "
           "(BOD 22-01); es una referencia, no una obligacion del cliente.{viejo}",
           v=kev["version"] or "-", f=kev["fecha"] or "-", n=len(en), a=len(orden), lineas="; ".join(lineas),
           mas=t(" (y {n} activos mas)", n=len(orden) - 10) if len(orden) > 10 else "",
           viejo=(" " + t("Catalogo del {f}; puede estar desactualizado.", f=kev["fecha"])) if viejo else "")
    finding(cap, "Alta", TITULO_KEV, ev,
            "CISA documenta explotacion real de estas vulnerabilidades; un activo con una de ellas "
            "abierta es un objetivo con antecedentes de ataque, no solo una falla teorica.",
            "Aplicar el parche o la mitigacion del aviso del fabricante en la ventana acordada; mientras "
            "tanto, restringir los conductos que alcanzan ese activo a lo imprescindible.",
            "Vulnerabilidades",
            activos=[str(ip) for k in orden for ip in (assets.get(k) or {}).get("ips") or ()])


def en_kev_abiertas(cruces: list) -> int:
    return sum(1 for c in cruces if c.get("kev") == "si" and _abierta_asociada(c))
