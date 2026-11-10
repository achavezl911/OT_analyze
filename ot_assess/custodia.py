"""Cadena de custodia de la evidencia: registro JSON Lines de solo agregar, encadenado por hash (K1, D95).

Cada linea lleva en `anterior` el SHA-256 de los bytes de la linea previa (sin el salto de linea final).
Detecta ediciones y borrados en medio del registro; NO detecta que se borren los ultimos eventos ni que se
reescriba toda la cadena: para eso se comunica la huella (SHA-256 de la ultima linea) por un canal aparte.
No cifra ni firma nada: el cifrado en reposo es del volumen o del contenedor y aqui solo se declara.
"""
from __future__ import annotations

import csv
import io
import json
import os
from html import escape as esc
from pathlib import Path

from . import entrega as ent
from . import i18n, json_entrada
from .i18n import t
from .report.common import celda_csv
from .report.style import HTML_CSS

FORMATO = "ot_assess.custodia/1"
CEROS = "0" * 64
EVENTOS = ("recepcion", "copia", "transferencia", "analisis", "entrega", "devolucion", "destruccion")
SIN_ARCHIVOS = ("devolucion", "destruccion")
NO_DECLARADO = "no declarado"
COLUMNAS_CSV = ("n", "fecha_utc", "evento", "entrega", "recibe", "medio", "cifrado", "ubicacion",
                "nombre", "bytes", "sha256", "nota")


class ErrorCustodia(Exception):
    """Ruta invalida o registro ilegible (codigo 2)."""


def _sha(b: bytes) -> str:
    return ent.sha256_bytes(b)


def linea_canonica(ev: dict) -> bytes:
    return json.dumps(ev, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def leer(ruta) -> bytes:
    try:
        return Path(ruta).read_bytes()
    except OSError as e:
        raise ErrorCustodia(f"no se pudo leer el registro '{ruta}': {e}") from e


def _estructura_ok(ev: dict) -> bool:
    arch = ev.get("archivos")
    return (isinstance(arch, list) and isinstance(ev.get("anterior"), str)
            and all(isinstance(a, dict) and isinstance(a.get("nombre"), str)
                    and isinstance(a.get("sha256"), str) for a in arch))


def analizar(datos: bytes) -> dict:
    """{eventos, rota (numero de linea o None), mensaje, huella, lineas}. Se detiene en la primera linea rota."""
    partes = datos.split(b"\n")
    sin_final = bool(partes[-1])
    if not sin_final:
        partes.pop()
    eventos: list = []
    previa = None
    rota, msg = None, ""
    for i, crudo in enumerate(partes, 1):
        if sin_final and i == len(partes):
            rota, msg = i, t("linea {i}: sin salto de linea final (linea truncada)", i=i)
            break
        try:
            ev = json_entrada.cargar(crudo.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            rota, msg = i, t("linea {i}: no es JSON valido (la linea fue editada)", i=i)
            break
        if not isinstance(ev, dict) or ev.get("formato") != FORMATO or not _estructura_ok(ev):
            rota, msg = i, t("linea {i}: formato desconocido o estructura invalida", i=i)
            break
        if ev.get("n") != i:
            rota, msg = i, t("linea {i}: n={n} y se esperaba {i} (se borro, agrego o reordeno un evento)",
                              i=i, n=ev.get("n"))
            break
        esperado = CEROS if previa is None else _sha(previa)
        if ev["anterior"] != esperado:
            msg = (t("linea {i}: el campo anterior de la primera linea no es 64 ceros", i=i) if i == 1 else
                   t("linea {i}: no encadena con la anterior (se modifico o borro el evento de la linea "
                     "{j} o uno previo, o se edito la linea {i})", i=i, j=i - 1))
            rota = i
            break
        eventos.append(ev)
        previa = crudo
    ultima = partes[-1] if partes else None
    huella = _sha(ultima) if ultima is not None else CEROS
    return {"eventos": eventos, "rota": rota, "mensaje": msg, "huella": huella, "lineas": len(partes)}


def cadena_texto(a: dict) -> str:
    return "integra" if a["rota"] is None else f"rota (linea {a['rota']})"


# ---- archivos ------------------------------------------------------------------------------------------

def listar(rutas: list) -> list:
    """[(Path, nombre)] sin enlaces simbolicos ni ocultos; carpetas en orden. ErrorCustodia si algo no existe."""
    out: list = []
    for r in rutas:
        p = Path(r).expanduser()
        if p.is_symlink() or not p.exists():
            raise ErrorCustodia(f"ruta invalida (no existe o es un enlace simbolico): '{r}'")
        if p.is_dir():
            for raiz, dirs, nombres in os.walk(p):
                dirs[:] = sorted(d for d in dirs
                                 if not d.startswith(".") and not (Path(raiz) / d).is_symlink())
                for n in sorted(nombres):
                    f = Path(raiz) / n
                    if n.startswith(".") or f.is_symlink() or not f.is_file():
                        continue
                    out.append((f, f.relative_to(p).as_posix()))
        elif p.is_file():
            out.append((p, p.name))
        else:
            raise ErrorCustodia(f"ruta invalida: '{r}'")
    return out


def describir(rutas: list) -> list:
    res = []
    for f, nombre in listar(rutas):
        try:
            with open(f, "rb") as fh:
                sha, n = ent.sha256_flujo(fh)
        except OSError as e:
            raise ErrorCustodia(f"no se pudo leer '{f.name}': {e}") from e
        res.append({"nombre": nombre, "bytes": n, "sha256": sha})
    return res


# ---- registrar -----------------------------------------------------------------------------------------

def registrar(registro, evento: str, rutas: list, *, entrega="", recibe="", medio="", cifrado="",
              ubicacion="", nota="", fecha=None) -> dict:
    """Agrega un evento. ErrorCustodia (ruta) o ValueError (cadena rota, mensaje de la rotura)."""
    if evento not in EVENTOS:
        raise ValueError(f"evento desconocido: {evento}")
    reg = Path(registro)
    datos = reg.read_bytes() if reg.exists() else b""
    a = analizar(datos)
    if a["rota"] is not None:
        raise ValueError(a["mensaje"])
    archivos = describir(rutas)
    previa = datos.rstrip(b"\n").rsplit(b"\n", 1)[-1] if datos else None
    ev = {"formato": FORMATO, "n": len(a["eventos"]) + 1,
          "fecha_utc": fecha if fecha else ent.ahora_utc(), "fecha_declarada": bool(fecha),
          "evento": evento, "entrega": entrega, "recibe": recibe, "medio": medio,
          "cifrado": cifrado.strip() or NO_DECLARADO, "ubicacion": ubicacion, "nota": nota,
          "archivos": archivos, "anterior": CEROS if previa is None else _sha(previa)}
    linea = linea_canonica(ev) + b"\n"
    fd = os.open(str(reg), os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    with os.fdopen(fd, "ab") as fh:
        fh.write(linea)
    return ev


# ---- verificar -----------------------------------------------------------------------------------------

def ultimos_hash(eventos: list) -> dict:
    """nombre -> sha256 del ultimo evento que lo registro."""
    m: dict = {}
    for ev in eventos:
        for a in ev["archivos"]:
            m[a["nombre"]] = a["sha256"]
    return m


def comparar_rutas(a: dict, rutas: list) -> list:
    """[(nombre, estado)] con estado coincide | modificado | no registrado."""
    conocidos = ultimos_hash(a["eventos"])
    out = []
    for d in describir(rutas):
        reg = conocidos.get(d["nombre"])
        out.append((d["nombre"], "no registrado" if reg is None else
                    "coincide" if reg == d["sha256"] else "modificado"))
    return out


def estado_capturas(registro, capturas: list) -> dict:
    """entorno.custodia: capturas = [(nombre, sha256)]. Compara por hash, sin importar el nombre."""
    a = analizar(leer(registro))
    hashes = {x["sha256"] for ev in a["eventos"] for x in ev["archivos"]}
    return {"registro": Path(registro).name, "huella": a["huella"], "cadena": cadena_texto(a),
            "capturas": [{"archivo": n, "sha256": s,
                          "estado": "registrada" if s in hashes else "no registrada"} for n, s in capturas]}


# ---- exportar ------------------------------------------------------------------------------------------

def filas_csv(eventos: list) -> list:
    filas = []
    for ev in eventos:
        base = [ev["n"], ev.get("fecha_utc", ""), ev.get("evento", ""), ev.get("entrega", ""),
                ev.get("recibe", ""), ev.get("medio", ""), ev.get("cifrado", ""), ev.get("ubicacion", "")]
        for a in ev["archivos"] or [None]:
            filas.append(base + ([a["nombre"], a.get("bytes", ""), a["sha256"]] if a else ["", "", ""])
                         + [ev.get("nota", "")])
    return filas


# Cabeceras cuyo texto en espanol ya es clave de otro significado en el catalogo (el evento "entrega",
# la severidad "Medio"): en ingles usan una clave propia. En espanol no se tocan.
_ALT = {"Entrega": "Quien entrega", "Recibe": "Quien recibe", "Medio": "Medio de transferencia",
        "entrega": "quien_entrega", "medio": "medio_de_transferencia"}


def _th(texto: str) -> str:
    return t(texto) if i18n.idioma() == "es" else t(_ALT.get(texto, texto))


def csv_bytes(eventos: list) -> bytes:
    buf = io.StringIO(newline="")
    w = csv.writer(buf, lineterminator="\n")
    w.writerow([str(_th(c)) for c in COLUMNAS_CSV])
    for f in filas_csv(eventos):
        w.writerow([celda_csv(c) for c in f])
    return buf.getvalue().encode("utf-8-sig")      # con BOM, como los demas CSV (Excel)


def html_bytes(a: dict, nombre_registro: str) -> bytes:
    ok = a["rota"] is None
    filas = []
    for ev in a["eventos"]:
        arch = "<br>".join(f"{esc(x['nombre'])} ({x.get('bytes', '')} B)<br><code>{esc(x['sha256'])}</code>"
                           for x in ev["archivos"]) or "-"
        fecha = esc(str(ev.get("fecha_utc", ""))) + (t(" (declarada)") if ev.get("fecha_declarada") else "")
        nombre_ev = ev.get("evento", "")
        celdas = [ev["n"], fecha, t(nombre_ev) if nombre_ev in EVENTOS else nombre_ev,
                  ev.get("entrega", ""), ev.get("recibe", ""),
                  ev.get("medio", ""), ev.get("cifrado", ""), ev.get("ubicacion", "")]
        filas.append("<tr>" + "".join(f"<td>{esc(str(c))}</td>" if i != 1 else f"<td>{c}</td>"
                                      for i, c in enumerate(celdas))
                     + f"<td>{arch}</td><td>{esc(ev.get('nota', ''))}</td>"
                     "<td style='min-width:140px'></td><td style='min-width:140px'></td></tr>")
    cols = ("N", "Fecha UTC", "Evento", "Entrega", "Recibe", "Medio", "Cifrado declarado", "Ubicacion",
            "Archivos (SHA-256)", "Nota", "Firma de quien entrega", "Firma de quien recibe")
    estado = t("Cadena integra.") if ok else t("CADENA ROTA: {m}", m=esc(a["mensaje"]))
    leidos = t("Eventos leidos: {n}.", n=len(a["eventos"]))
    registro = t("Registro: {r}. Evidencia tecnica de integridad; no es una firma ni un dictamen. "
                 "El cifrado en reposo es el que declara el analista (la herramienta no cifra).",
                 r=esc(nombre_registro))
    huella = t("Huella del registro (SHA-256 de la ultima linea): {h}", h=f"<code>{a['huella']}</code>")
    h = [f"<!doctype html><html lang='{i18n.idioma()}'><head><meta charset='utf-8'>"
         f"<title>{t('Cadena de custodia')}</title>",
         (f"<style>{HTML_CSS}@media print{{.wrap{{max-width:none;padding:0 8px}}}}</style></head><body>"
          f"<header class='port'><div class='inner'><h1>{t('Cadena de custodia de la evidencia')}</h1>"
          f"<p>{registro}</p></div></header><div class='wrap'>"),
         f"<h2>{t('Verificacion de la cadena')}</h2><p>{estado} {leidos}</p>",
         (f"<p>{huella}</p><p class='lead'>"
          + t("Comunique la huella por un canal aparte: sin ella, borrar los ultimos eventos no se detecta.")
          + "</p>"),
         f"<h2>{t('Eventos')}</h2><div class='tbl'><table><thead><tr>"
         + "".join(f"<th>{_th(c)}</th>" for c in cols) + "</tr></thead><tbody>" + "".join(filas)
         + "</tbody></table></div></div></body></html>\n"]
    return "".join(h).encode("utf-8")


def exportar(registro, out) -> dict:
    a = analizar(leer(registro))
    carpeta = Path(out)
    carpeta.mkdir(parents=True, exist_ok=True)
    (carpeta / "custodia.csv").write_bytes(csv_bytes(a["eventos"]))
    (carpeta / "custodia.html").write_bytes(html_bytes(a, Path(registro).name))
    return a

