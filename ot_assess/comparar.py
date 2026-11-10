"""E4: compara dos corridas (antes y despues) a partir de los CSV publicos que ambas escriben (D62).

Lee inventario.csv, comunicaciones.csv, control.csv, hallazgos.csv y firewall_contraste.csv; solo toma de
resultado.json los metadatos (version, perfil, tipo de corrida). Las filas de "atencion" no son hallazgos del motor
de reglas: ordenan la lectura del cambio. Nada aqui dice "cumple" ni "no cumple".
"""
from __future__ import annotations

import csv
import json
import re
from html import escape as esc
from pathlib import Path

from . import json_entrada
from .report.common import celda_csv
from .report.style import HTML_CSS

ORDEN_ATENCION = {"alta": 0, "media": 1, "baja": 2}
MAX_FILAS = 40
UMBRAL_DEFECTO = 10.0
_NIVEL_BAJO = re.compile(r"Nivel\s*[01]\b")
_NIVEL_CTRL = re.compile(r"Nivel\s*[012]\b")

COL_ACTIVOS = ["estado", "atencion", "razon", "equipo", "ips", "mac", "cambios"]
COL_CONDUCTOS = ["estado", "atencion", "razon", "origen_ip", "destino_ip", "servicio", "l4", "puerto",
                 "cruza_zona_antes", "cruza_zona_despues", "escrituras_antes", "escrituras_despues",
                 "bytes_antes", "bytes_despues", "razon_volumen"]
COL_ESCRITORES = ["estado", "atencion", "razon", "origen", "destino", "protocolo", "operaciones_nuevas",
                  "operaciones"]
COL_HALLAZGOS = ["estado", "atencion", "razon", "severidad_antes", "severidad_despues", "categoria", "titulo"]
COL_FIREWALL = ["cambio", "atencion", "razon", "origen_ip", "destino_ip", "servicio", "l4", "puerto",
                "resultado_antes", "resultado_despues", "regla_antes", "regla_despues"]


class ErrorComparar(Exception):
    pass


def leer_csv(carpeta: Path, nombre: str):
    """Lista de dict o None si el archivo no existe."""
    p = carpeta / nombre
    if not p.is_file():
        return None
    with open(p, newline="", encoding="utf-8-sig") as fh:
        return list(csv.DictReader(fh))


def _json(carpeta: Path) -> dict:
    try:
        return json_entrada.cargar((carpeta / "resultado.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _g(fila: dict, campo: str) -> str:
    return (fila.get(campo) or "").strip()


def _num(v) -> int:
    try:
        return int(float(str(v).replace(",", "")))
    except ValueError:
        return 0


def _partir(v: str) -> set:
    return {x.strip() for x in (v or "").split(";") if x.strip()}


# ---------------------------------------------------------------- identidad de conductos (regla de M2c)
def _l4_ok(a: str, b: str) -> bool:
    return a == b or a not in ("tcp", "udp") or b not in ("tcp", "udp")


def casar(antes: list, despues: list, bidir: bool = True) -> tuple:
    """Une filas del mismo conducto con la regla de D46/M2c: extremos, puerto y l4 igual o vacio.

    Cada fila: dict con src, dst, port, l4 y bidir. Con tcp y udp conocidos en el mismo extremo y puerto, un l4
    vacio es ambiguo y no casa. Devuelve ([(i, [j...])], [j sin pareja])."""
    grupos: dict = {}
    for j, d in enumerate(despues):
        grupos.setdefault((frozenset((d["src"], d["dst"])), d["port"]), []).append(j)
    usados: set = set()
    pares = []
    for i, a in enumerate(antes):
        idx = grupos.get((frozenset((a["src"], a["dst"])), a["port"]), [])
        conocidos = {despues[j]["l4"] for j in idx if despues[j]["l4"] in ("tcp", "udp")}
        hit = []
        for j in idx:
            d = despues[j]
            if not (bidir and (a["bidir"] or d["bidir"])) and (a["src"], a["dst"]) != (d["src"], d["dst"]):
                continue
            if a["l4"] and d["l4"]:
                ok = _l4_ok(a["l4"], d["l4"])
            else:
                ok = len(conocidos | ({a["l4"]} & {"tcp", "udp"})) <= 1
            if ok:
                hit.append(j)
        usados.update(hit)
        pares.append((i, hit))
    return pares, [j for j in range(len(despues)) if j not in usados]


def _agrupar(rows: list, clave, agregar) -> dict:
    """Filas de identidad exacta repetida -> una fila agregada por clave (orden de aparicion)."""
    g: dict = {}
    for r in rows:
        g.setdefault(clave(r), []).append(r)
    return {k: agregar(v) for k, v in g.items()}


def _emparejar(ga: dict, gd: dict, ident, bidir: bool = True) -> tuple:
    """Dos pasadas: clave exacta y, solo con lo que queda sin pareja, la regla compatible de `casar`.

    Devuelve ([(x, [y...])], [y nuevos]); x e y son las filas ya agregadas por clave exacta."""
    pares, usados, resto_a = [], set(), []
    for k, x in ga.items():
        if k in gd:
            pares.append((x, [gd[k]]))
            usados.add(k)
        else:
            resto_a.append(x)
    resto_d = [y for k, y in gd.items() if k not in usados]
    cas, libres = casar([ident(x) for x in resto_a], [ident(y) for y in resto_d], bidir=bidir)
    for i, js in cas:
        pares.append((resto_a[i], [resto_d[j] for j in js]))
    return pares, [resto_d[j] for j in libres]


def _conducto(f: dict) -> dict:
    return {"src": _g(f, "origen_ip"), "dst": _g(f, "destino_ip"), "port": _g(f, "puerto"),
            "l4": _g(f, "l4").lower(), "bidir": _g(f, "sentido").lower().startswith("bidirec")}


def _firewall_id(f: dict) -> dict:
    return {"src": _g(f, "origen_ip"), "dst": _g(f, "destino_ip"), "port": _g(f, "puerto"),
            "l4": _g(f, "l4").lower(), "bidir": False}


# ---------------------------------------------------------------- activos
def _cambios_activo(x: dict, y: dict) -> list:
    cambios = []
    for campo in ("rol_inferido", "fabricante", "firmware", "zona_asignada"):
        if _g(x, campo) != _g(y, campo):
            cambios.append(f"{campo}: {_g(x, campo) or '-'} -> {_g(y, campo) or '-'}")
    for campo in ("puertos_servidos", "protocolos"):
        nuevos = sorted(_partir(_g(y, campo)) - _partir(_g(x, campo)))
        if nuevos:
            cambios.append(f"{campo} nuevos: {', '.join(nuevos)}")
    return cambios


def _activos(a: list, d: list, avisos: list) -> tuple:
    mac_d, ip_d = {}, {}
    for j, x in enumerate(d):
        if _g(x, "mac"):
            mac_d.setdefault(_g(x, "mac").lower(), []).append(j)
        for ip in _partir(_g(x, "ips")):
            ip_d.setdefault(ip, []).append(j)
    usados, filas, coinciden = set(), [], 0
    for x in a:
        mac = _g(x, "mac").lower()
        js = []
        if mac and any(_g(y, "mac") for y in d):
            js = mac_d.get(mac, [])
        if not js:
            js = sorted({j for ip in _partir(_g(x, "ips")) for j in ip_d.get(ip, [])})
        nombre = _g(x, "equipo") or _g(x, "ips")
        if not js:
            filas.append(["desaparecido", "media", "activo desaparecido", nombre, _g(x, "ips"), _g(x, "mac"), ""])
            continue
        coinciden += 1
        usados.update(js)
        if len(js) > 1:
            avisos.append(f"El activo {nombre} coincide con {len(js)} activos de la corrida posterior "
                          "(se compara con el primero).")
        cambios, y = min(((_cambios_activo(x, d[j]), d[j]) for j in js), key=lambda t: len(t[0]))
        if cambios:
            filas.append(["cambiado", "baja", "cambia " + cambios[0].split(":")[0], nombre,
                          _g(y, "ips"), _g(y, "mac"), " | ".join(cambios)])
    for j, y in enumerate(d):
        if j in usados:
            continue
        ctrl = bool(_NIVEL_CTRL.search(_g(y, "zona_purdue"))) or "control" in _g(y, "zona_asignada").lower()
        filas.append(["nuevo", "alta" if ctrl else "baja",
                      "activo nuevo en zona de control" if ctrl else "activo nuevo",
                      _g(y, "equipo") or _g(y, "ips"), _g(y, "ips"), _g(y, "mac"), ""])
    return filas, coinciden, min(len(a), len(d))


# ---------------------------------------------------------------- conductos
def _agregar_conducto(v: list) -> dict:
    f = dict(v[0])
    for c in ("bytes", "paquetes", "escrituras"):
        if any(c in r for r in v):
            f[c] = str(sum(_num(r.get(c)) for r in v))
    if any(_g(r, "cruza_zona").lower() == "si" for r in v):
        f["cruza_zona"] = "si"
    return f


def _clave_conducto(f: dict) -> tuple:
    return (_g(f, "origen_ip"), _g(f, "destino_ip"), _g(f, "puerto"), _g(f, "l4").lower(), _g(f, "servicio"),
            _g(f, "sentido").lower())


def _conductos(a: list, d: list, umbral: float) -> list:
    pares, nuevos = _emparejar(_agrupar(a, _clave_conducto, _agregar_conducto),
                               _agrupar(d, _clave_conducto, _agregar_conducto), _conducto)
    filas = []

    def base(estado, att, razon, x, y):
        return [estado, att, razon, _g(x, "origen_ip"), _g(x, "destino_ip"), _g(x, "servicio"), _g(x, "l4"),
                _g(x, "puerto"), _g(x, "cruza_zona"), _g(y, "cruza_zona"), _g(x, "escrituras"),
                _g(y, "escrituras"), _g(x, "bytes"), _g(y, "bytes"), ""]
    for x, ys in pares:
        if not ys:
            filas.append(base("ya_no_se_ve", "baja", "conducto que ya no se ve", x, {}))
            continue
        y = ys[0]
        fila = base("persiste", "baja", "", x, y)
        fila[9] = "si" if any(_g(r, "cruza_zona").lower() == "si" for r in ys) else _g(y, "cruza_zona")
        fila[11] = str(sum(_num(r.get("escrituras")) for r in ys))
        fila[13] = str(sum(_num(r.get("bytes")) for r in ys))
        razones = []
        if _g(x, "cruza_zona") != fila[9]:
            razones.append(f"cruza_zona {_g(x, 'cruza_zona')} -> {fila[9]}")
        if _num(x.get("escrituras")) != _num(fila[11]):
            razones.append(f"escrituras {_g(x, 'escrituras')} -> {fila[11]}")
        ba, bd = _num(x.get("bytes")), _num(fila[13])
        if ba and bd and max(ba / bd, bd / ba) >= umbral:
            fila[14] = f"x{bd / ba:.2f}"
            razones.append("volumen " + fila[14])
        fila[2] = "; ".join(razones)
        filas.append(fila)
    for y in nuevos:
        cruza = _g(y, "cruza_zona").lower() == "si"
        esc_ = _num(y.get("escrituras")) > 0
        bajo = bool(_NIVEL_BAJO.search(_g(y, "destino_zona")))
        if esc_ or (cruza and bajo):
            att, razon = "alta", "conducto nuevo con escrituras" if esc_ else "conducto nuevo que cruza zona hacia nivel 0-1"
        elif cruza:
            att, razon = "media", "conducto nuevo que cruza zona"
        else:
            att, razon = "baja", "conducto nuevo"
        fila = base("nuevo", att, razon, y, y)
        fila[8] = ""
        fila[10] = ""
        fila[12] = ""
        filas.append(fila)
    return filas


# ---------------------------------------------------------------- escritores
def _pares_control(rows: list) -> dict:
    out: dict = {}
    for r in rows:
        out.setdefault((_g(r, "origen"), _g(r, "destino"), _g(r, "protocolo")), set()).add(_g(r, "operacion"))
    return out


def _escritores(a: list, d: list) -> list:
    pa, pd = _pares_control(a), _pares_control(d)
    filas = []
    for k in sorted(pd):
        if k not in pa:
            filas.append(["nuevo", "alta", "escritor nuevo", *k, "", "; ".join(sorted(pd[k]))])
        elif pd[k] - pa[k]:
            filas.append(["operaciones_nuevas", "alta", "operacion de control nueva", *k,
                          "; ".join(sorted(pd[k] - pa[k])), "; ".join(sorted(pd[k]))])
    for k in sorted(set(pa) - set(pd)):
        filas.append(["ya_no_se_ve", "baja", "escritor que ya no se ve", *k, "", "; ".join(sorted(pa[k]))])
    return filas


# ---------------------------------------------------------------- hallazgos
def _hallazgos(a: list, d: list) -> list:
    def mapa(rows):
        m: dict = {}
        for r in rows:
            m.setdefault(_g(r, "titulo"), r)
        return m
    ma, md = mapa(a), mapa(d)
    filas = []
    for tit, y in md.items():
        x = ma.get(tit)
        if x is None:
            sev = _g(y, "severidad")
            filas.append(["nuevo", "media" if sev == "Alta" else "baja",
                          "hallazgo nuevo Alta" if sev == "Alta" else "hallazgo nuevo", "", sev,
                          _g(y, "categoria"), tit])
        elif _g(x, "severidad") != _g(y, "severidad"):
            filas.append(["persiste", "baja", "cambia la severidad", _g(x, "severidad"), _g(y, "severidad"),
                          _g(y, "categoria"), tit])
        else:
            filas.append(["persiste", "baja", "", _g(x, "severidad"), _g(y, "severidad"), _g(y, "categoria"), tit])
    for tit, x in ma.items():
        if tit not in md:
            filas.append(["resuelto", "baja", "ya no aparece", _g(x, "severidad"), "", _g(x, "categoria"), tit])
    return filas


# ---------------------------------------------------------------- firewall
def _agregar_fw(v: list) -> dict:
    f = dict(v[0])
    f["_res"] = {_g(r, "resultado") for r in v if _g(r, "resultado")}
    f["_reglas"] = {_g(r, "regla") for r in v if _g(r, "regla")}
    return f


def _firewall(a: list, d: list, conductos_a: list, conductos_d: list) -> list:
    pares, _nuevos = _emparejar(_agrupar(a, _clave_conducto, _agregar_fw), _agrupar(d, _clave_conducto, _agregar_fw),
                                _firewall_id, bidir=False)
    esc_a = {(_g(c, "origen_ip"), _g(c, "destino_ip"), _g(c, "puerto")): c for c in conductos_a + conductos_d}
    filas = []
    for x, ys in pares:
        if not ys:
            continue
        sa, sd = x["_res"], set().union(*(z["_res"] for z in ys))
        reg_a, reg_d = x["_reglas"], set().union(*(z["_reglas"] for z in ys))
        ra, rd = "; ".join(sorted(sa)), "; ".join(sorted(sd))
        regla_a, regla_d = "; ".join(sorted(reg_a)), "; ".join(sorted(reg_d))
        c = esc_a.get((_g(x, "origen_ip"), _g(x, "destino_ip"), _g(x, "puerto")), {})
        sensible = _num(c.get("escrituras")) > 0 or _g(c, "criticidad").lower() == "alta"
        if "permitido" in sa and "permitido" not in sd and "denegado_observado" in sd:
            cambio, att = "se corto", "alta" if sensible else "baja"
            razon = "se corto un conducto con escrituras o criticidad alta" if sensible else "se corto"
        elif "permitido" in sd and "permitido" not in sa and "denegado_observado" in sa:
            cambio, att, razon = "se abrio", "media", "se abrio"
        elif sa == sd and "permitido" in sa and reg_a != reg_d:
            cambio, att, razon = "otra regla", "baja", "otra regla lo deja pasar"
        else:
            continue
        filas.append([cambio, att, razon, _g(x, "origen_ip"), _g(x, "destino_ip"), _g(x, "servicio"),
                      _g(x, "l4"), _g(x, "puerto"), ra, rd, regla_a, regla_d])
    return filas


# ---------------------------------------------------------------- avisos de comparabilidad
def _meta(carpeta: Path) -> dict:
    j = _json(carpeta)
    e = j.get("entorno") or {}
    p = j.get("perfil") or {}
    return {"version": str(e.get("ot_assess") or ""), "cliente": str(p.get("cliente") or ""),
            "sitio": str(p.get("sitio") or ""), "plataforma": str(e.get("plataforma") or ""),
            "tipo": "diagrama" if (carpeta / "hallazgos_importados.csv").is_file() else "capturas"}


def comparar(antes, despues, umbral: float = UMBRAL_DEFECTO) -> dict:
    antes, despues = Path(antes).expanduser(), Path(despues).expanduser()
    for nom, p in (("--antes", antes), ("--despues", despues)):
        if not p.is_dir():
            raise ErrorComparar(f"{nom} espera una carpeta existente: '{p}'")
    if umbral <= 1:
        raise ErrorComparar("--umbral-volumen debe ser mayor que 1")
    avisos: list = []
    ma, md = _meta(antes), _meta(despues)
    if ma["version"] and md["version"] and ma["version"] != md["version"]:
        avisos.append(f"Versiones distintas de la herramienta ({ma['version']} y {md['version']}): "
                      "parte de los cambios pueden venir de las reglas y no del entorno.")
    if (ma["cliente"], ma["sitio"]) != (md["cliente"], md["sitio"]):
        avisos.append("Perfiles o clientes distintos entre las dos corridas.")
    if ma["tipo"] != md["tipo"]:
        avisos.append(f"Tipo de corrida distinto ({ma['tipo']} contra {md['tipo']}): la comparacion puede "
                      "no ser equivalente.")
    csvs = {}
    for nom in ("inventario", "comunicaciones", "control", "hallazgos", "firewall_contraste"):
        csvs[nom] = (leer_csv(antes, nom + ".csv"), leer_csv(despues, nom + ".csv"))
        if (csvs[nom][0] is None) != (csvs[nom][1] is None) or (
                csvs[nom][0] is None and nom != "firewall_contraste"):
            falta = "ninguna" if csvs[nom][0] is None and csvs[nom][1] is None else (
                "la anterior" if csvs[nom][0] is None else "la posterior")
            avisos.append(f"{nom}.csv falta en {falta}: se omite esa comparacion.")
    tablas: dict = {}
    resumen: dict = {}
    ca, cd = csvs["inventario"]
    if ca is not None and cd is not None:
        filas, coinciden, chica = _activos(ca, cd, avisos)
        if chica and coinciden / chica < 0.05:
            avisos.append("Coinciden menos del 5 % de los activos de la corrida mas chica: quiza las corridas "
                          "no son comparables (una anonimizada y la otra no, o redes distintas).")
        tablas["activos"] = (COL_ACTIVOS, filas)
    ca, cd = csvs["comunicaciones"]
    conductos_a, conductos_d = ca or [], cd or []
    if ca is not None and cd is not None:
        tablas["conductos"] = (COL_CONDUCTOS, _conductos(ca, cd, umbral))
    ca, cd = csvs["control"]
    if ca is not None and cd is not None:
        tablas["escritores"] = (COL_ESCRITORES, _escritores(ca, cd))
    ca, cd = csvs["hallazgos"]
    if ca is not None and cd is not None:
        tablas["hallazgos"] = (COL_HALLAZGOS, _hallazgos(ca, cd))
    ca, cd = csvs["firewall_contraste"]
    if ca is not None and cd is not None:
        tablas["firewall"] = (COL_FIREWALL, _firewall(ca, cd, conductos_a, conductos_d))
    for nom, (cols, filas) in tablas.items():
        cuenta: dict = {}
        for f in filas:
            if f[0] == "persiste" and not f[2]:
                continue
            cuenta[f[0]] = cuenta.get(f[0], 0) + 1
        resumen[nom] = {"cambios": sum(cuenta.values()), "por_estado": cuenta,
                        "atencion_alta": sum(1 for f in filas if f[1] == "alta")}
    return {"antes": str(antes), "despues": str(despues), "umbral_volumen": umbral, "avisos": avisos,
            "resumen": resumen, "tablas": tablas, "meta": {"antes": ma, "despues": md}}


def _relevantes(nom: str, filas: list) -> list:
    """Filas con cambio (un conducto o hallazgo que persiste sin cambios no se lista), alta primero."""
    util = [f for f in filas if not (f[0] == "persiste" and not f[2])]
    return sorted(util, key=lambda f: ORDEN_ATENCION.get(f[1], 3))


# ---------------------------------------------------------------- salidas
def escribir(out: Path, r: dict) -> list:
    out.mkdir(parents=True, exist_ok=True)
    archivos = []
    for nom, (cols, filas) in r["tablas"].items():
        p = out / f"comparacion_{nom}.csv"
        with open(p, "w", newline="", encoding="utf-8-sig") as fh:
            w = csv.writer(fh)
            w.writerow(cols)
            w.writerows([[celda_csv(c) for c in f] for f in _relevantes(nom, filas)])
        archivos.append(p.name)
    js = {k: r[k] for k in ("antes", "despues", "umbral_volumen", "avisos", "resumen", "meta")}
    (out / "comparacion.json").write_text(json.dumps(js, indent=2, ensure_ascii=False), encoding="utf-8")
    (out / "comparacion.md").write_text(_md(r), encoding="utf-8")
    (out / "comparacion.html").write_text(_html(r), encoding="utf-8")
    return archivos + ["comparacion.json", "comparacion.md", "comparacion.html"]


TITULOS = {"activos": "Activos", "conductos": "Conductos", "escritores": "Escritores sobre el proceso",
           "hallazgos": "Hallazgos", "firewall": "Firewall"}


def _md(r: dict) -> str:
    L = ["# Comparacion de dos corridas", "",
         f"Antes: `{Path(r['antes']).name}` · Despues: `{Path(r['despues']).name}`", "",
         ("Evidencia tecnica de cambios entre corridas; no es un dictamen de cumplimiento. La atencion "
          "ordena la lectura y no proviene del motor de reglas."), ""]
    if r["avisos"]:
        L += ["## Avisos", ""] + [f"- {a}" for a in r["avisos"]] + [""]
    L += ["## Resumen", "", "| Seccion | Cambios | Atencion alta |", "|---|---|---|"]
    for nom, s in r["resumen"].items():
        detalle = ", ".join(f"{k}: {v}" for k, v in sorted(s["por_estado"].items()))
        L.append(f"| {TITULOS[nom]} | {s['cambios']} ({detalle}) | {s['atencion_alta']} |")
    for nom, (cols, filas) in r["tablas"].items():
        rel = _relevantes(nom, filas)
        L += ["", f"## {TITULOS[nom]}", ""]
        if not rel:
            L.append("Sin cambios.")
            continue
        corte = rel[:MAX_FILAS]
        L += ["| " + " | ".join(cols[:3] + cols[3:6]) + " |", "|" + "---|" * 6]
        for f in corte:
            L.append("| " + " | ".join(str(c).replace("|", "/") for c in f[:6]) + " |")
        if len(rel) > len(corte):
            L += ["", f"Se muestran {len(corte)} de {len(rel)} filas; detalle completo en comparacion_{nom}.csv."]
    return "\n".join(L) + "\n"


def _html(r: dict) -> str:
    h = ["<!doctype html><html lang='es'><head><meta charset='utf-8'><title>Comparacion de corridas</title>",
         f"<style>{HTML_CSS}</style></head><body><header class='port'><div class='inner'>"
         "<h1>Comparacion de dos corridas</h1><p>Evidencia tecnica de cambios; no es un dictamen de "
         "cumplimiento.</p></div></header><div class='wrap'>"]
    if r["avisos"]:
        h.append("<h2>Avisos</h2><ul>" + "".join(f"<li>{esc(a)}</li>" for a in r["avisos"]) + "</ul>")
    h.append("<div class='kpis'>" + "".join(
        f"<div class='kpi'><div class='n'>{s['cambios']}</div><div class='l'>{esc(TITULOS[n])}"
        f" ({s['atencion_alta']} alta)</div></div>" for n, s in r["resumen"].items()) + "</div>")
    for nom, (cols, filas) in r["tablas"].items():
        rel = _relevantes(nom, filas)
        h.append(f"<h2>{esc(TITULOS[nom])}</h2>")
        if not rel:
            h.append("<p class='lead'>Sin cambios.</p>")
            continue
        corte = rel[:MAX_FILAS]
        h.append("<div class='tbl'><table><thead><tr>" + "".join(f"<th>{esc(c)}</th>" for c in cols[:6]) +
                 "</tr></thead><tbody>" + "".join(
                     "<tr>" + "".join(f"<td>{esc(str(c))}</td>" for c in f[:6]) + "</tr>" for f in corte) +
                 "</tbody></table></div>")
        if len(rel) > len(corte):
            h.append(f"<p class='lead'>Se muestran {len(corte)} de {len(rel)} filas; detalle completo en "
                     f"comparacion_{esc(nom)}.csv.</p>")
    h.append("</div></body></html>")
    return "\n".join(h)
