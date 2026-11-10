"""Solicitud de Cambio (RFC) generica desde la politica propuesta y las rutas propuestas (SC1, D61).

Entradas: los CSV que el analista ya reviso (M3a/F5c). Salidas: .docx, .md y un CSV con un renglon por cambio.
La estructura (secciones, titulos, columnas, textos fijos) vive en data/solicitud_cambio.json; el codigo solo llena
cada seccion por su clave. No se conecta a nada ni afirma cumplimiento de normas.
"""
from __future__ import annotations

import csv
import re
from datetime import datetime
from pathlib import Path

from . import json_entrada
from .firewalls import exportar, fmc
from .firewalls import politica as pol
from .report import docx as _docx

DEFECTO = Path(__file__).parent / "data" / "solicitud_cambio.json"
CLAVES_SECCION = ("datos_generales", "descripcion", "alcance", "impacto", "plan", "pruebas", "reversion",
                  "aprobaciones", "anexos")
CLAVES_COLUMNA = ("id", "fase", "tipo", "accion", "elemento", "detalle", "justificacion", "riesgo", "validacion",
                  "reversion")
CLAVES_DATOS = ("folio", "fecha", "solicitante", "cliente_sitio", "equipo", "tipo_cambio", "ventana", "duracion")
CLAVES_SUP = ("version", "titulo", "secciones", "columnas_csv", "columnas_alcance", "encabezados", "datos_generales",
              "textos", "fases", "dias_observacion", "acciones", "aprobaciones")
FASE_CAMPOS = ("titulo", "descripcion", "criterio", "reversion")
ACCION_CAMPOS = ("riesgo", "validacion", "reversion")
COL_RUTAS = ("red", "interfaz", "siguiente_salto", "tipo", "accion", "razon", "conductos", "salto_en_arp")
COL_COMPARACION = tuple(pol.COL_COMPARACION)
COL_BLOQUEADOS = tuple(pol.COL_BLOQUEADOS)
ARCHIVOS_FMC = ("fmc_objetos.json", "fmc_reglas.json", "aplicar_fmc.py", "LEEME_FMC.txt")
MAX_BLOQUEADOS = 30
SALIDAS = ("solicitud_cambio.docx", "solicitud_cambio.md", "solicitud_cambio_cambios.csv")
_FORMULA = re.compile(r"^[=+\-@\t\r]")
_NUM = re.compile(r"^-?\d+([.,]\d+)?$")


class ErrorSC(Exception):
    """Entrada o plantilla que no se puede usar; el mensaje es para el analista."""


class _Seguro(dict):
    def __missing__(self, k):
        return "{" + k + "}"


def _fmt(texto: str, **kw) -> str:
    try:
        return texto.format_map(_Seguro(kw))
    except (ValueError, IndexError, AttributeError, KeyError) as e:
        raise ErrorSC(f"texto de la plantilla con llaves no validas: {texto[:60]!r} ({type(e).__name__})")


# ---------------------------------------------------------------- plantilla
def _leer_json(ruta) -> dict:
    try:
        d = json_entrada.cargar(Path(ruta).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as e:
        raise ErrorSC(f"no pude leer la plantilla {ruta}: {type(e).__name__}")
    if not isinstance(d, dict):
        raise ErrorSC("la plantilla debe ser un objeto JSON.")
    return d


def _txt_dict(d, donde: str, claves=None) -> dict:
    if not isinstance(d, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in d.items()):
        raise ErrorSC(f"plantilla: '{donde}' debe ser un objeto de textos.")
    if claves is not None:
        mal = [k for k in d if k not in claves]
        if mal:
            raise ErrorSC(f"plantilla: claves desconocidas en '{donde}': {', '.join(mal)}")
    return d


def _columnas(v, donde: str) -> list:
    if not isinstance(v, list) or not v or any(c not in CLAVES_COLUMNA for c in v):
        raise ErrorSC(f"plantilla: '{donde}' debe ser una lista no vacia de columnas validas "
                      f"({', '.join(CLAVES_COLUMNA)}).")
    return list(v)


def cargar_plantilla(ruta=None) -> dict:
    """Estructura por defecto, o la de `ruta` superpuesta: las claves de texto se completan con las de defecto."""
    base = _leer_json(DEFECTO)
    if ruta is None:
        return base
    t = _leer_json(ruta)
    mal = [k for k in t if k not in CLAVES_SUP]
    if mal:
        raise ErrorSC("plantilla: claves desconocidas: " + ", ".join(mal))
    if "secciones" in t:
        sec = t["secciones"]
        if not isinstance(sec, list) or not sec:
            raise ErrorSC("plantilla: 'secciones' debe ser una lista no vacia de {clave, titulo}.")
        vistas = set()
        for s in sec:
            if not isinstance(s, dict) or set(s) != {"clave", "titulo"} or not isinstance(s["titulo"], str) \
                    or not s["titulo"].strip():
                raise ErrorSC("plantilla: cada seccion debe ser {\"clave\": ..., \"titulo\": ...}.")
            if s["clave"] not in CLAVES_SECCION:
                raise ErrorSC(f"plantilla: clave de seccion desconocida '{s['clave']}' "
                              f"(validas: {', '.join(CLAVES_SECCION)}).")
            if s["clave"] in vistas:
                raise ErrorSC(f"plantilla: clave de seccion repetida '{s['clave']}'.")
            vistas.add(s["clave"])
        base["secciones"] = sec
    for k in ("columnas_csv", "columnas_alcance"):
        if k in t:
            base[k] = _columnas(t[k], k)
    if "titulo" in t:
        base["titulo"] = _txt_dict({"titulo": t["titulo"]}, "titulo")["titulo"]
    if "dias_observacion" in t:
        base["dias_observacion"] = _txt_dict({"d": t["dias_observacion"]}, "dias_observacion")["d"]
    if "encabezados" in t:
        base["encabezados"].update(_txt_dict(t["encabezados"], "encabezados", CLAVES_COLUMNA))
    if "textos" in t:
        base["textos"].update(_txt_dict(t["textos"], "textos", base["textos"]))
    if "datos_generales" in t:
        dg = t["datos_generales"]
        if not isinstance(dg, dict) or any(k not in ("tipo_cambio", "campos", "pendiente") for k in dg):
            raise ErrorSC("plantilla: 'datos_generales' solo admite tipo_cambio, campos y pendiente.")
        if "campos" in dg:
            c = dg["campos"]
            if not isinstance(c, list) or not c or any(
                    not isinstance(x, dict) or set(x) != {"clave", "etiqueta"} or x["clave"] not in CLAVES_DATOS
                    or not isinstance(x["etiqueta"], str) for x in c):
                raise ErrorSC("plantilla: 'datos_generales.campos' debe ser una lista de {clave, etiqueta} "
                              f"con clave entre {', '.join(CLAVES_DATOS)}.")
        for k in ("tipo_cambio", "pendiente"):
            if k in dg:
                _txt_dict({k: dg[k]}, "datos_generales." + k)
        base["datos_generales"].update(dg)
    if "fases" in t:
        fs = t["fases"]
        if not isinstance(fs, list) or [f.get("id") if isinstance(f, dict) else None for f in fs] != [1, 2, 3, 4]:
            raise ErrorSC("plantilla: 'fases' debe traer las fases con id 1, 2, 3 y 4, en ese orden.")
        for f in fs:
            _txt_dict({k: v for k, v in f.items() if k != "id"}, "fases", FASE_CAMPOS)
            if any(k not in f for k in FASE_CAMPOS):
                raise ErrorSC("plantilla: cada fase necesita " + ", ".join(FASE_CAMPOS) + ".")
        base["fases"] = fs
    if "acciones" in t:
        ac = t["acciones"]
        if not isinstance(ac, dict):
            raise ErrorSC("plantilla: 'acciones' debe ser un objeto.")
        for a, v in ac.items():
            if a not in base["acciones"]:
                raise ErrorSC(f"plantilla: accion desconocida '{a}'.")
            _txt_dict(v, "acciones." + a, ACCION_CAMPOS)
            base["acciones"][a].update(v)
    if "aprobaciones" in t:
        ap = t["aprobaciones"]
        if not isinstance(ap, dict) or any(k not in ("columnas", "roles") for k in ap) or any(
                not isinstance(v, list) or not v or any(not isinstance(x, str) for x in v) for v in ap.values()):
            raise ErrorSC("plantilla: 'aprobaciones' solo admite 'columnas' y 'roles' (listas de textos).")
        base["aprobaciones"].update(ap)
    if "version" in t:
        base["version"] = t["version"]
    return base


# ------------------------------------------------------------------ entradas
def leer_entradas(prop, objs, comparacion=None, rutas=None, bloqueados=None) -> dict:
    """Lee y valida los CSV. ErrorSC si falta una columna o un archivo."""
    try:
        p, o = fmc.leer_entradas(prop, objs)
        c = fmc._leer(comparacion, COL_COMPARACION) if comparacion else None
        r = fmc._leer(rutas, COL_RUTAS) if rutas else None
        b = fmc._leer(bloqueados, COL_BLOQUEADOS) if bloqueados else None
    except fmc.ErrorFmc as e:
        raise ErrorSC(str(e))
    return {"prop": p, "objs": o, "comparacion": c, "rutas": r, "bloqueados": b}


# ------------------------------------------------------------------- cambios
def _desc_obj(o: dict) -> str:
    return o["tipo"] + " " + (o["valor"] or ("miembros: " + o["miembros"].replace(";", ", ")))


def _lado(lista) -> str:
    return ", ".join(lista) if lista else "cualquiera"


def _entero(v) -> int:
    try:
        return int(str(v).strip())
    except ValueError:
        return 0


def archivos_carga(formato: str) -> list:
    if formato == "fmc":
        return list(ARCHIVOS_FMC)
    return [exportar.ARCHIVO[formato], exportar.LEEME_ARCHIVO[formato]]


def construir_cambios(res: dict, ent: dict, tpl: dict) -> tuple:
    """-> (cambios, sin_evidencia). Cambio = dict con CLAVES_COLUMNA y marcas internas '_...'; uno por fase."""
    acc = tpl["acciones"]
    cambios: list = []

    def nuevo(fase, tipo, accion, elemento, detalle, just, **extra):
        a = acc[accion]
        c = {"id": "", "fase": fase, "tipo": tipo, "accion": accion, "elemento": elemento, "detalle": detalle,
             "justificacion": just, "riesgo": a["riesgo"], "validacion": a["validacion"], "reversion": a["reversion"]}
        c.update(extra)
        cambios.append(c)

    nuevo(1, "politica", "crear politica", res["politica"], "Politica de acceso nueva, con registro, sin asignar.",
          "Sustituye a la politica vigente solo si se asigna en una fase posterior acordada.")
    ob = res["objetos"]
    for h in ob["hosts"]:
        nuevo(1, "objeto", "crear objeto", h["name"], "host " + h["value"], "Usado por las reglas nuevas.")
    for n in ob["redes"]:
        nuevo(1, "objeto", "crear objeto", n["name"], "red " + n["value"], "Usado por las reglas nuevas.")
    for g in ob["grupos_red"]:
        nuevo(1, "objeto", "crear objeto", g["name"], "grupo de red: " + ", ".join(x["name"] for x in g["objects"]),
              "Usado por las reglas nuevas.")
    for s in ob["servicios"]:
        nuevo(1, "objeto", "crear objeto", s["name"], f"servicio {s['protocol'].lower()}/{s['port']}",
              "Usado por las reglas nuevas.")
    for g in ob["grupos_servicio"]:
        nuevo(1, "objeto", "crear objeto", g["name"],
              "grupo de servicios: " + ", ".join(x["name"] for x in g["objects"]), "Usado por las reglas nuevas.")
    for r in res["reglas"]:
        det = (f"{_lado(r['sourceZones'])} -> {_lado(r['destinationZones'])}: {_lado(r['sourceNetworks'])} -> "
               f"{_lado(r['destinationNetworks'])} ({_lado(r['destinationPorts'])}); permitir con registro")
        just = (r["newComments"] or ["Conducto observado en la ventana de las fuentes."])[0]
        fila = {"_regla": r["name"], "_habilitada": r["enabled"]}
        nuevo(1, "regla", "crear regla" if r["enabled"] else "crear regla deshabilitada", r["name"], det, just, **fila)
    for r in res["reglas"]:
        if not r["enabled"]:
            nuevo(2, "regla", "habilitar regla", r["name"],
                  "Habilitar solo si la observacion confirma el conducto; la razon de revision esta en el comentario.",
                  (r["newComments"] or [""])[0], _regla=r["name"])

    sin_evidencia: list = []
    for f in ent["comparacion"] or []:
        est, aci = f["estado"], f["aciertos"].strip()
        base_just = (f"estado: {est}; aciertos: {aci or 'sin dato'}; conductos observados: "
                     f"{f['conductos_observados']}" + (f"; reglas propuestas: {f['reglas_propuestas']}"
                                                      if f["reglas_propuestas"] else "")
                     + (f"; {f['comentario']}" if f["comentario"] else ""))
        elem = (f["regla_actual"] + " " + f["nombre"]).strip()
        extra = {"_aciertos": _entero(aci), "_conductos": _entero(f["conductos_observados"]), "_actual": elem}
        if est == pol.E_REEMPLAZADA:
            nuevo(3, "regla actual", "deshabilitar regla actual", elem, "Cubierta por reglas de la politica nueva.",
                  base_just, **extra)
        elif est == pol.E_ACOTAR:
            nuevo(3, "regla actual", "acotar regla actual", elem, "Mas amplia que lo observado: acotar a los "
                  "conductos de las reglas propuestas.", base_just, **extra)
        elif est == pol.E_ELIMINAR:
            nuevo(3, "regla actual", "eliminar regla actual", elem, "Sin aciertos y sin conductos observados.",
                  base_just, **extra)
        elif est == pol.E_VALIDAR:
            cero = aci == "0" and "sin contadores" not in f["comentario"]
            if cero:
                nuevo(3, "regla actual", "eliminar regla actual", elem, "Validada con cero aciertos.", base_just,
                      **extra)
            else:
                sin_evidencia.append(elem)
        # bloqueos (explicitos o sustituidos por la accion por defecto): no se tocan

    for f in ent["rutas"] or []:
        a = f["accion"].strip().lower()
        if a not in ("eliminar", "revisar"):
            continue
        det = f"siguiente salto {f['siguiente_salto'] or 'sin dato'} por {f['interfaz'] or 'sin dato'}; tipo {f['tipo']}"
        just = f["razon"] + (f"; conductos observados: {f['conductos']}" if f["conductos"] else "")
        nuevo(4, "ruta", "eliminar ruta" if a == "eliminar" else "revisar ruta", f["red"], det, just,
              _conductos=_entero(f["conductos"]), _ruta=f)
    cambios.sort(key=lambda c: c["fase"])      # estable: conserva el orden dentro de cada fase
    for i, c in enumerate(cambios, 1):
        c["id"] = f"SC-{i:03d}"
    return cambios, sin_evidencia


# ------------------------------------------------------------------- bloques
def _tabla_cambios(cambios, cols, tpl):
    return ("tabla", [tpl["encabezados"][c] for c in cols], [[c[k] for k in cols] for c in cambios])


def _sec_datos(ctx, tpl, cambios, sin_ev):
    dg = tpl["datos_generales"]
    pend = dg["pendiente"]
    cs = " / ".join(x for x in (ctx.get("cliente"), ctx.get("sitio")) if x) or pend
    v = {"folio": "", "fecha": ctx["fecha"], "solicitante": ctx.get("solicitante") or pend, "cliente_sitio": cs,
         "equipo": ctx.get("firewall") or pend, "tipo_cambio": dg["tipo_cambio"],
         "ventana": ctx.get("ventana") or pend, "duracion": pend}
    return [("tabla", ["Campo", "Valor"], [[c["etiqueta"], v[c["clave"]]] for c in dg["campos"]])]


def _sec_descripcion(ctx, tpl, cambios, sin_ev):
    res, ent, t = ctx["res"], ctx["ent"], tpl["textos"]
    n_perm = sum(1 for r in res["reglas"] if r["enabled"])
    n_rev = len(res["reglas"]) - n_perm
    n_obj = sum(len(v) for v in res["objetos"].values())
    lin = [f"Reglas nuevas con decision permitir: {n_perm}",
           f"Reglas nuevas por revisar (deshabilitadas): {n_rev}",
           f"Reglas propuestas a bloquear (no se crea regla; las cubre la accion por defecto): "
           f"{res['omitidas']['bloquear']}",
           f"Objetos nuevos: {n_obj}"]
    if ent["comparacion"] is None:
        lin.append("Reglas actuales por estado de la comparacion: no se proporciono politica_comparacion.csv")
    else:
        cuenta: dict = {}
        for f in ent["comparacion"]:
            cuenta[f["estado"]] = cuenta.get(f["estado"], 0) + 1
        lin.append("Reglas actuales por estado de la comparacion: "
                   + ("; ".join(f"{k}: {n}" for k, n in sorted(cuenta.items())) or "sin reglas"))
    if ent["rutas"] is None:
        lin.append("Rutas por accion: no se proporcionaron rutas propuestas")
    else:
        cuenta = {}
        for f in ent["rutas"]:
            cuenta[f["accion"]] = cuenta.get(f["accion"], 0) + 1
        lin.append("Rutas por accion: " + ("; ".join(f"{k}: {n}" for k, n in sorted(cuenta.items())) or "sin rutas"))
    bl = [("p", t["descripcion_intro"]), ("lista", lin), ("p", t["descripcion_por_que"]), ("nota", pol.NOTA)]
    if sin_ev:
        bl.append(("p", f"Reglas actuales 'validar antes de eliminar' sin evidencia de cero aciertos, fuera de esta "
                        f"solicitud ({len(sin_ev)}): " + ", ".join(sin_ev[:20]) + (", ..." if len(sin_ev) > 20 else "")))
    return bl


def _sec_alcance(ctx, tpl, cambios, sin_ev):
    t = tpl["textos"]
    bl = [("p", t["alcance_intro"])]
    for f in tpl["fases"]:
        sub = [c for c in cambios if c["fase"] == f["id"]]
        bl.append(("h2", f["titulo"]))
        bl.append(_tabla_cambios(sub, tpl["columnas_alcance"], tpl) if sub else ("p", t["alcance_vacio"]))
    return bl


def _sec_impacto(ctx, tpl, cambios, sin_ev):
    t, ent = tpl["textos"], ctx["ent"]
    bl = [("p", t["impacto_riesgo"]), ("h2", t["impacto_bloqueados_titulo"])]
    if ent["bloqueados"] is None:
        bl.append(("p", t["impacto_bloqueados_sin_archivo"]))
    elif not ent["bloqueados"]:
        bl.append(("p", t["impacto_bloqueados_vacio"]))
    else:
        cols = ("servicio", "origenes", "destinos", "conductos", "bytes", "razon", "regla_actual")
        filas = ent["bloqueados"][:MAX_BLOQUEADOS]
        bl.append(("tabla", [c.replace("_", " ") for c in cols], [[f[c] for c in cols] for f in filas]))
        if len(ent["bloqueados"]) > len(filas):
            bl.append(("nota", f"Se muestran {len(filas)} de {len(ent['bloqueados'])}; el resto esta en "
                               "politica_bloqueados.csv."))
    bl.append(("h2", t["impacto_reglas_titulo"]))
    if ent["comparacion"] is None:
        bl.append(("p", t["impacto_reglas_sin_archivo"]))
    else:
        rs = [c for c in cambios if c["fase"] == 3 and c.get("_aciertos", 0) > 0]
        bl.append(("tabla", ["Regla actual", "Accion", "Aciertos", "Conductos observados"],
                   [[c["elemento"], c["accion"], c["_aciertos"], c["_conductos"]] for c in rs])
                  if rs else ("p", t["impacto_reglas_vacio"]))
    bl.append(("h2", t["impacto_rutas_titulo"]))
    if ent["rutas"] is None:
        bl.append(("p", t["impacto_rutas_sin_archivo"]))
    else:
        rs = [c for c in cambios if c["fase"] == 4 and c.get("_conductos", 0) > 0]
        bl.append(("tabla", ["Red", "Accion", "Conductos", "Detalle"],
                   [[c["elemento"], c["accion"], c["_conductos"], c["detalle"]] for c in rs])
                  if rs else ("p", t["impacto_rutas_vacio"]))
    return bl


def _sec_plan(ctx, tpl, cambios, sin_ev):
    bl = []
    arch = ", ".join(archivos_carga(ctx["formato"]))
    for f in tpl["fases"]:
        bl.append(("h2", f["titulo"]))
        bl.append(("p", _fmt(f["descripcion"], politica=ctx["res"]["politica"], formato=ctx["formato"], archivos=arch,
                             dias=tpl["dias_observacion"])))
        sub = [c for c in cambios if c["fase"] == f["id"]]
        bl.append(("tabla", [tpl["encabezados"][k] for k in ("id", "accion", "elemento")],
                   [[c["id"], c["accion"], c["elemento"]] for c in sub]) if sub
                  else ("p", tpl["textos"]["alcance_vacio"]))
    return bl


def _valor_obj(ctx, nombre: str) -> str:
    o = ctx["objetos"].get(nombre)
    if not o:
        return nombre
    return f"{nombre} ({o['valor'] or o['miembros'].replace(';', ', ')})"


def _sec_pruebas(ctx, tpl, cambios, sin_ev):
    t = tpl["textos"]
    reglas = [r for r in ctx["res"]["reglas"]]
    bl = [("p", t["pruebas_intro"])]
    if reglas:
        filas = []
        for r in reglas:
            filas.append([r["name"], ", ".join(_valor_obj(ctx, x) for x in r["sourceNetworks"]) or "cualquiera",
                          ", ".join(_valor_obj(ctx, x) for x in r["destinationNetworks"]) or "cualquiera",
                          ", ".join(_valor_obj(ctx, x) for x in r["destinationPorts"]) or "cualquier puerto",
                          t["pruebas_donde"] + ("" if r["enabled"] else " (regla deshabilitada: confirmar antes de "
                                                                          "habilitar)")])
        bl.append(("tabla", ["Regla", "Origen", "Destino", "Servicio", "Donde confirmar"], filas))
    else:
        bl.append(("p", t["pruebas_vacio"]))
    bl.append(("h2", t["pruebas_criterio_titulo"]))
    bl.append(("lista", [f["titulo"] + ": " + f["criterio"] for f in tpl["fases"]]))
    return bl


def _sec_reversion(ctx, tpl, cambios, sin_ev):
    t = tpl["textos"]
    bl = [("p", t["reversion_intro"])]
    for f in tpl["fases"]:
        sub = [c for c in cambios if c["fase"] == f["id"]]
        bl.append(("h2", f["titulo"]))
        bl.append(("p", _fmt(f["reversion"], politica=ctx["res"]["politica"], formato=ctx["formato"],
                             archivos="", dias=tpl["dias_observacion"])))
        if not sub:
            bl.append(("p", t["no_aplica"]))
        elif f["id"] == 4:
            bl.append(("tabla", ["Red", "Siguiente salto", "Interfaz", "Accion"],
                       [[c["_ruta"]["red"], c["_ruta"]["siguiente_salto"], c["_ruta"]["interfaz"], c["accion"]]
                        for c in sub]))
        else:
            bl.append(("lista", [f"{c['accion']}: {c['elemento']}" for c in sub]))
    return bl


def _sec_aprobaciones(ctx, tpl, cambios, sin_ev):
    ap = tpl["aprobaciones"]
    ncol = len(ap["columnas"])
    return [("p", tpl["textos"]["aprobaciones_intro"]),
            ("tabla", ap["columnas"], [[r] + [""] * (ncol - 1) for r in ap["roles"]])]


def _sec_anexos(ctx, tpl, cambios, sin_ev):
    t = tpl["textos"]
    return [("p", t["anexos_entrada"] + ":"), ("lista", ctx["entradas"]),
            ("p", t["anexos_carga"] + ":"), ("lista", archivos_carga(ctx["formato"])),
            ("nota", _fmt(t["anexos_carga_nota"], formato=ctx["formato"]))]


_SECCIONES = {"datos_generales": _sec_datos, "descripcion": _sec_descripcion, "alcance": _sec_alcance,
              "impacto": _sec_impacto, "plan": _sec_plan, "pruebas": _sec_pruebas, "reversion": _sec_reversion,
              "aprobaciones": _sec_aprobaciones, "anexos": _sec_anexos}


def construir_bloques(ctx: dict, tpl: dict, cambios: list, sin_ev: list) -> list:
    bloques: list = [("titulo", tpl["titulo"])]
    for s in tpl["secciones"]:
        bloques.append(("h1", s["titulo"]))
        bloques.extend(_SECCIONES[s["clave"]](ctx, tpl, cambios, sin_ev))
    return bloques


# ------------------------------------------------------------------- salidas
def _me(x) -> str:
    """Escapa texto para markdown: caracteres con significado y HTML."""
    s = str(x).replace("\r", " ").replace("\n", " ")
    for a, b in (("\\", "\\\\"), ("&", "&amp;"), ("<", "&lt;"), (">", "&gt;"), ("|", "\\|"), ("*", "\\*"),
                 ("`", "\\`")):
        s = s.replace(a, b)
    return s


def a_markdown(bloques: list) -> str:
    out: list = []
    for b in bloques:
        k = b[0]
        if k == "titulo":
            out.append("# " + _me(b[1]))
        elif k == "h1":
            out.append("## " + _me(b[1]))
        elif k == "h2":
            out.append("### " + _me(b[1]))
        elif k == "p":
            out.append(_me(b[1]))
        elif k == "nota":
            out.append("_" + _me(b[1]) + "_")
        elif k == "lista":
            out.append("\n".join("- " + _me(x) for x in b[1]))
        elif k == "tabla":
            cab = list(b[1])
            filas = ["| " + " | ".join(_me(c) for c in cab) + " |", "|" + "---|" * len(cab)]
            for f in b[2]:
                f = list(f) + [""] * (len(cab) - len(f))
                filas.append("| " + " | ".join(_me(c) for c in f) + " |")
            out.append("\n".join(filas))
    return "\n\n".join(out) + "\n"


def _celda_csv(v) -> str:
    s = str(v)
    if _FORMULA.match(s) and not _NUM.match(s):
        return "'" + s
    return s


def escribir(carpeta, bloques: list, cambios: list, tpl: dict) -> list:
    carpeta = Path(carpeta)
    carpeta.mkdir(parents=True, exist_ok=True)
    _docx.escribir_docx(carpeta / SALIDAS[0], bloques)
    (carpeta / SALIDAS[1]).write_text(a_markdown(bloques), encoding="utf-8")
    cols = tpl["columnas_csv"]
    with open(carpeta / SALIDAS[2], "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh)
        w.writerow([tpl["encabezados"][c] for c in cols])
        for c in cambios:
            w.writerow([_celda_csv(c[k]) for k in cols])
    return list(SALIDAS)


def generar(ent: dict, tpl: dict, politica: str, formato: str = "fmc", cliente: str = "", sitio: str = "",
            firewall: str = "", solicitante: str = "", ventana: str = "", fecha: str = None,
            entradas: list = None) -> dict:
    """-> {"bloques", "cambios", "res"}. ErrorSC si la propuesta no se puede construir (mismas reglas que politica-fmc)."""
    try:
        res = fmc.construir(ent["prop"], ent["objs"], politica, incluir_revisar=True)
    except fmc.ErrorFmc as e:
        raise ErrorSC(str(e))
    cambios, sin_ev = construir_cambios(res, ent, tpl)
    ctx = {"res": res, "ent": ent, "formato": formato, "cliente": cliente, "sitio": sitio, "firewall": firewall,
           "solicitante": solicitante, "ventana": ventana, "fecha": fecha or datetime.now().strftime("%Y-%m-%d"),
           "objetos": {o["nombre"]: o for o in ent["objs"] if o["nombre"]}, "entradas": entradas or []}
    return {"bloques": construir_bloques(ctx, tpl, cambios, sin_ev), "cambios": cambios, "res": res}
