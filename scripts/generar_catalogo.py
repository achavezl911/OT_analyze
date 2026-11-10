#!/usr/bin/env python3
"""Genera docs/CATALOGO.md desde el codigo: reglas, marcos, protocolos, puertos, opciones y columnas.

Lo que cambia con el codigo se documenta aqui y no a mano, para que la documentacion no se
desactualice. `--check` falla (codigo 1) si docs/CATALOGO.md no coincide con el codigo; lo corre
scripts/verificar.sh y tests/test_docs.py. Salida determinista: sin fechas.

    python3 scripts/generar_catalogo.py            # reescribe docs/CATALOGO.md
    python3 scripts/generar_catalogo.py --check    # solo verifica
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))
DESTINO = RAIZ / "docs" / "CATALOGO.md"

from ot_assess import __version__  # noqa: E402
from ot_assess import catalog, cobertura, standards  # noqa: E402
from ot_assess.detail import control as detalle_control  # noqa: E402
from ot_assess.rules import RULES  # noqa: E402
from ot_assess.rules.inventario import REGLAS_INVENTARIO  # noqa: E402

SIGLAS = {"mitre-ics": "M", "iec62443": "I", "nerc-cip": "C", "nist-800-82": "N", "nist-csf": "CSF"}


def tabla(cabecera: list, filas: list) -> str:
    esc = lambda x: str(x).replace("|", "\\|").replace("\n", " ")       # noqa: E731
    out = ["| " + " | ".join(cabecera) + " |", "|" + "---|" * len(cabecera)]
    out += ["| " + " | ".join(esc(c) for c in f) + " |" for f in filas]
    return "\n".join(out)


def _arbol(path: Path) -> ast.AST:
    return ast.parse(path.read_text(encoding="utf-8"))


def _hallazgos_de(fn_def: ast.FunctionDef) -> list:
    """[(severidad, titulo, categoria)] de cada llamada a finding() de una regla, en orden de aparicion."""
    llamadas = [n for n in ast.walk(fn_def)
                if isinstance(n, ast.Call) and getattr(n.func, "id", "") == "finding" and len(n.args) >= 3]
    out = []
    for n in sorted(llamadas, key=lambda c: c.lineno):      # ast.walk es en anchura, no en orden de codigo
        sev, titulo = n.args[1], n.args[2]
        cat = next((k.value for k in n.keywords if k.arg == "categoria"), None)
        out.append((sev.value if isinstance(sev, ast.Constant) else "(dinamica)",
                    titulo.value if isinstance(titulo, ast.Constant) else "(dinamico)",
                    cat.value if isinstance(cat, ast.Constant) else "Higiene"))
    return out


def seccion_reglas(registro=None, prueba="test_pipeline.py") -> str:
    # Solo test_pipeline.py corre el analisis completo; mencionar un titulo en otra prueba no demuestra la deteccion.
    registro = RULES if registro is None else registro
    pruebas = (RAIZ / "tests" / prueba).read_text(encoding="utf-8")
    arboles: dict = {}
    filas, con_prueba, total = [], 0, 0
    for i, fn in enumerate(registro, 1):
        ruta = RAIZ / (fn.__module__.replace(".", "/") + ".py")
        arboles.setdefault(ruta, _arbol(ruta))
        definicion = next(n for n in ast.walk(arboles[ruta])
                          if isinstance(n, ast.FunctionDef) and n.name == fn.__name__)
        for sev, titulo, cat in _hallazgos_de(definicion):
            refs = standards.referencias(titulo)
            marcos = "".join(SIGLAS.get(k, "+") for k in (*SIGLAS, *[e for e in standards.ESTANDARES if e not in SIGLAS])
                             if k in refs) or "-"
            probado = f'"{titulo}"' in pruebas
            total += 1
            con_prueba += probado
            filas.append([i, f"`{fn.__name__}`", fn.__module__.split(".")[-1], sev, cat, titulo,
                          "si" if probado else "**no**", marcos])
    cab = ["#", "Regla", "Modulo", "Severidad", "Categoria", "Titulo", "Deteccion probada de extremo a extremo", "Marcos"]
    return (f"{len(registro)} reglas registradas, {total} titulos de hallazgo; **{con_prueba} de {total}** se "
            f"afirman en la prueba de extremo a extremo (`tests/{prueba}`), {total - con_prueba} no. Ver docs/PRUEBAS.md, \"Brechas conocidas\".\n\n"
            "Marcos: `M` MITRE ATT&CK for ICS, `I` IEC 62443, `C` NERC CIP, `N` NIST 800-82, `CSF` NIST CSF 2.0; `-` sin referencia directa "
            "(a proposito, ver D2). El orden de la tabla es el orden de ejecucion y de los hallazgos.\n\n"
            + tabla(cab, filas))


def seccion_marcos() -> str:
    def fila(e, aviso):
        v = e.validacion
        val = v["estado"] + (f" por {v['por']}, {v['fecha']}" if v["estado"] == "revisado" else "")
        return [e.clave, e.nombre, len([x for x in e.refs.values() if x]), e.version_fuente, val, aviso]
    filas = [fila(e, e.alcance or "-") for e in standards.ESTANDARES.values()]
    filas.insert(0, fila(standards.MITRE, "Siempre presente; no se elige."))
    return tabla(["Clave", "Nombre", "Filas con referencia", "Version de la fuente", "Validacion",
                  "Aviso de alcance"], filas)


def seccion_cobertura() -> str:
    filas = []
    for p in sorted((standards.DIR_MARCOS / "cobertura").glob("*.json")):
        e = standards.ESTANDARES[p.stem]
        r = cobertura.resumen(cobertura.clasificar(cobertura.cargar(p.stem), e))
        suma = lambda k: sum(s[k] for s in r.values())      # noqa: E731
        filas.append([e.clave, e.nombre, sum(s["total"] for s in r.values()), suma(cobertura.DIRECTA),
                      suma(cobertura.APOYO), suma(cobertura.NO_EVID), f"`cobertura_{e.clave}.csv`"])
    return (cobertura.NOTA + " La clasificacion se calcula: `directa` si algun hallazgo del marco cita el "
            "requisito, `apoyo` si solo lo respaldan salidas de la herramienta, `no evidenciable` el resto.\n\n"
            + tabla(["Clave", "Marco", "Requisitos", "Directa", "Apoyo", "No evidenciable", "Salida"], filas))


def seccion_protocolos() -> str:
    filas = [[p.nombre, f"`{p.campo}`", p.puerto, len(p.codigos), "tabla `PROTOCOLOS`"] for p in detalle_control.PROTOCOLOS]
    filas.append(["CIP / EtherNet/IP", "`cip.service`", "(cualquiera)", len(detalle_control.CIP_CRITICAL),
                  "colector propio; solo peticiones (bit de respuesta 0x80 descartado)"])
    filas.append(["IEC 61850 MMS", "`mms.confirmedServiceRequest`", "(cualquiera)", "todas", "colector propio"])
    return ("Operaciones de escritura o comando que se registran en `control.csv`. La lectura no se registra.\n\n"
            + tabla(["Protocolo", "Campo de tshark", "Puerto del servidor", "Codigos", "Mecanismo"], filas))


def seccion_puertos() -> str:
    orden = {"ot": 0, "claro": 1, "it": 2}
    filas = [[p, l4, nombre, cat] for (p, l4), (nombre, cat) in
             sorted(catalog.OT_PORTS.items(), key=lambda kv: (orden[kv[1][1]], kv[0][0], kv[0][1]))]
    return ("`ot`: protocolo industrial; `claro`: administracion sin cifrar que en OT merece revision; "
            "`it`: servicio de TI relevante.\n\n" + tabla(["Puerto", "Transporte", "Servicio", "Categoria"], filas))


def seccion_cli() -> str:
    from ot_assess import cli, cli_diagrama
    partes = []
    for titulo, ap in (("`python ot_pcap_assess.py` (capturas)", cli.crear_parser()),
                       ("`python ot_pcap_assess.py diagrama` (exportaciones de plataformas)", cli_diagrama.crear_parser())):
        filas = []
        for a in ap._actions:
            if a.dest == "help":
                continue
            nombre = ", ".join(a.option_strings) or a.dest
            defecto = "-" if a.default in (None, [], False, "==SUPPRESS==") else a.default
            filas.append([f"`{nombre}`", "si" if (a.required or not a.option_strings) else "no", defecto,
                          " ".join((a.help or "").split())])
        partes.append(f"### {titulo}\n\n" + tabla(["Opcion", "Obligatoria", "Por defecto", "Descripcion"], filas))
    return "\n\n".join(partes)


def _cabeceras_csv(path: Path) -> dict:
    """{archivo.csv: [columnas]} desde la primera writerow de cada `with open(... "x.csv")`."""
    out = {}
    for w in (n for n in ast.walk(_arbol(path)) if isinstance(n, ast.With)):
        ctx = w.items[0].context_expr
        if not (isinstance(ctx, ast.Call) and getattr(ctx.func, "id", "") == "open" and ctx.args):
            continue
        destino = ctx.args[0]
        nombre = destino.right.value if isinstance(destino, ast.BinOp) and isinstance(destino.right, ast.Constant) else None
        if not nombre or not str(nombre).endswith(".csv"):
            continue
        llamada = next((n for n in ast.walk(w) if isinstance(n, ast.Call) and getattr(n.func, "attr", "") == "writerow"), None)
        if llamada is None:
            continue
        cols = [c.value for c in ast.walk(llamada.args[0]) if isinstance(c, ast.Constant) and isinstance(c.value, str)]
        if any(isinstance(c, ast.ListComp) for c in ast.walk(llamada.args[0])):
            cols.append("(+ una columna por marco elegido)")
        out[nombre] = cols
    return out


def seccion_salidas() -> str:
    cab = {**_cabeceras_csv(RAIZ / "ot_assess/report/csvout.py"), **_cabeceras_csv(RAIZ / "ot_assess/cli_diagrama.py")}
    filas = [[f"`{n}`", ", ".join(f"`{c}`" if not c.startswith("(") else c for c in cols)] for n, cols in sorted(cab.items())]
    base = next(n for n in ast.walk(_arbol(RAIZ / "ot_assess/rules/base.py"))
                if isinstance(n, ast.FunctionDef) and n.name == "finding")
    claves = [k.value for d in ast.walk(base) if isinstance(d, ast.Dict) for k in d.keys if isinstance(k, ast.Constant)]
    return (tabla(["Archivo", "Columnas (en orden)"], filas)
            + "\n\nCada hallazgo (`finding()` en `ot_assess/rules/base.py`, tambien en `resultado.json`) tiene las claves: "
            + ", ".join(f"`{k}`" for k in claves) + ". `referencias` es un dict {clave de marco: texto}.")


def generar() -> str:
    return "\n\n".join([
        "# Catalogo generado del codigo",
        f"> **No editar a mano.** Lo genera `scripts/generar_catalogo.py` (version del codigo: {__version__}). "
        "Si cambias una regla, un puerto, una opcion o una columna: ejecuta el script. "
        "`scripts/verificar.sh` y `tests/test_docs.py` fallan si este archivo esta desactualizado.",
        "## Reglas de hallazgo\n\n" + seccion_reglas(),
        "## Reglas sobre inventario importado\n\nReglas que corren sobre los activos y conductos de una exportacion de "
        "plataforma (sin captura). Heredan las referencias de las reglas de captura por el fragmento del titulo.\n\n"
        + seccion_reglas(REGLAS_INVENTARIO, "test_inventario.py"),
        "## Marcos de referencia\n\n" + seccion_marcos(),
        "## Cobertura por marco\n\n" + seccion_cobertura(),
        "## Operaciones de control detectadas\n\n" + seccion_protocolos(),
        "## Puertos y servicios del catalogo\n\n" + seccion_puertos(),
        "## Opciones de linea de comandos\n\n" + seccion_cli(),
        "## Archivos de salida\n\n" + seccion_salidas(),
    ]) + "\n"


def main() -> int:
    texto = generar()
    if "--check" in sys.argv:
        if not DESTINO.exists() or DESTINO.read_text(encoding="utf-8") != texto:
            print("[!] docs/CATALOGO.md esta desactualizado: ejecuta python3 scripts/generar_catalogo.py")
            return 1
        print("[ok] docs/CATALOGO.md al dia")
        return 0
    DESTINO.write_text(texto, encoding="utf-8")
    print(f"[ok] {DESTINO.relative_to(RAIZ)} generado")
    return 0


if __name__ == "__main__":
    sys.exit(main())
