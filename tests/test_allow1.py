"""ALLOW1 (D133): allowlist TO-BE con el vocabulario y las columnas del proyecto, y traslado entre corridas.

Sin tshark: la corrida usa el subcomando diagrama con exportaciones sinteticas de xDome (misma construccion del TO-BE
que la corrida de capturas).
"""
from __future__ import annotations

import contextlib
import csv
import io
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))
sys.path.insert(0, str(RAIZ / "tests"))

import gen_exports
from test_rm1 import _error, _perfil
from test_zonas import _inventario_xdome

from ot_assess import allowlist_proyecto as ap
from ot_assess import i18n
from ot_assess import tobe as tb
from ot_assess.cli_diagrama import main as main_diagrama

DEC3 = {"permitir": "Allow", "por DMZ": "Review", "revisar": "Review", "bloquear": "Deny"}


def _escribir(ruta: Path, filas: list, sep=",", bom=False) -> Path:
    buf = io.StringIO()
    csv.writer(buf, delimiter=sep).writerows(filas)
    ruta.write_bytes((b"\xef\xbb\xbf" if bom else b"") + buf.getvalue().encode("utf-8"))
    return ruta


def _leer(ruta: Path) -> list:
    with open(ruta, encoding="utf-8-sig", newline="") as fh:
        return list(csv.DictReader(fh))


class Base(unittest.TestCase):
    def setUp(self):
        i18n.usar("es")
        self.addCleanup(i18n.usar, "es")
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.n = 0
        com = gen_exports.xd_escribir_comunicaciones(self.tmp / "com.csv", [
            gen_exports.xd_fila("10.10.1.10", "10.10.2.20", "From A to B", 502, "Modbus", tipo_a="HMI", tipo_b="PLC"),
            gen_exports.xd_fila("10.10.1.10", "10.10.2.20", "From A to B", 502, "Modbus", "2026-11-03",
                                tipo_a="HMI", tipo_b="PLC"),
            gen_exports.xd_fila("10.10.1.10", "10.10.3.30", "From A to B", 445, "N/A")])
        inv = _inventario_xdome(self.tmp / "inv.csv", [("HMI-1", "10.10.1.10", "Operacion"),
                                                       ("PLC-1", "10.10.2.20", "Campo"),
                                                       ("SRV-1", "10.10.3.30", "Planta")])
        self.base = ["--activos", str(inv), "--enlaces", str(com), "--formato", "xdome"]

    def perfil(self, **extra) -> str:
        p = self.tmp / f"perfil{len(list(self.tmp.glob('perfil*')))}.json"
        p.write_text(json.dumps({"version": 1, "cliente": "ACME", "marcos": [{"clave": "iec62443"}], **extra}),
                     encoding="utf-8")
        return str(p)

    def correr(self, *extra, codigo=0) -> Path:
        self.n += 1
        out = self.tmp / f"out{self.n}"
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            if codigo:
                with self.assertRaises(SystemExit) as cm:
                    main_diagrama([*self.base, "-o", str(out), *extra])
                self.assertEqual(cm.exception.code, codigo)
            else:
                self.assertEqual(main_diagrama([*self.base, "-o", str(out), *extra]), 0)
        return out


class ValidacionTest(unittest.TestCase):
    def malo(self, v, fragmento):
        msg = _error({"allowlist_tobe": v})
        self.assertIn(fragmento, msg, msg)

    def test_validos(self):
        cfg = _perfil({"allowlist_tobe": {}})["allowlist_tobe"]
        self.assertEqual(cfg["decisiones_equipo"], ["permitir", "por DMZ", "revisar", "bloquear"])
        self.assertEqual(cfg["columnas_equipo"], ["funcion", "frecuencia", "owner", "necesidad"])
        cfg = _perfil({"allowlist_tobe": {"decisiones": DEC3}})["allowlist_tobe"]
        self.assertEqual(cfg["decisiones_equipo"], ["Allow", "Review", "Deny"])
        cfg = _perfil({"allowlist_tobe": {"decisiones": DEC3, "decisiones_equipo": ["Si", "No"],
                                          "columnas_equipo": ["a"]}})["allowlist_tobe"]
        self.assertEqual((cfg["decisiones_equipo"], cfg["columnas_equipo"]), (["Si", "No"], ["a"]))

    def test_invalidos(self):
        self.malo([], "debe ser un objeto")
        self.malo({"otra": 1}, "clave desconocida")
        self.malo({"decisiones": {"permitir": "A"}}, "cuatro claves")
        self.malo({"decisiones": {**DEC3, "bloquear": ""}}, "1 a 30")
        self.malo({"decisiones": {**DEC3, "bloquear": "x" * 31}}, "1 a 30")
        self.malo({"decisiones": {**DEC3, "bloquear": 3}}, "1 a 30")
        self.malo({"decisiones": dict.fromkeys(DEC3, "Igual")}, "menos de 2")
        self.malo({"decisiones_equipo": ["solo"]}, "2 a 8")
        self.malo({"decisiones_equipo": [str(i) for i in range(9)]}, "2 a 8")
        self.malo({"decisiones_equipo": ["a", "a"]}, "repetidas")
        self.malo({"decisiones_equipo": ["a", " b"]}, "1 a 30")
        self.malo({"columnas_equipo": []}, "1 a 10")
        self.malo({"columnas_equipo": [f"c{i}" for i in range(11)]}, "1 a 10")
        self.malo({"columnas_equipo": ["Mayus"]}, "no es un nombre valido")
        self.malo({"columnas_equipo": ["a", "a"]}, "repetidos")
        self.malo({"columnas_equipo": ["servicio"]}, "choca")
        self.malo({"columnas_equipo": ["observado"]}, "choca")


class ColumnasTest(Base):
    def test_defecto(self):
        o = self.correr("--perfil", self.perfil(allowlist_tobe={}))
        filas = _leer(o / tb.ARCHIVO_ALLOW)
        self.assertEqual(list(filas[0]), tb.COLUMNAS + ["id_flujo", "decision_proyecto", "decision_equipo", "funcion",
                                                        "frecuencia", "owner", "necesidad", "observado"])
        for f in filas:
            self.assertEqual(f["decision_proyecto"], f["decision"])
            self.assertEqual((f["observado"], f["decision_equipo"], f["funcion"]), ("si", "", ""))
            self.assertRegex(f["id_flujo"], r"^FL-[0-9a-f]{8}$")
        self.assertEqual(len({f["id_flujo"] for f in filas}), len(filas))

    def test_propias(self):
        o = self.correr("--perfil", self.perfil(allowlist_tobe={
            "decisiones": DEC3, "decisiones_equipo": ["Si", "No"], "columnas_equipo": ["quien", "cada_cuanto"]}))
        filas = _leer(o / tb.ARCHIVO_ALLOW)
        self.assertEqual(list(filas[0])[len(tb.COLUMNAS):], ["id_flujo", "decision_proyecto", "decision_equipo", "quien",
                                                             "cada_cuanto", "observado"])
        self.assertEqual(sorted((f["servicio"], f["decision"], f["decision_proyecto"]) for f in filas),
                         [("445", "revisar", "Review"), ("502", "permitir", "Allow")])

    def test_id_estable_entre_corridas(self):
        pf = self.perfil(allowlist_tobe={})
        a = _leer(self.correr("--perfil", pf) / tb.ARCHIVO_ALLOW)
        b = _leer(self.correr("--perfil", pf) / tb.ARCHIVO_ALLOW)
        self.assertEqual([f["id_flujo"] for f in a], [f["id_flujo"] for f in b])
        f = a[0]
        self.assertEqual(f["id_flujo"], ap.id_flujo(f["zona_origen"], f["zona_destino"], f["servicio"]))
        self.assertEqual(ap.id_flujo("A", "B", "tcp/1"), ap.id_flujo("A", "B", "tcp/1"))
        self.assertNotEqual(ap.id_flujo("A", "B", "tcp/1"), ap.id_flujo("B", "A", "tcp/1"))

    def test_encabezados_propios_no_se_traducen_en_ingles(self):
        o = self.correr("--idioma", "en", "--perfil", self.perfil(allowlist_tobe={}))
        cab = list(_leer(o / tb.ARCHIVO_ALLOW)[0])
        en = i18n.catalogo("en")
        self.assertEqual(cab[len(tb.COLUMNAS):],
                         [en["id_flujo"], en["decision_proyecto"], en["decision_equipo"], "funcion", "frecuencia",
                          "owner", "necesidad", en["observado"]])
        self.assertNotIn(en["funcion"], cab)       # "funcion" tiene traduccion en el catalogo: aqui no se aplica


class ImportacionTest(Base):
    def setUp(self):
        super().setUp()
        self.pf = self.perfil(allowlist_tobe={"decisiones": DEC3})
        self.o1 = self.correr("--perfil", self.pf)
        self.plantilla = _leer(self.o1 / tb.ARCHIVO_ALLOW)

    def llenar(self, sep=",", bom=False, nueva=True, cabecera=None) -> Path:
        cab = list(self.plantilla[0])
        filas = [dict(f) for f in self.plantilla]
        for f in filas:
            f["decision_equipo"] = "Allow" if f["servicio"] == "502" else "Deny"
            f["funcion"] = "Control " + f["servicio"]
            f["owner"] = "OT"
            f["estado_revision"] = "revisado"
            f["comentario"] = "ok; con punto y coma"
        if nueva:
            filas.append({c: "" for c in cab} | {"zona_origen": "Operacion", "zona_destino": "Planta",
                                                  "servicio": "tcp/9999", "decision_equipo": "Allow",
                                                  "funcion": "Respaldo mensual", "frecuencia": "mensual"})
        cab_sal = cabecera or cab
        return _escribir(self.tmp / "rev.csv", [cab_sal, *([f[c] for c in cab] for f in filas)], sep=sep, bom=bom)

    def test_traslada_y_conserva_no_observados(self):
        o = self.correr("--perfil", self.pf, "--allowlist-revision", str(self.llenar()))
        filas = _leer(o / tb.ARCHIVO_ALLOW)
        self.assertEqual(len(filas), 3)
        por = {f["servicio"]: f for f in filas}
        self.assertEqual((por["502"]["decision_equipo"], por["502"]["funcion"], por["502"]["observado"]),
                         ("Allow", "Control 502", "si"))
        self.assertEqual((por["445"]["decision_equipo"], por["445"]["estado_revision"]), ("Deny", "revisado"))
        self.assertEqual(por["445"]["comentario"], "ok; con punto y coma")
        nuevo = filas[-1]
        self.assertEqual((nuevo["servicio"], nuevo["observado"], nuevo["decision"], nuevo["decision_proyecto"],
                          nuevo["funcion"], nuevo["frecuencia"], nuevo["decision_equipo"]),
                         ("tcp/9999", "no", "", "", "Respaldo mensual", "mensual", "Allow"))
        self.assertEqual(nuevo["id_flujo"], ap.id_flujo("Operacion", "Planta", "tcp/9999"))

    def test_ida_y_vuelta_identica(self):
        r = self.llenar()
        o2 = self.correr("--perfil", self.pf, "--allowlist-revision", str(r))
        o3 = self.correr("--perfil", self.pf, "--allowlist-revision", str(o2 / tb.ARCHIVO_ALLOW))
        self.assertEqual((o2 / tb.ARCHIVO_ALLOW).read_bytes(), (o3 / tb.ARCHIVO_ALLOW).read_bytes())

    def test_formatos(self):
        ref = (self.correr("--perfil", self.pf, "--allowlist-revision", str(self.llenar()))
               / tb.ARCHIVO_ALLOW).read_bytes()
        for kw in ({"sep": ";"}, {"bom": True}, {"sep": ";", "bom": True}):
            with self.subTest(kw):
                o = self.correr("--perfil", self.pf, "--allowlist-revision", str(self.llenar(**kw)))
                self.assertEqual((o / tb.ARCHIVO_ALLOW).read_bytes(), ref)

    def test_cabeceras_en_ingles(self):
        en = i18n.catalogo("en")
        cab = [en.get(c, c) for c in self.plantilla[0]]
        r = self.llenar(cabecera=cab)
        ref = self.correr("--perfil", self.pf, "--allowlist-revision", str(self.llenar()))
        o = self.correr("--perfil", self.pf, "--allowlist-revision", str(r))
        self.assertEqual((o / tb.ARCHIVO_ALLOW).read_bytes(), (ref / tb.ARCHIVO_ALLOW).read_bytes())

    def test_sin_id_se_une_por_zonas_y_servicio(self):
        r = self.llenar(nueva=False)
        filas = _leer(r)
        for f in filas:
            f["id_flujo"] = ""
        cab = list(filas[0])
        _escribir(r, [cab, *([f[c] for c in cab] for f in filas)])
        o = self.correr("--perfil", self.pf, "--allowlist-revision", str(r))
        self.assertEqual({f["servicio"]: f["funcion"] for f in _leer(o / tb.ARCHIVO_ALLOW)},
                         {"502": "Control 502", "445": "Control 445"})

    def test_solo_la_opcion_activa_la_funcion_con_valores_por_defecto(self):
        r = _escribir(self.tmp / "m.csv", [["id_flujo", "decision_equipo", "owner"],
                                            [self.plantilla[0]["id_flujo"], "permitir", "OT"]])
        o = self.correr("--allowlist-revision", str(r))
        f = _leer(o / tb.ARCHIVO_ALLOW)
        self.assertIn("id_flujo", f[0])
        self.assertEqual(sum(1 for x in f if x["owner"] == "OT" and x["decision_equipo"] == "permitir"), 1)

    def test_errores_dan_codigo_2_sin_salidas(self):
        idf = self.plantilla[0]["id_flujo"]
        casos = {
            "no_existe.csv": None,
            "sin_llave.csv": [["decision_equipo"], ["Allow"]],
            "repetido.csv": [["id_flujo", "owner"], [idf, "a"], [idf, "b"]],
            "repetido_zonas.csv": [["zona_origen", "zona_destino", "servicio"], ["A", "B", "1"], ["A", "B", "1"]],
            "decision.csv": [["id_flujo", "decision_equipo"], [idf, "Quizas"]],
            "largo.csv": [["id_flujo", "owner"], [idf, "x" * 501]],
        }
        for nombre, filas in casos.items():
            ruta = self.tmp / nombre
            if filas is not None:
                _escribir(ruta, filas)
            out = self.tmp / ("err_" + nombre)
            with self.subTest(nombre), contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as cm:
                main_diagrama([*self.base, "-o", str(out), "--perfil", self.pf, "--allowlist-revision", str(ruta)])
            self.assertEqual(cm.exception.code, 2)
            self.assertFalse(out.exists() and any(out.iterdir()))


class SalidasTest(Base):
    def test_frase_y_json_con_conteos_y_matriz_diagrama_sin_no_observados(self):
        pf = self.perfil(allowlist_tobe={"decisiones": DEC3})
        plantilla = _leer(self.correr("--perfil", pf) / tb.ARCHIVO_ALLOW)
        cab = list(plantilla[0])
        por = {f["servicio"]: f for f in plantilla}
        filas = [
            {**por["502"], "decision_equipo": "Allow"},
            {c: "" for c in cab} | {"zona_origen": "Operacion", "zona_destino": "Planta", "servicio": "tcp/9999",
                                    "decision_equipo": "Deny"}]
        r = _escribir(self.tmp / "r.csv", [cab, *([f[c] for c in cab] for f in filas)])
        sin = self.correr("--perfil", self.perfil())
        con =self.correr("--perfil", pf, "--allowlist-revision", str(r))
        j = json.loads((con / "resultado.json").read_text(encoding="utf-8"))["tobe"]["allowlist_proyecto"]
        self.assertEqual(j, {"por_decision_proyecto": {"Allow": 1, "Review": 1, "Deny": 0},
                             "por_decision_equipo": {"Allow": 1, "Review": 0, "Deny": 1},
                             "pendientes": 1, "no_observados": 1})
        frase = "Decision del proyecto: Allow 1, Review 1, Deny 0. Decision del equipo: Allow 1, Review 0, Deny 1"
        for patron in ("*.md", "*.html"):
            self.assertIn(frase, "".join(p.read_text(encoding="utf-8") for p in con.glob(patron)))
        self.assertEqual((con / tb.ARCHIVO_MATRIZ).read_bytes(), (sin / tb.ARCHIVO_MATRIZ).read_bytes())
        self.assertEqual((con / "diagrama_tobe.svg").read_bytes(), (sin / "diagrama_tobe.svg").read_bytes())
        self.assertNotIn("9999", (con / "diagrama_tobe.svg").read_text(encoding="utf-8"))

    def test_ingles_sin_faltantes(self):
        i18n.FALTANTES.clear()
        o = self.correr("--idioma", "en", "--perfil", self.perfil(allowlist_tobe={}))
        html = (o / "reporte_ot.html").read_text(encoding="utf-8")
        self.assertIn("Project decision:", html)
        self.assertEqual({x for x in i18n.FALTANTES if "ecision" in x or "flujo" in x}, set())

    def test_sin_clave_ni_opcion_salidas_de_hoy(self):
        a, b = self.correr(), self.correr()
        con = self.correr("--perfil", self.perfil(allowlist_tobe={}))
        filas = _leer(a / tb.ARCHIVO_ALLOW)
        self.assertEqual(list(filas[0]), tb.COLUMNAS)
        self.assertTrue(all(f[c] == "" for f in filas for c in tb.COLUMNAS[-4:]))
        for n in (tb.ARCHIVO_ALLOW, tb.ARCHIVO_MATRIZ):
            self.assertEqual((a / n).read_bytes(), (b / n).read_bytes())
        self.assertEqual((a / tb.ARCHIVO_MATRIZ).read_bytes(), (con / tb.ARCHIVO_MATRIZ).read_bytes())
        ja = json.loads((a / "resultado.json").read_text(encoding="utf-8"))
        self.assertNotIn("allowlist_proyecto", ja["tobe"])
        self.assertNotIn("allowlist_revision", ja["entorno"])
        ha = (a / "reporte_ot.html").read_text(encoding="utf-8")
        self.assertNotIn("Decision del proyecto", ha)
        self.assertEqual(ha, (b / "reporte_ot.html").read_text(encoding="utf-8"))
        # con la funcion, lo de hoy queda como prefijo de la allowlist
        extendida = _leer(con / tb.ARCHIVO_ALLOW)
        self.assertEqual([{c: f[c] for c in tb.COLUMNAS} for f in extendida], filas)

    def test_entorno_registra_el_sha256_del_archivo(self):
        r = _escribir(self.tmp / "r.csv", [["id_flujo"], ["FL-00000000"]])
        o = self.correr("--allowlist-revision", str(r))
        ent = json.loads((o / "resultado.json").read_text(encoding="utf-8"))["entorno"]["allowlist_revision"]
        self.assertEqual(ent["archivo"], "r.csv")
        self.assertRegex(ent["sha256"], r"^[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main()


class SinFlujosObservadosTest(unittest.TestCase):
    def test_la_allowlist_lleva_solo_los_flujos_del_archivo(self):
        ident = ap.id_flujo("A", "B", "tcp/502")
        reg = {"zona_origen": "A", "zona_destino": "B", "servicio": "tcp/502", "decision_equipo": "permitir",
               "funcion": "respaldo mensual", "frecuencia": "", "owner": "", "necesidad": "",
               "estado_revision": "", "revisado_por": "", "fecha": "", "comentario": ""}
        tobe = tb._vacio(0)
        avisos = ap.combinar(tobe, ap.Plan(ap.defecto(), {ident: reg}))
        self.assertEqual(len(avisos), 1)
        tablas = tb.tablas(tobe)
        self.assertEqual([x[0] for x in tablas], [tb.ARCHIVO_ALLOW])
        cab, filas = tablas[0][2], tablas[0][3]
        self.assertEqual(len(filas), 1)
        fila = dict(zip([str(c) for c in cab], filas[0]))
        self.assertEqual((fila["id_flujo"], fila["zona_origen"], fila["funcion"], fila["observado"]),
                         (ident, "A", "respaldo mensual", "no"))
        self.assertEqual(tb.tablas(tb._vacio(0)), [])
