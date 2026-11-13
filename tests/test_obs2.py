"""OBS2 (D135): clases de obsolescencia del proyecto (umbral, fin de venta, etiquetas). Datos sinteticos."""
from __future__ import annotations

import contextlib
import csv
import datetime
import io
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from typing import ClassVar

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))
sys.path.insert(0, str(RAIZ / "tests"))

from test_obsolescencia import REF, _activo, _tabla
from test_rm1 import _error

from ot_assess import i18n
from ot_assess import inventario_normalizado as inv
from ot_assess import obsolescencia as ob
from ot_assess.cli_diagrama import main as main_diagrama


def _rep(config, filas_eos, ref=REF, n=1):
    """Un activo Acme/ZX-100 con la tabla del analista `filas_eos` (fin, venta)."""
    tmp = tempfile.mkdtemp()
    try:
        tabla = _tabla(tmp, [["Acme", "ZX-100", "", fin, venta, "t"] for fin, venta in filas_eos],
                       cab=("fabricante", "producto", "version", "fecha_fin_soporte", "fecha_fin_venta", "fuente"))
        filas, _ = ob.cargar_analista(tabla)
    finally:
        shutil.rmtree(tmp, True)
    activos = [_activo(i + 1, fabricante="Acme", modelo="ZX-100", firmware="1.0") for i in range(n)]
    return ob.construir(inv.construir(activos), filas, ref, "fin de la captura", config)


def _estado(config, fin, venta="", ref=REF):
    return _rep(config, [(fin, venta)], ref)["filas"][0]["estado"]


class ValidacionTest(unittest.TestCase):
    def test_validos(self):
        for d in ({}, {"meses_proximo": 1}, {"meses_proximo": 60, "fin_de_venta": False},
                  {"fin_de_venta": True, "clases": {ob.F_VENTA: "Discontinuado", ob.F_VENCIDO: "Obsoleto"}}):
            self.assertEqual(_error({"obsolescencia": d}), "", d)

    def test_cada_error(self):
        for d in ([], {"meses_proximo": 0}, {"meses_proximo": 61}, {"meses_proximo": "12"},
                  {"meses_proximo": True}, {"meses_proximo": 1.5}, {"fin_de_venta": "si"}, {"clases": []},
                  {"clases": {"inventado": "X"}}, {"clases": {ob.F_VENTA: "X"}},      # sin fin_de_venta
                  {"clases": {ob.F_VENCIDO: ""}}, {"clases": {ob.F_VENCIDO: "x" * 41}},
                  {"clases": {ob.F_VENCIDO: 3}}, {"otra": 1}):
            self.assertIn("obsolescencia", _error({"obsolescencia": d}), d)

    def test_la_clave_pasa_al_perfil(self):
        from test_rm1 import _perfil
        p = _perfil({"obsolescencia": {"meses_proximo": 6, "clases": {ob.F_VENCIDO: " Obsoleto "}}})
        self.assertEqual(p["obsolescencia"], {"meses_proximo": 6, "clases": {ob.F_VENCIDO: "Obsoleto"}})


    def test_clase_con_el_texto_de_sus_meses(self):
        from test_rm1 import _perfil
        p = _perfil({"obsolescencia": {"meses_proximo": 18,
                                       "clases": {"fin de soporte en 18 meses o menos": "Cercano"}}})
        self.assertEqual(p["obsolescencia"]["clases"], {ob.F_PRONTO: "Cercano"})
        self.assertIn("obsolescencia", _error({"obsolescencia": {
            "meses_proximo": 6, "clases": {"fin de soporte en 18 meses o menos": "Cercano"}}}))


class UmbralTest(unittest.TestCase):
    def test_bordes_seis_doce_y_dieciocho_meses(self):
        for meses, dentro, fuera in ((6, "2027-05-07", "2027-05-08"), (12, "2027-11-07", "2027-11-08"),
                                     (18, "2028-05-07", "2028-05-08")):
            cfg = {"meses_proximo": meses}
            self.assertEqual(_estado(cfg, dentro), ob._txt_pronto(meses), meses)
            self.assertEqual(_estado(cfg, fuera), ob.F_VIGENTE, meses)

    def test_doce_meses_conserva_el_texto_de_hoy(self):
        self.assertEqual(ob._txt_pronto(12), ob.F_PRONTO)
        self.assertEqual(_estado({"meses_proximo": 12}, "2027-11-07"), ob.F_PRONTO)
        self.assertEqual(_estado({"meses_proximo": 18}, "2028-05-07"), "fin de soporte en 18 meses o menos")

    def test_29_de_febrero_y_fin_de_mes(self):
        ref = datetime.date(2028, 2, 29)
        self.assertEqual(ob._mas_meses(ref, 12), datetime.date(2029, 2, 28))
        self.assertEqual(ob._mas_meses(ref, 6), datetime.date(2028, 8, 29))
        self.assertEqual(ob._mas_meses(datetime.date(2026, 8, 31), 6), datetime.date(2027, 2, 28))
        self.assertEqual(ob._mas_meses(datetime.date(2026, 11, 30), 3), datetime.date(2027, 2, 28))
        cfg = {"meses_proximo": 6}
        self.assertEqual(_estado(cfg, "2028-08-29", ref=ref), ob._txt_pronto(6))
        self.assertEqual(_estado(cfg, "2028-08-30", ref=ref), ob.F_VIGENTE)
        c12 = {"meses_proximo": 12}
        self.assertEqual(_estado(c12, "2029-02-28", ref=ref), ob.F_PRONTO)
        self.assertEqual(_estado(c12, "2029-03-01", ref=ref), ob.F_VIGENTE)

    def test_hallazgo_con_los_meses_del_proyecto(self):
        rep = _rep({"meses_proximo": 18}, [("2028-05-07", "")])
        extra = ob.agregar_hallazgos([], rep)
        self.assertEqual([h["titulo"] for h in extra.findings], ["Equipos con fin de soporte en los proximos 18 meses"])
        self.assertEqual(rep["resumen"]["meses_proximo"], 18)
        self.assertIn("fin de soporte en 18 meses o menos", rep["resumen"]["por_estado"])
        self.assertNotIn(ob.F_PRONTO, rep["resumen"]["por_estado"])


class FinDeVentaTest(unittest.TestCase):
    CFG: ClassVar[dict] = {"fin_de_venta": True}

    def test_venta_pasada_con_soporte_vigente(self):
        rep = _rep(self.CFG, [("2030-01-01", "2024-06-30")])
        self.assertEqual(rep["filas"][0]["estado"], ob.F_VENTA)
        self.assertEqual(rep["resumen"]["por_estado"][ob.F_VENTA], 1)

    def test_venta_futura_o_sin_fecha_sigue_con_soporte(self):
        self.assertEqual(_estado(self.CFG, "2030-01-01", "2029-01-01"), ob.F_VIGENTE)
        self.assertEqual(_estado(self.CFG, "2030-01-01", ""), ob.F_VIGENTE)
        self.assertEqual(_estado(self.CFG, "2030-01-01", REF.isoformat()), ob.F_VIGENTE)     # hoy no ha pasado

    def test_el_umbral_y_el_vencido_mandan_sobre_la_venta(self):
        self.assertEqual(_estado(self.CFG, "2027-01-01", "2020-01-01"), ob.F_PRONTO)
        self.assertEqual(_estado(self.CFG, "2020-01-01", "2019-01-01"), ob.F_VENCIDO)

    def test_sin_la_opcion_la_venta_no_cuenta(self):
        self.assertEqual(_estado({}, "2030-01-01", "2024-06-30"), ob.F_VIGENTE)
        self.assertNotIn(ob.F_VENTA, _rep({}, [("2030-01-01", "2024-06-30")])["resumen"]["por_estado"])

    def test_hallazgo_nuevo(self):
        rep = _rep(self.CFG, [("2030-01-01", "2024-06-30")], n=2)
        extra = ob.agregar_hallazgos([], rep)
        h = extra.findings[0]
        self.assertEqual((h["titulo"], h["severidad"], h["categoria"]), (ob.TIT_VENTA, "Baja", "Obsolescencia"))
        self.assertEqual(h["activos"], ["192.0.2.1", "192.0.2.2"])
        self.assertIn("EQ-1", h["evidencia"])
        self.assertIn("2024-06-30", h["evidencia"])
        self.assertTrue(h["referencias"])
        self.assertIsNone(ob.agregar_hallazgos([], _rep({}, [("2030-01-01", "2024-06-30")])))


class ClasesTest(unittest.TestCase):
    def test_etiquetas_en_csv_y_conteo(self):
        cfg = {"fin_de_venta": True, "clases": {ob.F_VENCIDO: "Obsoleto", ob.F_VENTA: "Discontinuado",
                                                ob.F_SIN_DATO: "Sin informacion", ob.F_SIN_VERSION: "Sin informacion"}}
        rep = _rep(cfg, [("2020-01-01", "2019-01-01")], n=2)
        t = ob.tablas(rep)[0]
        self.assertEqual(t[2][-2:], ["clase_proyecto", "fecha_fin_venta"])
        self.assertEqual(next(f[-2:] for f in t[3]), ["Obsoleto", "2019-01-01"])
        cl = rep["resumen"]["clases"]
        self.assertEqual(cl["Obsoleto"], 2)                       # el conteo sale del reporte construido
        self.assertEqual(cl["Sin informacion"], 0)

    def test_etiquetas_repetidas_suman_y_las_que_faltan_conservan_el_nombre(self):
        cfg = {"clases": {ob.F_SIN_DATO: "Sin informacion", ob.F_SIN_VERSION: "Sin informacion"}}
        activos = [_activo(1, fabricante="Zeta", modelo="Q1", firmware="1"), _activo(2)]
        rep = ob.construir(inv.construir(activos), [], REF, "x", cfg)
        self.assertEqual(rep["resumen"]["clases"]["Sin informacion"], 2)
        self.assertEqual(rep["resumen"]["clases"][ob.F_VENCIDO], 0)
        self.assertEqual({f["celdas"][-1] for f in rep["filas"]}, {"Sin informacion"})

    def test_seccion_con_conteo_por_clase(self):
        rep = _rep({"clases": {ob.F_VENCIDO: "Obsoleto"}}, [("2020-01-01", "")])
        filas = ob.seccion(rep)["tabla"][1]
        self.assertIn(["clase del proyecto", "Obsoleto", 1], filas)
        self.assertIn(["clase del proyecto", ob.F_VIGENTE, 0], filas)

    def test_ingles_traduce_la_clase_sin_etiqueta_propia(self):
        i18n.usar("en")
        self.addCleanup(i18n.usar, "es")
        rep = _rep({"fin_de_venta": True}, [("2020-01-01", "")])
        fila = ob.tablas(rep)[0][3][0]
        i_est = ob.COLUMNAS.index("estado")
        self.assertNotEqual(fila[i_est], ob.F_VENCIDO)
        self.assertEqual(fila[len(ob.COLUMNAS)], fila[i_est])

    def test_ingles_no_traduce_las_etiquetas_del_proyecto(self):
        i18n.usar("en")
        self.addCleanup(i18n.usar, "es")
        i18n.FALTANTES.clear()
        rep = _rep({"meses_proximo": 18, "fin_de_venta": True, "clases": {ob.F_VENCIDO: "Obsoleto",
                                                                           ob.F_PRONTO: "Cercano"}},
                   [("2020-01-01", "")], n=1)
        filas = ob.seccion(rep)["tabla"][1]
        self.assertIn(["project class", "Obsoleto", 1], filas)
        self.assertIn(["project class", "Cercano", 0], filas)
        self.assertIn(["status", "end of support within 18 months", 0], filas)
        self.assertIn(["status", "end of sale (still supported)", 0], filas)
        self.assertEqual(ob.tablas(rep)[0][2][-2:], ["clase_proyecto", "fecha_fin_venta"])
        self.assertEqual(i18n.t(ob._tit_proximo(18)), "Equipment reaching end of support within 18 months")
        self.assertEqual(sorted(i18n.FALTANTES), [])


class ExtremoAExtremoTest(unittest.TestCase):
    def setUp(self):
        i18n.usar("es")
        self.addCleanup(i18n.usar, "es")
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.n = 0
        (self.tmp / "a.csv").write_text(
            "Name,IP,Vendor,Model,Firmware,OS\nPLC-1,10.10.2.20,Acme,ZX-100,1.0,\nHMI-1,10.10.1.10,Beta,,,Windows 7\n",
            encoding="utf-8")
        (self.tmp / "e.csv").write_text(
            "Source,Destination,Port,Protocol,Packets\n10.10.1.10,10.10.2.20,502,Modbus,100\n", encoding="utf-8")
        # fin de soporte a 8 meses de hoy y venta ya pasada: cae segun el umbral
        fin = ob._mas_meses(datetime.date.today(), 8).isoformat()
        self.eos = _tabla(self.tmp, [["Acme", "ZX-100", "", fin, "2020-01-01", "t"]],
                          cab=("fabricante", "producto", "version", "fecha_fin_soporte", "fecha_fin_venta", "fuente"))

    def correr(self, obs=None, idioma="es"):
        self.n += 1
        d = {"version": 1, "cliente": "C", "marcos": [{"clave": "iec62443"}], "idioma": idioma}
        if obs is not None:
            d["obsolescencia"] = obs
        p = self.tmp / f"p{self.n}.json"
        p.write_text(json.dumps(d), encoding="utf-8")
        out = self.tmp / f"o{self.n}"
        with contextlib.redirect_stdout(io.StringIO()):
            rc = main_diagrama(["--activos", str(self.tmp / "a.csv"), "--enlaces", str(self.tmp / "e.csv"),
                                "--formato", "generico", "--perfil", str(p), "--fin-de-soporte", self.eos,
                                "-o", str(out)])
        self.assertEqual(rc, 0)
        return out

    @staticmethod
    def titulos(out):
        with open(out / "hallazgos.csv", encoding="utf-8-sig", newline="") as fh:
            return [f["titulo"] for f in csv.DictReader(fh)]

    def test_sin_la_clave_salidas_identicas_a_hoy(self):
        a = self.correr()
        for nombre in ("obsolescencia.csv", "hallazgos.csv"):
            cab = (a / nombre).read_text(encoding="utf-8-sig").splitlines()[0]
            self.assertNotIn("clase_proyecto", cab)
        self.assertIn(ob.TIT_PROXIMO, self.titulos(a))        # 8 meses cae en el umbral de hoy (12)
        r = json.loads((a / "resultado.json").read_text(encoding="utf-8"))["obsolescencia"]
        self.assertEqual(set(r), {"filas", "activos", "por_estado", "referencia", "referencia_origen",
                                  "filas_analista"})
        self.assertEqual(list(r["por_estado"]), list(ob.ESTADOS))
        # la clave vacia ({}) solo agrega las columnas y el conteo; los hallazgos y el estado no cambian
        b = self.correr({})
        self.assertEqual(self.titulos(a), self.titulos(b))
        with open(a / "obsolescencia.csv", encoding="utf-8-sig", newline="") as fh:
            fa = list(csv.reader(fh))
        with open(b / "obsolescencia.csv", encoding="utf-8-sig", newline="") as fh:
            fb = list(csv.reader(fh))
        self.assertEqual([x[:len(fa[0])] for x in fb], fa)
        self.assertEqual(fb[0][-1], "clase_proyecto")

    def test_con_la_clave_csv_json_html_y_hallazgo_de_venta(self):
        o = self.correr({"meses_proximo": 6, "fin_de_venta": True,
                         "clases": {ob.F_VENTA: "Discontinuado", ob.F_VIGENTE: "Vigente", ob.F_SIN_DATO: "Sin informacion"}})
        with open(o / "obsolescencia.csv", encoding="utf-8-sig", newline="") as fh:
            filas = {f["nombre"]: f for f in csv.DictReader(fh)}
        self.assertEqual((filas["PLC-1"]["estado"], filas["PLC-1"]["clase_proyecto"], filas["PLC-1"]["fecha_fin_venta"]),
                         (ob.F_VENTA, "Discontinuado", "2020-01-01"))
        self.assertEqual(filas["HMI-1"]["clase_proyecto"], ob.F_VENCIDO)        # sin etiqueta: nombre de la herramienta
        r = json.loads((o / "resultado.json").read_text(encoding="utf-8"))["obsolescencia"]
        self.assertEqual(r["meses_proximo"], 6)
        self.assertEqual(r["clases"]["Discontinuado"], 1)
        self.assertIn(ob.TIT_VENTA, self.titulos(o))
        self.assertNotIn(ob.TIT_PROXIMO, self.titulos(o))             # 8 meses queda fuera del umbral de 6
        html = (o / "reporte_ot.html").read_text(encoding="utf-8")
        self.assertIn("Discontinuado", html)
        self.assertIn("Equipos en fin de venta con soporte vigente", (o / "reporte_ot.md").read_text(encoding="utf-8"))

    def test_ingles_extremo_a_extremo(self):
        i18n.FALTANTES.clear()
        o = self.correr({"meses_proximo": 18, "fin_de_venta": True, "clases": {ob.F_VENCIDO: "Obsoleto"}}, "en")
        head = (o / "obsolescencia.csv").read_text(encoding="utf-8-sig").splitlines()[0]
        self.assertTrue(head.endswith("project_class,end_of_sale_date"))
        self.assertIn("Obsoleto", (o / "obsolescencia.csv").read_text(encoding="utf-8-sig"))
        self.assertEqual(sorted(i18n.FALTANTES), [])


class PlaybookTest(unittest.TestCase):
    def test_playbook_con_cualquier_umbral_y_de_fin_de_venta(self):
        from ot_assess import playbooks
        for meses in (6, 12, 18):
            self.assertEqual(playbooks.para_titulo(ob._tit_proximo(meses)), "pb-fin-de-soporte-proximo")
        self.assertEqual(playbooks.para_titulo(ob.TIT_VENTA), "pb-fin-de-venta")


if __name__ == "__main__":
    unittest.main()
