"""Consolidado multi-sitio (M1, D94): carpetas sinteticas, sin tshark."""
import contextlib
import csv
import hashlib
import io
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ot_assess import cli, i18n
from ot_assess import sitios as st
from ot_assess.i18n import t

HALL = ["id", "captura", "severidad", "categoria", "titulo"]
RIESGO = ["id_riesgo", "id_hallazgo", "titulo", "categoria", "severidad", "zonas", "activos", "probabilidad",
          "impacto", "puntuacion", "nivel", "quick_win", "recomendacion"]
# sha256 de las salidas csv/json de (a, b, c) con el codigo de main antes de I2.
SHA_SALIDAS_ES = "ae98e4fbca228006944911f71b0a52f723f5cafc7d85f47d237db8f5346cead5"
TITULOS = {"H1": "Anomalia"}      # clave real del catalogo: en ingles es "Anomaly"
MAD = ["dominio", "nivel_actual", "nivel_objetivo", "brecha"]


def _csv(carpeta, nombre, cab, filas):
    with open(carpeta / nombre, "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh)
        w.writerow(cab)
        w.writerows(filas)


def _sitio(raiz, carpeta, sitio, hallazgos, riesgos=(), madurez=None, inv=(), vulns=(), perfil=True, idioma="es"):
    """Carpeta sintetica; con idioma en escribe cabeceras y valores como el analisis con --idioma en."""
    i18n.usar(idioma)
    try:
        return _escribir(raiz, carpeta, sitio, hallazgos, riesgos, madurez, inv, vulns, perfil, idioma)
    finally:
        i18n.usar("es")


def _escribir(raiz, carpeta, sitio, hallazgos, riesgos, madurez, inv, vulns, perfil, idioma):
    def cab(cols):
        return [str(t(c)) for c in cols]
    c = raiz / carpeta
    c.mkdir()
    if perfil:
        (c / "resultado.json").write_text(json.dumps(
            {"perfil": {"cliente": "ACME", "sitio": sitio, "idioma": idioma}, "entorno": {"ot_assess": "0.41.0"}}))
    _csv(c, "hallazgos.csv", cab(HALL), [[i, "x", t(sev), t("Segmentacion"), t(TITULOS.get(i, f"Titulo {i}"))]
                                         for i, sev in hallazgos])
    _csv(c, "riesgos.csv", cab(RIESGO), [[i, i, "T", t("Segmentacion"), t("Alta"), "", "", 3, 3, p, t("Alto"),
                                           "no", "R"] for i, p in riesgos])
    if madurez is not None:
        _csv(c, "madurez.csv", cab(MAD), [[t(m[0]), *m[1:]] for m in madurez])   # el dominio, como el analisis
    _csv(c, "inventario_normalizado.csv", cab(["id", "fabricante", "modelo", "firmware"]), inv)
    _csv(c, "vulnerabilidades_firmware.csv", cab(["cve", "cvss", "severidad", "kev", "fabricante", "modelo"]),
         [[v[0], v[1], t(v[2]), "yes" if idioma == "en" else v[3], v[4], v[5]] for v in vulns])
    return c


class TestSitios(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.raiz = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(i18n.usar, "es")
        dom = "Gestion de activos"
        self.a = _sitio(self.raiz, "a", "Norte", [("H1", "Alta"), ("H2", "Baja")], [("R1", 10), ("R2", 4)],
                        [[dom, 2, 3, 1]], [["1", "Siemens", "S7-1500", "2.9"], ["2", "Siemens", "S7-1500", "2.9"]],
                        [["CVE-1", 9.8, "Alta", "si", "Siemens", "S7-1500"]])
        self.b = _sitio(self.raiz, "b", "Sur", [("H1", "Media")], [("R3", 20)], [[dom, 4, 4, 0]],
                        [["1", "Siemens", "S7-1500", "2.9"]], [["CVE-1", 9.8, "Alta", "si", "Siemens", "S7-1500"]])
        self.c = _sitio(self.raiz, "c", "Centro", [("H1", "Alta")], [("R4", 7)], None)

    def _cli(self, *args):
        o, e = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(o), contextlib.redirect_stderr(e):
            rc = cli.main(["sitios", *map(str, args)])
        return rc, o.getvalue(), e.getvalue()

    def _tabla(self, out, nombre):
        with open(out / nombre, newline="", encoding="utf-8-sig") as fh:
            return list(csv.DictReader(fh))

    def _nombres_hojas(self, out):
        with zipfile.ZipFile(out / st.LIBRO) as z:
            x = z.read("xl/workbook.xml").decode()
        return [p.split('"')[0] for p in x.split('<sheet name="')[1:]]

    def test_hallazgo_en_varias_capturas_cuenta_una_vez_por_sitio(self):
        d = self.raiz / "d"
        d.mkdir()
        (d / "resultado.json").write_text(json.dumps({"perfil": {"sitio": "Oeste"}, "entorno": {"ot_assess": "0.41.0"}}))
        _csv(d, "hallazgos.csv", HALL, [["H1", "p1.pcap", "Media", "Cat", "T"], ["H1", "p2.pcap", "Alta", "Cat", "T"]])
        out = self.raiz / "out_d"
        rc, _o, _e = self._cli(d, self.c, "-o", out)
        self.assertEqual(rc, 0)
        fila = next(r for r in self._tabla(out, "sitios.csv") if r["sitio"] == "Oeste")
        self.assertEqual((fila["hallazgos"], fila["hallazgos_alta"], fila["hallazgos_media"]), ("1", "1", "0"))
        largo = [r for r in self._tabla(out, "hallazgos_sitios.csv") if r["sitio"] == "Oeste"]
        self.assertEqual(sorted(r["captura"] for r in largo), ["p1.pcap", "p2.pcap"])

    def test_hallazgos_comunes(self):
        out = self.raiz / "o"
        rc, _, _ = self._cli(self.a, self.b, self.c, "-o", out)
        self.assertEqual(rc, 0)
        f = self._tabla(out, "hallazgos_comunes.csv")
        self.assertEqual((f[0]["id"], f[0]["sitios"], f[0]["porcentaje_sitios"], f[0]["severidad_max"]),
                         ("H1", "3", "100%", "Alta"))
        self.assertEqual(f[0]["lista_sitios"], "Norte; Sur; Centro")
        self.assertEqual((f[1]["id"], f[1]["sitios"], f[1]["porcentaje_sitios"], f[1]["lista_sitios"]),
                         ("H2", "1", "33%", "Norte"))

    def test_madurez_ausente_aviso_y_promedio(self):
        out = self.raiz / "o"
        _, salida, _ = self._cli(self.a, self.b, self.c, "-o", out)
        self.assertIn("sitio Centro: falta madurez.csv", salida)
        self.assertIn("Madurez", self._nombres_hojas(out))
        prom = [f for f in self._tabla(out, "madurez_sitios.csv") if f["sitio"] == "Promedio"]
        self.assertEqual(prom[0]["nivel_actual"], "3.0")
        sitios = {f["sitio"]: f for f in self._tabla(out, "sitios.csv")}
        self.assertEqual(sitios["Centro"]["madurez_actual_promedio"], "")
        self.assertEqual(sitios["Norte"]["activos"], "2")
        self.assertEqual(sitios["Norte"]["kev"], "1")

    def test_nombre_repetido(self):
        d = _sitio(self.raiz, "d", "Norte", [("H9", "Baja")])
        out = self.raiz / "o"
        rc, _, err = self._cli(self.a, d, "-o", out)
        self.assertEqual(rc, 2)
        self.assertIn("--nombre", err)
        self.assertFalse(out.exists())
        rc, _, _ = self._cli(self.a, d, "--nombre", f"{d}=Norte2", "-o", out)
        self.assertEqual(rc, 0)
        self.assertEqual([f["sitio"] for f in self._tabla(out, "sitios.csv")], ["Norte", "Norte2"])

    def test_hojas_fijas_sin_opcionales(self):
        vacio = self.raiz / "v"
        vacio.mkdir()
        out = self.raiz / "o"
        rc, salida, _ = self._cli(vacio, self.c, "-o", out)
        self.assertEqual(rc, 0)
        self.assertEqual(self._nombres_hojas(out), [h for _, h, _ in st.SALIDAS])
        self.assertEqual(len(self._nombres_hojas(out)), 8)
        self.assertEqual([f["sitio"] for f in self._tabla(out, "sitios.csv")], ["v", "Centro"])
        self.assertIn("sitio v: falta hallazgos.csv", salida)

    def test_determinista(self):
        o1, o2 = self.raiz / "o1", self.raiz / "o2"
        self._cli(self.a, self.b, self.c, "-o", o1)
        self._cli(self.a, self.b, self.c, "-o", o2)
        for n in sorted(p.name for p in o1.iterdir()):
            if n.endswith((".csv", ".json")):
                self.assertEqual((o1 / n).read_bytes(), (o2 / n).read_bytes(), n)

    def test_riesgos_orden_entre_sitios(self):
        out = self.raiz / "o"
        self._cli(self.a, self.b, self.c, "-o", out)
        f = self._tabla(out, "riesgos_sitios.csv")
        self.assertEqual([(x["sitio"], x["id_riesgo"]) for x in f],
                         [("Sur", "R3"), ("Norte", "R1"), ("Centro", "R4"), ("Norte", "R2")])

    def test_idioma_en(self):
        out = self.raiz / "o"
        self._cli(self.a, self.b, "--idioma", "en", "-o", out)
        self.assertEqual(self._nombres_hojas(out)[0:2], ["Sites", "Common findings"])
        self.assertEqual(i18n.idioma(), "es")

    def test_ayuda_principal(self):
        o = io.StringIO()
        with contextlib.redirect_stdout(o), self.assertRaises(SystemExit):
            cli.main(["-h"])
        self.assertIn("sitios --help", o.getvalue())

    def test_en_json_traduce_todo(self):
        i18n.FALTANTES.clear()
        r = st.consolidar([self.a, self.b])
        st.escribir(self.raiz / "o", r, "en")
        self.assertEqual(i18n.FALTANTES, set())

    def _par(self, sufijo=""):
        """La misma carpeta en es y en en, con el mismo escritor."""
        datos = ([("H1", "Alta"), ("H2", "Baja")], [("R1", 10), ("R2", 4)], [["Gestion de activos", 2, 3, 1]],
                 [["1", "Siemens", "S7-1500", "2.9"]], [["CVE-1", 9.8, "Alta", "si", "Siemens", "S7-1500"]])
        return (_sitio(self.raiz, "pes" + sufijo, "Par", *datos),
                _sitio(self.raiz, "pen" + sufijo, "Par", *datos, idioma="en"))

    def test_carpeta_en_ingles_da_los_mismos_conteos(self):
        es, en = self._par()
        self.assertIn("severity", (en / "hallazgos.csv").read_text(encoding="utf-8-sig").splitlines()[0])
        r_es, r_en = st.consolidar([es]), st.consolidar([en])
        self.assertEqual(r_en["avisos"], r_es["avisos"])
        f_es, f_en = r_es["tablas"]["Sitios"][0], r_en["tablas"]["Sitios"][0]
        self.assertEqual(f_en[4:], f_es[4:])
        cab = dict(zip(st.CAB_SITIOS, f_en))
        self.assertEqual((cab["hallazgos_alta"], cab["hallazgos_baja"], cab["riesgos_alto"], cab["kev"],
                          cab["vulnerabilidades"], cab["activos"]), (1, 1, 2, 1, 1, 1))
        self.assertEqual(r_en["sitios"][0]["idioma"], "en")
        self.assertEqual(st.idioma_defecto(r_en), "en")
        for hoja in ("Hallazgos comunes", "Riesgos", "Vulnerabilidades", "Madurez"):
            self.assertEqual(r_en["tablas"][hoja], r_es["tablas"][hoja], hoja)

    def test_consolidado_en_ingles_traduce_valores(self):
        es, _en = self._par("v")
        st.escribir(self.raiz / "oen", st.consolidar([es]), "en")
        def leer(nombre):
            return list(csv.DictReader(open(self.raiz / "oen" / nombre, encoding="utf-8-sig")))
        com = {f["id"]: f for f in leer("hallazgos_comunes.csv")}
        self.assertEqual((com["H1"]["title"], com["H1"]["category"]), ("Anomaly", "Segmentation"))
        self.assertEqual({f["id"]: f[str(i18n.catalogo("en")["severidad_max"])] for f in com.values()},
                         {"H1": "High", "H2": "Low"})
        self.assertEqual({f["level"] for f in leer("riesgos_sitios.csv")}, {"High"})
        mad = leer("madurez_sitios.csv")
        self.assertEqual({(f["site"], f["domain"]) for f in mad},
                         {("Par", "Asset management"), ("Average", "Asset management")})
        self.assertEqual([f["kev"] for f in leer("vulnerabilidades_sitios.csv")], ["yes"])
        self.assertEqual(i18n.idioma(), "es")

    def test_mezcla_es_y_en(self):
        en = _sitio(self.raiz, "me", "Este", [("H1", "Media")], [("R9", 5)], None, idioma="en")
        r = st.consolidar([en, self.a])
        com = {f[0]: f for f in r["tablas"]["Hallazgos comunes"]}
        self.assertEqual((com["H1"][1], com["H1"][3], com["H1"][4], com["H1"][6]), ("Anomalia", "Alta", 2, "Este; Norte"))
        self.assertEqual(com["H1"][2], "Segmentacion")
        self.assertEqual([s for s in r["avisos"] if "idiomas distintos" in s],
                         [("las carpetas estan en idiomas distintos (en, es): se normalizaron al idioma del "
                           "consolidado (los titulos sin traduccion exacta quedan como vienen)")])
        sitios = {f[0]: f for f in r["tablas"]["Sitios"]}
        self.assertEqual(dict(zip(st.CAB_SITIOS, sitios["Este"]))["hallazgos_media"], 1)
        # un titulo sin traduccion exacta queda como viene
        self.assertEqual({f[5] for f in r["tablas"]["Hallazgos por sitio"] if f[0] == "Norte"},
                         {"Anomalia", "Titulo H2"})

    def test_en_sin_hallazgos_o_con_columna_faltante_avisa(self):
        d = _sitio(self.raiz, "x1", "Sin", [("H1", "Alta")], [("R1", 1)], None, idioma="en")
        (d / "hallazgos.csv").unlink()
        txt = (d / "riesgos.csv").read_text(encoding="utf-8-sig").replace("score", "puntaje")
        (d / "riesgos.csv").write_text(txt, encoding="utf-8-sig")
        r = st.consolidar([d])
        self.assertIn("sitio Sin: falta hallazgos.csv", r["avisos"])
        self.assertIn("sitio Sin: a riesgos.csv le falta la columna puntuacion", r["avisos"])
        self.assertEqual(r["sitios"][0]["idioma"], "en")      # sin hallazgos.csv manda el perfil

    def test_carpetas_en_espanol_igual_que_main(self):
        out = self.raiz / "o"
        self._cli(self.a, self.b, self.c, "-o", out)
        h = hashlib.sha256()
        for n in sorted(p.name for p in out.iterdir() if p.suffix in (".csv", ".json")):
            b = (out / n).read_bytes()
            if n == st.JSON:        # SALP1 (D121): "uso" es la unica clave nueva; el resto sigue igual que en main
                js = json.loads(b)
                self.assertIn("uso", js)
                del js["uso"]
                b = json.dumps(js, indent=2, ensure_ascii=False, sort_keys=True).encode("utf-8")
            h.update(n.encode() + b)
        self.assertEqual(h.hexdigest(), SHA_SALIDAS_ES)

    def test_json_y_fuentes(self):
        out = self.raiz / "o"
        self._cli(self.a, "-o", out)
        js = json.loads((out / st.JSON).read_text(encoding="utf-8"))
        self.assertEqual(js["sitios"][0]["carpeta"], "a")
        self.assertTrue(all(len(f["sha256"]) == 64 for f in js["fuentes"]))


if __name__ == "__main__":
    unittest.main()
