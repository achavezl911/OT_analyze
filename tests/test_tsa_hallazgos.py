"""TSA2 (D118): referencias de la TSA SD 1580/82 por hallazgo, derivadas por SP 800-53."""
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

from ot_assess import i18n, perfil
from ot_assess import standards as st
from ot_assess import tsa_hallazgos as th
from ot_assess.cli import main

MARCOS = RAIZ / "ot_assess" / "marcos"
TSA = json.loads((MARCOS / "tsa_sd_1580_82.json").read_text(encoding="utf-8"))["requisitos"]
NIST = json.loads((MARCOS / "nist-800-82.json").read_text(encoding="utf-8"))["referencias"]


def base(c):
    return c.split("(")[0].strip()


def esperado(texto_nist):
    bases = {base(p.split(" (")[0]) for p in texto_nist.split("; ")}
    return [r for r in TSA if r["tipo"] == "tecnico" and bases & {base(c) for c in r["sp800_53"]}]


class DerivacionTest(unittest.TestCase):
    def test_cada_fragmento_se_deriva_de_los_dos_json(self):
        refs = st.ESTANDARES[th.CLAVE].refs
        for frag, txt in NIST.items():
            ms = esperado(txt)
            if ms:
                self.assertEqual(refs[frag], "; ".join(f"{m['id']} ({m['titulo']})" for m in ms), frag)
            else:
                self.assertNotIn(frag, refs, frag)

    def test_hay_fragmentos_con_y_sin_referencia(self):
        refs = st.ESTANDARES[th.CLAVE].refs
        self.assertTrue(refs)
        self.assertLess(len(refs), len(NIST))

    def test_sin_repetidos_en_orden_de_la_directiva_y_solo_tecnicas(self):
        orden = [r["id"] for r in TSA]
        tec = {r["id"] for r in TSA if r["tipo"] == "tecnico"}
        for txt in st.ESTANDARES[th.CLAVE].refs.values():
            ids = [p.split(" (")[0] for p in txt.split("; ")]
            self.assertEqual(len(ids), len(set(ids)))
            self.assertEqual(ids, sorted(ids, key=orden.index))
            self.assertLessEqual(set(ids), tec)

    def test_mejora_cuenta_por_su_base(self):
        medidas = [r for r in TSA if r["tipo"] == "tecnico"]
        r = th.derivar({"x": "SC-7(3) (mejora)"}, medidas)
        self.assertEqual(r["x"], "; ".join(f"{m['id']} ({m['titulo']})" for m in esperado("SC-7")))
        self.assertTrue(r["x"])

    def test_control_sin_medida_tecnica_no_tiene_referencia(self):
        medidas = [r for r in TSA if r["tipo"] == "tecnico"]
        usados = {base(c) for m in medidas for c in m["sp800_53"]}
        self.assertEqual(th.derivar({"x": "ZZ-99 (inexistente)"}, medidas), {})
        solo_doc = sorted({base(c) for r in TSA if r["tipo"] == "documental" for c in r["sp800_53"]} - usados)
        if solo_doc:
            self.assertEqual(th.derivar({"x": f"{solo_doc[0]} (doc)"}, medidas), {})

    def test_metadatos(self):
        e = st.ESTANDARES[th.CLAVE]
        self.assertEqual(e.validacion, {"estado": "sin revisar"})
        self.assertIn("01E", e.version_fuente)
        self.assertIn("seccion III", e.fuente)
        primera = next(r["id"] for r in TSA if r["tipo"] == "tecnico" and "SC-7" in r["sp800_53"])
        self.assertIn(primera, e.cruce)
        self.assertNotIn(th.CLAVE, [x.clave for x in st.elegir("iec62443")])
        self.assertEqual(list(st.ESTANDARES)[-1], th.CLAVE)


class SeleccionTest(unittest.TestCase):
    def test_elegir_ambos(self):
        self.assertEqual([e.clave for e in st.elegir("iec62443,tsa-sd-1580-82")], ["iec62443", th.CLAVE])

    def test_perfil_acepta_la_clave(self):
        d = {"version": 1, "cliente": "X", "marcos": [{"clave": "iec62443"}, {"clave": th.CLAVE}]}
        with tempfile.TemporaryDirectory() as tmp:
            ruta = Path(tmp) / "perfil.json"
            ruta.write_text(json.dumps(d), encoding="utf-8")
            p = perfil.cargar(ruta)
        self.assertEqual([m["clave"] for m in p["marcos"]], ["iec62443", th.CLAVE])
        self.assertEqual([e.clave for e in st.elegir(",".join(m["clave"] for m in p["marcos"]))], ["iec62443", th.CLAVE])


class CorridaTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        i18n.usar("es")
        cls.tmp = Path(tempfile.mkdtemp())
        est = gen_exports.escribir(cls.tmp / "ex")["b"]
        cls.args = ["diagrama", "--activos", str(est["activos"]), "--enlaces", str(est["enlaces"])]
        cls.sin = cls.correr("sin")
        cls.con = cls.correr("con", "--estandar", "iec62443,tsa-sd-1580-82")
        cls.en = cls.correr("en", "--estandar", "tsa-sd-1580-82", "--idioma", "en")
        i18n.usar("es")

    @classmethod
    def tearDownClass(cls):
        i18n.usar("es")
        shutil.rmtree(cls.tmp, ignore_errors=True)

    @classmethod
    def correr(cls, destino, *extra):
        out = cls.tmp / destino
        with contextlib.redirect_stdout(io.StringIO()):
            assert main([*cls.args, "-o", str(out), *extra]) == 0
        return out

    @staticmethod
    def filas(carpeta):
        with open(carpeta / "hallazgos.csv", newline="", encoding="utf-8-sig") as fh:
            return list(csv.reader(fh))

    def test_columna_solo_con_el_marco(self):
        sin, con = self.filas(self.sin), self.filas(self.con)
        self.assertNotIn(th.CLAVE, sin[0])
        self.assertEqual(con[0], sin[0] + [th.CLAVE])
        self.assertTrue(any(f[-1].startswith("III.") for f in con[1:]))

    def test_ingles_traducido(self):
        filas = self.filas(self.en)
        col = filas[0].index(th.CLAVE)
        citas = " ".join(f[col] for f in filas[1:])
        self.assertIn("III.", citas)
        for r in TSA:
            self.assertNotIn(r["titulo"], citas)


if __name__ == "__main__":
    unittest.main()
