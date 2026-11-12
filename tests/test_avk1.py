"""AVK1 (D124): paquete verificado de avisos ICS de CISA y KEV para sitios sin red. Datos ficticios."""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import shutil
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))
sys.path.insert(0, str(RAIZ / "tests"))

import gen_exports
import test_avisos_cisa as ta

from ot_assess import i18n, perfil
from ot_assess import paquete_avisos as pa
from ot_assess.cli import main

CRUCES = ("avisos_ics.csv", "vulnerabilidades.csv", "vulnerabilidades_firmware.csv", "hallazgos.csv")


def ejecutar(argv):
    """-> (codigo, stdout, stderr). SystemExit (ap.error) se convierte en codigo."""
    o, e = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(o), contextlib.redirect_stderr(e):
        try:
            rc = main(argv)
        except SystemExit as x:
            rc = x.code if isinstance(x.code, int) else 1
    return rc, o.getvalue(), e.getvalue()


class PaqueteAvisosTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        cls.kev = ta.escribir_kev_json(cls.tmp / "kev.json")
        cls.avisos = ta.carpeta_avisos(cls.tmp)
        cls.pkg = cls.tmp / "paquete"
        cls.rc, cls.salida, _ = ejecutar(["paquete-avisos", "--avisos-ics", str(cls.avisos), "--kev", str(cls.kev),
                                          "-o", str(cls.pkg), "--zip"])
        est = gen_exports.escribir(cls.tmp / "ex")["b"]
        cls.vul = cls.tmp / "vul.csv"
        cls.vul.write_text("ip,cve,severidad,cvss,estado,producto,version,fuente\n"
                           "10.20.1.11,CVE-2099-0001,Critical,9.8,open,Firmware,1.0,Escaner\n"
                           "10.20.1.12,CVE-2099-0002,High,7.5,mitigated,Firmware,1.0,Escaner\n", encoding="utf-8")
        cls.base = ["diagrama", "--activos", str(est["activos"]), "--enlaces", str(est["enlaces"]),
                    "--vulnerabilidades", str(cls.vul)]

    @classmethod
    def tearDownClass(cls):
        i18n.usar("es")
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def copia(self, nombre):
        d = self.tmp / nombre
        shutil.copytree(self.pkg, d)
        return d

    def test_crear_manifiestos(self):
        self.assertEqual(self.rc, 0)
        self.assertIn("Avisos CSAF:", self.salida)
        self.assertIn("KEV:", self.salida)
        man = json.loads((self.pkg / pa.MANIFIESTO).read_text(encoding="utf-8"))
        self.assertEqual(man["formato"], "ot_assess.avisos/1")
        self.assertEqual(man["kev"]["catalogVersion"], "2099.02.10")
        self.assertEqual(man["kev"]["registros"], len(ta.KEV))
        c = man["csaf"]
        self.assertEqual((c["avisos_csaf"], c["aviso_mas_reciente"]), (3, "2099-02-01"))
        self.assertEqual(c["archivos"] - c["avisos_csaf"], c["saltados"])
        rutas = [a["ruta"] for a in man["archivos"]]
        self.assertIn("kev/kev.json", rutas)
        self.assertIn("csaf/sub/ICSA-99-002-01.json", rutas)
        self.assertNotIn("csaf/enlace.json", rutas)
        self.assertTrue(all(a["sha256"] == hashlib.sha256((self.pkg / a["ruta"]).read_bytes()).hexdigest()
                            for a in man["archivos"]))

    def test_sha256_estandar(self):
        n = 0
        for ln in (self.pkg / pa.SUMAS).read_text(encoding="utf-8").splitlines():
            h, ruta = ln.split("  ", 1)
            self.assertEqual(hashlib.sha256((self.pkg / ruta).read_bytes()).hexdigest(), h)
            n += 1
        self.assertGreaterEqual(n, 7)

    def test_zip(self):
        z = Path(str(self.pkg) + ".zip")
        with zipfile.ZipFile(z) as zf:
            self.assertIn(pa.SUMAS, zf.namelist())
            self.assertEqual(len({i.date_time for i in zf.infolist()}), 1)
        self.assertEqual(ejecutar(["paquete-avisos", "--verificar", str(z)])[0], 0)

    def test_verificar_intacto(self):
        rc, out, _ = ejecutar(["paquete-avisos", "--verificar", str(self.pkg)])
        self.assertEqual(rc, 0)
        self.assertIn("OK", out)

    def test_verificar_detecta_cambios(self):
        d = self.copia("v1")
        f = d / "kev" / "kev.json"
        b = bytearray(f.read_bytes())
        b[10] ^= 1
        f.write_bytes(bytes(b))
        rc, out, _ = ejecutar(["paquete-avisos", "--verificar", str(d)])
        self.assertEqual(rc, 2)
        self.assertIn("kev/kev.json", out)
        d = self.copia("v2")
        (d / "csaf" / "sub" / "ICSA-99-002-01.json").unlink()
        rc, out, _ = ejecutar(["paquete-avisos", "--verificar", str(d)])
        self.assertEqual(rc, 2)
        self.assertIn("FALTANTE", out)
        d = self.copia("v3")
        (d / "csaf" / "nuevo.json").write_text("{}", encoding="utf-8")
        rc, out, _ = ejecutar(["paquete-avisos", "--verificar", str(d)])
        self.assertEqual(rc, 2)
        self.assertIn("SOBRANTE", out)

    def test_verificar_manifiesto_ilegible_y_zip_inseguro(self):
        d = self.copia("v4")
        (d / pa.MANIFIESTO).write_text("no es json", encoding="utf-8")
        self.assertEqual(ejecutar(["paquete-avisos", "--verificar", str(d)])[0], 2)
        z = self.tmp / "malo.zip"
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr("../fuera.txt", "x")
            zf.writestr(pa.SUMAS, "")
            zf.writestr(pa.MANIFIESTO, "{}")
        rc, _, err = ejecutar(["paquete-avisos", "--verificar", str(z)])
        self.assertEqual(rc, 2)
        self.assertIn("ruta no permitida", err)

    def test_salida_no_vacia(self):
        d = self.tmp / "ocupada"
        d.mkdir()
        (d / "algo").write_text("x", encoding="utf-8")
        rc, _, _ = ejecutar(["paquete-avisos", "--kev", str(self.kev), "-o", str(d)])
        self.assertEqual((rc, sorted(p.name for p in d.iterdir())), (2, ["algo"]))
        rc, _, _ = ejecutar(["paquete-avisos", "--kev", str(self.kev), "-o", str(self.pkg)])
        self.assertEqual(rc, 2)

    def test_exige_fuente(self):
        self.assertEqual(ejecutar(["paquete-avisos", "-o", str(self.tmp / "sinfuente")])[0], 2)

    def test_corrida_igual_a_directa(self):
        directa = self.tmp / "directa"
        paquete = self.tmp / "conpaquete"
        self.assertEqual(ejecutar([*self.base, "--avisos-ics", str(self.avisos), "--kev", str(self.kev),
                                   "-o", str(directa)])[0], 0)
        self.assertEqual(ejecutar([*self.base, "--paquete-avisos", str(self.pkg), "-o", str(paquete)])[0], 0)
        for n in CRUCES:
            self.assertEqual((directa / n).exists(), (paquete / n).exists(), n)
            if (directa / n).exists():
                self.assertEqual((directa / n).read_bytes(), (paquete / n).read_bytes(), n)
        self.assertTrue((paquete / "avisos_ics.csv").exists())
        r = json.loads((paquete / "resultado.json").read_text(encoding="utf-8"))
        info = r["entorno"]["paquete_avisos"]
        self.assertEqual(info["sha256"], hashlib.sha256((self.pkg / pa.MANIFIESTO).read_bytes()).hexdigest())
        self.assertEqual((info["version_kev"], info["avisos_csaf"], info["verificado"]), ("2099.02.10", 3, True))
        rd = json.loads((directa / "resultado.json").read_text(encoding="utf-8"))
        self.assertNotIn("paquete_avisos", rd["entorno"])
        self.assertEqual(r["entorno"]["avisos_ics"]["sha256"], rd["entorno"]["avisos_ics"]["sha256"])

    def test_paquete_alterado_no_escribe(self):
        d = self.copia("alterado")
        (d / "kev" / "kev.json").write_bytes(b"{}")
        out = self.tmp / "salida_alterada"
        rc, _, err = ejecutar([*self.base, "--paquete-avisos", str(d), "-o", str(out)])
        self.assertEqual(rc, 2)
        self.assertIn("no verifica", err)
        self.assertFalse(out.exists())

    def test_zip_no_se_acepta_en_la_corrida(self):
        out = self.tmp / "salida_zip"
        rc, _, _ = ejecutar([*self.base, "--paquete-avisos", str(self.pkg) + ".zip", "-o", str(out)])
        self.assertEqual(rc, 2)
        self.assertFalse(out.exists())

    def test_no_se_combina(self):
        out = self.tmp / "salida_comb"
        rc, _, _ = ejecutar([*self.base, "--paquete-avisos", str(self.pkg), "--kev", str(self.kev), "-o", str(out)])
        self.assertEqual(rc, 2)
        self.assertFalse(out.exists())

    def test_perfil_solo_paquete(self):
        pf = self.tmp / "perfil.json"
        pf.write_text(json.dumps({"version": 1, "cliente": "X", "marcos": [{"clave": "iec62443"}],
                                  "avisos_solo_paquete": True}), encoding="utf-8")
        out = self.tmp / "salida_pf"
        rc, _, err = ejecutar([*self.base, "--perfil", str(pf), "--avisos-ics", str(self.avisos), "-o", str(out)])
        self.assertEqual(rc, 2)
        self.assertIn("--paquete-avisos", err)
        self.assertFalse(out.exists())
        rc, _, _ = ejecutar([*self.base, "--perfil", str(pf), "--paquete-avisos", str(self.pkg), "-o", str(out)])
        self.assertEqual(rc, 0)
        self.assertTrue((out / "avisos_ics.csv").exists())

    def test_perfil_valores(self):
        pf = self.tmp / "perfil_f.json"
        pf.write_text(json.dumps({"version": 1, "cliente": "X", "marcos": [{"clave": "iec62443"}],
                                  "avisos_solo_paquete": False}), encoding="utf-8")
        self.assertIs(perfil.cargar(pf)["avisos_solo_paquete"], False)
        out = self.tmp / "salida_pf_f"
        self.assertEqual(ejecutar([*self.base, "--perfil", str(pf), "--avisos-ics", str(self.avisos),
                                   "-o", str(out)])[0], 0)
        for v in ("si", 1, None):
            pf.write_text(json.dumps({"version": 1, "cliente": "X", "marcos": [{"clave": "iec62443"}],
                                      "avisos_solo_paquete": v}), encoding="utf-8")
            with self.assertRaises(SystemExit):
                perfil.cargar(pf)


if __name__ == "__main__":
    unittest.main()
