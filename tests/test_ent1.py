"""ENT1 (D126): catalogo de entregables del proyecto y mapeo requisito -> entregable. Sin tshark."""
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

from ot_assess import entregables as en
from ot_assess import i18n
from ot_assess import perfil as pf
from ot_assess.cli_diagrama import main as main_diagrama
from ot_assess.model import Assessment, Capture
from ot_assess.report.csvout import write_csvs
from ot_assess.report.jsonout import write_json
from ot_assess.standards import ESTANDARES

CATALOGO = [{"id": "D-02", "nombre": "Inventario", "salidas": ["hallazgos.csv", "cobertura_*.csv", "no_existe.docx"]},
            {"id": "D-07a", "nombre": "Metodo de riesgo"},
            {"id": "D-09", "nombre": "Plan", "salidas": ["entregables.csv"]}]


def _ent(mapeo, catalogo=None):
    return {"catalogo": catalogo or CATALOGO, "mapeo": mapeo}


def _validar(v):
    def fallo(msg):
        raise SystemExit(msg)
    return en.validar(v, fallo)


def _plan(mapeo):
    return en.plan({"entregables": _validar(_ent(mapeo))})


def _hallazgo(refs):
    return {"titulo": "t", "severidad": "alta", "categoria": "c", "evidencia": "e", "por_que_importa": "p",
            "recomendacion": "r", "captura": "a.pcap", "referencias": refs}


class Validacion(unittest.TestCase):
    def malo(self, v, frag=""):
        with self.assertRaises(SystemExit) as cm:
            _validar(v)
        self.assertIn(frag, str(cm.exception))

    def test_valido(self):
        v = _validar(_ent({"iec62443:SR 1.*": ["D-02"], "nist-csf:PR.AA-01": ["D-02", "D-09"]}))
        self.assertEqual(len(v["catalogo"]), 3)
        self.assertEqual(v["catalogo"][1]["salidas"], [])

    def test_invalidos(self):
        self.malo(_ent({"vpn:SR 1.1": ["D-02"]}), "marco desconocido")
        self.malo(_ent({"iec62443:SR 1.1": ["D-99"]}), "no esta en el catalogo")
        self.malo(_ent({"iec62443:SR 1.1": []}), "lista de 1 a 20")
        self.malo(_ent({"iec62443": ["D-02"]}), "marco:requisito")
        self.malo(_ent({"iec62443:SR 1.1": ["D-02"]}, CATALOGO + [dict(CATALOGO[0])]), "repetido")
        self.malo(_ent({"iec62443:SR 1.1": ["X"]}, [{"id": "X" * 21, "nombre": "n"}]), "invalido")
        self.malo(_ent({"iec62443:SR 1.1": ["X"]}, [{"id": "X", "nombre": "a\nb"}]), "nombre")
        self.malo(_ent({"iec62443:SR 1.1": ["X"]}, [{"id": "X", "nombre": "n", "salidas": "a.csv"}]), "salidas")
        self.malo(_ent({"iec62443:SR 1.1": ["X"]}, [{"id": f"I{i}", "nombre": "n"} for i in range(101)]), "1 a 100")
        self.malo("texto", "objeto")
        self.malo({"catalogo": CATALOGO}, "objeto")

    def test_perfil_cargar(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "p.json"
            base = {"version": 1, "cliente": "ACME", "marcos": [{"clave": "iec62443"}]}
            p.write_text(json.dumps({**base, "entregables": _ent({"cis:4.*": ["D-02"]})}), encoding="utf-8")
            self.assertEqual(pf.cargar(p)["entregables"]["mapeo"], {"cis:4.*": ["D-02"]})
            p.write_text(json.dumps({**base, "entregables": _ent({"x:1": ["D-02"]})}), encoding="utf-8")
            with self.assertRaises(SystemExit):
                pf.cargar(p)


class Resolucion(unittest.TestCase):
    def test_exacto_prefijo_y_normalizacion(self):
        p = _plan({"iec62443:SR 1.1": ["D-09"], "iec62443:SR 1.*": ["D-02"], "cis:4.*": ["D-07a"],
                   "nist-800-53:AC-*": ["D-09"]})
        self.assertEqual(en.resolver(p, "iec62443", ["sr   1.1"]), ["D-02", "D-09"])
        self.assertEqual(en.resolver(p, "iec62443", ["SR 1.2"]), ["D-02"])
        self.assertEqual(en.resolver(p, "iec62443", ["SR 2.1"]), [])
        self.assertEqual(en.resolver(p, "cis", ["4.1", "4.2"]), ["D-07a"])
        self.assertEqual(en.resolver(p, "nist-800-53", ["AC-2(1)"]), ["D-09"])

    def test_mejora_con_base_exacta_no_casa(self):
        p = _plan({"nist-800-53:AC-2": ["D-02"], "nist-800-53:AC-2(1)": ["D-09"]})
        self.assertEqual(en.resolver(p, "nist-800-53", ["AC-2"]), ["D-02"])
        self.assertEqual(en.resolver(p, "nist-800-53", ["AC-2(1)"]), ["D-09"])

    def test_hallazgo_orden_catalogo_sin_repetidos(self):
        p = _plan({"iec62443:SR 7.1": ["D-09", "D-02"], "nist-csf:PR.IR-03": ["D-02"],
                   "mitre-ics:T0800": ["D-07a"], "nist-800-82:SC-5": ["D-09"]})
        f = _hallazgo({"iec62443": "SR 7.1 DoS; SR 6.2 Monitoreo", "nist-csf": "PR.IR-03 (resiliencia)",
                       "mitre-ics": "T0800 Unauthorized Command Message", "nist-800-82": "SC-5 (x); SI-4 (y)"})
        self.assertEqual(en.texto_hallazgo(p, f), "D-02; D-07a; D-09")

    def test_matriz_equivalencia(self):
        p = _plan({"nist-800-53:AC-*": ["D-02"], "nist-csf:GV.OC-01": ["D-07a"], "cis:4.1": ["D-09"]})
        self.assertEqual(en.texto_fila(p, "NIST SP 800-82r3", "AC-2(1)"), "D-02")
        self.assertEqual(en.texto_fila(p, "CSF 2.0", "GV.OC-01"), "D-07a")
        self.assertEqual(en.texto_fila(p, "CIS Controls v8.1", "4.1"), "D-09")
        self.assertEqual(en.texto_fila(p, "Desconocido", "4.1"), "")


class Exclusiones(unittest.TestCase):
    def test_csf_11_y_tecnica_revocada(self):
        p = _plan({"nist-csf:ID.BE-2": ["D-02"], "nist-csf:GV.OC-01": ["D-02"], "mitre-ics:T0803": ["D-02"],
                   "mitre-ics:T0807": ["D-02"], "mitre-ics:T0800": ["D-02"], "nist-csf:ID.AM": ["D-02"]})
        ex = {x["clave"]: x for x in p["excluidos"]}
        self.assertEqual(set(ex), {"nist-csf:ID.BE-2", "mitre-ics:T0803", "mitre-ics:T0807"})
        self.assertEqual(ex["nist-csf:ID.BE-2"]["motivo"], "CSF 1.1 retirada o reubicada")
        self.assertIn("GV.OC-01", ex["nist-csf:ID.BE-2"]["sustituto"])
        self.assertEqual((ex["mitre-ics:T0803"]["motivo"], ex["mitre-ics:T0803"]["sustituto"]),
                         ("tecnica revocada", "T1691.001"))
        self.assertEqual(ex["mitre-ics:T0807"]["motivo"], "obsoleta")
        self.assertEqual(p["no_reconocidos"], 0)
        self.assertNotIn("nist-csf:ID.BE-2", p["vigentes"])
        self.assertEqual(en.resolver(p, "nist-csf", ["ID.BE-2"]), [])

    def test_id_inventado_se_conserva(self):
        p = _plan({"nist-csf:XX.ZZ-99": ["D-02"], "iec62443:SR 99.9": ["D-09"], "cis:99.9": ["D-09"]})
        self.assertEqual(p["no_reconocidos"], 2)          # cis no tiene catalogo para reconocer
        self.assertEqual(p["excluidos"], [])
        self.assertEqual(en.resolver(p, "nist-csf", ["XX.ZZ-99"]), ["D-02"])

    def test_avisos_en_consola(self):
        perfil = {"entregables": _validar(_ent({"mitre-ics:T0803": ["D-02"], "nist-csf:XX.ZZ-99": ["D-02"]}))}
        with contextlib.redirect_stderr(io.StringIO()) as err:
            en.avisos(perfil)
        self.assertIn("T0803", err.getvalue())
        self.assertIn("1 requisito", err.getvalue())
        with contextlib.redirect_stderr(io.StringIO()) as err:
            en.avisos({})
        self.assertEqual(err.getvalue(), "")


def _rd(ruta):
    with open(ruta, encoding="utf-8-sig", newline="") as fh:
        return list(csv.DictReader(fh))


def _res(perfil):
    cap = Capture(Path("a.pcap"))
    cap.findings = [_hallazgo({"iec62443": "SR 7.1 DoS", "nist-csf": "PR.IR-03 (resiliencia)",
                               "mitre-ics": "T0800 Unauthorized Command Message"}),
                    _hallazgo({"iec62443": "SR 5.2 Segmentacion"})]
    cap.findings[1]["titulo"] = "otro"
    return Assessment([cap], {}, [], None, estandares=[ESTANDARES["iec62443"], ESTANDARES["nist-csf"]],
                      perfil=perfil)


class Base(unittest.TestCase):
    def setUp(self):
        i18n.usar("es")
        self.addCleanup(i18n.usar, "es")
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)


_PERFIL = {"entregables": _validar(_ent({"iec62443:SR 7.*": ["D-02"], "nist-csf:PR.IR-03": ["D-07a"],
                                            "mitre-ics:T0800": ["D-07a"], "iec62443:SR 5.2": ["D-09"],
                                            "mitre-ics:T0803": ["D-09"]}))}


class Corrida(Base):
    def test_columnas_y_entregables_csv(self):
        res = _res(_PERFIL)
        write_csvs(res, self.tmp)
        write_json(res, self.tmp)
        h = _rd(self.tmp / "hallazgos.csv")
        self.assertEqual(list(h[0])[-1], "entregables")
        self.assertEqual(sorted(x["entregables"] for x in h), ["D-02; D-07a", "D-09"])
        cob = _rd(self.tmp / "cobertura_iec62443.csv")
        por_id = {x["id"]: x["entregables"] for x in cob}
        self.assertEqual((por_id["SR 7.1"], por_id["SR 5.2"], por_id["SR 1.1"]), ("D-02", "D-09", ""))
        self.assertEqual({x["id"]: x["entregables"] for x in _rd(self.tmp / "cobertura_nist-csf.csv")}["PR.IR-03"],
                         "D-07a")
        en.write_entregables(res, self.tmp)
        filas = {x["id_entregable"]: x for x in _rd(self.tmp / "entregables.csv")}
        self.assertEqual(list(filas), ["D-02", "D-07a", "D-09"])
        self.assertEqual((filas["D-02"]["hallazgos"], filas["D-07a"]["hallazgos"], filas["D-09"]["hallazgos"]),
                         ("1", "1", "1"))
        self.assertEqual(filas["D-02"]["salidas_presentes"],
                         "cobertura_iec62443.csv; cobertura_nist-csf.csv; hallazgos.csv")
        self.assertEqual(filas["D-02"]["salidas_ausentes"], "no_existe.docx")
        self.assertEqual(filas["D-09"]["salidas_presentes"], "entregables.csv")
        self.assertEqual(filas["D-02"]["requisitos_mapeados"], "iec62443:SR 7.*")
        self.assertEqual(filas["D-09"]["requisitos_mapeados"], "iec62443:SR 5.2")      # T0803 excluida
        self.assertTrue(int(filas["D-02"]["filas_cobertura"]) >= 1)
        self.assertEqual(filas["D-07a"]["filas_cobertura"], "1")
        j = json.loads((self.tmp / "resultado.json").read_text(encoding="utf-8"))["entregables"]
        self.assertEqual((j["catalogo"], j["mapeo"], j["no_reconocidos"], j["hallazgos_con_entregable"]), (3, 4, 0, 2))
        self.assertEqual(j["excluidos"][0]["clave"], "mitre-ics:T0803")
        self.assertEqual(j["por_entregable"], {"D-02": 1, "D-07a": 1, "D-09": 1})

    def test_matriz_agrega_columna(self):
        res = _res(_PERFIL)
        res.perfil = {"entregables": _validar(_ent({"cis:4.*": ["D-02"], "nist-800-53:AC-*": ["D-09"]}))}
        cab = ["marco", "id", "otra"]
        filas = [["CIS Controls v8.1", "4.1", "x"], ["NIST SP 800-82r3", "AC-2(1)", "y"], ["CSF 2.0", "GV.OC-01", "z"]]
        c2, f2 = en.agregar_columna(res, "matriz_controles.csv", cab, filas)
        self.assertEqual((c2[-1], [f[-1] for f in f2]), ("entregables", ["D-02", "D-09", ""]))
        self.assertEqual(en.agregar_columna(res, "inventario.csv", cab, filas), (cab, filas))

    def test_sin_clave_no_hay_nada(self):
        res = _res({})
        write_csvs(res, self.tmp)
        write_json(res, self.tmp)
        en.write_entregables(res, self.tmp)
        self.assertFalse((self.tmp / "entregables.csv").exists())
        self.assertNotIn("entregables", list(_rd(self.tmp / "hallazgos.csv")[0]))
        self.assertNotIn("entregables", list(_rd(self.tmp / "cobertura_iec62443.csv")[0]))
        self.assertNotIn("entregables", json.loads((self.tmp / "resultado.json").read_text(encoding="utf-8")))

    def test_sin_clave_identico_con_clave_vacia_de_efecto(self):
        """Con la clave pero un mapeo que no casa nada, las columnas originales quedan igual."""
        a, b = self.tmp / "a", self.tmp / "b"
        a.mkdir()
        b.mkdir()
        write_csvs(_res({}), a)
        write_csvs(_res({"entregables": _validar(_ent({"cis:99.*": ["D-02"]}))}), b)
        self.assertEqual(sorted(x.name for x in a.iterdir()), sorted(x.name for x in b.iterdir()))
        for n in ("hallazgos.csv", "cobertura_iec62443.csv"):
            fa, fb = _rd(a / n), _rd(b / n)
            self.assertEqual([{k: v for k, v in r.items() if k != "entregables"} for r in fb], fa)
            self.assertTrue(all(r["entregables"] == "" for r in fb))


class Diagrama(Base):
    def _correr(self, nombre, perfil=None):
        (self.tmp / "a.csv").write_text(
            "id,name,ip,type,level,zone\n1,HMI-1,10.0.0.1,Windows XP SP3,2,Z\n2,PLC-1,10.0.0.2,PLC,1,Z\n",
            encoding="utf-8")
        (self.tmp / "e.csv").write_text("from,to,protocol,port\n1,2,telnet,23\n", encoding="utf-8")
        args = ["--activos", str(self.tmp / "a.csv"), "--enlaces", str(self.tmp / "e.csv"),
                "-o", str(self.tmp / nombre)]
        if perfil is not None:
            p = self.tmp / "perfil.json"
            p.write_text(json.dumps({"version": 1, "cliente": "ACME", "marcos": [{"clave": "iec62443"}],
                                     **perfil}), encoding="utf-8")
            args += ["--perfil", str(p)]
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(main_diagrama(args), 0)
        return self.tmp / nombre, err.getvalue()

    def test_diagrama_con_y_sin_clave(self):
        sin, _ = self._correr("sin")
        self.assertFalse((sin / "entregables.csv").exists())
        mapeo = {"iec62443:SR *": ["D-02"], "mitre-ics:T0803": ["D-09"]}
        con, err = self._correr("con", {"entregables": _ent(mapeo)})
        self.assertIn("T0803", err)
        self.assertTrue((con / "entregables.csv").is_file())
        filas_con, filas_sin = _rd(con / "hallazgos_importados.csv"), _rd(sin / "hallazgos_importados.csv")
        self.assertEqual(list(filas_con[0])[-1], "entregables")
        self.assertNotIn("entregables", list(filas_sin[0]))
        self.assertTrue(any(x["entregables"] == "D-02" for x in filas_con))
        self.assertEqual(list(_rd(con / "hallazgos.csv")[0])[-1], "entregables")
        e = {x["id_entregable"]: x for x in _rd(con / "entregables.csv")}
        self.assertGreaterEqual(int(e["D-02"]["hallazgos"]), 1)
        self.assertIn("hallazgos.csv", e["D-02"]["salidas_presentes"])
        self.assertEqual(e["D-02"]["salidas_ausentes"], "no_existe.docx")
        j = json.loads((con / "resultado.json").read_text(encoding="utf-8"))["entregables"]
        self.assertEqual(j["catalogo"], 3)
        self.assertNotIn("entregables", json.loads((sin / "resultado.json").read_text(encoding="utf-8")))
        self.assertEqual(sorted(x.name for x in sin.iterdir()),
                         sorted(x.name for x in con.iterdir() if x.name != "entregables.csv"))


if __name__ == "__main__":
    unittest.main()
