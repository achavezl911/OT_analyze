"""Pruebas del plan de remediacion (S4a). El e2e requiere tshark y scapy."""
from __future__ import annotations

import csv
import importlib.util
import json
import shutil
import sys
import tempfile
import unittest
import zipfile
from html import escape
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))
sys.path.insert(0, str(RAIZ / "tests"))

HAY_SCAPY = importlib.util.find_spec("scapy") is not None

from ot_assess import perfil, remediacion


def activo(ips, rol):
    return {"ips": set(ips), "role": rol}


def hallazgo(titulo, sev, evidencia, cap="a.pcap"):
    return {"titulo": titulo, "severidad": sev, "evidencia": evidencia, "captura": cap,
            "recomendacion": "Rec " + titulo}


def corrida(assets, hallazgos, declaradas=None):
    cap = SimpleNamespace(findings=hallazgos)
    return SimpleNamespace(
        caps=[cap], extras=[], assets={i: a for i, a in enumerate(assets)},
        perfil={"criticidad_activos": declaradas} if declaradas else {})


PLC = "Controlador / dispositivo de campo (PLC, RTU, IED)"
WIN = "Host Windows (estacion de trabajo o servidor)"


class PlanTest(unittest.TestCase):
    def una(self, assets, sev, ev, declaradas=None):
        filas = remediacion.plan(corrida(assets, [hallazgo("H", sev, ev)], declaradas))
        self.assertEqual(len(filas), 1)
        return filas[0]

    def test_tabla_de_fases(self):
        for pts, fase in ((9, "Inmediato"), (6, "Inmediato"), (4, "Corto plazo"),
                          (3, "Corto plazo"), (2, "Mediano plazo"), (1, "Mediano plazo")):
            self.assertEqual(remediacion.fase(pts), fase, pts)

    def test_puntuacion_severidad_por_criticidad(self):
        a = [activo(["10.0.0.1"], PLC)]
        f = self.una(a, "Alta", "x 10.0.0.1")
        self.assertEqual((f["puntuacion"], f["fase"], f["criticidad"]), (9, "Inmediato", "Critica"))
        f = self.una([activo(["10.0.0.1"], WIN)], "Baja", "x 10.0.0.1")
        self.assertEqual((f["puntuacion"], f["fase"]), (1, "Mediano plazo"))

    def test_declarada_gana_a_inferida(self):
        a = [activo(["10.0.0.1"], PLC)]
        f = self.una(a, "Alta", "x 10.0.0.1", {"10.0.0.1": "Baja"})
        self.assertEqual((f["criticidad"], f["origen_criticidad"], f["puntuacion"]),
                         ("Baja", "declarada", 3))
        f = self.una(a, "Alta", "x 10.0.0.1")
        self.assertEqual(f["origen_criticidad"], "inferida")

    def test_sin_ips_no_determinada(self):
        f = self.una([activo(["10.0.0.1"], PLC)], "Alta", "sin direcciones aqui")
        self.assertEqual((f["criticidad"], f["origen_criticidad"], f["puntuacion"], f["activos"]),
                         ("No determinada", "sin activo en la evidencia", 3, ""))
        # IP que no es de ningun activo: tambien sin activo
        f = self.una([activo(["10.0.0.1"], PLC)], "Media", "x 10.9.9.9")
        self.assertEqual((f["criticidad"], f["puntuacion"]), ("No determinada", 2))

    def test_informativa_excluida(self):
        r = corrida([activo(["10.0.0.1"], PLC)],
                    [hallazgo("I", "Informativa", "10.0.0.1"), hallazgo("A", "Alta", "10.0.0.1")])
        self.assertEqual([f["titulo"] for f in remediacion.plan(r)], ["A"])

    def test_coincidencia_exacta_de_ip(self):
        a = [activo(["10.10.1.10"], WIN), activo(["10.10.1.100"], PLC)]
        f = self.una(a, "Media", "trafico de 10.10.1.100 hacia fuera.")
        self.assertEqual(f["activos"], "10.10.1.100")
        f = self.una(a, "Media", "trafico de 10.10.1.10")
        self.assertEqual((f["activos"], f["criticidad"]), ("10.10.1.10", "Media"))
        f = self.una([activo(["10.10.1.10"], PLC)], "Media", "solo 10.10.1.100")
        self.assertEqual(f["criticidad"], "No determinada")

    def test_mayor_criticidad_de_sus_activos_y_orden(self):
        a = [activo(["10.0.0.1"], WIN), activo(["10.0.0.2"], PLC)]
        r = corrida(a, [hallazgo("B", "Media", "10.0.0.1 y 10.0.0.2"),
                        hallazgo("A", "Media", "10.0.0.1"),
                        hallazgo("C", "Alta", "10.0.0.1")])
        filas = remediacion.plan(r)
        self.assertEqual([(f["titulo"], f["puntuacion"]) for f in filas],
                         [("B", 6), ("C", 3), ("A", 2)])
        self.assertEqual(filas[0]["activos"], "10.0.0.1;10.0.0.2")

    def test_roles(self):
        for rol, crit in ((PLC, "Critica"), ("Dispositivo CIP (x)", "Critica"),
                          ("HMI / estacion SCADA", "Alta"), ("Nodo EtherNet/IP", "Alta"),
                          ("Equipo de red (switch / router)", "Alta"),
                          ("Dispositivo OT (Acme)", "Alta"), (WIN, "Media"),
                          ("Indeterminado", "Media")):
            self.assertEqual(remediacion.criticidad_por_rol(rol), crit, rol)


class PerfilCriticidadTest(unittest.TestCase):
    def cargar(self, extra):
        d = {"version": 1, "cliente": "C", "marcos": [{"clave": "iec62443"}], **extra}
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        (tmp / "p.json").write_text(json.dumps(d), encoding="utf-8")
        return perfil.cargar(tmp / "p.json")

    def test_valido(self):
        p = self.cargar({"criticidad_activos": {"10.10.1.20": "Critica"}})
        self.assertEqual(p["criticidad_activos"], {"10.10.1.20": "Critica"})

    def test_ejemplo_declara_criticidad(self):
        p = perfil.cargar(RAIZ / "docs" / "ejemplos" / "perfil.json")
        self.assertEqual(p["criticidad_activos"], {"10.10.1.20": "Critica"})

    def test_invalidos(self):
        for c in ({"10.10.1.999": "Alta"}, {"nada": "Alta"}, {"10.10.1.20": "Maxima"},
                  {"10.10.1.20": 3}, ["10.10.1.20"]):
            with self.assertRaises(SystemExit, msg=str(c)):
                self.cargar({"criticidad_activos": c})


@unittest.skipUnless(shutil.which("tshark") and HAY_SCAPY, "requiere tshark y scapy")
class PlanE2ETest(unittest.TestCase):
    def test_csv_del_plan(self):
        import gen_pcaps

        from ot_assess.cli import main
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        sys.argv = ["gen", str(tmp / "pcaps")]
        gen_pcaps.main()
        main([str(tmp / "pcaps"), "-o", str(tmp / "out")])
        with open(tmp / "out" / "plan_remediacion.csv", newline="", encoding="utf-8-sig") as fh:
            filas = list(csv.reader(fh))
        self.assertEqual(filas[0], remediacion.COLUMNAS)
        self.assertEqual(filas[0], ["id_hallazgo", "fase", "puntuacion", "severidad", "criticidad",
                                    "origen_criticidad", "activos", "titulo", "recomendacion",
                                    "capturas", "playbook", "esfuerzo"])
        self.assertGreaterEqual(len(filas), 2)
        self.assertTrue(all(f[-1] == "" and f[2] != "Informativa" for f in filas[1:]))

    def _correr(self, tmp, salida):
        import gen_pcaps

        from ot_assess.cli import main
        sys.argv = ["gen", str(tmp / "pcaps")]
        gen_pcaps.main()
        main([str(tmp / "pcaps"), "-o", str(tmp / salida)])
        return tmp / salida

    def _textos(self, out):
        t = {"html": (out / "reporte_ot.html").read_text(encoding="utf-8"),
             "md": (out / "reporte_ot.md").read_text(encoding="utf-8")}
        with zipfile.ZipFile(out / "informe_ot.docx") as z:
            t["docx"] = z.read("word/document.xml").decode("utf-8")
        with zipfile.ZipFile(out / "reporte_ot.xlsx") as z:
            t["xlsx"] = z.read("xl/workbook.xml").decode("utf-8")
        return t

    def test_reportes_muestran_el_plan(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        out = self._correr(tmp, "out")
        with open(out / "plan_remediacion.csv", newline="", encoding="utf-8-sig") as fh:
            titulo = list(csv.DictReader(fh))[0]["titulo"]
        t = self._textos(out)
        self.assertIn("Plan de remediacion", t["xlsx"])
        for k in ("html", "md", "docx"):
            self.assertIn("Plan de remediacion", t[k], k)
            self.assertIn("Mediano plazo: ", t[k], k)
            self.assertIn(escape(titulo), t[k], k)
            self.assertNotIn(remediacion.SIN_PRIORIZAR, t[k], k)

    def test_sin_hallazgos_priorizables(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        with mock.patch.object(remediacion, "plan", return_value=[]):
            t = self._textos(self._correr(tmp, "vacio"))
        for k in ("html", "md", "docx"):
            self.assertIn("Sin hallazgos que priorizar.", t[k], k)


if __name__ == "__main__":
    unittest.main()


class CriticidadImportadosTest(unittest.TestCase):
    """Activos de una plataforma: rol = tipo de la plataforma (PLC, HMI) y tipo normalizado del importador."""

    def test_plc_y_hmi_de_plataforma(self):
        from ot_assess import remediacion as rm
        self.assertEqual(rm.criticidad_activo({"ips": ["10.0.0.1"], "role": "PLC", "tipo": "controlador"}, {})[0], "Critica")
        self.assertEqual(rm.criticidad_activo({"ips": ["10.0.0.2"], "role": "HMI", "tipo": "supervision"}, {})[0], "Alta")
        self.assertEqual(rm.criticidad_activo({"ips": ["10.0.0.3"], "role": "", "tipo": "controlador"}, {})[0], "Critica")
        self.assertEqual(rm.criticidad_activo({"ips": ["10.0.0.4"], "role": "PC", "tipo": "host"}, {})[0], "Media")
        self.assertEqual(rm.criticidad_activo({"ips": ["10.0.0.5"], "role": "Network Equipment", "tipo": "red"}, {})[0], "Alta")
        # la declarada manda
        self.assertEqual(rm.criticidad_activo({"ips": ["10.0.0.1"], "role": "PLC", "tipo": "controlador"},
                                              {"10.0.0.1": "Baja"})[0], "Baja")


class ActivosDelHallazgoTest(unittest.TestCase):
    """Z2b: el hallazgo puede traer la lista de IP que involucra; manda sobre las IPv4 de la evidencia."""

    def setUp(self):
        self.assets = [activo(["10.0.0.1"], PLC), activo(["10.0.0.2"], WIN)]

    def plan(self, hallazgos):
        return remediacion.plan(corrida(self.assets, hallazgos))

    def test_activos_manda_sobre_la_evidencia(self):
        con = dict(hallazgo("H", "Alta", "sin ip alguna"), activos=["10.0.0.2", "10.0.0.1"])
        f = self.plan([con])[0]
        self.assertEqual((f["criticidad"], f["puntuacion"], f["activos"]), ("Critica", 9, "10.0.0.1;10.0.0.2"))
        # sin la lista rige la evidencia de siempre
        f = self.plan([hallazgo("H", "Alta", "sin ip alguna")])[0]
        self.assertEqual((f["criticidad"], f["origen_criticidad"]), ("No determinada", "sin activo en la evidencia"))
        f = self.plan([hallazgo("H", "Alta", "solo 10.0.0.2")])[0]
        self.assertEqual(f["criticidad"], "Media")

    def test_agrupar_une_las_listas(self):
        from ot_assess.report.common import agrupar_hallazgos
        caps = [SimpleNamespace(findings=[dict(hallazgo("H", "Alta", "e1", "a"), activos=["10.0.0.1", "10.0.0.3"])]),
                SimpleNamespace(findings=[dict(hallazgo("H", "Alta", "e2", "b"), activos=["10.0.0.3", "10.0.0.2"])]),
                SimpleNamespace(findings=[hallazgo("H", "Alta", "e3", "c")])]
        g = agrupar_hallazgos(caps)
        self.assertEqual(len(g), 1)
        self.assertEqual(g[0]["activos"], ["10.0.0.1", "10.0.0.2", "10.0.0.3"])

    def test_finding_guarda_activos_solo_si_hay(self):
        from ot_assess.rules.base import finding
        cap = SimpleNamespace(findings=[], name="x")
        finding(cap, "Alta", "T1", "e", "p", "r", activos=["10.0.0.2", "10.0.0.1", "10.0.0.2"])
        finding(cap, "Alta", "T2", "e", "p", "r")
        self.assertEqual(cap.findings[0]["activos"], ["10.0.0.1", "10.0.0.2"])
        self.assertNotIn("activos", cap.findings[1])

    def test_vulnerabilidades_y_zcr_traen_activos(self):
        from ot_assess import conductos_zcr, vulnerabilidades
        cap = SimpleNamespace(findings=[], name="v")
        cruces = [{"vuln": {"estado": "abierta", "severidad": "Alta", "cve": "CVE-2099-1"}, "activo": "m1"},
                  {"vuln": {"estado": "abierta", "severidad": "Media", "cve": "CVE-2099-2"}, "activo": "m2"}]
        assets = {"m1": {"nombre": "PLC1", "ips": {"10.0.0.1"}}, "m2": {"nombre": "PC2", "ips": {"10.0.0.2"}}}
        vulnerabilidades.agregar_hallazgo(cap, cruces, assets)
        self.assertEqual(cap.findings[0]["activos"], ["10.0.0.1", "10.0.0.2"])
        f = self.plan(cap.findings)[0]          # la evidencia solo nombra equipos, no IP
        self.assertEqual((f["criticidad"], f["puntuacion"]), ("Critica", 9))

        cap = SimpleNamespace(findings=[], name="z")
        fila = {"id": "C-01", "zona_a": "Z1", "zona_b": "Z2", "origen_a": "perfil", "origen_b": "perfil",
                "servicios": [("Telnet", 1)], "brechas": [conductos_zcr.B_RIESGO], "critico": False,
                "ips": ["10.0.0.1", "10.0.0.2"]}
        conductos_zcr.agregar_hallazgos(cap, {"filas": [fila]})
        self.assertEqual(cap.findings[0]["activos"], ["10.0.0.1", "10.0.0.2"])
        f = self.plan(cap.findings)[0]
        self.assertEqual((f["criticidad"], f["puntuacion"]), ("Critica", 6))

    def test_columna_activos_y_n_mas(self):
        ips = [f"10.1.0.{i}" for i in range(1, 13)]
        self.assets = [activo(ips, PLC)]
        f = self.plan([dict(hallazgo("H", "Alta", "x"), activos=ips)])[0]
        self.assertEqual(f["activos"], ";".join(sorted(ips)[:10]) + " y 2 mas")
        self.assertEqual(f["criticidad"], "Critica")
