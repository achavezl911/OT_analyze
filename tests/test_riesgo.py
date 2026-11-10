"""R1 (D83): ID estable de hallazgo, registro de riesgos (P x I), mapa de calor y quick wins. Sin tshark."""
from __future__ import annotations

import ast
import contextlib
import csv
import io
import json
import re
import shutil
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))
sys.path.insert(0, str(RAIZ / "tests"))

import gen_exports

from ot_assess import i18n, perfil, playbooks, riesgo
from ot_assess.cli import main

PLC = "Controlador / dispositivo de campo (PLC, RTU, IED)"
WIN = "Host Windows (estacion de trabajo o servidor)"
T_ANY = "Reglas de firewall que permiten cualquier origen hacia cualquier destino"   # playbook, esfuerzo bajo
T_VULN = "Vulnerabilidades conocidas en activos (segun el archivo importado)"        # playbook, esfuerzo medio


def activo(ip, rol, zona=""):
    return {"ips": {ip}, "role": rol, "zona_asignada": zona}


def hallazgo(titulo, sev, ip="10.0.0.1", **extra):
    return {"titulo": titulo, "severidad": sev, "categoria": "Higiene", "evidencia": "x " + ip, "captura": "a.pcap",
            "recomendacion": "Rec", "activos": [ip], "referencias": {"mitre-ics": "T0886"},
            "id": riesgo.id_hallazgo(titulo), **extra}


def corrida(assets, hallazgos, perf=None, rutas=None):
    return SimpleNamespace(caps=[SimpleNamespace(findings=hallazgos)], extras=[],
                           assets={i: a for i, a in enumerate(assets)}, perfil=perf or {},
                           rutas_ataque=rutas or {}, riesgos={})


def desde_internet(ip):
    return {"filas": [{"origen": "Internet", "objetivo": ip,
                       "camino": f"203.0.113.5 (Internet) -[tcp/22]-> {ip} (Control)"}]}


def una(sev, assets, titulo="H", **kw):
    filas = riesgo.construir(corrida(assets, [hallazgo(titulo, sev)], **kw))["filas"]
    assert len(filas) == 1
    return filas[0]


class RiesgoBase(unittest.TestCase):
    def setUp(self):
        i18n.usar("es")

    def tearDown(self):
        i18n.usar("es")


class IdTest(RiesgoBase):
    def test_mismo_titulo_mismo_id_en_dos_corridas_e_idiomas(self):
        a = riesgo.id_hallazgo(T_ANY)
        self.assertRegex(a, r"^H-[0-9a-f]{6}$")
        i18n.usar("en")
        self.assertEqual(riesgo.id_hallazgo(T_ANY), a)
        self.assertNotEqual(riesgo.id_hallazgo(T_VULN), a)

    def test_ids_distintos_para_todos_los_titulos_conocidos(self):
        titulos = {pb["hallazgo"] for pb in playbooks.cargar().values()}
        for p in sorted((RAIZ / "ot_assess").rglob("*.py")):
            arbol = ast.parse(p.read_text(encoding="utf-8"))
            for n in ast.walk(arbol):
                if isinstance(n, ast.Call) and getattr(n.func, "id", "") == "finding" and len(n.args) > 2 \
                        and isinstance(n.args[2], ast.Constant) and isinstance(n.args[2].value, str):
                    titulos.add(n.args[2].value)
                if isinstance(n, ast.Assign) and isinstance(n.value, ast.Constant) and isinstance(n.value.value, str) \
                        and any(getattr(x, "id", "").startswith("TIT") for x in n.targets):
                    titulos.add(n.value.value)
        self.assertGreater(len(titulos), 80)
        ids = {riesgo.id_hallazgo(x) for x in titulos}
        self.assertEqual(len(ids), len(titulos))

    def test_finding_pone_el_id(self):
        from ot_assess.rules.base import finding
        cap = SimpleNamespace(name="a.pcap", findings=[])
        finding(cap, "Media", T_ANY, "e", "p", "r")
        self.assertEqual(cap.findings[0]["id"], riesgo.id_hallazgo(T_ANY))


class PuntuacionTest(RiesgoBase):
    def test_media_sin_exposicion_con_activo_critico(self):
        r = una("Media", [activo("10.0.0.1", PLC)])
        self.assertEqual((r["probabilidad"], r["impacto"], r["puntuacion"], r["nivel"]), (3, 5, 15, "Alto"))
        self.assertIn("sin rutas de ataque calculadas", r["motivo_probabilidad"])
        self.assertEqual((r["origen"], r["dimension_impacto"]), ("inferido", "produccion (inferida)"))
        self.assertEqual((r["id_riesgo"], r["id_hallazgo"]), ("R-" + r["id_hallazgo"][2:], riesgo.id_hallazgo("H")))
        self.assertEqual(r["tecnicas_mitre_ics"], "T0886")

    def test_alcanzable_desde_internet_suma_uno(self):
        r = una("Media", [activo("10.0.0.1", PLC)], rutas=desde_internet("10.0.0.1"))
        self.assertEqual((r["probabilidad"], r["impacto"], r["puntuacion"], r["nivel"]), (4, 5, 20, "Muy alto"))
        self.assertEqual(r["motivo_probabilidad"], "severidad Media (3) + alcanzable desde Internet (+1)")

    def test_paso_de_un_camino_tambien_suma_y_tope_5(self):
        rutas = {"filas": [{"origen": "Corp IT", "objetivo": "10.0.0.9",
                            "camino": "10.9.9.9 (Corp IT) -[tcp/3389]-> 10.0.0.1 (Control) -[tcp/502]-> 10.0.0.9 (Control)"}]}
        r = una("Alta", [activo("10.0.0.1", WIN)], rutas=rutas)
        self.assertEqual(r["probabilidad"], 5)
        self.assertIn("zona IT Corp IT", r["motivo_probabilidad"])

    def test_sin_exposicion_con_rutas_lo_dice(self):
        r = una("Baja", [activo("10.0.0.1", WIN)], rutas=desde_internet("10.0.0.7"))
        self.assertEqual(r["probabilidad"], 2)
        self.assertIn("sin exposicion observada", r["motivo_probabilidad"])

    def test_kev_suma_uno(self):
        from ot_assess.avisos_cisa import TITULO_KEV
        r = una("Alta", [activo("10.0.0.1", WIN)], titulo=TITULO_KEV)
        self.assertEqual(r["probabilidad"], 5)
        self.assertIn("KEV", r["motivo_probabilidad"])

    def test_sin_activo_impacto_3(self):
        res = corrida([activo("10.0.0.1", PLC)], [dict(hallazgo("H", "Media"), activos=[], evidencia="sin ip")])
        r = riesgo.construir(res)["filas"][0]
        self.assertEqual((r["impacto"], r["dimension_impacto"]), (3, "produccion (inferida)"))

    def test_niveles(self):
        for pts, niv in ((1, "Bajo"), (4, "Bajo"), (5, "Medio"), (9, "Medio"), (10, "Alto"), (16, "Alto"),
                         (20, "Muy alto"), (25, "Muy alto")):
            self.assertEqual(riesgo.nivel(pts), niv, pts)

    def test_informativa_fuera_y_orden(self):
        res = corrida([activo("10.0.0.1", PLC), activo("10.0.0.2", WIN)],
                      [hallazgo("Info", "Informativa"), hallazgo("B", "Baja", "10.0.0.2"),
                       hallazgo("A", "Alta", "10.0.0.1")])
        filas = riesgo.construir(res)["filas"]
        self.assertEqual([f["titulo"] for f in filas], ["A", "B"])
        self.assertEqual([f["puntuacion"] for f in filas], [20, 6])


class ImpactoPerfilTest(RiesgoBase):
    def setUp(self):
        super().setUp()
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def perfil(self, **extra):
        p = self.tmp / "p.json"
        p.write_text(json.dumps({"version": 1, "cliente": "X", "marcos": [{"clave": "iec62443"}], **extra}),
                     encoding="utf-8")
        return perfil.cargar(p)

    def zona(self, impacto):
        return {"zonas": [{"nombre": "Proceso", "redes": ["10.0.0.0/24"], "impacto": impacto}]}

    def test_impacto_declarado_por_zona_y_dimension(self):
        pf = self.perfil(**self.zona({"seguridad": 5, "financiero": 2}))
        r = una("Media", [activo("10.0.0.1", WIN, "Proceso")], perf=pf)
        self.assertEqual((r["impacto"], r["dimension_impacto"], r["zonas"]), (5, "seguridad", "Proceso"))
        self.assertIn("zona Proceso declara seguridad = 5", r["motivo_impacto"])

    def test_empate_gana_la_primera_dimension(self):
        pf = self.perfil(**self.zona({"reputacion": 4, "ambiente": 4}))
        r = una("Media", [activo("10.0.0.1", WIN, "Proceso")], perf=pf)
        self.assertEqual((r["impacto"], r["dimension_impacto"]), (4, "ambiente"))

    def test_impacto_fuera_de_rango_o_clave_desconocida_es_error(self):
        for imp in ({"seguridad": 6}, {"seguridad": 0}, {"seguridad": True}, {"vida": 3}, {}):
            with self.assertRaises(SystemExit, msg=imp):
                self.perfil(**self.zona(imp))

    def test_ajuste_con_justificacion(self):
        hid = riesgo.id_hallazgo("H")
        pf = self.perfil(ajustes_riesgo={hid: {"probabilidad": 1, "justificacion": "Equipo aislado en sitio"}})
        r = una("Alta", [activo("10.0.0.1", PLC)], perf=pf)
        self.assertEqual((r["origen"], r["probabilidad"], r["impacto"]), ("analista", 1, 5))
        self.assertEqual(r["motivo_probabilidad"], "ajustado por el analista: Equipo aislado en sitio")
        self.assertIn("criticidad Critica", r["motivo_impacto"])       # el impacto no se ajusto

    def test_ajuste_sin_justificacion_es_error(self):
        with self.assertRaises(SystemExit):
            self.perfil(ajustes_riesgo={"H-abcdef": {"probabilidad": 2}})
        with self.assertRaises(SystemExit):
            self.perfil(ajustes_riesgo={"H-abcdef": {"justificacion": "x"}})       # ni probabilidad ni impacto
        with self.assertRaises(SystemExit):
            self.perfil(ajustes_riesgo={"H-abcdef": {"probabilidad": 9, "justificacion": "x"}})
        with self.assertRaises(SystemExit):
            self.perfil(ajustes_riesgo={"abcdef": {"probabilidad": 2, "justificacion": "x"}})

    def test_id_ausente_es_aviso_no_error(self):
        pf = self.perfil(ajustes_riesgo={"H-000000": {"impacto": 2, "justificacion": "x"}})
        reg = riesgo.construir(corrida([activo("10.0.0.1", PLC)], [hallazgo("H", "Alta")], perf=pf))
        self.assertEqual(len(reg["avisos"]), 1)
        self.assertIn("H-000000", reg["avisos"][0])
        self.assertEqual(reg["filas"][0]["origen"], "inferido")


class QuickWinTest(RiesgoBase):
    def test_alto_con_esfuerzo_bajo_es_quick_win(self):
        r = una("Alta", [activo("10.0.0.1", PLC)], titulo=T_ANY)
        self.assertEqual((r["nivel"], r["esfuerzo_estimado"], r["quick_win"]), ("Muy alto", "bajo", "si"))

    def test_medio_con_esfuerzo_bajo_no(self):
        r = una("Baja", [activo("10.0.0.1", WIN)], titulo=T_ANY)
        self.assertEqual((r["nivel"], r["esfuerzo_estimado"], r["quick_win"]), ("Medio", "bajo", "no"))

    def test_alto_con_esfuerzo_medio_no_y_sin_playbook_no(self):
        r = una("Alta", [activo("10.0.0.1", PLC)], titulo=T_VULN)
        self.assertEqual((r["nivel"], r["esfuerzo_estimado"], r["quick_win"]), ("Muy alto", "medio", "no"))
        r = una("Alta", [activo("10.0.0.1", PLC)], titulo="Sin playbook")
        self.assertEqual((r["esfuerzo_estimado"], r["quick_win"]), ("no determinado", "no"))

    def test_todos_los_playbooks_traen_esfuerzo(self):
        for pid, pb in playbooks.cargar().items():
            self.assertIn(pb["esfuerzo_estimado"], playbooks.ESFUERZOS, pid)
        pb = dict(next(iter(playbooks.cargar().values())))
        del pb["esfuerzo_estimado"]
        with self.assertRaises(ValueError):
            playbooks.validar(pb)


class MapaTest(RiesgoBase):
    def test_la_suma_del_mapa_es_el_numero_de_riesgos(self):
        res = corrida([activo("10.0.0.1", PLC), activo("10.0.0.2", WIN)],
                      [hallazgo("A", "Alta"), hallazgo("B", "Media", "10.0.0.2"), hallazgo("C", "Baja", "10.0.0.2")])
        reg = riesgo.construir(res)
        self.assertEqual(len(reg["mapa"]), 25)
        self.assertEqual(sum(c["riesgos"] for c in reg["mapa"]), len(reg["filas"]))
        self.assertEqual([c["impacto"] for c in reg["mapa"][:5]], [5] * 5)
        self.assertEqual([c["probabilidad"] for c in reg["mapa"][:5]], [1, 2, 3, 4, 5])
        cab, filas, niveles = riesgo.cuadricula(reg)
        self.assertEqual(niveles[0][5], "Muy alto")           # P 5 x I 5
        self.assertEqual(niveles[4][1], "Bajo")                # P 1 x I 1


class ReporteTest(unittest.TestCase):
    """Camino `diagrama` de punta a punta, en espanol e ingles, con un ajuste que lleva un riesgo a P 5 x I 5."""

    @classmethod
    def setUpClass(cls):
        i18n.usar("es")
        cls.tmp = Path(tempfile.mkdtemp())
        est = gen_exports.escribir(cls.tmp / "ex")["b"]
        vul = cls.tmp / "vul.csv"
        vul.write_text("ip,cve,severidad,cvss,estado,producto,version,fuente\n"
                       "10.20.1.11,CVE-2099-0001,Critical,9.8,open,Firmware PLC ficticio,1.0,Escaner\n",
                       encoding="utf-8")
        cls.hid = riesgo.id_hallazgo(T_VULN)
        pf = cls.tmp / "perfil.json"
        pf.write_text(json.dumps({
            "version": 1, "cliente": "Prueba", "marcos": [{"clave": "iec62443"}],
            "ajustes_riesgo": {cls.hid: {"probabilidad": 5, "impacto": 5, "justificacion": "Decision de prueba"}}}),
            encoding="utf-8")
        cls.args = ["diagrama", "--activos", str(est["activos"]), "--enlaces", str(est["enlaces"]),
                    "--vulnerabilidades", str(vul)]
        cls.es = cls.correr("es", "--perfil", str(pf))
        i18n.FALTANTES.clear()
        cls.en = cls.correr("en", "--perfil", str(pf), "--idioma", "en")
        cls.faltantes = set(i18n.FALTANTES)
        i18n.usar("es")

    @classmethod
    def tearDownClass(cls):
        i18n.usar("es")
        i18n.FALTANTES.clear()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    @classmethod
    def correr(cls, destino, *extra):
        out = cls.tmp / destino
        with contextlib.redirect_stdout(io.StringIO()):
            assert main([*cls.args, "-o", str(out), *extra]) == 0
        return out

    @staticmethod
    def leer(ruta):
        with open(ruta, newline="", encoding="utf-8-sig") as fh:
            return list(csv.DictReader(fh))

    def test_hallazgos_csv_trae_el_id_primero_y_el_plan_su_id(self):
        with open(self.es / "hallazgos.csv", newline="", encoding="utf-8-sig") as fh:
            cab = next(csv.reader(fh))
        self.assertEqual(cab[0], "id")
        ids_h = {f["titulo"]: f["id"] for f in self.leer(self.es / "hallazgos.csv")}
        for titulo, hid in ids_h.items():
            self.assertEqual(hid, riesgo.id_hallazgo(titulo))
        plan = self.leer(self.es / "plan_remediacion.csv")
        self.assertEqual(list(plan[0])[0], "id_hallazgo")
        for f in plan:
            self.assertEqual(f["id_hallazgo"], riesgo.id_hallazgo(f["titulo"]))
        # en ingles el ID es el mismo (se calcula sobre el titulo en espanol)
        self.assertEqual({f["id"] for f in self.leer(self.en / "hallazgos.csv")}, set(ids_h.values()))

    def test_registro_csv_y_ajuste(self):
        filas = self.leer(self.es / "riesgos.csv")
        self.assertEqual(list(filas[0]), riesgo.COLUMNAS)
        puntos = [int(f["puntuacion"]) for f in filas]
        self.assertEqual(puntos, sorted(puntos, reverse=True))
        aj = next(f for f in filas if f["id_hallazgo"] == self.hid)
        self.assertEqual((aj["probabilidad"], aj["impacto"], aj["puntuacion"], aj["nivel"], aj["origen"]),
                         ("5", "5", "25", "Muy alto", "analista"))
        self.assertIn("ajustado por el analista: Decision de prueba", aj["motivo_probabilidad"])
        self.assertTrue(all(f["origen"] in ("inferido", "analista") for f in filas))
        mapa = self.leer(self.es / "mapa_calor_riesgo.csv")
        self.assertEqual(list(mapa[0]), riesgo.COL_MAPA)
        self.assertEqual(len(mapa), 25)
        self.assertEqual(sum(int(c["riesgos"]) for c in mapa), len(filas))
        self.assertNotIn("Informativa", {f["severidad"] for f in filas})

    def test_html_celda_5x5_roja_y_seccion(self):
        html = (self.es / "reporte_ot.html").read_text(encoding="utf-8")
        self.assertIn("Registro de riesgos y mapa de calor", html)
        cuerpo = html.split('<table class="mapa-calor">')[1].split("</table>")[0]
        primera = re.search(r"<tbody>\s*<tr>(.*?)</tr>", cuerpo, re.S).group(1)      # impacto 5
        celdas = re.findall(r'<td class="([^"]+)"[^>]*>(\d+)</td>', primera)
        self.assertEqual(celdas[-1][0], "mc-muy-alto")      # impacto 5 x probabilidad 5
        self.assertGreaterEqual(int(celdas[-1][1]), 1)
        self.assertEqual([c for c, _n in celdas[:4]], ["mc-medio", "mc-alto", "mc-alto", "mc-muy-alto"])
        self.assertIn(".mc-muy-alto{background:#FF5050}", html)
        self.assertIn("R-" + self.hid[2:], html)
        self.assertIn(self.hid, html)                  # el ID junto al titulo del hallazgo

    def test_md_word_json_y_xlsx(self):
        md = (self.es / "reporte_ot.md").read_text(encoding="utf-8")
        self.assertIn("## Registro de riesgos y mapa de calor", md)
        self.assertRegex(md, r"\| \d+ \(Muy alto\) \|\n")
        self.assertIn(f"({self.hid})", md)
        with zipfile.ZipFile(self.es / "informe_ot.docx") as z:
            self.assertIsNone(z.testzip())
            doc = z.read("word/document.xml").decode("utf-8")
        self.assertIn("Registro de riesgos y mapa de calor", doc)
        self.assertIn('w:fill="FF5050"', doc)
        with zipfile.ZipFile(self.es / "reporte_ot.xlsx") as z:
            self.assertIsNone(z.testzip())
            libro = z.read("xl/workbook.xml").decode("utf-8")
            estilos = z.read("xl/styles.xml").decode("utf-8")
            hojas = re.findall(r'<sheet name="([^"]+)"', libro)
            mapa = z.read(f"xl/worksheets/sheet{hojas.index('Mapa de calor de riesgo') + 1}.xml").decode("utf-8")
        self.assertIn("Registro de riesgos", hojas)
        self.assertIn("Mapa de calor de riesgo", hojas)
        self.assertIn("FFFF5050", estilos)
        self.assertIn('s="5"', mapa)
        datos = json.loads((self.es / "resultado.json").read_text(encoding="utf-8"))["riesgos"]
        self.assertEqual(set(datos), {"registro", "mapa", "quick_wins", "nota"})
        self.assertEqual(len(datos["mapa"]), 25)

    def test_ingles(self):
        html = (self.en / "reporte_ot.html").read_text(encoding="utf-8")
        self.assertIn("Risk register and heat map", html)
        cab = self.leer(self.en / "riesgos.csv")
        self.assertIn("likelihood", list(cab[0]))
        self.assertEqual(self.faltantes, set())


if __name__ == "__main__":
    unittest.main()
