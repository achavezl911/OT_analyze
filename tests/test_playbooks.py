"""P1a: playbooks de remediacion (datos en ot_assess/playbooks/*.json). Sin tshark."""
from __future__ import annotations

import contextlib
import copy
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

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))
sys.path.insert(0, str(RAIZ / "tests"))

import gen_exports
from test_i18n import _espanol_en, _visible_docx, _visible_html
from test_remediacion import PLC, activo, corrida, hallazgo
from test_standards import titulos_de_las_reglas

from ot_assess import i18n, playbooks, remediacion
from ot_assess import standards as st
from ot_assess.cli import main

EJEMPLOS = RAIZ / "docs" / "ejemplos"
NOTA_SINTAXIS = "verificar la sintaxis en la documentacion del fabricante para la version instalada"
PREFIJOS = ("IEC 62443 ", "NERC ", "NIST 800-82 ", "NIST CSF ", "MITRE ICS ")
RE_COMANDO = re.compile(r"#|>|\b(?:set|config|conf t)\s", re.IGNORECASE)
FW = ("FW1# show running-config\n"
      "access-list CSM_FW_ACL_ advanced permit ip ifc superv any ifc campo any rule-id 1\n"
      "access-list CSM_FW_ACL_ advanced deny ip any any rule-id 2\n"
      "FW1# show route\nCodes: L - local, C - connected, S - static\n"
      "S*  0.0.0.0 0.0.0.0 [1/0] via 192.0.2.1, outside\n"
      "C   10.20.1.0 255.255.255.0 is directly connected, campo\n"
      "C   10.20.2.0 255.255.255.0 is directly connected, superv\n"
      "FW1# show nameif\nInterface Name Security\nGigabitEthernet0/0 outside 0\n")
T_VULN = "Vulnerabilidades conocidas en activos (segun el archivo importado)"
T_OPCUA = "OPC UA sin seguridad de mensajes (politica None)"
T_MB_DIAG = "Modbus FC8 de diagnostico (sin reinicio ni silencio)"


def textos(pb: dict) -> list:
    out = [pb[k] for k in ("objetivo", "prioridad_ot", "responsable")]
    for k in ("pasos", "verificacion", "reversion", "precauciones"):
        out += pb[k]
    for pasos in pb["por_plataforma"].values():
        out += pasos
    return out


class FormatoTest(unittest.TestCase):
    def test_todos_cargan_y_validan_contra_titulos_reales(self):
        pbs = playbooks.cargar()
        titulos = titulos_de_las_reglas()
        for pid, pb in pbs.items():
            playbooks.validar(pb, pid, titulos)
            self.assertEqual(pid, pb["id"])
        self.assertEqual(len({pb["hallazgo"] for pb in pbs.values()}), len(pbs))

    def test_cobertura_total_cada_titulo_tiene_exactamente_un_playbook(self):
        """P1b: todo hallazgo que puede generar la herramienta tiene playbook, y uno solo."""
        pbs = playbooks.cargar()
        titulos = titulos_de_las_reglas()
        sin = [x for x in titulos if not playbooks.para_titulo(x)]
        self.assertEqual(sin, [], "titulos sin playbook")
        for x in titulos:
            self.assertEqual([p for p, pb in pbs.items() if pb["hallazgo"] in x], [playbooks.para_titulo(x)], x)
        self.assertEqual(len(pbs), len(set(titulos)))

    def test_un_hallazgo_sin_playbook_no_lo_tiene(self):
        self.assertEqual(playbooks.para_titulo("Hallazgo que no existe"), "")
        self.assertEqual(playbooks.para_titulo(T_MB_DIAG), "pb-modbus-diagnostico")
        self.assertEqual(playbooks.para_titulo(T_OPCUA), "pb-opcua-sin-seguridad")

    def valido(self) -> dict:
        return copy.deepcopy(playbooks.cargar()["pb-vulnerabilidades"])

    def test_plataforma_no_permitida_falla_con_mensaje_claro(self):
        pb = self.valido()
        pb["por_plataforma"]["Palo Alto"] = ["a", "b"]
        with self.assertRaisesRegex(ValueError, "plataforma no permitida 'Palo Alto'"):
            playbooks.validar(pb, "x.json")

    def test_hallazgo_inexistente_o_ambiguo_falla(self):
        pb = self.valido()
        pb["hallazgo"] = "Hallazgo que no existe"
        with self.assertRaisesRegex(ValueError, "exactamente un titulo.*coincide con 0"):
            playbooks.validar(pb, "x.json", titulos_de_las_reglas())
        pb["hallazgo"] = "Modbus FC8"      # coincide con el grave y el de diagnostico
        with self.assertRaisesRegex(ValueError, "coincide con 2"):
            playbooks.validar(pb, "x.json", titulos_de_las_reglas())

    def test_claves_y_longitudes(self):
        pb = self.valido()
        del pb["reversion"]
        with self.assertRaisesRegex(ValueError, "faltan: reversion"):
            playbooks.validar(pb, "x.json")
        pb = self.valido()
        pb["pasos"] = pb["pasos"][:3]
        with self.assertRaisesRegex(ValueError, "'pasos' debe tener entre 4 y 8"):
            playbooks.validar(pb, "x.json")
        pb = self.valido()
        pb["por_plataforma"]["Linux"] = ["solo uno"]
        with self.assertRaisesRegex(ValueError, "'Linux' debe tener entre 2 y 6"):
            playbooks.validar(pb, "x.json")

    def test_referencias_son_las_que_ya_usa_el_hallazgo(self):
        for pb in playbooks.cargar().values():
            titulo = next(x for x in titulos_de_las_reglas() if pb["hallazgo"] in x)
            usadas = " | ".join(st.referencias(titulo).values())
            for ref in pb["referencias"]:
                pref = next((p for p in PREFIJOS if ref.startswith(p)), None)
                self.assertIsNotNone(pref, ref)
                self.assertIn(ref[len(pref):], usadas, f"{pb['id']}: {ref} no esta en los marcos del hallazgo")


class ContenidoTest(unittest.TestCase):
    def test_sin_cumple_ni_elimina_el_riesgo(self):
        for pb in playbooks.cargar().values():
            for x in [*textos(pb), playbooks.NOTA]:
                bajo = x.lower()
                self.assertNotIn("cumple", bajo, x)
                self.assertNotIn("elimina el riesgo", bajo, x)

    def test_todo_comando_o_menu_lleva_la_nota_de_sintaxis(self):
        n = 0
        for pb in playbooks.cargar().values():
            for x in textos(pb):
                if RE_COMANDO.search(x):
                    n += 1
                    self.assertIn(NOTA_SINTAXIS, x, f"{pb['id']}: {x}")
        self.assertGreater(n, 5)            # la prueba si ve rutas de menu

    def test_cada_playbook_nombra_las_precauciones_basicas_de_ot(self):
        for pb in playbooks.cargar().values():
            todo = " ".join(textos(pb)).lower()
            for palabra in ("ventana", "laboratorio", "respald", "registro", "dueno del proceso"):
                self.assertIn(palabra, todo, f"{pb['id']}: falta '{palabra}'")
            self.assertTrue(pb["responsable"] and not re.search(r"@|\bing\. [A-Z]", pb["responsable"]))

    def test_nunca_se_recomienda_reiniciar_sin_ventana(self):
        for pb in playbooks.cargar().values():
            for x in textos(pb):
                if re.search(r"\breinici", x.lower()) and re.search(r"controlador|equipo|outstation", x.lower()):
                    self.assertRegex(x.lower(), r"ventana|incidente|no |evitar|comando|diagnostico|reinicio o paro",
                                     f"{pb['id']}: {x}")


class PlanTest(unittest.TestCase):
    def test_columna_playbook_en_el_plan(self):
        self.assertEqual(remediacion.COLUMNAS[-2:], ["playbook", "esfuerzo"])
        assets = [activo(["10.0.0.1"], PLC)]
        res = corrida(assets, [hallazgo(T_VULN, "Alta", "x 10.0.0.1"), hallazgo("Hallazgo sin playbook", "Alta", "x"),
                               hallazgo(T_OPCUA, "Media", "x 10.0.0.1")])
        filas = {f["titulo"]: f["playbook"] for f in remediacion.plan(res)}
        self.assertEqual(filas, {T_VULN: "pb-vulnerabilidades", "Hallazgo sin playbook": "",
                                 T_OPCUA: "pb-opcua-sin-seguridad"})
        tabla = remediacion.tabla(res)
        i = remediacion.COLUMNAS.index("playbook")
        self.assertEqual(sorted(f[i] for f in tabla), ["", "pb-opcua-sin-seguridad", "pb-vulnerabilidades"])
        self.assertEqual([f[-1] for f in tabla], ["", "", ""])      # esfuerzo sigue vacio

    def test_seccion_solo_con_los_presentes_y_en_el_orden_del_plan(self):
        assets = [activo(["10.0.0.1"], PLC)]
        res = corrida(assets, [hallazgo(T_OPCUA, "Baja", "x 10.0.0.1"), hallazgo(T_VULN, "Alta", "x 10.0.0.1"),
                               hallazgo(T_VULN, "Alta", "otra", cap="b.pcap")])
        sec = remediacion.resumen(res)["playbooks"]
        self.assertEqual([p["id"] for p in sec], ["pb-vulnerabilidades", "pb-opcua-sin-seguridad"])
        etiquetas = [b[0] for b in sec[0]["bloques"]]
        self.assertEqual(etiquetas[:3], ["Objetivo", "Que se rompe si se hace mal", "Pasos"])
        self.assertIn("Por plataforma: Claroty xDome", etiquetas)
        self.assertEqual(etiquetas[-5:-3], ["Verificacion", "Reversion"])
        self.assertIsNone(remediacion.resumen(corrida(assets, [hallazgo("Otro", "Alta", "x")]))["playbooks"])


class ReporteTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        est = gen_exports.escribir(cls.tmp / "ex")["b"]
        fw = cls.tmp / "fw.txt"
        fw.write_text(FW, encoding="utf-8")
        vul = cls.tmp / "vul.csv"
        vul.write_text("ip,cve,severidad,cvss,estado,producto,version,fuente\n"
                       "10.20.1.11,CVE-2099-0001,Critical,9.8,open,Firmware PLC ficticio,1.0,Escaner\n",
                       encoding="utf-8")
        cls.args = ["diagrama", "--activos", str(est["activos"]), "--enlaces", str(est["enlaces"]),
                    "--firewall", str(fw), "--vulnerabilidades", str(vul),
                    "--alertas", str(EJEMPLOS / "alertas.csv")]
        cls.es = cls.correr("es")
        i18n.FALTANTES.clear()
        cls.en = cls.correr("en", "--idioma", "en")
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

    def ids_del_plan(self, d=None) -> list:
        with open((d or self.es) / "plan_remediacion.csv", newline="", encoding="utf-8-sig") as fh:
            vistos: list = []
            for f in csv.DictReader(fh):
                if f["playbook"] and f["playbook"] not in vistos:
                    vistos.append(f["playbook"])
        return vistos

    def docx(self, d) -> str:
        with zipfile.ZipFile(d / "informe_ot.docx") as z:
            return z.read("word/document.xml").decode("utf-8")

    def test_el_plan_trae_playbooks_y_no_todos(self):
        ids = self.ids_del_plan()
        self.assertIn("pb-vulnerabilidades", ids)
        self.assertGreaterEqual(len(ids), 3)
        self.assertLess(len(ids), len(playbooks.cargar()))

    def test_html_md_y_word_solo_con_los_de_los_hallazgos_presentes(self):
        ids = self.ids_del_plan()
        ausentes = [i for i in playbooks.cargar() if i not in ids]
        html = (self.es / "reporte_ot.html").read_text(encoding="utf-8")
        md = (self.es / "reporte_ot.md").read_text(encoding="utf-8")
        doc = self.docx(self.es)
        for nombre, txt in (("html", html), ("md", md), ("docx", doc)):
            self.assertIn("Playbooks de remediacion", txt, nombre)
            self.assertEqual(re.findall(r"\((pb-[a-z0-9-]+)\)", txt), ids, nombre)     # orden del plan
            for i in ausentes:
                self.assertNotIn(i, txt, nombre)
        self.assertIn("<h3>", html)
        self.assertIn("### ", md)
        self.assertIn('<w:pStyle w:val="Heading2"/>', doc)
        self.assertIn("ListParagraph", doc)
        self.assertIn("Por plataforma: Claroty xDome", md)

    def test_ingles_sin_faltantes_ni_espanol(self):
        self.assertEqual(self.faltantes, set())
        html = (self.en / "reporte_ot.html").read_text(encoding="utf-8")
        md = (self.en / "reporte_ot.md").read_text(encoding="utf-8")
        for txt in (_visible_html(html), md, _visible_docx(self.docx(self.en))):
            self.assertIn("Remediation playbooks", txt)
            self.assertIn("By platform", txt)
            self.assertEqual(_espanol_en(txt), [])
        self.assertEqual(self.ids_del_plan(self.en), self.ids_del_plan())

    def test_catalogo_cubre_cada_texto_de_cada_playbook(self):
        cat = json.loads((RAIZ / "ot_assess" / "catalogos" / "en.json").read_text(encoding="utf-8"))["en"]
        claves = list(playbooks.PLATAFORMAS) + list(playbooks.ETIQUETAS) + [playbooks.TITULO, playbooks.NOTA]
        for pb in playbooks.cargar().values():
            claves += textos(pb)
        self.assertEqual(sorted({k for k in claves if k not in cat}), [])

    def test_ingles_de_todos_los_playbooks_sin_espanol(self):
        cat = json.loads((RAIZ / "ot_assess" / "catalogos" / "en.json").read_text(encoding="utf-8"))["en"]
        for pb in playbooks.cargar().values():
            for x in textos(pb):
                self.assertEqual(_espanol_en(cat[x]), [], f"{pb['id']}: {cat[x]}")


if __name__ == "__main__":
    unittest.main()
