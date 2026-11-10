"""F1c: conductos que no cruzan el firewall, marcas de higiene de reglas y hallazgos. Texto sintetico de FTD."""
from __future__ import annotations

import contextlib
import csv
import io
import shutil
import sys
import tempfile
import time
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))
sys.path.insert(0, str(RAIZ / "tests"))

import gen_exports
from test_firewalls_integracion import RUTAS, _c, _sesion

try:
    import scapy  # noqa: F401
    HAY_SCAPY = True
except ImportError:
    HAY_SCAPY = False

from ot_assess import i18n, remediacion
from ot_assess.cli import main
from ot_assess.firewalls import cisco
from ot_assess.firewalls import higiene as hg
from ot_assess.firewalls import integracion as fi
from ot_assess.model import Capture
from ot_assess.standards import ESTANDARES, MITRE

ACL = "access-list CSM_FW_ACL_ advanced "
DEFECTO = ("access-list CSM_FW_ACL_ remark rule-id 99: L4 RULE: DEFAULT ACTION RULE\n"
           + ACL + "deny ip any any rule-id 99\n")


def _contraste(reglas: str, conductos: list, hits: str = "") -> dict:
    fw = cisco.analizar_texto(_sesion(RUTAS, reglas, hits))
    return fi.contrastar(fw, conductos, "fw.txt", [])


def _marcas(r: dict) -> dict:
    return {x["id"]: [m for m in x["marcas"].split("; ") if m] for x in r["reglas"]}


class NoCruzaTest(unittest.TestCase):
    def test_misma_interfaz_o_sin_interfaz_no_cruza(self):
        reglas = ACL + "permit ip any any rule-id 1\n" + DEFECTO
        r = _contraste(reglas, [_c("10.10.1.5", "10.10.1.9"), _c("10.10.1.5", "10.10.9.5"),
                                _c("no-es-ip", "10.10.9.5")])
        self.assertEqual([x["resultado"] for x in r["resultados"]], ["no_cruza", "permitido", "no_cruza"])
        self.assertEqual(r["resumen"]["no_cruza"], 2)
        tab = {x["id"]: x for x in r["reglas"]}
        self.assertEqual(tab["1"]["conductos_observados"], 1)    # solo el que cruza
        self.assertEqual(r["resultados"][0]["regla"], "")

    def test_no_cruza_no_hace_a_una_regla_con_trafico(self):
        r = _contraste(ACL + "permit tcp any any eq 80 rule-id 1\n" + DEFECTO, [_c("10.10.1.5", "10.10.1.9")])
        self.assertEqual([x["regla"] for x in r["sin_trafico"]], ["1"])
        self.assertEqual(r["resumen"]["reglas_sin_trafico"], 1)
        self.assertIn("sin conductos observados", _marcas(r)["1"])


class MarcasTest(unittest.TestCase):
    def test_any_any_y_regla_por_defecto_excluida(self):
        reglas = (ACL + "permit ip any any rule-id 1\n"
                  + ACL + "permit tcp any any eq 80 rule-id 2\n"
                  + "access-list CSM_FW_ACL_ remark rule-id 98: L4 RULE: DEFAULT TUNNEL ACTION RULE\n"
                  + ACL + "permit ip any any rule-id 98\n" + DEFECTO)
        m = _marcas(_contraste(reglas, []))
        self.assertIn("any-any", m["1"])
        self.assertNotIn("any-any", m["2"])
        self.assertNotIn("any-any", m["98"])
        self.assertNotIn("any-any", m["99"])

    def test_ultima_de_la_politica_ftd_no_es_any_any(self):
        m = _marcas(_contraste(ACL + "permit ip any any rule-id 7\n", []))
        self.assertNotIn("any-any", m["7"])

    def test_confiar_es_sin_inspeccion(self):
        m = _marcas(_contraste(ACL + "trust tcp any any eq 80 rule-id 1\n" + ACL + "permit tcp any any eq 22 rule-id 2\n"
                               + DEFECTO, []))
        self.assertIn("confia sin inspeccion", m["1"])
        self.assertNotIn("confia sin inspeccion", m["2"])

    def test_sombreada(self):
        a = ACL + "permit ip 10.0.0.0 255.0.0.0 any rule-id 1\n"
        b = ACL + "permit tcp 10.1.1.0 255.255.255.0 any eq 443 rule-id 2\n"
        m = _marcas(_contraste(a + b + DEFECTO, []))
        self.assertIn("sombreada por 1", m["2"])
        self.assertFalse([x for x in m["1"] if x.startswith("sombreada")])
        # accion distinta
        m = _marcas(_contraste(a.replace("permit", "deny") + b + DEFECTO, []))
        self.assertIn("sombreada por 1 (accion distinta)", m["2"])
        # una subregla no cubierta: no esta sombreada
        b2 = b + ACL + "permit tcp 192.168.0.0 255.255.0.0 any eq 443 rule-id 2\n"
        m = _marcas(_contraste(a + b2 + DEFECTO, []))
        self.assertFalse([x for x in m["2"] if x.startswith("sombreada")])
        # mas amplia despues no sombrea a la anterior; puerto distinto tampoco
        m = _marcas(_contraste(b + a + DEFECTO, []))
        self.assertFalse([x for x in m["1"] if x.startswith("sombreada")])
        m = _marcas(_contraste(ACL + "permit tcp any any eq 80 rule-id 1\n" + b + DEFECTO, []))
        self.assertFalse([x for x in m["2"] if x.startswith("sombreada")])

    def test_sombreada_respeta_interfaces(self):
        a = ACL + "permit ip ifc inside any ifc outside any rule-id 1\n"
        b_igual = ACL + "permit tcp ifc inside any ifc outside any eq 80 rule-id 2\n"
        b_otra = ACL + "permit tcp ifc dmz any ifc outside any eq 80 rule-id 3\n"
        m = _marcas(_contraste(a + b_igual + b_otra + DEFECTO, []))
        self.assertTrue(any(x.startswith("sombreada") for x in m["2"]))
        self.assertFalse(any(x.startswith("sombreada") for x in m["3"]))

    def test_sin_aciertos_y_sin_conductos(self):
        reglas = (ACL + "permit tcp 10.10.1.0 255.255.255.0 any eq 80 rule-id 1\n"
                  + ACL + "permit tcp any any eq 22 rule-id 2\n" + DEFECTO)
        hits = ("FW1# show rule hits\nRuleID Hit Count First Hit Time(UTC) Last Hit Time(UTC)\n"
                "1   5   10:01:02 Oct 5 2024   11:22:33 Nov 3 2024\n")
        m = _marcas(_contraste(reglas, [_c("10.10.1.5", "8.8.8.8", 80)], hits))
        self.assertEqual(m["1"], [])
        self.assertIn("sin aciertos", m["2"])
        self.assertIn("sin conductos observados", m["2"])
        # sin contadores no hay "sin aciertos"
        m = _marcas(_contraste(reglas, [_c("10.10.1.5", "8.8.8.8", 80)]))
        self.assertNotIn("sin aciertos", m["2"])

    def test_costo_acotado(self):
        lineas = "".join(
            ACL + f"permit tcp 10.{i // 250}.{i % 250}.0 255.255.255.0 any eq {1000 + i} rule-id {i + 1000}\n"
            for i in range(1200))
        t0 = time.time()
        m = _marcas(_contraste(lineas + DEFECTO, []))
        self.assertLess(time.time() - t0, 10)
        self.assertEqual(len(m), 1201)


class HallazgosTest(unittest.TestCase):
    REGLAS = (ACL + "deny tcp 10.10.9.0 255.255.255.0 any rule-id 1\n"
              + ACL + "permit tcp 10.10.9.128 255.255.255.128 any eq 443 rule-id 2\n"
              + ACL + "permit ip any any rule-id 3\n"
              + ACL + "trust tcp any any eq 502 rule-id 4\n" + DEFECTO)

    def _hallazgos(self, conductos):
        r = _contraste(self.REGLAS, conductos)
        cap = Capture(Path("firewall fw.txt"))
        hg.agregar_hallazgos(cap, r)
        return r, {f["titulo"]: f for f in cap.findings}

    def test_cuatro_hallazgos_con_severidad_y_referencias(self):
        # 10.10.9.5 -> 8.8.8.8:443 cae en la deny 1 (denegado observado); 10.10.1.5 -> 8.8.8.8:22 en la 3
        _r, f = self._hallazgos([_c("10.10.9.5", "8.8.8.8", 443), _c("10.10.1.5", "8.8.8.8", 22)])
        self.assertEqual({x["titulo"] for x in f.values()},
                         {hg.TIT_ANY, hg.TIT_CONFIA, hg.TIT_SOMBRA, hg.TIT_DENEGADO})
        self.assertEqual(f[hg.TIT_ANY]["severidad"], "Alta")      # la regla 3 tiene conductos
        self.assertEqual(f[hg.TIT_CONFIA]["severidad"], "Media")
        self.assertEqual(f[hg.TIT_SOMBRA]["severidad"], "Media")  # la 2 esta sombreada por una deny
        self.assertEqual(f[hg.TIT_DENEGADO]["severidad"], "Media")
        self.assertIn("3", f[hg.TIT_ANY]["evidencia"])
        self.assertNotIn("99", f[hg.TIT_ANY]["evidencia"].split("Con aciertos")[1])
        for x in f.values():
            self.assertIn("(segun la configuracion del firewall)", x["titulo"])
            self.assertEqual(set(x["referencias"]), {e.clave for e in ESTANDARES.values()})
            self.assertNotIn(MITRE.clave, x["referencias"])
        self.assertIn("SC-7", f[hg.TIT_ANY]["referencias"]["nist-800-82"])
        self.assertIn("CIP-005 R1", f[hg.TIT_CONFIA]["referencias"]["nerc-cip"])
        self.assertIn("SR 5.1", f[hg.TIT_SOMBRA]["referencias"]["iec62443"])
        self.assertIn("PR.IR-01", f[hg.TIT_DENEGADO]["referencias"]["nist-csf"])
        self.assertIn("otro camino", f[hg.TIT_DENEGADO]["recomendacion"])
        for x in f.values():
            for txt in (x["evidencia"], x["recomendacion"], x["por_que_importa"]):
                self.assertNotIn("cumple", txt.lower())

    def test_any_any_sin_uso_es_media_y_sombra_misma_accion_es_baja(self):
        reglas = (ACL + "permit tcp 10.10.1.0 255.255.255.0 any eq 80 rule-id 1\n"
                  + ACL + "permit tcp 10.10.1.0 255.255.255.0 any eq 80 rule-id 2\n"
                  + ACL + "permit ip any any rule-id 3\n" + DEFECTO)
        cap = Capture(Path("x"))
        hg.agregar_hallazgos(cap, _contraste(reglas, []))
        f = {x["titulo"]: x for x in cap.findings}
        self.assertEqual(f[hg.TIT_ANY]["severidad"], "Media")
        self.assertEqual(f[hg.TIT_SOMBRA]["severidad"], "Baja")
        self.assertNotIn(hg.TIT_CONFIA, f)
        self.assertNotIn(hg.TIT_DENEGADO, f)

    def test_sin_marcas_no_hay_hallazgos(self):
        cap = Capture(Path("x"))
        hg.agregar_hallazgos(cap, {"reglas": [], "resultados": []})
        self.assertEqual(cap.findings, [])

    def test_entran_al_plan_de_remediacion(self):
        _, f = self._hallazgos([_c("10.10.9.5", "8.8.8.8", 443)])
        cap = Capture(Path("firewall fw.txt"))
        cap.findings = list(f.values())
        res = SimpleNamespace(caps=[], extras=[cap], assets={}, perfil={})
        titulos = {x["titulo"] for x in remediacion.plan(res)}
        self.assertEqual(titulos, {hg.TIT_ANY, hg.TIT_CONFIA, hg.TIT_SOMBRA, hg.TIT_DENEGADO})

    def test_en_ingles(self):
        i18n.usar("en")
        self.addCleanup(i18n.usar, "es")
        i18n.FALTANTES.clear()
        _, f = self._hallazgos([_c("10.10.9.5", "8.8.8.8", 443)])
        for x in f.values():
            for k in ("titulo", "evidencia", "por_que_importa", "recomendacion", "categoria"):
                i18n.t(x[k])
            for ref in x["referencias"].values():
                for pieza in ref.split("; "):
                    i18n.t(pieza)
        i18n.t("No cruza este firewall")
        i18n.t("no_cruza")
        self.assertEqual(i18n.t(hg.TIT_ANY)[:8], "Firewall")
        self.assertFalse(i18n.FALTANTES, i18n.FALTANTES)


RUTAS_X = (RUTAS
           + "S        172.16.0.0 255.255.0.0 [1/0] via 10.10.1.254, inside\n"
           + "S        172.16.5.0 255.255.255.0 [1/0] via 10.10.1.254, inside\n"
           + "S        10.50.0.0 255.255.255.128 [1/0] via 10.10.9.1, dmz\n"
           + "S        10.50.0.7 255.255.255.255 [1/0] via 10.10.9.2, dmz\n"
           + "S        10.60.0.0 255.255.255.0 [1/0] via 10.10.9.1, dmz\n")
ARP = ("FW1# show arp\n"
       "        inside 10.10.1.9 0011.2233.4455 12\n"
       "        dmz 10.10.9.1 0011.2233.4466 -\n"
       "        dmz 10.10.9.2 0011.2233.4477 alias\n"
       "        outside 192.0.2.1 aaaa.bbbb.cccc 300\n")
REGLA_ANY = ACL + "permit ip any any rule-id 1\n" + DEFECTO
CONDUCTOS_X = [_c("10.10.9.5", "172.16.5.7"), _c("10.10.1.5", "10.50.0.9"), _c("10.10.1.5", "10.50.0.7"),
               _c("10.10.1.5", "10.10.1.9")]


def _rutas_estado(arp: str = ARP, conductos=None) -> tuple:
    fw = cisco.analizar_texto(_sesion(RUTAS_X, REGLA_ANY, arp))
    r = fi.contrastar(fw, CONDUCTOS_X if conductos is None else conductos, "fw.txt", [])
    return fw, r, {(x["red"], x["siguiente_salto"]): x for x in r["rutas_estado"]}


class RutasTest(unittest.TestCase):
    def test_show_arp_leido_con_edad_guion_y_alias(self):
        fw, _r, _ = _rutas_estado()
        self.assertEqual([(a.interfaz, a.ip, a.mac, a.edad) for a in fw.arp],
                         [("inside", "10.10.1.9", "0011.2233.4455", 12),
                          ("dmz", "10.10.9.1", "0011.2233.4466", None),
                          ("dmz", "10.10.9.2", "0011.2233.4477", None),
                          ("outside", "192.0.2.1", "aaaa.bbbb.cccc", 300)])
        self.assertNotIn("sin show arp: no se valida el salto", fw.avisos)

    def test_salto_fuera_del_arp_y_sin_show_arp(self):
        _fw, _r, f = _rutas_estado()
        self.assertEqual(f["172.16.0.0/16", "10.10.1.254"]["salto_en_arp"], "no")
        self.assertIn("salto sin ARP", f["172.16.0.0/16", "10.10.1.254"]["marcas"])
        self.assertEqual(f["10.60.0.0/24", "10.10.9.1"]["salto_en_arp"], "si")
        self.assertEqual(f["0.0.0.0/0", "192.0.2.1"]["salto_en_arp"], "si")
        self.assertEqual(f["10.10.1.0/24", ""]["salto_en_arp"], "")
        self.assertEqual(f["10.10.1.0/24", ""]["marcas"], "")
        fw, r, f = _rutas_estado(arp="")
        self.assertIn("sin show arp: no se valida el salto", fw.avisos)
        self.assertTrue(all(x["salto_en_arp"] in ("", "sin dato") for x in f.values()))
        self.assertFalse(any("salto sin ARP" in x["marcas"] for x in f.values()))
        self.assertIn("sin show arp", fi.resumen_rutas_texto(r))

    def test_conductos_por_ruta_mas_especifica_y_sin_trafico(self):
        _fw, _r, f = _rutas_estado()
        self.assertEqual(f["172.16.5.0/24", "10.10.1.254"]["conductos"], 1)
        self.assertEqual(f["172.16.0.0/16", "10.10.1.254"]["conductos"], 0)
        self.assertEqual(f["10.50.0.7/32", "10.10.9.2"]["conductos"], 1)
        self.assertEqual(f["10.50.0.0/25", "10.10.9.1"]["conductos"], 1)     # la .9, no la .7
        self.assertEqual(f["10.10.1.0/24", ""]["conductos"], 0)              # no_cruza no cuenta
        self.assertIn("sin trafico observado", f["10.60.0.0/24", "10.10.9.1"]["marcas"])
        self.assertIn("sin trafico observado", f["172.16.0.0/16", "10.10.1.254"]["marcas"])
        self.assertNotIn("sin trafico observado", f["10.50.0.7/32", "10.10.9.2"]["marcas"])
        self.assertNotIn("sin trafico observado", f["0.0.0.0/0", "192.0.2.1"]["marcas"])

    def test_cubierta_y_mismo_prefijo_en_dos_saltos(self):
        _fw, _r, f = _rutas_estado()
        self.assertIn("cubierta por 172.16.0.0/16", f["172.16.5.0/24", "10.10.1.254"]["marcas"])
        self.assertNotIn("cubierta", f["172.16.0.0/16", "10.10.1.254"]["marcas"])
        self.assertIn("mismo prefijo en dos saltos", f["10.50.0.0/25", "10.10.9.1"]["marcas"])
        self.assertIn("mismo prefijo en dos saltos", f["10.50.0.7/32", "10.10.9.2"]["marcas"])
        self.assertNotIn("mismo prefijo", f["172.16.5.0/24", "10.10.1.254"]["marcas"])
        self.assertNotIn("mismo prefijo", f["0.0.0.0/0", "192.0.2.1"]["marcas"])

    def _hallazgo(self, conductos):
        _fw, r, _ = _rutas_estado(conductos=conductos)
        cap = Capture(Path("firewall fw.txt"))
        hg.agregar_hallazgos(cap, r)
        return {x["titulo"]: x for x in cap.findings}

    def test_hallazgo_severidad_referencias_y_plan(self):
        f = self._hallazgo(CONDUCTOS_X)
        h = f[hg.TIT_RUTAS]
        self.assertEqual(h["severidad"], "Media")                # hay trafico hacia 172.16.5.0/24 sin ARP
        self.assertIn("172.16.5.0/24 -> 10.10.1.254 (inside)", h["evidencia"])
        self.assertEqual(set(h["referencias"]), {e.clave for e in ESTANDARES.values()})
        self.assertNotIn(MITRE.clave, h["referencias"])
        self.assertIn("CM-2", h["referencias"]["nist-800-82"])
        self.assertIn("SR 7.6", h["referencias"]["iec62443"])
        self.assertIn("CIP-010 R1", h["referencias"]["nerc-cip"])
        self.assertIn("PR.PS-01", h["referencias"]["nist-csf"])
        for txt in (h["evidencia"], h["recomendacion"], h["por_que_importa"]):
            self.assertNotIn("cumple", txt.lower())
        self.assertEqual(self._hallazgo([_c("10.10.1.5", "10.50.0.9")])[hg.TIT_RUTAS]["severidad"], "Baja")
        cap = Capture(Path("firewall fw.txt"))
        cap.findings = [h]
        res = SimpleNamespace(caps=[], extras=[cap], assets={}, perfil={})
        self.assertEqual({x["titulo"] for x in remediacion.plan(res)}, {hg.TIT_RUTAS})

    def test_sin_rutas_marcadas_no_hay_hallazgo(self):
        cap = Capture(Path("x"))
        hg.agregar_hallazgos(cap, {"reglas": [], "resultados": [],
                                   "rutas_estado": [{"red": "10.0.0.0/8", "interfaz": "a", "siguiente_salto": "",
                                                     "tipo": "conectada", "salto_en_arp": "", "conductos": 0,
                                                     "marcas": ""}]})
        self.assertEqual(cap.findings, [])

    def test_filas_y_resumen_en_ingles(self):
        _fw, r, _ = _rutas_estado()
        filas = fi.filas_rutas(r)
        self.assertEqual(len(filas[0]), len(fi.COL_RUTAS))
        i18n.usar("en")
        self.addCleanup(i18n.usar, "es")
        i18n.FALTANTES.clear()
        self.assertIn("yes", {x[4] for x in fi.filas_rutas(r)})
        self.assertIn("firewall routes", fi.resumen_rutas_texto(r))
        i18n.t(hg.TIT_RUTAS)
        i18n.t("Rutas del firewall")
        self.assertFalse(i18n.FALTANTES, i18n.FALTANTES)


class ReportesTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        est = gen_exports.escribir(cls.tmp / "ex")["b"]
        fw = cls.tmp / "fw.txt"
        # todo el direccionamiento detras de una sola interfaz: ningun conducto cruza
        fw.write_text(_sesion("C   10.0.0.0 255.0.0.0 is directly connected, campo\n",
                              ACL + "permit ip any any rule-id 1\n" + ACL + "trust tcp any any eq 502 rule-id 2\n"
                              + DEFECTO), encoding="utf-8")
        cls.out = cls.tmp / "out"
        with contextlib.redirect_stdout(io.StringIO()):
            rc = main(["diagrama", "--activos", str(est["activos"]), "--enlaces", str(est["enlaces"]),
                       "-o", str(cls.out), "--firewall", str(fw)])
        assert rc == 0
        cls.fw = fw

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    @staticmethod
    def _textos(out):
        for p in sorted(out.glob("*.html")) + sorted(out.glob("*.md")):
            yield p.name, p.read_text(encoding="utf-8")
        for p in sorted(out.glob("*.docx")):
            with zipfile.ZipFile(p) as z:
                yield p.name, z.read("word/document.xml").decode("utf-8")

    @unittest.skipUnless(shutil.which("tshark") and HAY_SCAPY, "requiere tshark y scapy")
    def test_etiqueta_no_cruza_en_html_md_y_word(self):
        import gen_pcaps
        sys.argv = ["gen", str(self.tmp / "pcaps")]
        gen_pcaps.main()
        out = self.tmp / "cap"
        with contextlib.redirect_stdout(io.StringIO()):
            main([str(self.tmp / "pcaps"), "-o", str(out), "--firewall", str(self.fw)])
        textos = dict(self._textos(out))
        vistos = {e: any("No cruza este firewall" in x for n, x in textos.items() if n.endswith(e))
                  for e in (".html", ".md", ".docx")}
        self.assertEqual(vistos, {".html": True, ".md": True, ".docx": True}, sorted(textos))
        linea = {e: any("firewall_rutas.csv" in x for n, x in textos.items() if n.endswith(e))
                 for e in (".html", ".md", ".docx")}
        self.assertEqual(linea, {".html": True, ".md": True, ".docx": True})
        self.assertTrue((out / "firewall_rutas.csv").exists())
        with contextlib.redirect_stdout(io.StringIO()):
            main([str(self.tmp / "pcaps"), "-o", str(self.tmp / "cap_en"), "--firewall", str(self.fw),
                  "--idioma", "en"])
        self.addCleanup(i18n.usar, "es")
        en = dict(self._textos(self.tmp / "cap_en"))
        for e in (".html", ".md", ".docx"):
            self.assertTrue(any("Does not cross this firewall" in x for n, x in en.items() if n.endswith(e)), e)
        self.assertTrue(any(hg.TIT_ANY in x for n, x in textos.items() if n.endswith(".md")))

    def test_hallazgos_y_marcas_en_las_salidas(self):
        with open(self.out / "firewall_reglas.csv", newline="", encoding="utf-8-sig") as fh:
            marcas = {f["id"]: f["marcas"] for f in csv.DictReader(fh)}
        self.assertIn("any-any", marcas["1"])
        self.assertIn("confia sin inspeccion", marcas["2"])
        html = (self.out / "diagramas.html").read_text(encoding="utf-8")
        self.assertIn(hg.TIT_ANY, html)
        self.assertIn(hg.TIT_CONFIA, html)

    def test_firewall_rutas_csv_y_linea_de_resumen(self):
        with open(self.out / "firewall_rutas.csv", newline="", encoding="utf-8-sig") as fh:
            filas = list(csv.DictReader(fh))
        self.assertEqual(list(filas[0]), fi.COL_RUTAS)
        self.assertEqual(filas[0]["red"], "10.0.0.0/8")


IDA = ACL + "permit tcp ifc inside 10.10.1.0 255.255.255.0 ifc dmz any eq 443 rule-id 1\n"


def _retorno(puerto=443, origen="any", nombre="Retorno"):
    return ("access-list CSM_FW_ACL_ remark rule-id 2: RULE: " + nombre + "\n"
            + ACL + f"permit tcp ifc dmz {origen} ifc inside 10.10.1.0 255.255.255.0 eq {puerto} rule-id 2\n")


def _hallazgo_retorno(reglas, conductos):
    r = _contraste(reglas, conductos)
    cap = Capture(Path("firewall fw.txt"))
    hg.agregar_hallazgos(cap, r)
    return r, {f["titulo"]: f for f in cap.findings}


class RetornoTest(unittest.TestCase):
    def test_espejo_marcado_y_puerto_distinto_no(self):
        m = _marcas(_contraste(IDA + _retorno() + DEFECTO, []))
        self.assertIn("espejo de 1 (retorno)", m["2"])
        self.assertFalse([x for x in m["1"] if x.startswith("espejo")])
        m = _marcas(_contraste(IDA + _retorno(8443) + DEFECTO, []))
        self.assertFalse([x for x in m["2"] if x.startswith("espejo")])
        # interfaces sin intercambiar (misma direccion que la ida): tampoco
        mismo = IDA.replace("rule-id 1", "rule-id 2")
        m = _marcas(_contraste(IDA + mismo + DEFECTO, []))
        self.assertFalse([x for x in m["2"] if x.startswith("espejo")])

    def test_espejo_anterior_a_la_ida(self):
        # la de retorno va primero: por el nombre sigue siendo ella la marcada, no la ida
        m = _marcas(_contraste(_retorno() + IDA + DEFECTO, []))
        self.assertIn("espejo de 1 (retorno)", m["2"])
        self.assertFalse([x for x in m["1"] if x.startswith("espejo")])
        # sin pista de nombre, en un reflejo mutuo se marca la que abre entrada (any -> equipos), no la ida
        m = _marcas(_contraste(_retorno(nombre="X") + IDA + DEFECTO, []))
        self.assertIn("espejo de 1 (retorno)", m["2"])
        self.assertFalse([x for x in m["1"] if x.startswith("espejo")])

    def test_nombre_de_retorno_sin_criterio_avisa_sin_marca(self):
        r = _contraste(IDA + _retorno(8443, nombre="Regreso-TEST") + DEFECTO, [])
        self.assertFalse([x for x in _marcas(r)["2"] if x.startswith("espejo")])
        av = {x["id"]: x["avisos"] for x in r["reglas"]}
        self.assertIn(hg.AVISO_RETORNO, av["2"])
        self.assertEqual(av["1"], "")
        # con el criterio cumplido no hay aviso de nombre
        r = _contraste(IDA + _retorno(nombre="Regreso-TEST") + DEFECTO, [])
        self.assertEqual({x["id"]: x["avisos"] for x in r["reglas"]}["2"], "")

    def test_hallazgo_alta_con_conducto_y_media_sin_el(self):
        reglas = IDA + _retorno() + DEFECTO
        _r, f = _hallazgo_retorno(reglas, [_c("10.10.9.5", "10.10.1.5", 443)])
        x = f[hg.TIT_RETORNO]
        self.assertEqual(x["severidad"], "Alta")
        self.assertIn("1 -> 2 (Retorno)", x["evidencia"])
        self.assertEqual(set(x["referencias"]), {e.clave for e in ESTANDARES.values()} | {MITRE.clave})
        self.assertIn("SR 7.7", x["referencias"]["iec62443"])
        self.assertIn("SC-7 (5)", x["referencias"]["nist-800-82"])
        self.assertIn("CIP-007 R1", x["referencias"]["nerc-cip"])
        self.assertIn("PR.IR-01", x["referencias"]["nist-csf"])
        self.assertIn("T0886", x["referencias"][MITRE.clave])
        self.assertNotIn("cumple", (x["evidencia"] + x["recomendacion"] + x["por_que_importa"]).lower())
        _r, f = _hallazgo_retorno(reglas, [])
        self.assertEqual(f[hg.TIT_RETORNO]["severidad"], "Media")
        # origen acotado con conducto: Media
        acotada = IDA + _retorno(origen="10.10.9.0 255.255.255.0") + DEFECTO
        _r, f = _hallazgo_retorno(acotada, [_c("10.10.9.5", "10.10.1.5", 443)])
        self.assertEqual(f[hg.TIT_RETORNO]["severidad"], "Media")
        # sin espejo no hay hallazgo
        _r, f = _hallazgo_retorno(IDA + _retorno(8443) + DEFECTO, [])
        self.assertNotIn(hg.TIT_RETORNO, f)

    def test_plan_e_ingles(self):
        _r, f = _hallazgo_retorno(IDA + _retorno() + DEFECTO, [])
        cap = Capture(Path("firewall fw.txt"))
        cap.findings = list(f.values())
        res = SimpleNamespace(caps=[], extras=[cap], assets={}, perfil={})
        self.assertIn(hg.TIT_RETORNO, {x["titulo"] for x in remediacion.plan(res)})
        i18n.usar("en")
        self.addCleanup(i18n.usar, "es")
        i18n.FALTANTES.clear()
        _r, f = _hallazgo_retorno(IDA + _retorno() + DEFECTO, [_c("10.10.9.5", "10.10.1.5", 443)])
        x = f[hg.TIT_RETORNO]
        for k in ("titulo", "evidencia", "por_que_importa", "recomendacion", "categoria"):
            i18n.t(x[k])
        for ref in x["referencias"].values():
            for pieza in ref.split("; "):
                i18n.t(pieza)
        i18n.t(hg.AVISO_RETORNO)
        self.assertEqual(i18n.t(hg.TIT_RETORNO)[:6], "Return")
        self.assertFalse(i18n.FALTANTES, i18n.FALTANTES)


if __name__ == "__main__":
    unittest.main()


class DosSaltosResumenTest(unittest.TestCase):
    def test_resumen_con_especificas_no_se_marca(self):
        import ipaddress

        from ot_assess.firewalls.modelo import Firewall, Ruta
        R = lambda red, salto: Ruta(red=ipaddress.ip_network(red), interfaz="in", salto=salto, tipo="estatica", codigo="S")
        fw = Firewall(rutas=[R("10.0.0.0/8", "10.9.9.1"), R("10.130.0.0/16", "10.9.9.2"),
                             R("192.168.100.0/25", "10.9.9.3"), R("192.168.100.2/32", "10.9.9.4")])
        filas = {f["red"]: f["marcas"] for f in hg.estado_rutas(fw, [])}
        self.assertNotIn(hg.M_DOS_SALTOS, filas["10.0.0.0/8"])
        self.assertNotIn(hg.M_DOS_SALTOS, filas["10.130.0.0/16"])
        self.assertIn(hg.M_DOS_SALTOS, filas["192.168.100.0/25"])
        self.assertIn(hg.M_DOS_SALTOS, filas["192.168.100.2/32"])


class EspejoSinNombreTest(unittest.TestCase):
    """Sin pista en el nombre, el retorno es la regla que abre entrada (any -> equipos), no la de ida."""

    def test_la_ida_no_se_marca(self):
        import ipaddress

        from ot_assess.firewalls.modelo import Regla, Subregla
        N = ipaddress.ip_network

        def regla(i, nombre, o, d, zo, zd):
            sub = Subregla(protocolos=["tcp"], origen=[N(o)], destino=[N(d)], puertos_origen=[],
                           puertos_destino=[(443, 443)], zonas_origen=[zo], zonas_destino=[zd], linea="")
            return Regla(id=i, nombre=nombre, accion="permitir", protocolos=["tcp"], origen=[N(o)], destino=[N(d)],
                         puertos=[(443, 443)], zonas_origen=[zo], zonas_destino=[zd], subreglas=[sub], acl="CSM_FW_ACL_")
        entrada = regla("1", "Servidores-salida-b", "0.0.0.0/0", "10.1.1.5/32", "out", "in")   # primero en la ACL
        ida = regla("2", "Servidores-salida", "10.1.1.5/32", "0.0.0.0/0", "in", "out")
        esp = hg._espejos([entrada, ida])
        self.assertEqual(esp.get(0), [1])   # la que abre entrada (any -> servidor) es el retorno
        self.assertFalse(esp.get(1))         # la ida no se marca aunque vaya despues
