"""Pruebas del idioma de los reportes (D39, B5a)."""
from __future__ import annotations

import json
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))
sys.path.insert(0, str(RAIZ / "tests"))

from ot_assess import i18n, perfil

try:
    import scapy  # noqa: F401
    HAY_SCAPY = True
except ImportError:
    HAY_SCAPY = False

CAT = RAIZ / "ot_assess" / "catalogos" / "en.json"


class TraduccionTest(unittest.TestCase):
    def tearDown(self):
        i18n.usar("es")
        i18n.FALTANTES.clear()

    def test_es_devuelve_el_texto(self):
        i18n.usar("es")
        self.assertEqual(i18n.idioma(), "es")
        self.assertEqual(i18n.t("Resumen"), "Resumen")
        self.assertEqual(i18n.t("{n} activos", n=3), "3 activos")
        self.assertEqual(i18n.t("llaves {sin} formato"), "llaves {sin} formato")   # sin kw no formatea
        self.assertFalse(i18n.FALTANTES)

    def test_en_traduce_con_y_sin_kw(self):
        i18n.usar("en")
        self.assertEqual(i18n.idioma(), "en")
        self.assertEqual(i18n.t("Resumen"), "Summary")
        self.assertEqual(i18n.t("Generado el {now}", now="hoy"), "Generated on hoy")
        self.assertFalse(i18n.FALTANTES)

    def test_clave_faltante_devuelve_espanol_y_se_registra(self):
        i18n.usar("en")
        self.assertEqual(i18n.t("Texto inexistente {x}", x=1), "Texto inexistente 1")
        self.assertIn("Texto inexistente {x}", i18n.FALTANTES)

    def test_idioma_invalido_falla(self):
        with self.assertRaises(SystemExit):
            i18n.usar("fr")

    def test_catalogo_ordenado_y_mismos_placeholders(self):
        d = json.loads(CAT.read_text(encoding="utf-8"))
        self.assertEqual(d["version"], 1)
        claves = list(d["en"])
        self.assertEqual(claves, sorted(claves))
        ph = re.compile(r"\{(\w+)\}")
        for es, en in d["en"].items():
            self.assertEqual(sorted(ph.findall(es)), sorted(ph.findall(en)), es)
            self.assertTrue(en.isascii(), en)


class PerfilIdiomaTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.addCleanup(i18n.usar, "es")

    def perfil(self, idioma):
        p = self.tmp / "perfil.json"
        p.write_text(json.dumps({"version": 1, "cliente": "C", "idioma": idioma,
                                 "marcos": [{"clave": "iec62443"}]}), encoding="utf-8")
        return p

    def test_en_se_acepta_y_fr_falla(self):
        self.assertEqual(perfil.cargar(self.perfil("en"))["idioma"], "en")
        with self.assertRaises(SystemExit):
            perfil.cargar(self.perfil("fr"))

    def test_opcion_manda_sobre_el_perfil(self):
        from ot_assess.cli import crear_parser
        ap = crear_parser()
        a = ap.parse_args(["x", "--perfil", str(self.perfil("en"))])
        perfil.aplicar(ap, a, {"titulo": "t", "cliente": "c", "estandar": "iec62443"})
        self.assertEqual(i18n.idioma(), "en")
        a = ap.parse_args(["x", "--perfil", str(self.perfil("en")), "--idioma", "es"])
        perfil.aplicar(ap, a, {"titulo": "t", "cliente": "c", "estandar": "iec62443"})
        self.assertEqual(i18n.idioma(), "es")
        a = ap.parse_args(["x", "--idioma", "en"])
        perfil.aplicar(ap, a, {"titulo": "t", "cliente": "c", "estandar": "iec62443"})
        self.assertEqual(i18n.idioma(), "en")


@unittest.skipUnless(shutil.which("tshark") and HAY_SCAPY, "requiere tshark y scapy")
class HtmlIdiomaTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import gen_pcaps

        from ot_assess.cli import main
        cls.tmp = Path(tempfile.mkdtemp())
        pcaps = cls.tmp / "pcaps"
        sys.argv = ["gen", str(pcaps)]
        gen_pcaps.main()
        i18n.FALTANTES.clear()
        main([str(pcaps), "-o", str(cls.tmp / "es"), "--idioma", "es"])
        cls.faltan_es = set(i18n.FALTANTES)
        main([str(pcaps), "-o", str(cls.tmp / "en"), "--idioma", "en"])
        cls.faltan_en = set(i18n.FALTANTES)
        main([str(pcaps), "-o", str(cls.tmp / "en_propio"), "--idioma", "en",
              "--titulo", "Assessment de ciberseguridad OT", "--cliente", "Analisis de trafico de planta"])
        i18n.usar("es")

    @classmethod
    def tearDownClass(cls):
        i18n.FALTANTES.clear()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def html(self, d):
        return (self.tmp / d / "reporte_ot.html").read_text(encoding="utf-8")

    def test_ingles(self):
        h = self.html("en")
        self.assertIn('<html lang="en">', h)
        for x in ("1. Asset inventory", "2. Communications matrix", "3. Findings",
                  "4. Scope and visibility gap", "6. Analysis environment"):
            self.assertIn(x, h)
        self.assertNotIn("1. Inventario de activos", h)

    def test_hallazgos_en_ingles(self):
        h = self.html("en")
        for x in ("Address conflict: the same IP advertised by several MACs",
                  "Write or control operations observed in the capture"):
            self.assertIn(x, h)
        for x in ("Conflicto de direcciones", "Operaciones de escritura o control observadas"):
            self.assertNotIn(x, h)

    def test_ingles_sin_claves_faltantes(self):
        self.assertEqual(self.faltan_en, set())

    def test_espanol_no_cambia(self):
        h = self.html("es")
        self.assertIn('<html lang="es">', h)
        for x in ("1. Inventario de activos", "2. Matriz de comunicaciones", "Vista de rejilla",
                  "Hallazgo alta", "unidireccional"):
            self.assertIn(x, h)
        self.assertNotIn("Asset inventory", h)
        self.assertEqual(self.faltan_es, set())

    # --- B5b: Markdown, Word, CSV, Excel, titulos por defecto --------------------------------- #
    def md(self, d):
        return (self.tmp / d / "reporte_ot.md").read_text(encoding="utf-8")

    def docx(self, d):
        import zipfile
        with zipfile.ZipFile(self.tmp / d / "informe_ot.docx") as z:
            return z.read("word/document.xml").decode("utf-8")

    def csv_cab(self, d, nombre):
        return (self.tmp / d / nombre).read_text(encoding="utf-8-sig").splitlines()[0]

    def hojas(self, d):
        import zipfile
        with zipfile.ZipFile(self.tmp / d / "reporte_ot.xlsx") as z:
            return re.findall(r'<sheet name="([^"]+)"', z.read("xl/workbook.xml").decode("utf-8"))

    def test_markdown_ingles(self):
        m = self.md("en")
        for x in ("## 3. Asset inventory", "## 9. Questions for the client session",
                  "| # | Device | IP | MAC | Manufacturer | Model / description | Firmware | "
                  "Inferred role | Zone | VLAN | Packets |", "| Possible cause | Confirmed here |",
                  "Editable source:", "**Evidence**"):
            self.assertIn(x, m)
        for x in ("Inventario de activos", "Causa posible", "Fuente editable", "Preguntas para la sesion"):
            self.assertNotIn(x, m)

    def test_markdown_espanol_no_cambia(self):
        m = self.md("es")
        for x in ("## 3. Inventario de activos", "## 9. Preguntas para la sesion con el cliente",
                  "| # | Equipo | IP | MAC | Fabricante | Modelo / descripcion | Firmware | "
                  "Rol inferido | Zona | VLAN | Paquetes |", "| Causa posible | Confirmada aqui |",
                  "| # | Severidad | Categoria | Hallazgo | Capturas |", "**Evidencia**", "unidireccional"):
            self.assertIn(x, m)
        self.assertNotIn("Asset inventory", m)

    def test_word_ingles(self):
        d = self.docx("en")
        for x in ("Asset inventory", "Communications matrix", "Questions for the session",
                  "Analysis environment", "inferred_role"):
            self.assertIn(x, d)
        for x in ("Preguntas para la sesion", "Matriz de comunicaciones", "rol_inferido"):
            self.assertNotIn(x, d)
        d = self.docx("es")
        for x in ("Matriz de comunicaciones", "Preguntas para la sesion", "rol_inferido"):
            self.assertIn(x, d)

    def test_csv_cabeceras(self):
        self.assertTrue(self.csv_cab("es", "inventario.csv").startswith(
            "equipo,ips,mac,fabricante,modelo_descripcion,firmware,rol_inferido,zona_purdue,"))
        self.assertTrue(self.csv_cab("en", "inventario.csv").startswith(
            "device,ips,mac,manufacturer,model_description,firmware,inferred_role,purdue_zone,"))
        self.assertTrue(self.csv_cab("en", "hallazgos.csv").startswith(
            "id,capture,severity,category,title,evidence,why_it_matters,recommendation,mitre_ics,iec62443"))

    def test_nombres_de_hoja(self):
        self.assertEqual(self.hojas("en"), [
            "Inventory", "Capture coverage", "Network health", "Top devices", "Top conduits", "Protocol mix",
            "Traffic baseline", "Sensors", "Sensor gaps", "Normalized inventory", "Inventory provenance", "Obsolescence", "Communications", "Zones", "Hardening by type", "Hardening by asset", "Log sources", "IP addressing", "Specific baseline", "Conduit baseline", "General baseline",
            "Baseline 2-1", "Controls matrix", "Identity", "Findings", "Remediation plan", "Risk register", "Maturity by domain",
            "Maturity questionnaire", "DNS records",
            "DNS resolutions", "DNS servers", "Control", "Coverage iec62443", "Risk heat map"])
        self.assertEqual(self.hojas("es")[:25], [
            "Inventario", "Cobertura de captura", "Salud de la red", "Top equipos", "Top conductos", "Mezcla de protocolos",
            "Linea base de trafico", "Sensores", "Brechas de sensores", "Inventario normalizado", "Inventario procedencia", "Obsolescencia", "Comunicaciones", "Zonas", "Hardening por tipo", "Hardening por activo", "Fuentes de log", "Direccionamiento IP", "Linea base especifica", "Linea base conductos",
            "Linea base general", "Linea base 2-1", "Matriz de controles", "Identidad", "Hallazgos"])

    def test_titulo_por_defecto_se_traduce_y_el_del_usuario_no(self):
        self.assertIn("<title>OT cybersecurity assessment</title>", self.html("en"))
        self.assertIn("Plant traffic analysis", self.html("en"))
        self.assertIn("<title>Assessment de ciberseguridad OT</title>", self.html("es"))
        h = self.html("en_propio")
        self.assertIn("<title>Assessment de ciberseguridad OT</title>", h)
        self.assertIn("Analisis de trafico de planta", h)
        self.assertNotIn("OT cybersecurity assessment", h)

    def test_columnas_y_hojas_estan_en_el_catalogo(self):
        from ot_assess import (
            alertas,
            registros_dns,
            remediacion,
            rutas_firewall,
            vulnerabilidades,
        )
        from ot_assess.report.csvout import COLUMNAS_COBERTURA
        cols = (alertas.COLUMNAS + registros_dns.COL_REGISTROS + registros_dns.COL_RESOLUCIONES
                + registros_dns.COL_SERVIDORES + remediacion.COLUMNAS + rutas_firewall.COL_INTERFACES
                + rutas_firewall.COL_MATRIZ + vulnerabilidades.COLUMNAS + COLUMNAS_COBERTURA)
        cat = json.loads(CAT.read_text(encoding="utf-8"))["en"]
        self.assertEqual([c for c in cols if c not in cat], [])


class DiagramaIdiomaTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import gen_exports

        from ot_assess.cli_diagrama import main
        cls.tmp = Path(tempfile.mkdtemp())
        e = gen_exports.escribir(cls.tmp / "exp")["a"]
        i18n.FALTANTES.clear()
        for idioma in ("es", "en"):
            main(["--activos", str(e["activos"]), "--enlaces", str(e["enlaces"]),
                  "-o", str(cls.tmp / idioma), "--idioma", idioma])
            setattr(cls, "faltan_" + idioma, set(i18n.FALTANTES))
        i18n.usar("es")

    @classmethod
    def tearDownClass(cls):
        i18n.FALTANTES.clear()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def pagina(self, d):
        return (self.tmp / d / "diagramas.html").read_text(encoding="utf-8")

    def test_pagina_en_ingles(self):
        h = self.pagina("en")
        self.assertIn('<html lang="en">', h)
        self.assertIn("<title>OT network diagrams</title>", h)
        for x in ("Source data and quality", "Interpreted column", "Findings from the export", "Scope"):
            self.assertIn(x, h)
        self.assertNotIn("Datos de origen y calidad", h)
        self.assertEqual(self.faltan_en, set())

    def test_pagina_en_espanol_no_cambia(self):
        h = self.pagina("es")
        self.assertIn('<html lang="es">', h)
        self.assertIn("<title>Diagramas de red OT</title>", h)
        for x in ("Datos de origen y calidad", "Columna interpretada", "Hallazgos segun la exportacion"):
            self.assertIn(x, h)
        self.assertEqual(self.faltan_es, set())


# --- B5c: hallazgos ------------------------------------------------------------------------- #
def _claves_de_hallazgos() -> set:
    """Textos fijos que el codigo pasa a finding() y t() en reglas, vulnerabilidades y alertas (AST)."""
    import ast

    from ot_assess import alertas, vulnerabilidades
    from ot_assess.catalog import OBSOLETE_PATTERNS
    from ot_assess.rules.inventario import AVISO
    claves = {vulnerabilidades.TITULO, alertas.TITULO, AVISO, "Higiene", "Critica", "Alta", "Media",
              "Baja", "Informativa", "Inmediato", "Corto plazo", "Mediano plazo"}
    claves |= {nota for _p, _e, nota in OBSOLETE_PATTERNS}
    archivos = sorted((RAIZ / "ot_assess" / "rules").glob("*.py"))
    archivos += [RAIZ / "ot_assess" / "vulnerabilidades.py", RAIZ / "ot_assess" / "alertas.py"]
    for p in archivos:
        for n in ast.walk(ast.parse(p.read_text(encoding="utf-8"))):
            if not (isinstance(n, ast.Call) and isinstance(n.func, ast.Name)):
                continue
            if n.func.id == "t" and n.args and isinstance(n.args[0], ast.Constant):
                claves.add(n.args[0].value)
            elif n.func.id == "finding":
                claves |= {a.value for a in n.args[2:] if isinstance(a, ast.Constant)}
                claves |= {k.value.value for k in n.keywords if k.arg == "categoria"}
    return claves


class TraducidoTest(unittest.TestCase):
    def tearDown(self):
        i18n.usar("es")
        i18n.FALTANTES.clear()

    def test_t_devuelve_traducido_y_no_lo_vuelve_a_buscar(self):
        i18n.usar("en")
        x = i18n.t("Alta")
        self.assertIsInstance(x, i18n.Traducido)
        self.assertEqual(x, "High")
        self.assertEqual(i18n.t(x), "High")
        self.assertEqual(i18n.t(i18n.Traducido("texto que no esta")), "texto que no esta")
        self.assertFalse(i18n.FALTANTES)

    def test_unir_solo_marca_si_todo_esta_traducido(self):
        i18n.usar("en")
        self.assertIsInstance(i18n.unir("; ", [i18n.t("Alta"), i18n.t("Baja")]), i18n.Traducido)
        self.assertNotIsInstance(i18n.unir("; ", [i18n.t("Alta"), "plano"]), i18n.Traducido)

    def test_catalogo_cubre_los_textos_fijos_de_los_hallazgos(self):
        cat = json.loads(CAT.read_text(encoding="utf-8"))["en"]
        self.assertEqual(sorted(k for k in _claves_de_hallazgos() if k not in cat), [])


class MarcosIdiomaTest(unittest.TestCase):
    """Referencias a los marcos, textos de cada marco y matriz de cobertura en ingles (B5d)."""

    def tearDown(self):
        i18n.usar("es")
        i18n.FALTANTES.clear()

    def test_cada_pieza_de_cada_referencia_tiene_traduccion(self):
        from ot_assess import standards
        i18n.usar("en")
        cat = json.loads(CAT.read_text(encoding="utf-8"))["en"]
        piezas = 0
        for e in standards.ESTANDARES.values():
            for txt in e.refs.values():
                out = standards.traducir_refs(txt)
                piezas += len(txt.split("; ")) if txt else 0
                self.assertEqual([p for p in txt.split("; ") if p and p not in cat], [])
                self.assertEqual(len(out.split("; ")), len(txt.split("; ")))
        self.assertGreater(piezas, 100)
        standards.avisos(list(standards.ESTANDARES.values()))
        for e in standards.ESTANDARES.values():
            i18n.t(e.cruce) if e.cruce else None
            standards.etiqueta_mapeo(e)
        self.assertEqual(i18n.FALTANTES, set())

    def test_nombres_oficiales_en_ingles(self):
        from ot_assess.standards import traducir_refs
        i18n.usar("en")
        for es, en in (
                ("SI-4 (monitoreo del sistema)", "SI-4 (System Monitoring)"),
                ("SC-21 (resolucion recursiva segura)",
                 "SC-21 (Secure Name/Address Resolution Service (Recursive or Caching Resolver))"),
                ("SR 6.2 Monitoreo continuo; SR 5.2 Proteccion del limite de zona",
                 "SR 6.2 Continuous monitoring; SR 5.2 Zone boundary protection"),
                ("SR 7.7 Funcionalidad minima", "SR 7.7 Least functionality"),
                ("CIP-007 R1 (puertos y servicios)", "CIP-007 R1 (Ports and Services)"),
                ("DE.CM-01 (monitoreo de redes)", "DE.CM-01 (network monitoring)")):
            self.assertEqual(traducir_refs(es), en)
        i18n.usar("es")
        self.assertEqual(traducir_refs("SI-4 (monitoreo del sistema)"), "SI-4 (monitoreo del sistema)")

    def test_cobertura_traduce_iec_y_deja_csf(self):
        from ot_assess import cobertura
        from ot_assess.standards import ESTANDARES
        filas = {}
        for idioma in ("es", "en"):
            i18n.usar(idioma)
            i18n.FALTANTES.clear()
            for clave in ("iec62443", "nist-csf"):
                filas[(clave, idioma)] = cobertura.clasificar(cobertura.cargar(clave), ESTANDARES[clave])
            self.assertEqual(i18n.FALTANTES, set(), idioma)
        self.assertEqual(len([f for f in filas[("iec62443", "en")]]), 51)
        iec = {f["id"]: f for f in filas[("iec62443", "en")]}
        self.assertEqual(iec["SR 7.7"]["texto"], "Least functionality")
        self.assertEqual(iec["SR 1.1"]["categoria"], "Identification and authentication control (IAC)")
        self.assertEqual({f["id"]: f["texto"] for f in filas[("nist-csf", "es")]},
                         {f["id"]: f["texto"] for f in filas[("nist-csf", "en")]})
        # la clave de cobertura (la usa el resumen y el JSON) no cambia con el idioma
        self.assertEqual([f["cobertura"] for f in filas[("iec62443", "es")]],
                         [f["cobertura"] for f in filas[("iec62443", "en")]])

    def test_etiquetas_y_notas_de_cobertura_estan_en_el_catalogo(self):
        from ot_assess import cobertura
        cat = json.loads(CAT.read_text(encoding="utf-8"))["en"]
        textos = [cobertura.NOTA, cobertura.TEXTO_NO_EVID, cobertura.DIRECTA, cobertura.APOYO,
                  cobertura.NO_EVID, "sin referencia directa", *cobertura.NOTAS_MARCO.values()]
        for clave in ("iec62443", "nist-csf"):
            textos += cobertura.cargar(clave)["apoyo"].values()
        self.assertEqual([x for x in textos if x not in cat], [])

    def test_idioma_textos_es_obligatorio_y_valido(self):
        from ot_assess import cobertura
        d = json.loads((RAIZ / "ot_assess" / "marcos" / "cobertura" / "iec62443.json").read_text(encoding="utf-8"))
        d["idioma_textos"] = "fr"
        with self.assertRaises(SystemExit):
            cobertura.validar(d, "x")
        del d["idioma_textos"]
        with self.assertRaises(SystemExit):
            cobertura.validar(d, "x")


@unittest.skipUnless(shutil.which("tshark") and HAY_SCAPY, "requiere tshark y scapy")
class MarcosReporteIdiomaTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import gen_pcaps

        from ot_assess.cli import main
        cls.tmp = Path(tempfile.mkdtemp())
        pcaps = cls.tmp / "pcaps"
        sys.argv = ["gen", str(pcaps)]
        gen_pcaps.main()
        i18n.FALTANTES.clear()
        for idioma in ("es", "en"):
            main([str(pcaps), "-o", str(cls.tmp / idioma), "--idioma", idioma,
                  "--estandar", "iec62443,nerc-cip,nist-800-82,nist-csf"])
            setattr(cls, "faltan_" + idioma, set(i18n.FALTANTES))
        i18n.usar("es")

    @classmethod
    def tearDownClass(cls):
        i18n.FALTANTES.clear()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def leer(self, d, nombre):
        return (self.tmp / d / nombre).read_text(encoding="utf-8-sig")

    def test_html_en_ingles_con_nombres_oficiales(self):
        h = self.leer("en", "reporte_ot.html")
        self.assertIn("SR 7.7 Least functionality", h)
        self.assertNotIn("SR 7.7 Funcionalidad minima", h)
        self.assertRegex(h, r"(SC-7 \(Boundary Protection\)|SI-4 \(System Monitoring\)"
                            r"|CM-7 \(Least Functionality\))")
        self.assertIn("Annex: coverage of", h)
        self.assertIn("not reviewed", h)

    def test_cobertura_en_ingles(self):
        h = self.leer("en", "reporte_ot.html")
        self.assertIn("<td>Network segmentation</td>", h)          # IEC 62443, traducido
        csv_iec = self.leer("en", "cobertura_iec62443.csv")
        self.assertIn("Zone boundary protection", csv_iec)
        self.assertIn("direct", csv_iec)
        self.assertNotIn("Proteccion del limite de zona", csv_iec)
        import csv
        import io

        def textos(idioma):    # id, categoria y texto del requisito (el texto oficial de CSF ya es ingles)
            filas = list(csv.reader(io.StringIO(self.leer(idioma, "cobertura_nist-csf.csv"))))[1:]
            return [(f[0], f[2], f[3]) for f in filas]
        self.assertEqual(textos("en"), textos("es"))
        self.assertIn("not evidenceable", self.leer("en", "cobertura_nist-csf.csv"))

    def test_espanol_igual_que_antes(self):
        h = self.leer("es", "reporte_ot.html")
        self.assertIn("SR 7.7 Funcionalidad minima", h)
        self.assertIn("sin revisar", h)
        self.assertNotIn("Least functionality", h)

    def test_sin_claves_faltantes(self):
        self.assertEqual(self.faltan_en - self.faltan_es, set())
        self.assertEqual(self.faltan_en, set())


class HallazgosIdiomaTest(unittest.TestCase):
    """Reglas de DNS, de inventario y de vulnerabilidades/alertas en ingles, sin tshark."""

    def tearDown(self):
        i18n.usar("es")
        i18n.FALTANTES.clear()

    def hallazgos(self):
        from types import SimpleNamespace

        import test_reglas_dns as td

        from ot_assess import alertas, vulnerabilidades
        from ot_assess.model import Capture
        from ot_assess.rules.inventario import evaluar_inventario
        ev = ([td.q(td.C, td.S, "wpad"), td.q(td.C, "8.8.8.8", "www.example.com"),
               td.q(td.C, td.S, "a" * 51 + ".x.com"), td.q(td.C, td.S, "planta.local", "AXFR")]
              + [td.q(td.C, td.S, f"h{i}.example.com") for i in range(13)]
              + sum((td.par(i, "NXDOMAIN") for i in range(50)), [])
              + sum((td.par(100 + i, "SERVFAIL") for i in range(30)), [])
              + [td.q(td.C, td.S, "x.planta.local", id_=f"s{i}") for i in range(25)])
        flujo = {"src": td.C, "dst": "1.1.1.1", "dport": "853", "l4": "tcp", "pkts": 4}
        cap = SimpleNamespace(name="a.pcap", dns_eventos=ev, flows={("k",): flujo}, findings=[],
                              dominios_internos=())
        for regla in (td.rdns.dns_wpad, td.rdns.dns_publico, td.rdns.dns_dominios_internet,
                      td.rdns.dns_fallas, td.rdns.dns_nxdomain, td.rdns.dns_tunel,
                      td.rdns.dns_transferencia_zona, td.rdns.dns_dot):
            regla(cap)
        activos = {"PC": {"mac": "PC", "ips": {"10.0.0.7"}, "nombre": "PC", "vendor": "", "modelo": "",
                          "firmware": "Windows XP", "tipo_texto": "", "purdue": "", "zona": ""}}
        cond = [{"src": "10.0.0.7", "dst": "8.8.8.8", "l4": "tcp", "port": "23", "servicio": "telnet",
                 "categoria": "claro"}]
        hallazgos = cap.findings + evaluar_inventario(activos, cond, "xDome")
        extra = Capture(Path("x"))
        vuln = {"cve": "CVE-2021-0001", "severidad": "Critica", "estado": "abierta", "cvss": None}
        vulnerabilidades.agregar_hallazgo(extra, [{"vuln": vuln, "activo": "PC"}], activos)
        al = {"alerta": {"origen": "10.0.0.7", "destino": "8.8.8.8", "firma": "x", "severidad": "Alta",
                         "conteo": 2}, "conducto": None}
        alertas.agregar_hallazgo(extra, [al])
        return hallazgos + extra.findings

    def test_evidencia_traducida_y_titulos_en_ingles(self):
        i18n.usar("en")
        hs = self.hallazgos()
        self.assertGreaterEqual(len(hs), 12)
        for f in hs:
            self.assertIsInstance(f["evidencia"], i18n.Traducido, f["titulo"])
            for c in ("titulo", "severidad", "categoria", "por_que_importa", "recomendacion"):
                i18n.t(f[c])
        self.assertEqual(i18n.FALTANTES, set())
        titulos = {i18n.t(f["titulo"]) for f in hs}
        self.assertIn("DNS zone transfer attempt", titulos)
        self.assertIn("Known vulnerabilities in assets (per the imported file)", titulos)

    def test_identificadores_y_referencias_no_cambian_con_el_idioma(self):
        i18n.usar("es")
        es = [(f["titulo"], f["severidad"], f["categoria"], f["referencias"]) for f in self.hallazgos()]
        i18n.usar("en")
        en = [(f["titulo"], f["severidad"], f["categoria"], f["referencias"]) for f in self.hallazgos()]
        self.assertEqual(es, en)
        self.assertTrue(any(x[3] for x in es))

    def test_espanol_evidencia_igual_que_antes(self):
        i18n.usar("es")
        ev = " | ".join(str(f["evidencia"]) for f in self.hallazgos())
        for x in ("1 consultas; nombres: wpad", "y 5 mas", "1 cliente:", "Abiertas: Critica 1.",
                  "Total 2 alertas (Alta 2, Media 0, Baja 0)."):
            self.assertIn(x, ev)
        i18n.usar("en")
        ev = " | ".join(str(f["evidencia"]) for f in self.hallazgos())
        for x in ("1 queries; names: wpad", "and 5 more", "1 client:", "Open: Critical 1.",
                  "Total 2 alerts (High 2, Medium 0, Low 0)."):
            self.assertIn(x, ev)


# --- B5e: prueba de cierre ------------------------------------------------------------------ #
PALABRAS_ES = ["hallazgo", "hallazgos", "conducto", "conductos", "activo", "activos", "captura", "capturas", "segun", "tambien", "recomendacion", "evidencia", "interno", "externo", "cliente", "servidor", "origen", "destino", "puerto", "red", "redes", "ninguno", "sin", "con", "para", "los", "las", "del", "una", "que"]
RE_PALABRAS_ES = re.compile(r"(?<![\w-])(" + "|".join(PALABRAS_ES) + r")(?![\w-])", re.IGNORECASE)
# Excepciones: valores que vienen de los datos de entrada de las pruebas, no del idioma del reporte
# (el cliente del perfil de ejemplo y los textos de los CSV de ejemplo de docs/ejemplos).
EXCEPCIONES_ES = (
    # perfil de ejemplo (docs/ejemplos/perfil.json): valores escritos por el usuario
    "Cliente Ejemplo", "Regulacion sectorial declarada por el cliente", "pasivo; sin pentesting",
    "Zona de control", "Zona de supervision",
    # firmas de docs/ejemplos/alertas.csv: datos de la plataforma importada
    "Telnet en la red de control", "Par sin trafico observado",
    # palabra inglesa que coincide con la lista (el color)
    "In red,")
EJEMPLOS = RAIZ / "docs" / "ejemplos"


def _visible_html(s: str) -> str:
    import html as _h
    s = re.sub(r"(?is)<(script|style)\b.*?</\1>", " ", s)
    return _h.unescape(re.sub(r"(?s)<[^>]+>", " ", s))


def _visible_docx(s: str) -> str:
    import html as _h
    return _h.unescape(" ".join(re.findall(r"(?s)<w:t(?: [^>]*)?>(.*?)</w:t>", s)))


def _visible_drawio(s: str) -> str:
    import html as _h
    return _h.unescape(_h.unescape(" ".join(re.findall(r'value="([^"]*)"', s))))


def _espanol_en(texto: str) -> list:
    for x in EXCEPCIONES_ES:
        texto = texto.replace(x, " ")
    return sorted({m.group(1).lower() for m in RE_PALABRAS_ES.finditer(texto)})


@unittest.skipUnless(HAY_SCAPY, "falta scapy")
class CierreInglesTest(unittest.TestCase):
    """Con --idioma en no queda texto en espanol en ninguna salida (B5e)."""

    @classmethod
    def setUpClass(cls):
        import gen_exports
        import gen_pcaps

        from ot_assess.cli import main
        from ot_assess.cli_diagrama import main as main_diagrama
        cls.tmp = Path(tempfile.mkdtemp())
        pcaps = cls.tmp / "pcaps"
        sys.argv = ["gen", str(pcaps)]
        gen_pcaps.main()
        i18n.FALTANTES.clear()
        comunes = ["--vulnerabilidades", str(EJEMPLOS / "vulnerabilidades.csv"),
                   "--alertas", str(EJEMPLOS / "alertas.csv"),
                   "--rutas-firewall", str(EJEMPLOS / "rutas_firewall.csv")]
        marcos = ["--estandar", "iec62443,nerc-cip,nist-800-82,nist-csf"]   # excluyente con --perfil
        perfil_ = ["--perfil", str(EJEMPLOS / "perfil.json")]
        fw = ["--reglas-firewall", str(EJEMPLOS / "reglas_firewall.csv")]
        main([str(pcaps), "-o", str(cls.tmp / "en"), "--idioma", "en"] + perfil_ + fw + comunes)
        main([str(pcaps), "-o", str(cls.tmp / "en_marcos"), "--idioma", "en"] + marcos + fw + comunes)
        main([str(pcaps), "-o", str(cls.tmp / "en_base"), "--idioma", "en"])   # bandas Purdue, sin opciones
        cls.dirs = [cls.tmp / "en", cls.tmp / "en_marcos", cls.tmp / "en_base"]
        exp = gen_exports.escribir(cls.tmp / "exp")
        for k, e in exp.items():
            salida = cls.tmp / ("dg_" + k)
            main_diagrama(["--activos", str(e["activos"]), "--enlaces", str(e["enlaces"]),
                           "-o", str(salida), "--idioma", "en"] + comunes
                          + (perfil_ if k == "a" else marcos))
            cls.dirs.append(salida)
        cls.faltantes = set(i18n.FALTANTES)
        i18n.usar("es")

    @classmethod
    def tearDownClass(cls):
        i18n.FALTANTES.clear()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def textos(self):
        import zipfile
        for d in self.dirs:
            for p in sorted(d.rglob("*")):
                if p.suffix == ".html":
                    yield p, _visible_html(p.read_text(encoding="utf-8"))
                elif p.suffix == ".md":
                    yield p, p.read_text(encoding="utf-8")
                elif p.suffix == ".svg":
                    yield p, _visible_html(p.read_text(encoding="utf-8"))
                elif p.suffix == ".drawio":
                    yield p, _visible_drawio(p.read_text(encoding="utf-8"))
                elif p.suffix == ".docx":
                    with zipfile.ZipFile(p) as z:
                        yield p, _visible_docx(z.read("word/document.xml").decode("utf-8"))

    def test_sin_claves_faltantes(self):
        self.assertEqual(self.faltantes, set())

    def test_no_queda_espanol_visible(self):
        n = 0
        for p, txt in self.textos():
            n += 1
            self.assertEqual(_espanol_en(txt), [], str(p.relative_to(self.tmp)))
        self.assertGreaterEqual(n, 10)

    def test_el_detector_reconoce_espanol(self):
        self.assertEqual(_espanol_en("Hallazgo sobre los activos, segun la captura"),
                         ["activos", "captura", "hallazgo", "los", "segun"])
        self.assertEqual(_espanol_en("Finding on the assets (Cliente Ejemplo)"), [])


if __name__ == "__main__":
    unittest.main()
