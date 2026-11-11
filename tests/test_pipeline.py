"""Prueba de extremo a extremo sobre capturas sinteticas.

Requiere tshark y scapy; si faltan, se omite. Genera las capturas con
tests/gen_pcaps.py, corre el CLI completo y verifica lo que se detecta.
"""
from __future__ import annotations

import collections
import csv
import hashlib
import json
import os
import shutil
import stat
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))
sys.path.insert(0, str(RAIZ / "tests"))

try:
    import scapy  # noqa: F401
    HAY_SCAPY = True
except ImportError:
    HAY_SCAPY = False


def _csv(path: Path) -> list[dict]:
    with open(path, newline="", encoding="utf-8-sig") as fh:
        return list(csv.DictReader(fh))


@unittest.skipUnless(shutil.which("tshark") and HAY_SCAPY, "requiere tshark y scapy")
class PipelineTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import gen_pcaps

        from ot_assess.cli import main

        cls.tmp = Path(tempfile.mkdtemp())
        pcaps, cls.out = cls.tmp / "pcaps", cls.tmp / "out"
        sys.argv = ["gen", str(pcaps)]
        gen_pcaps.main()
        cls.umask_antes = os.umask(0o022)
        try:
            cls.rc = main([str(pcaps), "-o", str(cls.out)])
            cls.umask_despues = os.umask(0o022)
        finally:
            os.umask(cls.umask_antes)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_permisos_de_la_salida(self):
        """SEG-04: carpeta nueva 0700, archivos 0600 y umask restaurado."""
        if os.name != "posix":
            return
        self.assertEqual(self.umask_despues, 0o022)
        self.assertEqual(stat.S_IMODE(self.out.stat().st_mode), 0o700)
        for n in ("reporte_ot.html", "hallazgos.csv"):
            self.assertEqual(stat.S_IMODE((self.out / n).stat().st_mode), 0o600, n)

    def test_termina_bien_y_genera_los_archivos(self):
        self.assertEqual(self.rc, 0)
        for n in ("reporte_ot.html", "reporte_ot.md", "inventario.csv", "comunicaciones.csv",
                  "hallazgos.csv", "control.csv", "identidad.csv", "resultado.json",
                  "diagrama_zonas.svg", "diagrama_zonas.mmd", "diagrama_red.svg", "diagrama_red.mmd"):
            self.assertTrue((self.out / n).exists(), n)

    def test_xlsx_tiene_las_mismas_tablas_que_los_csv(self):
        import re
        import zipfile

        from ot_assess.importers.lector import leer_xlsx
        ruta = self.out / "reporte_ot.xlsx"
        with zipfile.ZipFile(ruta) as z:
            wb = z.read("xl/workbook.xml").decode("utf-8")
        hojas = re.findall(r'<sheet name="([^"]+)"', wb)
        self.assertEqual(hojas, ["Inventario", "Cobertura de captura", "Salud de la red", "Top equipos", "Top conductos",
                             "Mezcla de protocolos", "Linea base de trafico", "Sensores", "Brechas de sensores", "Inventario normalizado", "Inventario procedencia",
                                 "Obsolescencia", "Comunicaciones", "Zonas", "Hardening por tipo", "Hardening por activo",
                                 "Fuentes de log", "Direccionamiento IP", "Linea base especifica",
                                 "Linea base conductos", "Linea base general", "Linea base 2-1",
                                 "Matriz de controles", "Identidad",
                                 "Hallazgos", "ATT&amp;CK ICS cobertura", "Plan de remediacion", "Registro de riesgos", "Madurez por dominio",
                                 "Cuestionario de madurez", "DNS registros",
                                 "DNS resoluciones", "DNS servidores", "Control",
                                 "Cobertura iec62443", "Mapa de calor de riesgo"])
        esperado = _csv(self.out / "inventario.csv")
        obtenido = leer_xlsx(ruta.read_bytes())
        self.assertGreater(len(esperado), 0)
        self.assertEqual(len(obtenido), len(esperado))
        for e, o in zip(esperado, obtenido):
            self.assertEqual(e, {k: str(v) for k, v in o.items()})

    def test_operaciones_de_control_por_protocolo(self):
        # punto_a: 2 Modbus, 1 S7, 1 IEC-104, 1 CIP, 1 DNP3; punto_b: 3 IEC-104.
        por = collections.Counter(r["protocolo"] for r in _csv(self.out / "control.csv"))
        self.assertEqual(por["Modbus/TCP"], 2)
        self.assertEqual(por["S7comm"], 1)
        self.assertEqual(por["IEC 60870-5-104"], 4)
        self.assertEqual(por["CIP / EtherNet/IP"], 1)
        self.assertEqual(por["DNP3"], 1)

    def test_hallazgos_esperados(self):
        """Titulos que la red sintetica dispara. Las otras reglas no tienen escenario: ver docs/PRUEBAS.md."""
        titulos = {r["titulo"] for r in _csv(self.out / "hallazgos.csv")}
        esperados = {
            "Actividad de ingenieria sobre controladores (descarga, arranque o paro)",
            "Conflicto de direcciones: una misma IP anunciada por varias MAC",
            "Consultas DNS a servidores publicos",
            "Credenciales o administracion en texto claro",
            "DHCP activo en el segmento de control",
            "La captura no contiene ningun paquete que revele identidad de equipos",
            "La mayoria de las conversaciones aparece en un solo sentido",
            "Multiples subredes conviviendo en el mismo dominio de difusion",
            "Muy pocos paquetes de identidad en la captura",
            "Operaciones de escritura o control observadas en la captura",
            "Proporcion alta de trafico de difusion",
            "Protocolos de gestion sin cifrar en uso",
            "Resolucion de dominios de Internet desde la red",
            "Software o sistema operativo fuera de soporte",
            "Trafico con direcciones IP publicas desde la red OT",
            "Ventana de captura corta",
            "Version de firmware expuesta en protocolos de descubrimiento",
            "Wireshark marco deteccion de direccion duplicada en ARP",
        }
        self.assertEqual(esperados - titulos, set(), "detecciones que dejaron de dispararse")
        self.assertEqual(titulos - esperados, set(), "detecciones nuevas: afirmalas aqui")

    def test_hallazgos_llevan_referencias(self):
        fila = next(r for r in _csv(self.out / "hallazgos.csv")
                    if r["titulo"].startswith("Operaciones de escritura"))
        self.assertIn("T1692.001", fila["mitre_ics"])
        self.assertIn("SR 2.1", fila["iec62443"])

    def test_inventario_une_los_dos_puntos_de_captura(self):
        macs = [r["mac"] for r in _csv(self.out / "inventario.csv") if r["mac"]]  # I3: las filas por IP no llevan MAC
        self.assertEqual(len(macs), len(set(macs)))
        rtu = next(r for r in _csv(self.out / "inventario.csv") if r["ips"] == "10.10.2.6")
        self.assertEqual(set(rtu["visto_en_capturas"].split(";")), {"punto_a.pcap", "punto_b.pcap"})

    def test_diagramas_en_el_reporte(self):
        for svg in ("diagrama_zonas.svg", "diagrama_red.svg"):
            ET.parse(self.out / svg)                     # XML valido
        html = (self.out / "reporte_ot.html").read_text(encoding="utf-8")
        self.assertIn("<svg", html)
        self.assertIn("Diagrama de zonas y conductos", html)
        md = (self.out / "reporte_ot.md").read_text(encoding="utf-8")
        self.assertIn("![Diagrama de comunicaciones por activo](diagrama_red.svg)", md)

    def test_salida_determinista(self):
        """Dos corridas sobre las mismas capturas dan el mismo inventario y hallazgos."""
        from ot_assess.cli import main
        otra = self.tmp / "out2"
        main([str(self.tmp / "pcaps"), "-o", str(otra)])
        for n in ("hallazgos.csv", "inventario.csv", "comunicaciones.csv", "control.csv",
                  "reporte_ot.xlsx", "diagrama_red.svg", "diagrama_zonas.svg",
                  "diagrama_red.drawio", "diagrama_zonas.drawio"):
            a, b = (self.out / n).read_bytes(), (otra / n).read_bytes()
            if n.endswith((".svg", ".drawio")):
                # los diagramas llevan la fecha del dia (diagram.fecha): la corrida de setUpClass y esta pueden
                # quedar a ambos lados de la medianoche (fallo real en la revision de T8)
                import re
                a, b = (re.sub(rb"\d\d/\d\d/\d{4}", b"FECHA", x) for x in (a, b))
            self.assertEqual(a, b, n)
        import xml.etree.ElementTree as ET
        for n in ("diagrama_red.drawio", "diagrama_zonas.drawio"):
            self.assertEqual(ET.parse(self.out / n).getroot().tag, "mxfile", n)

    @staticmethod
    def _docx(carpeta: Path) -> str:
        import zipfile
        with zipfile.ZipFile(carpeta / "informe_ot.docx") as z:
            return z.read("word/document.xml").decode("utf-8")

    def test_informe_docx(self):
        from ot_assess.cli import main
        doc = self._docx(self.out)
        for x in ("Hallazgos", "Protocolos de gestion sin cifrar en uso", "Inventario de activos",
                  "Matriz de comunicaciones", "Entorno de analisis", "Cobertura de IEC 62443",
                  "Preguntas para la sesion"):
            self.assertIn(x, doc)
        for x in ("Cliente Ejemplo", "Politica de firewall"):
            self.assertNotIn(x, doc)
        perfil = self.tmp / "perfil_docx.json"
        perfil.write_text(json.dumps({"version": 1, "cliente": "Cliente Ejemplo",
                                      "marcos": [{"clave": "iec62443"}]}), encoding="utf-8")
        otra = self.tmp / "out_docx"
        main([str(self.tmp / "pcaps"), "-o", str(otra), "--perfil", str(perfil),
              "--reglas-firewall", str(RAIZ / "docs" / "ejemplos" / "reglas_firewall.csv")])
        doc = self._docx(otra)
        self.assertIn("Cliente Ejemplo", doc)
        self.assertIn("Perfil del proyecto", doc)
        self.assertIn("Politica de firewall", doc)

    def test_docx_incrusta_diagramas(self):
        import zipfile
        with zipfile.ZipFile(self.out / "informe_ot.docx") as z:
            nombres = z.namelist()
            for n in ("diagrama_red", "diagrama_zonas"):
                self.assertIn(f"word/media/{n}.svg", nombres)
            doc = z.read("word/document.xml").decode("utf-8")
        self.assertIn("Diagramas", doc)
        self.assertIn("svgBlip", doc)

    def test_estandar_nerc_cip(self):
        from ot_assess.cli import main
        otra = self.tmp / "out_cip"
        main([str(self.tmp / "pcaps"), "-o", str(otra), "--estandar", "nerc-cip,nist-800-82"])
        filas = _csv(otra / "hallazgos.csv")
        self.assertIn("nerc-cip", filas[0])
        self.assertIn("nist-800-82", filas[0])
        self.assertNotIn("iec62443", filas[0])
        escritura = next(r for r in filas if r["titulo"].startswith("Operaciones de escritura"))
        self.assertIn("CIP-005 R1", escritura["nerc-cip"])
        html = (otra / "reporte_ot.html").read_text(encoding="utf-8")
        self.assertIn("Acceso Electronico (EAP)", html)       # el primero rige el texto
        self.assertIn("NERC CIP:", html)
        self.assertIn("Validacion del mapeo: sin revisar", html)
        self.assertIn("Fuente: NERC CIP (CIP-005", html)
        self.assertNotIn("zonas y conductos de IEC 62443", html)

    def test_estandar_nist_csf(self):
        from ot_assess.cli import main
        otra = self.tmp / "out_csf"
        main([str(self.tmp / "pcaps"), "-o", str(otra), "--estandar", "nist-csf,nist-800-82"])
        filas = _csv(otra / "hallazgos.csv")
        self.assertIn("nist-csf", filas[0])
        self.assertIn("nist-800-82", filas[0])
        html = (otra / "reporte_ot.html").read_text(encoding="utf-8")
        self.assertIn("NIST CSF 2.0", html)
        self.assertIn("Govern (GV) no tiene evidencia", html)
        self.assertEqual(len(_csv(otra / "cobertura_nist-csf.csv")), 106)
        self.assertIn("Anexo: cobertura de NIST CSF 2.0", html)
        self.assertIn("Detalle en `cobertura_nist-csf.csv`", (otra / "reporte_ot.md").read_text(encoding="utf-8"))
        self.assertIn("nist-csf", json.loads((otra / "resultado.json").read_text(encoding="utf-8"))["cobertura"])

    def test_cobertura_iec_y_csf(self):
        from ot_assess.cli import main
        otra = self.tmp / "out_iec_csf"
        main([str(self.tmp / "pcaps"), "-o", str(otra), "--estandar", "iec62443,nist-csf"])
        self.assertEqual(len(_csv(otra / "cobertura_iec62443.csv")), 51)
        self.assertEqual(len(_csv(otra / "cobertura_nist-csf.csv")), 106)
        html = (otra / "reporte_ot.html").read_text(encoding="utf-8")
        self.assertIn("Anexo: cobertura de NIST CSF 2.0", html)
        self.assertIn("falta cotejarlos con el texto de la norma", html)
        self.assertEqual(html.count("Anexo: cobertura de"), 2)

    def test_sin_archivo_de_cobertura_no_hay_anexo(self):
        from ot_assess.cli import main
        otra = self.tmp / "out_sin_cob"
        main([str(self.tmp / "pcaps"), "-o", str(otra), "--estandar", "nerc-cip,nist-800-82"])
        self.assertEqual([p.name for p in otra.glob("cobertura_*.csv")
                          if not p.name.startswith(("cobertura_captura", "cobertura_zonas"))], [])
        self.assertNotIn("Anexo: cobertura", (otra / "reporte_ot.html").read_text(encoding="utf-8"))
        self.assertEqual(json.loads((otra / "resultado.json").read_text(encoding="utf-8"))["cobertura"], {})

    def test_perfil(self):
        from ot_assess.cli import main
        perfil = self.tmp / "perfil.json"
        perfil.write_text(json.dumps({
            "version": 1, "cliente": "Cliente Ejemplo", "sitio": "Planta Norte",
            "marcos": [{"clave": "iec62443", "edicion": "2018", "partes": ["3-3"]},
                       {"clave": "nist-800-82"}]}), encoding="utf-8")
        otra = self.tmp / "out_perfil"
        main([str(self.tmp / "pcaps"), "-o", str(otra), "--perfil", str(perfil)])
        for n in ("reporte_ot.html", "reporte_ot.md"):
            t = (otra / n).read_text(encoding="utf-8")
            for x in ("Perfil del proyecto", "Cliente Ejemplo", "2018", "3-3"):
                self.assertIn(x, t, n)
        r = json.loads((otra / "resultado.json").read_text(encoding="utf-8"))
        self.assertEqual(r["perfil"]["cliente"], "Cliente Ejemplo")
        self.assertEqual(r["entorno"]["perfil"]["sha256"],
                         hashlib.sha256(perfil.read_bytes()).hexdigest())
        cols = _csv(otra / "hallazgos.csv")[0]
        self.assertIn("iec62443", cols)
        self.assertIn("nist-800-82", cols)
        # sin perfil: objeto vacio y entorno.perfil nulo
        r0 = json.loads((self.out / "resultado.json").read_text(encoding="utf-8"))
        self.assertEqual(r0["perfil"], {})
        self.assertIsNone(r0["entorno"]["perfil"])
        with self.assertRaises(SystemExit) as cm:
            main([str(self.tmp / "pcaps"), "-o", str(self.tmp / "x"), "--perfil", str(perfil),
                  "--estandar", "nerc-cip"])
        self.assertEqual(cm.exception.code, 2)

    def test_flujos_entre_interfaces_del_firewall(self):
        import re
        import zipfile

        from ot_assess.cli import main
        titulo = "Flujos entre interfaces del firewall"
        for n in ("reporte_ot.html", "reporte_ot.md"):  # sin la opcion no sale la seccion
            self.assertNotIn(titulo, (self.out / n).read_text(encoding="utf-8"), n)
        self.assertNotIn(titulo, self._docx(self.out))
        self.assertFalse((self.out / "firewall_matriz.csv").exists())
        rutas = RAIZ / "docs" / "ejemplos" / "rutas_firewall.csv"
        otra = self.tmp / "out_rutas"
        main([str(self.tmp / "pcaps"), "-o", str(otra), "--rutas-firewall", str(rutas)])
        fila = _csv(otra / "firewall_matriz.csv")[0]
        par = f"{fila['interfaz_origen']}</td><td>{fila['interfaz_destino']}"
        self.assertEqual(fila["interfaz_destino"], "DMZ-CORP (ruta por defecto)")
        html = (otra / "reporte_ot.html").read_text(encoding="utf-8")
        self.assertIn("<h2>" + titulo + "</h2>", html)
        self.assertIn(par, html)
        md = (otra / "reporte_ot.md").read_text(encoding="utf-8")
        self.assertIn("## " + titulo, md)
        self.assertIn(f"| {fila['interfaz_origen']} | {fila['interfaz_destino']} |", md)
        doc = self._docx(otra)
        self.assertIn(titulo, doc)
        self.assertIn(fila["interfaz_destino"], doc)
        with zipfile.ZipFile(otra / "reporte_ot.xlsx") as z:
            hojas = re.findall(r'<sheet name="([^"]+)"', z.read("xl/workbook.xml").decode("utf-8"))
        self.assertIn("FW interfaces", hojas)
        self.assertIn("FW matriz", hojas)
        # los diagramas se agrupan por interfaz
        self.assertIn('["OT-NET"]', (otra / "diagrama_red.mmd").read_text(encoding="utf-8"))
        self.assertNotIn("OT-NET", (self.out / "diagrama_red.mmd").read_text(encoding="utf-8"))

    def test_reglas_firewall(self):
        import re
        import zipfile

        from ot_assess.cli import main
        reglas = RAIZ / "docs" / "ejemplos" / "reglas_firewall.csv"
        otra = self.tmp / "out_fw"
        main([str(self.tmp / "pcaps"), "-o", str(otra), "--reglas-firewall", str(reglas)])
        r = json.loads((otra / "resultado.json").read_text(encoding="utf-8"))
        fw = r["firewall"]
        self.assertEqual(fw["archivo"], "reglas_firewall.csv")
        self.assertEqual(fw["resumen"], {"permitido": 2, "denegado_observado": 1,
                                         "sin_regla": 10, "reglas_sin_trafico": 1})
        self.assertEqual(r["entorno"]["reglas_firewall"]["sha256"],
                         hashlib.sha256(reglas.read_bytes()).hexdigest())
        con = _csv(otra / "firewall_contraste.csv")
        self.assertEqual(len(con), len(_csv(otra / "comunicaciones.csv")))
        orden = [f["resultado"] for f in con]
        self.assertEqual(orden, sorted(orden, key=["sin_regla", "denegado_observado",
                                                   "permitido"].index))
        self.assertEqual([f["regla"] for f in con if f["resultado"] == "denegado_observado"],
                         ["FW-02"])
        sin = _csv(otra / "firewall_reglas_sin_trafico.csv")
        self.assertEqual([(s["regla"], s["origen"], s["puerto"]) for s in sin],
                         [("FW-04", "10.10.9.0/24", "502")])
        with zipfile.ZipFile(otra / "reporte_ot.xlsx") as z:
            hojas = re.findall(r'<sheet name="([^"]+)"', z.read("xl/workbook.xml").decode("utf-8"))
        self.assertIn("Firewall", hojas)
        self.assertIn("Reglas sin trafico", hojas)
        html = (otra / "reporte_ot.html").read_text(encoding="utf-8")
        self.assertIn("Politica de firewall contra trafico observado", html)
        self.assertIn("no es necesariamente innecesaria", html)
        md = (otra / "reporte_ot.md").read_text(encoding="utf-8")
        self.assertIn("firewall_contraste.csv", md)
        # sin la opcion: nada de lo anterior
        self.assertFalse((self.out / "firewall_contraste.csv").exists())
        self.assertFalse((self.out / "firewall_reglas_sin_trafico.csv").exists())
        self.assertNotIn("Politica de firewall",
                         (self.out / "reporte_ot.html").read_text(encoding="utf-8"))
        r0 = json.loads((self.out / "resultado.json").read_text(encoding="utf-8"))
        self.assertEqual(r0["firewall"], {})
        self.assertIsNone(r0["entorno"]["reglas_firewall"])

    def test_vulnerabilidades(self):
        import re
        import zipfile

        from ot_assess.cli import main
        vul = RAIZ / "docs" / "ejemplos" / "vulnerabilidades.csv"
        otra = self.tmp / "out_vul"
        main([str(self.tmp / "pcaps"), "-o", str(otra), "--vulnerabilidades", str(vul),
              "--estandar", "iec62443,nerc-cip,nist-800-82,nist-csf"])
        h = [f for f in _csv(otra / "hallazgos.csv") if f["categoria"] == "Vulnerabilidades"]
        self.assertEqual(len(h), 1)
        h = h[0]
        self.assertEqual(h["captura"], "vulnerabilidades vulnerabilidades.csv")
        self.assertEqual(h["severidad"], "Alta")
        self.assertIn("Filas sin activo en el inventario: 1", h["evidencia"])
        self.assertIn("CVE-2099-0001", h["evidencia"])
        self.assertNotIn("CVE-2099-0004", h["evidencia"])      # mitigada
        for col in ("mitre_ics", "iec62443", "nerc-cip", "nist-800-82", "nist-csf"):
            self.assertTrue(h[col], col)
        filas = _csv(otra / "vulnerabilidades.csv")
        self.assertEqual(len(filas), 5)
        self.assertEqual(filas[-1]["activo"], "")
        self.assertEqual(filas[-1]["cve"], "CVE-2099-0005")
        self.assertEqual({f["asociado_por"] for f in filas[:-1]}, {"ip"})
        with zipfile.ZipFile(otra / "reporte_ot.xlsx") as z:
            hojas = re.findall(r'<sheet name="([^"]+)"', z.read("xl/workbook.xml").decode("utf-8"))
        self.assertIn("Vulnerabilidades", hojas)
        nota = "la herramienta no consulta bases de CVE"
        html = (otra / "reporte_ot.html").read_text(encoding="utf-8")
        self.assertIn("Vulnerabilidades importadas", html)
        self.assertIn(nota, html)
        self.assertIn("Vulnerabilidades importadas", self._docx(otra))
        self.assertIn(nota, self._docx(otra))
        self.assertIn(nota, (otra / "reporte_ot.md").read_text(encoding="utf-8"))
        r = json.loads((otra / "resultado.json").read_text(encoding="utf-8"))
        self.assertEqual(r["vulnerabilidades"]["total"], 5)
        self.assertEqual(r["vulnerabilidades"]["sin_activo"], 1)
        self.assertEqual(r["entorno"]["vulnerabilidades"]["sha256"],
                         hashlib.sha256(vul.read_bytes()).hexdigest())
        # sin la opcion: nada de lo anterior
        self.assertFalse((self.out / "vulnerabilidades.csv").exists())
        self.assertNotIn("Vulnerabilidades importadas",
                         (self.out / "reporte_ot.html").read_text(encoding="utf-8"))
        self.assertNotIn("Vulnerabilidades", self._docx(self.out))
        self.assertFalse([f for f in _csv(self.out / "hallazgos.csv")
                          if f["categoria"] == "Vulnerabilidades"])
        r0 = json.loads((self.out / "resultado.json").read_text(encoding="utf-8"))
        self.assertEqual(r0["vulnerabilidades"], {})

    def test_alertas(self):
        import re
        import zipfile

        from ot_assess.cli import main
        ale = RAIZ / "docs" / "ejemplos" / "alertas.csv"
        otra = self.tmp / "out_ale"
        main([str(self.tmp / "pcaps"), "-o", str(otra), "--alertas", str(ale),
              "--estandar", "iec62443,nerc-cip,nist-800-82,nist-csf"])
        h = [f for f in _csv(otra / "hallazgos.csv") if f["categoria"] == "Deteccion"]
        self.assertEqual(len(h), 1)
        h = h[0]
        self.assertEqual(h["captura"], "alertas alertas.csv")
        self.assertEqual(h["severidad"], "Alta")
        self.assertIn("Alertas sin conducto observado: 1", h["evidencia"])
        for col in ("iec62443", "nerc-cip", "nist-800-82", "nist-csf"):
            self.assertTrue(h[col], col)
        self.assertEqual(h["mitre_ics"], "")
        filas = _csv(otra / "alertas.csv")
        self.assertEqual(len(filas), 5)
        self.assertEqual([f["conducto_observado"] for f in filas], ["si", "si", "si", "si", "no"])
        with zipfile.ZipFile(otra / "reporte_ot.xlsx") as z:
            hojas = re.findall(r'<sheet name="([^"]+)"', z.read("xl/workbook.xml").decode("utf-8"))
        self.assertIn("Alertas", hojas)
        nota = "no valida las firmas ni descarta falsos positivos"
        html = (otra / "reporte_ot.html").read_text(encoding="utf-8")
        self.assertIn("Alertas importadas", html)
        self.assertIn(nota, html)
        self.assertIn("Alertas importadas", self._docx(otra))
        self.assertIn(nota, self._docx(otra))
        self.assertIn(nota, (otra / "reporte_ot.md").read_text(encoding="utf-8"))
        r = json.loads((otra / "resultado.json").read_text(encoding="utf-8"))
        self.assertEqual(r["alertas"]["total"], 8)
        self.assertEqual(r["alertas"]["sin_conducto"], 1)
        self.assertEqual(r["entorno"]["alertas"]["sha256"], hashlib.sha256(ale.read_bytes()).hexdigest())
        # sin la opcion: nada de lo anterior
        self.assertFalse((self.out / "alertas.csv").exists())
        self.assertNotIn("Alertas importadas", (self.out / "reporte_ot.html").read_text(encoding="utf-8"))
        self.assertNotIn("Alertas importadas", self._docx(self.out))
        self.assertFalse([f for f in _csv(self.out / "hallazgos.csv") if f["categoria"] == "Deteccion"])
        r0 = json.loads((self.out / "resultado.json").read_text(encoding="utf-8"))
        self.assertEqual(r0["alertas"], {})

    def test_estandar_invalido_termina_con_error(self):
        from ot_assess.cli import main
        with self.assertRaises(SystemExit):
            main([str(self.tmp / "pcaps"), "-o", str(self.tmp / "x"), "--estandar", "no-existe"])

    def test_sin_diagramas(self):
        from ot_assess.cli import main
        otra = self.tmp / "out3"
        main([str(self.tmp / "pcaps"), "-o", str(otra), "--no-diagrams"])
        self.assertFalse((otra / "diagrama_red.svg").exists())
        import zipfile
        with zipfile.ZipFile(otra / "informe_ot.docx") as z:
            self.assertFalse([n for n in z.namelist() if "media" in n])
            self.assertNotIn("Diagramas", z.read("word/document.xml").decode())
        self.assertNotIn("<svg", (otra / "reporte_ot.html").read_text(encoding="utf-8"))

    def test_json_completo(self):
        datos = json.loads((self.out / "resultado.json").read_text(encoding="utf-8"))["capturas"]
        self.assertEqual(len(datos), 2)

    def test_entorno_en_reportes_y_json(self):
        """COR-03: el reporte registra con que se analizo (tshark, hash de cada captura)."""
        datos = json.loads((self.out / "resultado.json").read_text(encoding="utf-8"))
        ent = datos["entorno"]
        self.assertTrue(ent["tshark"].startswith("TShark"))
        pcap = sorted((self.tmp / "pcaps").iterdir())[0]
        sha = hashlib.sha256(pcap.read_bytes()).hexdigest()
        self.assertIn(sha, [c["sha256"] for c in ent["capturas"]])
        for n in ("reporte_ot.html", "reporte_ot.md"):
            t = (self.out / n).read_text(encoding="utf-8")
            self.assertIn("Entorno de analisis", t, n)
            self.assertIn(ent["tshark"], t, n)
            self.assertIn(sha, t, n)
            self.assertIn("Campos ignorados por este tshark", t, n)

    def test_campo_ignorado_aparece_en_el_reporte(self):
        from unittest import mock

        from ot_assess import cli
        otra = self.tmp / "out_campo"
        with mock.patch.object(cli, "DETAIL_FIELDS", list(cli.DETAIL_FIELDS) + ["campo.inexistente_xyz"]):
            cli.main([str(self.tmp / "pcaps"), "-o", str(otra)])
        for n in ("reporte_ot.html", "reporte_ot.md"):
            self.assertIn("campo.inexistente_xyz", (otra / n).read_text(encoding="utf-8"), n)


# PRU-01: un escenario por grupo de detecciones (punto_c y punto_d de tests/gen_pcaps.py).
# Los titulos van completos y entre comillas porque scripts/generar_catalogo.py los busca aqui.
DETECCIONES_PUNTO_C = {
    "Protocolos de descubrimiento de Windows activos en la red de control":
        "LLMNR: 1 tramas, NBT-NS: 1 tramas, mDNS: 1 tramas, SSDP/UPnP: 1 tramas",
    "Servicio de licenciamiento Sentinel HASP (puerto 1947) en difusion": "desde 10.10.5.30",
    "Equipos con direccion APIPA (169.254.x.x)": "169.254.10.20",
    "RIP activo en la red de control": "1 tramas RIP",
    "Barrido ARP: un equipo pregunta por muchas direcciones": "30 IPs distintas",
    # 30 SYN mas la difusion de Sentinel, que sale de la misma IP
    "Patron compatible con escaneo de red": "10.10.5.30: contacto con 31 destinos distintos",
    "Cambios de topologia STP frecuentes": "25 notificaciones",
    "No se observaron escrituras ni comandos de control": "Solo trafico de lectura",
}
DETECCIONES_PUNTO_D = {
    "Captura truncada (snaplen por debajo del MTU)": "96",
    "El punto de captura casi no ve trafico unicast": "Solo 0 de 2100",
    "El trafico es casi todo I/O ciclico, que no revela identidad": "2100 de 2100",
    "Sin segmentacion por VLAN visible en el punto de captura": "ninguna",
}


@unittest.skipUnless(shutil.which("tshark") and HAY_SCAPY, "requiere tshark y scapy")
class DeteccionesTest(unittest.TestCase):
    """Cada deteccion se dispara con un escenario sintetico y cita la evidencia correcta."""

    @classmethod
    def setUpClass(cls):
        import gen_pcaps

        from ot_assess.cli import main

        cls.tmp = Path(tempfile.mkdtemp())
        pcaps = cls.tmp / "pcaps"
        pcaps.mkdir()
        gen_pcaps.guardar(gen_pcaps.punto_c(), pcaps / "punto_c.pcap")
        gen_pcaps.guardar(gen_pcaps.punto_d(), pcaps / "punto_d.pcap")
        gen_pcaps.fijar_snaplen(pcaps / "punto_d.pcap", 96)
        cls.rc = main([str(pcaps), "-o", str(cls.tmp / "out")])
        cls.filas = _csv(cls.tmp / "out" / "hallazgos.csv")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _evidencia(self, captura: str, titulo: str) -> str:
        previstas = [r["evidencia"] for r in self.filas if r["captura"] == captura and r["titulo"] == titulo]
        self.assertEqual(len(previstas), 1, f"{captura}: {titulo}")
        return previstas[0]

    def test_termina_bien(self):
        self.assertEqual(self.rc, 0)

    def test_punto_c(self):
        for titulo, evidencia in DETECCIONES_PUNTO_C.items():
            self.assertIn(evidencia, self._evidencia("punto_c.pcap", titulo), titulo)

    def test_punto_d(self):
        for titulo, evidencia in DETECCIONES_PUNTO_D.items():
            self.assertIn(evidencia, self._evidencia("punto_d.pcap", titulo), titulo)


TITULO_ILEGIBLE = "Captura ilegible o sin paquetes"
MALAS = ("corrupta.pcap", "vacia.pcap", "truncada.pcap")


@unittest.skipUnless(shutil.which("tshark") and HAY_SCAPY, "requiere tshark y scapy")
class CapturaIlegibleTest(unittest.TestCase):
    """COR-01: una captura ilegible no puede dar un reporte 'exitoso' ni hallazgos de ausencia."""

    @classmethod
    def setUpClass(cls):
        import gen_pcaps

        from ot_assess.cli import main

        cls.tmp = Path(tempfile.mkdtemp())
        buena = cls.tmp / "buena.pcap"
        gen_pcaps.guardar(gen_pcaps.punto_b(), buena)
        cls.malas = cls.tmp / "solo_malas"
        cls.malas.mkdir()
        (cls.malas / "corrupta.pcap").write_bytes(bytes(range(256)) * 12)    # no es una captura
        (cls.malas / "vacia.pcap").write_bytes(b"")
        (cls.malas / "truncada.pcap").write_bytes(buena.read_bytes()[:-10])  # cortada en un paquete
        cls.mezcla = cls.tmp / "mezcla"
        shutil.copytree(cls.malas, cls.mezcla)
        shutil.copy(buena, cls.mezcla / "buena.pcap")
        cls.out = cls.tmp / "out"
        cls.rc = main([str(cls.mezcla), "-o", str(cls.out)])
        cls.rc_todas = main([str(cls.malas), "-o", str(cls.tmp / "out_malas")])

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_el_codigo_de_salida_avisa(self):
        self.assertEqual(self.rc, 2)

    def test_cada_ilegible_tiene_su_hallazgo_y_ningun_otro(self):
        filas = _csv(self.out / "hallazgos.csv")
        for nombre in MALAS:
            titulos = {r["titulo"] for r in filas if r["captura"] == nombre}
            self.assertEqual(titulos, {TITULO_ILEGIBLE}, nombre)

    def test_la_captura_buena_se_analiza(self):
        filas = [r for r in _csv(self.out / "hallazgos.csv") if r["captura"] == "buena.pcap"]
        self.assertTrue(filas)
        self.assertNotIn(TITULO_ILEGIBLE, {r["titulo"] for r in filas})
        self.assertEqual(len(_csv(self.out / "control.csv")), 3)

    def test_el_json_marca_la_causa(self):
        datos = {Path(d["archivo"]).name: d for d in
                 json.loads((self.out / "resultado.json").read_text(encoding="utf-8"))["capturas"]}
        for nombre in MALAS:
            self.assertTrue(datos[nombre]["error"], nombre)
        self.assertEqual(datos["buena.pcap"]["error"], "")

    def test_si_ninguna_es_legible_no_hay_reporte(self):
        self.assertEqual(self.rc_todas, 1)
        self.assertFalse((self.tmp / "out_malas" / "reporte_ot.html").exists())


class ContarDuplicadosTest(unittest.TestCase):
    """COR-02: parseo de la salida de editcap -d, sin tshark."""

    def test_linea_real(self):
        from ot_assess.tools import contar_duplicados
        txt = "4 packets seen, 2 packets skipped with duplicate window of 5 packets.\n"
        self.assertEqual(contar_duplicados(txt), 2)

    def test_cero(self):
        from ot_assess.tools import contar_duplicados
        self.assertEqual(contar_duplicados("4 packets seen, 0 packets skipped with duplicate window of 5 packets."), 0)

    def test_texto_ajeno(self):
        from ot_assess.tools import contar_duplicados
        self.assertIsNone(contar_duplicados("editcap: error"))


@unittest.skipUnless(shutil.which("tshark") and shutil.which("editcap") and HAY_SCAPY,
                     "requiere tshark, editcap y scapy")
class DuplicadosTest(unittest.TestCase):
    """COR-02: la regla de duplicados se dispara con editcap -d y solo si hay duplicados."""
    TITULO = "Paquetes duplicados en la captura"

    @classmethod
    def setUpClass(cls):
        import gen_pcaps
        from scapy.all import IP, UDP, Ether

        from ot_assess.cli import main

        cls.tmp = Path(tempfile.mkdtemp())
        pcaps = cls.tmp / "pcaps"
        pcaps.mkdir()
        a = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=1000, dport=2000) / b"uno"
        b = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=1000, dport=2000) / b"otro"
        gen_pcaps.guardar([a, a.copy(), a.copy(), b], pcaps / "con_duplicados.pcap")
        gen_pcaps.guardar([a, b], pcaps / "sin_duplicados.pcap")
        cls.rc = main([str(pcaps), "-o", str(cls.tmp / "out")])
        cls.filas = _csv(cls.tmp / "out" / "hallazgos.csv")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_con_duplicados(self):
        ev = [r["evidencia"] for r in self.filas
              if r["captura"] == "con_duplicados.pcap" and r["titulo"] == self.TITULO]
        self.assertEqual(len(ev), 1)
        self.assertIn(": 2", ev[0])

    def test_sin_duplicados(self):
        self.assertFalse([r for r in self.filas
                          if r["captura"] == "sin_duplicados.pcap" and r["titulo"] == self.TITULO])


class TsharkConErrorTest(unittest.TestCase):
    """tshark que termina con error (sin que capinfos lo haya visto) no deja un analisis parcial."""

    def setUp(self):
        from ot_assess.tools import Tshark
        self.dir = tempfile.TemporaryDirectory()
        falso = Path(self.dir.name) / "tshark"
        falso.write_text("#!/bin/sh\nprintf 'a\\tb\\n'\necho 'tshark: boom' >&2\nexit 2\n")
        falso.chmod(0o755)
        self.ts = Tshark(str(falso), "capinfos", "editcap", Path(self.dir.name) / "probe")

    def tearDown(self):
        self.dir.cleanup()

    def test_fields_pass_no_ignora_el_codigo_de_salida(self):
        from ot_assess.tools import CapturaIlegible
        with self.assertRaises(CapturaIlegible):
            list(self.ts.fields_pass(Path("x.pcap"), ["frame.number"], None, 0))

    def test_phs_no_ignora_el_codigo_de_salida(self):
        from ot_assess.tools import CapturaIlegible
        with self.assertRaises(CapturaIlegible):
            self.ts.phs(Path("x.pcap"))

    def test_la_captura_se_marca_ilegible_y_no_se_evalua(self):
        import argparse

        from ot_assess.cli import analyze_capture
        args = argparse.Namespace(max_packets=0, no_detail=True)
        cap = analyze_capture(self.ts, Path("x.pcap"), {"Number of packets": "5"}, [], [], "", args)
        self.assertEqual(cap.error, "tshark: boom")
        self.assertEqual({f["titulo"] for f in cap.findings}, {TITULO_ILEGIBLE})


if __name__ == "__main__":
    unittest.main()
