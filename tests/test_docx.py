"""S2a: escritor DOCX minimo."""
from __future__ import annotations

import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))

from ot_assess.report.docx import escribir_docx

W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
PARTES = ["[Content_Types].xml", "_rels/.rels", "word/document.xml", "word/styles.xml",
          "word/numbering.xml", "word/_rels/document.xml.rels"]


class TestDocx(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        self.addCleanup(self.d.cleanup)

    def _escribir(self, bloques, nombre="a.docx"):
        return Path(escribir_docx(Path(self.d.name) / nombre, bloques))

    def _doc(self, bloques):
        with zipfile.ZipFile(self._escribir(bloques)) as z:
            return ET.fromstring(z.read("word/document.xml"))

    def test_partes_bien_formadas_y_declaradas(self):
        p = self._escribir([("p", "x")])
        with zipfile.ZipFile(p) as z:
            self.assertEqual(z.namelist(), PARTES)
            for n in PARTES:
                ET.fromstring(z.read(n))
            ct = z.read("[Content_Types].xml").decode()
            for n in PARTES[2:5]:
                self.assertIn(f'PartName="/{n}"', ct)
            estilos = z.read("word/styles.xml").decode()
            for s in ("Normal", "Title", "Subtitle", "Heading1", "Heading2", "TablaBordes"):
                self.assertIn(f'w:styleId="{s}"', estilos)
            self.assertIn("w:outlineLvl", estilos)
            self.assertIn('w:w="12240" w:h="15840"', z.read("word/document.xml").decode())

    def test_bloques_con_estilo_y_orden(self):
        doc = self._doc([("titulo", "T"), ("subtitulo", "S"), ("h1", "H1"), ("h2", "H2"),
                         ("p", "P"), ("nota", "N"), ("lista", ["a", "b"]), ("salto",)])
        esperado = [("Title", "T"), ("Subtitle", "S"), ("Heading1", "H1"), ("Heading2", "H2"),
                    (None, "P"), (None, "N"), ("ListParagraph", "a"), ("ListParagraph", "b")]
        reales = []
        for p in doc.find(f"{W}body").findall(f"{W}p"):
            st = p.find(f"{W}pPr/{W}pStyle")
            reales.append((st.get(f"{W}val") if st is not None else None,
                           "".join(t.text or "" for t in p.iter(f"{W}t"))))
        self.assertEqual(reales[:8], esperado)
        self.assertEqual(len(doc.findall(f".//{W}numId")), 2)
        self.assertEqual(doc.find(f".//{W}br").get(f"{W}type"), "page")
        nota = doc.findall(f".//{W}p")[5]
        self.assertIsNotNone(nota.find(f".//{W}i"))

    def test_tabla(self):
        doc = self._doc([("tabla", ["A", "B"], [["x", 1], [2.5, None], ["y", "z"]])])
        trs = doc.findall(f".//{W}tr")
        self.assertEqual(len(trs), 4)
        self.assertIsNotNone(trs[0].find(f"{W}trPr/{W}tblHeader"))
        self.assertEqual(len(doc.findall(f".//{W}tblHeader")), 1)
        self.assertIsNotNone(trs[0].find(f".//{W}shd"))
        self.assertIsNotNone(trs[0].find(f".//{W}b"))
        celdas = [["".join(t.text or "" for t in tc.iter(f"{W}t")) for tc in tr.findall(f"{W}tc")]
                  for tr in trs]
        self.assertEqual(celdas, [["A", "B"], ["x", "1"], ["2.5", ""], ["y", "z"]])

    def test_escape_y_control(self):
        doc = self._doc([("p", "a<&\"'>b\x00\x01\x0bc")])
        self.assertEqual("".join(t.text for t in doc.iter(f"{W}t")), "a<&\"'>bc")
        with zipfile.ZipFile(self._escribir([("p", "<&\"")])) as z:
            crudo = z.read("word/document.xml").decode()
        self.assertIn("&lt;&amp;&quot;", crudo)

    def test_salto_de_linea(self):
        doc = self._doc([("p", "uno\ndos")])
        p = doc.find(f".//{W}p")
        self.assertEqual(len(p.findall(f".//{W}br")), 1)
        self.assertEqual([t.text for t in p.iter(f"{W}t")], ["uno", "dos"])
        for t in p.iter(f"{W}t"):
            self.assertEqual(t.get("{http://www.w3.org/XML/1998/namespace}space"), "preserve")

    def test_bloque_desconocido(self):
        with self.assertRaises(ValueError):
            self._escribir([("nada", "x")])

    SVG = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d"><rect width="5" height="5"/></svg>'

    def _con_imagen(self, svg, nombre="diagrama_red"):
        z = zipfile.ZipFile(self._escribir([("imagen_svg", svg, nombre, "pie")]))
        self.addCleanup(z.close)
        return z

    def test_imagen_partes_y_relaciones(self):
        z = self._con_imagen(self.SVG % (200, 100))
        nombres = z.namelist()
        for n in ("word/media/diagrama_red.svg", "word/media/diagrama_red.png"):
            self.assertIn(n, nombres)
        ct = z.read("[Content_Types].xml").decode()
        self.assertIn('Extension="svg" ContentType="image/svg+xml"', ct)
        self.assertIn('Extension="png" ContentType="image/png"', ct)
        rels = ET.fromstring(z.read("word/_rels/document.xml.rels"))
        destinos = {r.get("Id"): r.get("Target") for r in rels}
        doc = ET.fromstring(z.read("word/document.xml"))
        a = "{http://schemas.openxmlformats.org/drawingml/2006/main}"
        r = "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}embed"
        blip = doc.find(".//" + a + "blip")
        svgb = doc.find(".//{http://schemas.microsoft.com/office/drawing/2016/SVG/main}svgBlip")
        self.assertEqual(destinos[blip.get(r)], "media/diagrama_red.png")
        self.assertEqual(destinos[svgb.get(r)], "media/diagrama_red.svg")
        self.assertIn("pie", z.read("word/document.xml").decode())

    def test_sin_imagen_no_hay_media(self):
        with zipfile.ZipFile(self._escribir([("p", "x")])) as z:
            self.assertFalse([n for n in z.namelist() if "media" in n])
            self.assertNotIn("svg", z.read("[Content_Types].xml").decode())

    def _extent(self, svg):
        z = self._con_imagen(svg)
        e = ET.fromstring(z.read("word/document.xml")).find(
            ".//{http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing}extent")
        return int(e.get("cx")), int(e.get("cy"))

    def test_imagen_tamano(self):
        self.assertEqual(self._extent(self.SVG % (200, 100)), (5940000, 2970000))
        cx, cy = self._extent(self.SVG % (100, 400))
        self.assertEqual(cy, 7920000)
        self.assertAlmostEqual(cx / cy, 0.25, places=3)
        w = '<svg xmlns="http://www.w3.org/2000/svg" width="300px" height="150"></svg>'
        self.assertEqual(self._extent(w), (5940000, 2970000))

    def test_imagen_png_valido(self):
        import struct
        import zlib
        png = self._con_imagen(self.SVG % (2, 1)).read("word/media/diagrama_red.png")
        self.assertEqual(png[:8], b"\x89PNG\r\n\x1a\n")
        pos, trozos = 8, {}
        while pos < len(png):
            n, tipo = struct.unpack(">I4s", png[pos:pos + 8])
            datos = png[pos + 8:pos + 8 + n]
            crc = struct.unpack(">I", png[pos + 8 + n:pos + 12 + n])[0]
            self.assertEqual(crc, zlib.crc32(tipo + datos) & 0xFFFFFFFF)
            trozos[tipo] = datos
            pos += 12 + n
        self.assertEqual(struct.unpack(">II", trozos[b"IHDR"][:8]), (8, 8))
        self.assertEqual(len(zlib.decompress(trozos[b"IDAT"])), 8 * (1 + 24))
        self.assertIn(b"IEND", trozos)

    def test_imagen_svg_autonomo_y_errores(self):
        z = self._con_imagen('<svg viewBox="0 0 10 10"><rect/></svg>')
        svg = z.read("word/media/diagrama_red.svg").decode()
        self.assertTrue(svg.startswith('<?xml version="1.0" encoding="UTF-8"?>\n<svg xmlns='))
        ET.fromstring(svg.encode())
        with self.assertRaises(ValueError):
            self._escribir([("imagen_svg", "<svg><rect/></svg>", "x", "p")])

    def test_determinista(self):
        b = [("titulo", "T"), ("tabla", ["A"], [["x"]]), ("lista", ["a"])]
        a = self._escribir(b, "a.docx").read_bytes()
        c = self._escribir(b, "b.docx").read_bytes()
        self.assertEqual(a, c)


if __name__ == "__main__":
    unittest.main()
