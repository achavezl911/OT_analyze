"""K1 (D95): cadena de custodia encadenada por hash: registrar, verificar, exportar y --custodia."""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))
sys.path.insert(0, str(RAIZ / "tests"))

from ot_assess import custodia as cu
from ot_assess import i18n
from ot_assess.cli import main
from test_i18n import _espanol_en, _visible_html

try:
    import scapy  # noqa: F401
    HAY_SCAPY = True
except ImportError:
    HAY_SCAPY = False
HAY = bool(shutil.which("tshark") and HAY_SCAPY)


def correr(*argv):
    so, se = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(so), contextlib.redirect_stderr(se):
        try:
            rc = main(list(argv))
        except SystemExit as e:
            rc = e.code
    return rc, so.getvalue(), se.getvalue()


class CustodiaTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.a = self.tmp / "a.pcap"
        self.a.write_bytes(b"captura A" * 100)
        self.b = self.tmp / "b.pcap"
        self.b.write_bytes(b"captura B")
        self.reg = self.tmp / "reg.jsonl"

    def reg_ev(self, evento="recepcion", *rutas, **kw):
        return correr("custodia", "registrar", "--registro", str(self.reg), "--evento", evento,
                      *[x for k, v in kw.items() for x in (f"--{k}", v)], *map(str, rutas))

    def tres(self):
        self.assertEqual(self.reg_ev("recepcion", self.a, entrega="Cliente X", recibe="Analista Y",
                                     medio="USB", cifrado="BitLocker")[0], 0)
        self.assertEqual(self.reg_ev("copia", self.b, fecha="2026-11-08T10:00:00Z")[0], 0)
        self.assertEqual(self.reg_ev("analisis", self.a)[0], 0)

    def verificar(self, *rutas):
        return correr("custodia", "verificar", "--registro", str(self.reg), *map(str, rutas))

    def lineas(self):
        return self.reg.read_bytes().split(b"\n")[:-1]

    def test_dos_eventos_verifican_con_huella_estable(self):
        self.reg_ev("recepcion", self.a)
        self.reg_ev("copia", self.b)
        rc, so, _ = self.verificar()
        rc2, so2, _ = self.verificar()
        self.assertEqual((rc, rc2), (0, 0))
        huella = hashlib.sha256(self.lineas()[-1]).hexdigest()
        self.assertIn(huella, so)
        self.assertEqual(so, so2)
        self.assertEqual(oct(self.reg.stat().st_mode & 0o777), "0o600")

    def test_editar_linea_1_rompe_en_linea_2(self):
        self.tres()
        datos = self.reg.read_bytes().replace(b"Cliente X", b"Cliente Z", 1)
        self.reg.write_bytes(datos)
        rc, so, _ = self.verificar()
        self.assertEqual(rc, 1)
        self.assertIn("linea 2", so)
        self.assertIn("CADENA ROTA", so)

    def test_borrar_linea_media(self):
        self.tres()
        ls = self.lineas()
        self.reg.write_bytes(ls[0] + b"\n" + ls[2] + b"\n")
        rc, so, _ = self.verificar()
        self.assertEqual(rc, 1)
        self.assertIn("linea 2", so)

    def test_linea_truncada_o_basura(self):
        self.tres()
        self.reg.write_bytes(self.reg.read_bytes() + b"{no es json")
        self.assertEqual(self.verificar()[0], 1)

    def test_archivo_modificado_y_no_registrado(self):
        self.reg_ev("recepcion", self.a)
        self.assertEqual(self.verificar(self.a)[0], 0)
        self.a.write_bytes(b"otra cosa")
        rc, so, _ = self.verificar(self.a)
        self.assertEqual(rc, 1)
        self.assertIn("MODIFICADO: a.pcap", so)
        rc, so, _ = self.verificar(self.b)
        self.assertEqual(rc, 1)
        self.assertIn("NO REGISTRADO: b.pcap", so)

    def test_registrar_sobre_cadena_rota_no_agrega(self):
        self.tres()
        ls = self.lineas()
        self.reg.write_bytes(ls[0] + b"\n" + ls[2] + b"\n")
        antes = self.reg.read_bytes()
        rc, _, se = self.reg_ev("copia", self.b)
        self.assertEqual(rc, 1)
        self.assertIn("no se agrego nada", se)
        self.assertEqual(self.reg.read_bytes(), antes)

    def test_sin_rutas_absolutas_y_carpetas(self):
        d = self.tmp / "carpeta"
        (d / "sub").mkdir(parents=True)
        (d / "sub" / "x.pcap").write_bytes(b"x")
        (d / ".oculto").write_bytes(b"h")
        try:
            os.symlink(self.a, d / "enlace.pcap")
        except OSError:
            pass
        self.reg_ev("recepcion", d)
        self.assertEqual(self.reg_ev("destruccion", nota="Borrado seguro")[0], 0)
        ev = [json.loads(x) for x in self.lineas()]
        self.assertEqual([a["nombre"] for a in ev[0]["archivos"]], ["sub/x.pcap"])
        self.assertEqual(ev[1]["archivos"], [])
        self.assertNotIn(str(self.tmp), self.reg.read_text(encoding="utf-8"))
        correr("custodia", "exportar", "--registro", str(self.reg), "-o", str(self.tmp / "o"))
        self.assertNotIn(str(self.tmp), (self.tmp / "o" / "custodia.csv").read_text(encoding="utf-8"))

    def test_reglas_de_rutas(self):
        self.assertEqual(self.reg_ev("recepcion", self.tmp / "no_existe")[0], 2)
        self.assertEqual(self.reg_ev("destruccion")[0], 2)          # sin rutas ni nota: error de uso
        self.assertEqual(correr("custodia", "verificar", "--registro", str(self.tmp / "nada"))[0], 2)
        self.assertFalse(self.reg.exists())

    def test_exportar_y_determinismo(self):
        self.tres()
        o1, o2 = self.tmp / "o1", self.tmp / "o2"
        self.assertEqual(correr("custodia", "exportar", "--registro", str(self.reg), "-o", str(o1))[0], 0)
        correr("custodia", "exportar", "--registro", str(self.reg), "-o", str(o2))
        for n in ("custodia.csv", "custodia.html"):
            self.assertEqual((o1 / n).read_bytes(), (o2 / n).read_bytes())
        html = (o1 / "custodia.html").read_text(encoding="utf-8")
        self.assertIn("Firma de quien entrega", html)
        self.assertIn("Firma de quien recibe", html)
        self.assertIn(hashlib.sha256(self.lineas()[-1]).hexdigest(), html)
        self.assertIn("Cadena integra", html)
        self.assertTrue((o1 / "custodia.csv").read_bytes().startswith(b"\xef\xbb\xbf"))   # BOM (Excel)
        filas = (o1 / "custodia.csv").read_text(encoding="utf-8-sig").splitlines()
        self.assertTrue(filas[0].startswith("n,fecha_utc,evento,entrega,recibe,medio,cifrado,ubicacion,nombre"))
        self.assertEqual(len(filas), 4)
        self.assertIn("no declarado", filas[2])
        self.assertIn("BitLocker", filas[1])

    def test_exportar_cadena_rota_avisa(self):
        self.tres()
        ls = self.lineas()
        self.reg.write_bytes(ls[0] + b"\n" + ls[2] + b"\n")
        rc, _, _ = correr("custodia", "exportar", "--registro", str(self.reg), "-o", str(self.tmp / "o"))
        self.assertEqual(rc, 1)
        self.assertIn("CADENA ROTA", (self.tmp / "o" / "custodia.html").read_text(encoding="utf-8"))

    def test_estado_capturas_por_hash(self):
        self.reg_ev("recepcion", self.a)
        r = cu.estado_capturas(self.reg, [("renombrada.pcap", hashlib.sha256(self.a.read_bytes()).hexdigest()),
                                          ("otra.pcap", "0" * 64)])
        self.assertEqual([c["estado"] for c in r["capturas"]], ["registrada", "no registrada"])
        self.assertEqual(r["cadena"], "integra")
        self.assertEqual(r["registro"], "reg.jsonl")


@unittest.skipUnless(HAY, "requiere tshark y scapy")
def registro_fijo(tmp: Path) -> Path:
    """Registro sintetico y determinista con los siete tipos de evento (fechas declaradas)."""
    (tmp / "cap_a.pcap").write_bytes(b"A" * 300)
    (tmp / "cap_b.pcap").write_bytes(b"B" * 9)
    reg = tmp / "reg.jsonl"
    seq = [("recepcion", ["cap_a.pcap"]), ("copia", ["cap_b.pcap"]), ("transferencia", ["cap_a.pcap"]),
           ("analisis", ["cap_a.pcap", "cap_b.pcap"]), ("entrega", ["cap_b.pcap"]), ("devolucion", []),
           ("destruccion", [])]
    for i, (ev, rutas) in enumerate(seq):
        cu.registrar(reg, ev, [str(tmp / r) for r in rutas], entrega="Operator A", recibe="Analyst B",
                     medio="USB drive", cifrado="BitLocker", ubicacion="Lab 2", nota=f"note {i}",
                     fecha=f"2026-11-0{i + 1}T10:00:00Z")
    return reg


# sha256 de custodia.html / custodia.csv que produce main (antes de I2) con registro_fijo.
SHA_HTML_ES = "df85d0462f271819be04427970a1c8a02b22e3f3f42c80a73d97df43aea872fd"
SHA_CSV_ES = "df63bfecc900f9b8b48f9107117a593a99d7894154c39e7ca29c0afe9b68ded9"


class CustodiaIdiomaTest(unittest.TestCase):
    """I2 (D100): custodia exportar --idioma en."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.addCleanup(i18n.usar, "es")
        self.reg = registro_fijo(self.tmp)

    def exportar(self, nombre, *extra):
        o = self.tmp / nombre
        rc, _so, se = correr("custodia", "exportar", "--registro", str(self.reg), "-o", str(o), *extra)
        return rc, se, (o / "custodia.html").read_text(encoding="utf-8"), (o / "custodia.csv").read_bytes()

    def test_html_en_ingles_sin_espanol_y_valores_intactos(self):
        i18n.FALTANTES.clear()
        rc, _se, h, _c = self.exportar("en", "--idioma", "en")
        self.assertEqual(rc, 0)
        self.assertIn("<html lang='en'>", h)
        self.assertEqual(_espanol_en(_visible_html(h)), [])
        self.assertEqual(i18n.FALTANTES, set())
        for x in ("Chain of custody", "Chain intact.", "Events read: 7.", "receipt", "destruction", "(declared)",
                  "Delivered by", "Transfer medium", "Operator A", "Analyst B", "USB drive", "BitLocker",
                  "Lab 2", "note 6", "cap_a.pcap"):
            self.assertIn(x, h)
        self.assertNotIn("Cadena", h)
        self.assertEqual(i18n.idioma(), "es")

    def test_cadena_rota_en_ingles_trae_mensaje_traducido(self):
        self.reg.write_bytes(self.reg.read_bytes().replace(b"Operator A", b"Operator Z", 1))
        rc, se, h, _c = self.exportar("en", "--idioma", "en")
        self.assertEqual(rc, 1)
        self.assertIn("CHAIN BROKEN: line 2: does not chain to the previous one", h)
        self.assertEqual(_espanol_en(_visible_html(h)), [])
        self.assertIn("linea 2: no encadena", se)          # la consola sigue en espanol
        rc, se, h, _c = self.exportar("es")
        self.assertIn("CADENA ROTA: linea 2: no encadena", h)

    def test_csv_en_ingles_cabeceras_traducidas_y_valores_intactos(self):
        _rc, _se, _h, c = self.exportar("en", "--idioma", "en")
        filas = c.decode("utf-8-sig").splitlines()
        self.assertEqual(filas[0], "#,date_utc,event,delivered_by,received_by,transfer_medium,encryption,"
                                   "location,name,bytes,sha256,note")
        self.assertTrue(filas[1].startswith("1,2026-11-01T10:00:00Z,recepcion,Operator A,Analyst B,USB drive,"
                                            "BitLocker,Lab 2,cap_a.pcap,300,"))

    def test_espanol_igual_que_main(self):
        _rc, _se, h, c = self.exportar("es")
        self.assertEqual(hashlib.sha256(h.encode("utf-8")).hexdigest(), SHA_HTML_ES)
        self.assertEqual(hashlib.sha256(c).hexdigest(), SHA_CSV_ES)
        _rc, _se, h2, c2 = self.exportar("es2", "--idioma", "es")
        self.assertEqual((h, c), (h2, c2))


class CorridaCustodiaTest(unittest.TestCase):
    def test_corrida_con_custodia(self):
        import gen_pcaps as g
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        pc = tmp / "pcaps"
        pc.mkdir()
        g.guardar(g.punto_a(), pc / "punto_a.pcap")
        g.guardar(g.punto_b(), pc / "punto_b.pcap")
        reg = tmp / "reg.jsonl"
        self.assertEqual(correr("custodia", "registrar", "--registro", str(reg), "--evento", "recepcion",
                                str(pc / "punto_a.pcap"))[0], 0)
        rc0, _, _ = correr(str(pc), "-o", str(tmp / "sin"), "--no-diagrams")
        rc1, _, se = correr(str(pc), "-o", str(tmp / "con"), "--no-diagrams", "--custodia", str(reg))
        self.assertEqual((rc0, rc1), (0, 0))
        sin = json.loads((tmp / "sin" / "resultado.json").read_text(encoding="utf-8"))
        con = json.loads((tmp / "con" / "resultado.json").read_text(encoding="utf-8"))
        self.assertNotIn("custodia", sin["entorno"])
        self.assertEqual(set(con["entorno"]) - set(sin["entorno"]), {"custodia"})
        est = {c["archivo"]: c["estado"] for c in con["entorno"]["custodia"]["capturas"]}
        self.assertEqual(est, {"punto_a.pcap": "registrada", "punto_b.pcap": "no registrada"})
        self.assertIn("punto_b.pcap", se)
        self.assertNotIn("punto_a.pcap", se)
        md = (tmp / "con" / "reporte_ot.md").read_text(encoding="utf-8")
        self.assertIn("1 de 2 capturas registradas", md)


if __name__ == "__main__":
    unittest.main()
