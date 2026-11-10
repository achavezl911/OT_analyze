"""F5a: inventario de lo que cruza el firewall. Texto sintetico de FTD y conductos sinteticos."""
from __future__ import annotations

import contextlib
import csv
import io
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
from test_firewalls_integracion import RUTAS, _sesion

from ot_assess import i18n
from ot_assess.cli import main
from ot_assess.firewalls import cisco, cruces
from ot_assess.firewalls import integracion as fi

ACL = "access-list CSM_FW_ACL_ advanced "
REGLAS = (ACL + "permit tcp ifc inside any ifc outside any eq 3389 rule-id 11\n"
          + ACL + "permit udp ifc inside any ifc outside any eq 53 rule-id 12\n"
          + ACL + "deny tcp ifc inside any ifc outside any eq 445 rule-id 13\n"
          + ACL + "permit tcp ifc inside any ifc dmz any eq 502 rule-id 14\n"
          + ACL + "permit tcp ifc dmz any ifc inside any eq 8080 rule-id 15\n")


def _k(src, dst, port, l4="tcp", servicio="-", by=0, **kw):
    return {"src": src, "dst": dst, "l4": l4, "port": str(port), "servicio": servicio, "bytes": by, **kw}


def _cruces(conductos, assets=None):
    fw = cisco.analizar_texto(_sesion(RUTAS, REGLAS))
    return fi.contrastar(fw, conductos, "fw.txt", [], assets)


def _fila(cr, ip_d, puerto):
    return next(f for f in cr["detalle"] if f["ip_destino"] == ip_d and f["puerto"] == puerto)


class CrucesTest(unittest.TestCase):
    def test_no_cruza_no_entra(self):
        r = _cruces([_k("10.10.1.5", "10.10.1.6", 502), _k("10.10.1.5", "10.10.9.5", 502)])
        cr = r["cruces"]
        self.assertEqual(cr["totales"]["no_cruza"], 1)
        self.assertEqual(cr["totales"]["conductos_cruzan"], 1)
        self.assertEqual([f["ip_destino"] for f in cr["detalle"]], ["10.10.9.5"])

    def test_detalle_y_agregado(self):
        assets = {"a1": {"ips": {"10.10.1.5"}, "nombre": "PLC-1", "tipo": "controlador"}}
        c = [_k("10.10.1.5", "10.10.9.5", 502, by=100), _k("10.10.1.6", "10.10.9.5", 502, by=50),
             _k("10.10.1.7", "10.10.9.6", 502), _k("10.10.1.5", "8.8.8.8", 445)]
        cr = _cruces(c, assets)["cruces"]
        t = cr["totales"]
        self.assertEqual((t["pares_interfaces"], t["filas_agregadas"], t["conductos_cruzan"], t["destinos_internet"]),
                         (2, 2, 4, 1))
        d = _fila(cr, "10.10.9.5", 502)
        self.assertEqual((d["nombre_origen"], d["regla_actual"], d["resultado"], d["ambito_destino"]),
                         ("PLC-1" if d["ip_origen"] == "10.10.1.5" else "", "14", "permitido", "interna"))
        self.assertEqual(sum(f["bytes"] or 0 for f in cr["detalle"] if f["puerto"] == 502), 150)
        self.assertEqual(_fila(cr, "10.10.9.6", 502)["bytes"], "")
        a = next(x for x in cr["agregado"] if x["puerto"] == 502)
        self.assertEqual((a["interfaz_origen"], a["interfaz_destino"], a["origenes"], a["destinos"], a["conductos"],
                          a["bytes"], a["permitidos"], a["denegados"], a["reglas_actuales"], a["destino_internet"]),
                         ("inside", "dmz", 3, 2, 3, 150, 3, 0, "14", 0))
        self.assertEqual(a["ejemplos_origen"], "10.10.1.5 (PLC-1); 10.10.1.6; 10.10.1.7")
        n = next(x for x in cr["agregado"] if x["puerto"] == 445)
        self.assertEqual((n["denegados"], n["destino_internet"], n["reglas_actuales"]), (1, 1, "13"))
        self.assertEqual([x["interfaz_destino"] for x in cr["agregado"]], ["dmz", "outside"])

    def test_etiquetas(self):
        c = [_k("10.10.1.5", "8.8.8.8", 3389), _k("10.10.1.5", "8.8.4.4", 445),
             _k("10.10.1.5", "8.8.8.8", 53, "udp"), _k("10.10.1.5", "10.10.9.5", 502),
             _k("10.10.9.5", "10.10.1.5", 8080), _k("10.10.9.5", "10.10.1.5", 30000, servicio="MMS")]
        cr = _cruces(c)["cruces"]
        e = lambda ip, p: _fila(cr, ip, p)["etiquetas"]
        self.assertIn(cruces.ACCESO_REMOTO, e("8.8.8.8", 3389))
        self.assertIn(cruces.ARCHIVOS, e("8.8.4.4", 445))
        self.assertIn(cruces.DENEGADO, e("8.8.4.4", 445))
        self.assertTrue({cruces.DNS_EXT, cruces.HACIA_NET} <= set(e("8.8.8.8", 53)))
        self.assertTrue({cruces.OT, cruces.CLARO} <= set(e("10.10.9.5", 502)))
        self.assertIn(cruces.ALTO, e("10.10.1.5", 8080))
        self.assertNotIn(cruces.ALTO, e("10.10.1.5", 30000))    # con protocolo de aplicacion conocido
        self.assertNotIn(cruces.ALTO, e("10.10.9.5", 502))

    def test_desde_internet_y_administracion(self):
        self.assertIn(cruces.DESDE_NET, cruces.etiquetas_de(443, "tcp", "", "10.0.0.1", "8.8.8.8", "red", False))
        self.assertIn(cruces.ADMIN, cruces.etiquetas_de(443, "tcp", "", "10.0.0.1", "10.0.0.2", "firewall", False))
        self.assertNotIn(cruces.ADMIN, cruces.etiquetas_de(443, "tcp", "", "10.0.0.1", "10.0.0.2", "servidor", False))

    def test_muchos_origenes_y_destinos(self):
        c = [_k(f"10.10.1.{i}", "10.10.9.5", 502) for i in range(1, 61)]
        c += [_k("10.10.1.5", f"10.10.9.{i}", 502, "tcp") for i in range(100, 160)]
        a = _cruces(c)["cruces"]["agregado"][0]
        self.assertEqual((a["origenes"], a["destinos"]), (60, 61))
        self.assertTrue({cruces.MUCHOS_O, cruces.MUCHOS_D} <= set(a["etiquetas"]))
        self.assertEqual(len(a["ejemplos_origen"].split("; ")), 5)
        pocos = _cruces([_k(f"10.10.1.{i}", "10.10.9.5", 502) for i in range(1, 11)])["cruces"]["agregado"][0]
        self.assertNotIn(cruces.MUCHOS_O, pocos["etiquetas"])

    def test_ingles_sin_palabras_espanolas_y_sin_faltantes(self):
        cr = _cruces([_k("10.10.1.5", "8.8.8.8", 3389), _k("10.10.1.5", "8.8.4.4", 445),
                      _k("10.10.1.5", "10.10.9.5", 502)])["cruces"]
        i18n.usar("en")
        self.addCleanup(i18n.usar, "es")
        i18n.FALTANTES.clear()
        filas = cruces.filas_agregado(cr) + cruces.filas_detalle(cr)
        for c in cruces.COL_AGREGADO + cruces.COL_DETALLE:
            i18n.t(c)
        i18n.t(cruces.HOJA_AGREGADO)
        i18n.t(cruces.HOJA_DETALLE)
        i18n.t(cruces.TITULO)
        i18n.t(cruces.NOTA)
        cruces.resumen_texto(cr)
        cruces.cabecera_pares()
        texto = " ".join(str(x) for f in filas for x in f)
        self.assertIn("remote access", texto)
        self.assertIn("file sharing", texto)
        self.assertNotIn("acceso remoto", texto)
        self.assertNotIn("compartir", texto)
        self.assertFalse(i18n.FALTANTES, i18n.FALTANTES)


RUTAS_EXP = ("C        10.20.1.0 255.255.255.0 is directly connected, inside\n"
             "C        10.20.2.0 255.255.255.0 is directly connected, dmz\n"
             "C        192.0.2.0 255.255.255.0 is directly connected, outside\n")


class SalidasTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        est = gen_exports.escribir(cls.tmp / "ex")["b"]
        fw = cls.tmp / "fw.txt"
        fw.write_text(_sesion(RUTAS_EXP, ACL + "permit ip any any rule-id 1\n"), encoding="utf-8")
        cls.out = cls.tmp / "out"
        with contextlib.redirect_stdout(io.StringIO()):
            rc = main(["diagrama", "--activos", str(est["activos"]), "--enlaces", str(est["enlaces"]),
                       "-o", str(cls.out), "--firewall", str(fw)])
        assert rc == 0

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_csv_por_diagrama(self):
        for nombre, cab in (("firewall_cruces.csv", cruces.COL_AGREGADO),
                            ("firewall_cruces_detalle.csv", cruces.COL_DETALLE)):
            with open(self.out / nombre, newline="", encoding="utf-8-sig") as fh:
                filas = list(csv.DictReader(fh))
            self.assertEqual(list(filas[0]), cab)
            self.assertTrue(any(f["interfaz_origen"] != f["interfaz_destino"] for f in filas))


try:
    import scapy  # noqa: F401
    HAY_SCAPY = True
except ImportError:
    HAY_SCAPY = False


@unittest.skipUnless(shutil.which("tshark") and HAY_SCAPY, "requiere tshark y scapy")
class CapturaCompletaTest(unittest.TestCase):
    def test_xlsx_y_secciones(self):
        import gen_pcaps
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        sys.argv = ["gen", str(tmp / "pcaps")]
        gen_pcaps.main()
        fw = tmp / "fw.txt"
        # 10.0.0.0/8 en una interfaz y el resto por la ruta por defecto: lo que sale de la red cruza
        fw.write_text(_sesion("S*       0.0.0.0 0.0.0.0 [1/0] via 192.0.2.1, outside\n"
                              "C        192.0.2.0 255.255.255.0 is directly connected, outside\n"
                              "C        10.0.0.0 255.0.0.0 is directly connected, inside\n"
                              "C        192.168.0.0 255.255.0.0 is directly connected, dmz\n",
                              ACL + "permit ip any any rule-id 1\n"), encoding="utf-8")
        for idioma in ("es", "en"):
            out = tmp / ("o_" + idioma)
            with contextlib.redirect_stdout(io.StringIO()):
                main([str(tmp / "pcaps"), "-o", str(out), "--firewall", str(fw), "--idioma", idioma])
            i18n.usar("es")
            if not (out / ("firewall_cruces.csv")).exists():
                self.skipTest("las capturas sinteticas no cruzan este firewall")
            with zipfile.ZipFile(out / "reporte_ot.xlsx") as z:
                libro = z.read("xl/workbook.xml").decode("utf-8")
            hojas = ("Firewall crossings", "Firewall crossings (detail)") if idioma == "en" else \
                ("Cruces del firewall", "Cruces del firewall (detalle)")
            for h in hojas:
                self.assertIn(h, libro)
            marca = "Traffic crossing the firewall" if idioma == "en" else "Trafico que cruza el firewall"
            for ext in (".html", ".md"):
                self.assertTrue(any(marca in p.read_text(encoding="utf-8") for p in out.glob("*" + ext)), ext)
            self.assertTrue(any(marca in zipfile.ZipFile(p).read("word/document.xml").decode("utf-8")
                                for p in out.glob("*.docx")))


if __name__ == "__main__":
    unittest.main()
