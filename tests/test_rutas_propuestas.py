"""F5c (D49): rutas propuestas por firewall. Texto sintetico de FTD (con show arp) y conductos sinteticos."""
from __future__ import annotations

import contextlib
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

from test_firewalls_integracion import RUTAS, _c, _sesion
from test_firewalls_topologia import _cadena

try:
    import scapy  # noqa: F401
    HAY_SCAPY = True
except ImportError:
    HAY_SCAPY = False

from ot_assess import i18n
from ot_assess.cli import main
from ot_assess.firewalls import cisco
from ot_assess.firewalls import integracion as fi
from ot_assess.firewalls import rutas_propuestas as rp

ACL = "access-list CSM_FW_ACL_ advanced "
PERMITE = ACL + "permit ip any any rule-id 1\n"
ARP = ("FW1# show arp\n"
       "        inside 10.10.1.9 0011.2233.4455 12\n"
       "        dmz 10.10.9.1 0011.2233.4466 -\n"
       "        dmz 10.10.9.2 0011.2233.4477 5\n"
       "        outside 192.0.2.1 aaaa.bbbb.cccc 300\n")
# saltos en ARP: 10.10.9.1 y 10.10.9.2 (dmz); sin ARP: 10.10.1.253 y 10.10.1.254 (inside)
EXTRA = ("S        172.16.0.0 255.255.0.0 [1/0] via 10.10.1.254, inside\n"       # sin ARP, sin trafico
         "S        172.17.0.0 255.255.0.0 [1/0] via 10.10.1.253, inside\n"       # sin ARP, con trafico
         "S        10.20.0.0 255.255.0.0 [1/0] via 10.10.9.1, dmz\n"             # en ARP, con trafico
         "S        10.20.5.0 255.255.255.0 [1/0] via 10.10.9.1, dmz\n"           # cubierta por 10.20.0.0/16
         "S        10.1.0.0 255.255.255.0 [1/0] via 10.10.9.1, dmz\n"
         "S        10.1.1.0 255.255.255.0 [1/0] via 10.10.9.1, dmz\n"
         "S        10.3.0.0 255.255.255.0 [1/0] via 10.10.9.2, dmz\n"
         "S        10.3.2.0 255.255.255.0 [1/0] via 10.10.9.2, dmz\n"
         "S        10.4.0.0 255.255.255.0 [1/0] via 10.10.9.2, dmz\n")           # en ARP, sin trafico
CONDUCTOS = [_c("10.10.9.5", "172.17.5.5"), _c("10.10.1.5", "10.20.1.1"), _c("10.10.1.5", "10.1.0.7"),
             _c("10.10.1.5", "10.1.1.7"), _c("10.10.1.5", "10.3.0.7"), _c("10.10.1.5", "10.3.2.7"),
             _c("10.10.1.5", "8.8.8.8"), _c("10.10.1.5", "8.8.8.9"), _c("10.10.1.5", "10.10.9.50")]


def _prop(extra: str = EXTRA, conductos=None, arp: str = ARP) -> tuple:
    fw = cisco.analizar_texto(_sesion(RUTAS + extra, PERMITE, arp))
    d = fi.contrastar(fw, CONDUCTOS if conductos is None else conductos, "fw.txt", [])
    p = d["rutas_propuestas"]
    return p, {x["red"]: x for x in p["rutas"]}


class AccionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.p, cls.r = _prop()

    def test_salto_sin_arp_sin_trafico_se_elimina(self):
        x = self.r["172.16.0.0/16"]
        self.assertEqual(x["accion"], rp.A_ELIMINAR)
        self.assertEqual(x["razon"][0], rp.R_SIN_ARP_SIN)

    def test_salto_sin_arp_con_trafico_se_revisa_y_su_red_sale_en_destinos(self):
        x = self.r["172.17.0.0/16"]
        self.assertEqual((x["accion"], x["razon"][0]), (rp.A_REVISAR, rp.R_SIN_ARP_CON))
        d = [s for s in self.p["sin_ruta"] if s["red"] == "172.17.5.0/24"]
        self.assertEqual(len(d), 1)
        self.assertEqual((d[0]["ruta_actual"], d[0]["siguiente_salto"], d[0]["razon"], d[0]["conductos"]),
                         ("172.17.0.0/16", "10.10.1.253", rp.D_SALTO_MUERTO, 1))
        self.assertEqual(d[0]["ejemplos"], ["172.17.5.5"])

    def test_cubierta_por_otra_con_el_mismo_salto_se_elimina(self):
        x = self.r["10.20.5.0/24"]
        self.assertEqual(x["accion"], rp.A_ELIMINAR)
        self.assertEqual(x["razon"], [rp.R_CUBIERTA, {"red": "10.20.0.0/16"}])
        self.assertIn("cubierta por 10.20.0.0/16", rp.filas_rutas(self.p)[list(self.r).index("10.20.5.0/24")][5])
        self.assertEqual(self.r["10.20.0.0/16"]["accion"], rp.A_MANTENER)

    def test_cubierta_por_otro_salto_no_se_elimina(self):
        # entre la /24 y la /16 hay una /20 por otro salto: quitar la /24 cambiaria el salto de su trafico
        extra = EXTRA + "S        10.20.0.0 255.255.240.0 [1/0] via 10.10.9.2, dmz\n"
        _p, r = _prop(extra)
        self.assertNotEqual(r["10.20.5.0/24"]["accion"], rp.A_ELIMINAR)

    def test_contiguas_se_resumen_y_no_contiguas_no(self):
        for red in ("10.1.0.0/24", "10.1.1.0/24"):
            self.assertEqual(self.r[red]["accion"], rp.A_RESUMIR)
            self.assertEqual(self.r[red]["resumen"], "10.1.0.0/23")
        self.assertEqual([x["red_resumida"] for x in self.p["resumidas"]], ["10.1.0.0/23"])
        self.assertEqual(self.p["resumidas"][0]["rutas"], 2)
        fila = rp.filas_rutas(self.p)[list(self.r).index("10.1.1.0/24")]
        self.assertEqual(fila[4], "resumir en 10.1.0.0/23")
        for red in ("10.3.0.0/24", "10.3.2.0/24"):      # hueco en 10.3.1.0/24: la /23 cubriria direcciones de mas
            self.assertEqual(self.r[red]["accion"], rp.A_MANTENER)

    def test_resumen_solo_con_el_mismo_salto(self):
        extra = ("S        10.1.0.0 255.255.255.0 [1/0] via 10.10.9.1, dmz\n"
                 "S        10.1.1.0 255.255.255.0 [1/0] via 10.10.9.2, dmz\n")
        _p, r = _prop(extra, [_c("10.10.1.5", "10.1.0.7"), _c("10.10.1.5", "10.1.1.7")])
        self.assertNotIn(rp.A_RESUMIR, {x["accion"] for x in r.values()})

    def test_sin_trafico_con_salto_en_arp_se_revisa(self):
        x = self.r["10.4.0.0/24"]
        self.assertEqual((x["accion"], x["razon"][0]), (rp.A_REVISAR, rp.R_SIN_TRAFICO))

    def test_mismo_prefijo_en_dos_saltos_se_revisa(self):
        extra = ("S        10.50.0.0 255.255.255.128 [1/0] via 10.10.9.1, dmz\n"
                 "S        10.50.0.7 255.255.255.255 [1/0] via 10.10.9.2, dmz\n")
        _p, r = _prop(extra, [_c("10.10.1.5", "10.50.0.9"), _c("10.10.1.5", "10.50.0.7")])
        self.assertEqual(r["10.50.0.0/25"]["accion"], rp.A_REVISAR)
        self.assertEqual(r["10.50.0.0/25"]["razon"][0], rp.R_DOS_SALTOS)

    def test_internet_por_la_ruta_por_defecto_no_es_destino_sin_ruta(self):
        # Internet sale por la ruta por defecto: es lo esperado (el caso interno lo cubre InternetPorDefectoTest)
        self.assertNotIn("8.8.8.0/24", {s["red"] for s in self.p["sin_ruta"]})
        # destinos con ruta propia (en ARP) o que no cruzan no aparecen
        self.assertEqual({s["red"] for s in self.p["sin_ruta"]}, {"172.17.5.0/24"})

    def test_conectadas_y_locales_intactas(self):
        for red in ("10.10.1.0/24", "10.10.1.2/32", "10.10.9.0/24", "192.0.2.0/24"):
            x = self.r[red]
            self.assertEqual((x["accion"], x["razon"][0]), (rp.A_MANTENER, rp.R_CONECTADA), red)
        self.assertEqual(self.r["0.0.0.0/0"]["accion"], rp.A_MANTENER)

    def test_totales_y_columnas(self):
        cu = self.p["resumen"]["por_accion"]
        self.assertEqual(sum(cu.values()), len(self.p["rutas"]))
        self.assertEqual(cu[rp.A_RESUMIR], 2)
        self.assertEqual(cu[rp.A_ELIMINAR], 2)
        for fila in rp.filas_rutas(self.p):
            self.assertEqual(len(fila), len(rp.COL_RUTAS))
        for fila in rp.filas_destinos(self.p):
            self.assertEqual(len(fila), len(rp.COL_DESTINOS))

    def test_sin_show_arp_no_se_elimina_por_salto(self):
        _p, r = _prop(arp="")
        self.assertNotIn(rp.R_SIN_ARP_SIN, {x["razon"][0] for x in r.values()})
        self.assertEqual(r["172.17.0.0/16"]["accion"], rp.A_MANTENER)


class VariosFirewallsTest(unittest.TestCase):
    def test_archivos_con_prefijo(self):
        fws = _cadena()
        res = fi.integrar_modelos(fws, [f.hostname + ".txt" for f in fws], {}, [], None)[1]
        prop = res["rutas_propuestas"]
        self.assertTrue(prop["multiple"])
        archivos = [a for a, _h, _c, _f in rp.tablas(prop)]
        self.assertIn("FW-IT_rutas_propuestas.csv", archivos)
        self.assertIn("FW-SCADA_rutas_destinos_sin_ruta.csv", archivos)
        self.assertIn("FW-DMZ Rutas propuestas", [str(h) for _a, h, _c, _f in rp.tablas(prop)])


class IdiomaTest(unittest.TestCase):
    def test_salidas_en_ingles_sin_faltantes(self):
        p, _r = _prop()
        prop = {"firewalls": [dict(p, id="FW1", prefijo="FW1")], "multiple": False}
        i18n.usar("en")
        self.addCleanup(i18n.usar, "es")
        i18n.FALTANTES.clear()
        salida = []
        for _a, hoja, cab, filas in rp.tablas(prop):
            salida += [hoja, *cab] + [str(c) for f in filas for c in f]
            for c in (hoja, *cab):
                i18n.t(c)
        for _tit, cab, filas in rp.tablas_reporte(prop):
            salida += [_tit, *cab] + [str(c) for f in filas for c in f]
        salida += [rp.resumen_texto(prop), i18n.t(rp.NOTA), i18n.t(rp.TITULO)]
        self.assertFalse(i18n.FALTANTES, sorted(i18n.FALTANTES))
        texto = "\n".join(salida)
        for palabra in ("mantener", "eliminar", "resumir", "revisar", "estatica", "salto sin", "Razon"):
            self.assertNotIn(palabra, texto)
        self.assertIn("summarize into 10.1.0.0/23", texto)


@unittest.skipUnless(shutil.which("tshark") and HAY_SCAPY, "requiere tshark y scapy")
class SalidasTest(unittest.TestCase):
    def test_seccion_y_hojas_en_html_md_word_y_xlsx(self):
        import gen_pcaps
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        sys.argv = ["gen", str(tmp / "pcaps")]
        gen_pcaps.main()
        fw = tmp / "fw.txt"
        fw.write_text(_sesion("S*       0.0.0.0 0.0.0.0 [1/0] via 192.0.2.1, outside\n"
                              "C        192.0.2.0 255.255.255.0 is directly connected, outside\n"
                              "C        10.0.0.0 255.0.0.0 is directly connected, inside\n"
                              "C        192.168.0.0 255.255.0.0 is directly connected, dmz\n"
                              "S        172.30.0.0 255.255.0.0 [1/0] via 192.168.0.254, dmz\n",
                              PERMITE, ARP), encoding="utf-8")
        self.addCleanup(i18n.usar, "es")
        for idioma in ("es", "en"):
            out = tmp / ("o_" + idioma)
            with contextlib.redirect_stdout(io.StringIO()):
                main([str(tmp / "pcaps"), "-o", str(out), "--firewall", str(fw), "--idioma", idioma])
            i18n.FALTANTES.clear()
            titulo, hoja = ("Proposed routes", "Proposed routes") if idioma == "en" else \
                ("Rutas propuestas", "Rutas propuestas")
            self.assertTrue((out / "rutas_propuestas.csv").exists())
            self.assertTrue((out / "rutas_destinos_sin_ruta.csv").exists())
            for ext in (".html", ".md"):
                self.assertTrue(any(titulo in p.read_text(encoding="utf-8") for p in out.glob("*" + ext)), ext)
            self.assertTrue(any(titulo in zipfile.ZipFile(p).read("word/document.xml").decode("utf-8")
                                for p in out.glob("*.docx")))
            with zipfile.ZipFile(out / "reporte_ot.xlsx") as z:
                libro = z.read("xl/workbook.xml").decode("utf-8")
            self.assertIn(hoja, libro)
            self.assertIn("Rutas destinos sin ruta" if idioma == "es" else "Routes destinations no route", libro)
            if idioma == "en":
                md = next(out.glob("*.md")).read_text(encoding="utf-8")
                self.assertNotIn("resumir en", md)
                self.assertFalse(i18n.FALTANTES, sorted(i18n.FALTANTES))


if __name__ == "__main__":
    unittest.main()


class InternetPorDefectoTest(unittest.TestCase):
    def test_destino_de_internet_por_la_ruta_por_defecto_no_es_destino_sin_ruta(self):
        import ipaddress

        from ot_assess.firewalls import rutas_propuestas as rp
        from ot_assess.firewalls.modelo import Firewall, Ruta
        fw = Firewall(rutas=[Ruta(red=ipaddress.ip_network("0.0.0.0/0"), interfaz="out", salto="10.0.0.1",
                                  tipo="defecto", codigo="S*")])
        destinos = [int(ipaddress.IPv4Address(x)) for x in ("8.8.8.8", "10.20.30.40", "224.0.0.251", "255.255.255.255")]
        from ot_assess.firewalls import higiene as hg
        p = rp.construir(fw, hg.estado_rutas(fw, destinos), destinos)
        redes = {x["red"] for x in p["sin_ruta"]}
        self.assertEqual(redes, {"10.20.30.0/24"})      # ni Internet ni multicast ni broadcast
