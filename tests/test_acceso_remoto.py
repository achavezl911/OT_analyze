"""T8 (D68): herramientas de acceso remoto de terceros (AnyDesk, TeamViewer, ScreenConnect, RustDesk...).

Unitarias (sin tshark): catalogo, coincidencia de dominio, severidad y exportaciones.
Extremo a extremo (tshark y scapy): capturas sinteticas de tests/gen_pcaps.py (punto_t8, punto_t8_trampa) y una
exportacion sintetica de xDome con side_b_domains por el camino `diagrama`.
"""
from __future__ import annotations

import csv
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))
sys.path.insert(0, str(RAIZ / "tests"))

try:
    import scapy  # noqa: F401
    HAY_SCAPY = True
except ImportError:
    HAY_SCAPY = False

from ot_assess import acceso_remoto as ar
from ot_assess import rutas_ataque as ra
from ot_assess.catalog import OT_PORTS
from ot_assess.firewalls import cruces as cr
from ot_assess.model import Capture
from ot_assess.rules import acceso_remoto as rar

T_HALLAZGO = "Herramienta de acceso remoto de terceros en la red"
CLI = "10.80.1.10"


def host(ip, purdue="", nombre=""):
    return {"mac": "aa:" + ip, "ips": {ip}, "purdue": purdue, "hostnames": {nombre} if nombre else set()}


def flujo(src, dst, dport, l4="tcp", nbytes=100):
    return {"src": src, "dst": dst, "dport": str(dport), "l4": l4, "pkts": 2, "bytes": nbytes,
            "first": 1_700_000_000.0, "last": 1_700_000_010.0, "proto": "", "sports": set()}


def captura(purdue="", dns=(), sni=(), flujos=()):
    cap = Capture(Path("x.pcap"))
    cap.hosts = {"aa:1": host(CLI, purdue)}
    cap.dns_eventos = [{"t": 1_700_000_005.0, "src": CLI, "dst": "10.80.1.53", "id": "1", "resp": False,
                        "nombre": n, "tipo": "A", "rcode": "", "respuestas": []} for n in dns]
    cap.nombres_servidor = [{"fuente": "TLS SNI", "ip": "203.0.113.60", "nombre": n, "src": CLI,
                             "t": 1_700_000_006.0} for n in sni]
    cap.flows = {(f["src"], f["dst"], f["dport"], f["l4"]): f for f in flujos}
    return cap


def correr_regla(cap):
    rar.acceso_remoto_terceros(cap)
    return [f for f in cap.findings if f["titulo"] == T_HALLAZGO]


class CatalogoTest(unittest.TestCase):
    def test_dominio_por_sufijo_con_limite_de_etiqueta(self):
        for nombre in ("teamviewer.com", "master3.teamviewer.com", "MASTER3.TeamViewer.COM", "x.y.teamviewer.com.",
                       "net.anydesk.com", "relay-1.anydesk.com"):
            self.assertIsNotNone(ar.herramienta_de_nombre(nombre), nombre)
        for nombre in ("teamviewer.com.example.net", "noteamviewer.com", "anydesk.com.evil.net", "evilanydesk.com",
                       "teamviewer", "", "com"):
            self.assertIsNone(ar.herramienta_de_nombre(nombre), nombre)

    def test_puertos_del_catalogo(self):
        self.assertEqual(ar.herramienta_de_puerto(5938, "tcp")["herramienta"], "TeamViewer")
        self.assertEqual(ar.herramienta_de_puerto("5938", "udp")["herramienta"], "TeamViewer")
        self.assertEqual(ar.herramienta_de_puerto(6568, "tcp")["herramienta"], "AnyDesk")
        self.assertEqual(ar.herramienta_de_puerto(21116, "udp")["herramienta"], "RustDesk")
        self.assertEqual(ar.herramienta_de_puerto(8041, "tcp")["estado"], "sin verificar")

    def test_puertos_que_no_son_indicador(self):
        for p, l4 in ((443, "tcp"), (80, "tcp"), (7070, "tcp"), (50001, "udp"), (21116, "icmp"), ("", "tcp")):
            self.assertIsNone(ar.herramienta_de_puerto(p, l4), (p, l4))

    def test_estados_y_fuentes(self):
        for e in ar.CATALOGO:
            self.assertIn(e["estado"], ("verificado", "sin verificar"), e["herramienta"])
            self.assertTrue(e["fuente"] and e["dominios"], e["herramienta"])
            for x in e["puertos"]:
                self.assertNotIn(x["puerto"], (80, 443), e["herramienta"])
        sin_verificar = {e["herramienta"] for e in ar.CATALOGO if e["estado"] == "sin verificar"}
        self.assertIn("ScreenConnect (ConnectWise Control)", sin_verificar)

    def test_catalog_py_solo_trae_puertos_verificados(self):
        for e in ar.CATALOGO:
            for x in e["puertos"]:
                esta = (x["puerto"], x["l4"]) in OT_PORTS
                self.assertEqual(esta, e["estado"] == "verificado", (e["herramienta"], x))

    def test_cuentan_como_acceso_remoto_donde_cuentan_rdp_y_vnc(self):
        for p in (5938, 6568, 21116, 3389, 5900):
            self.assertIn(cr.ACCESO_REMOTO, cr.etiquetas_de(p, "tcp", "", "10.0.0.5", "10.0.0.6", "", False), p)
            self.assertTrue(ra._remoto(f"tcp/{p}"), p)
        self.assertNotIn(cr.ACCESO_REMOTO, cr.etiquetas_de(443, "tcp", "", "10.0.0.5", "10.0.0.6", "", False))
        self.assertFalse(ra._remoto("tcp/443"))
        self.assertLessEqual(ar.puertos_verificados(), cr._REMOTO)


class ReglaTest(unittest.TestCase):
    def test_cuatro_indicadores_y_un_solo_hallazgo(self):
        cap = captura(dns=["master3.teamviewer.com"], sni=["net.anydesk.com"], flujos=[
            flujo(CLI, "203.0.113.70", 5938), flujo(CLI, "203.0.113.80", 21116, "udp")])
        inds = ar.de_captura(cap)
        self.assertEqual(sorted((x["herramienta"], x["metodo"], x["indicador"]) for x in inds), [
            ("AnyDesk", "SNI", "net.anydesk.com"), ("RustDesk", "puerto", "udp/21116"),
            ("TeamViewer", "DNS", "master3.teamviewer.com"), ("TeamViewer", "puerto", "tcp/5938")])
        h = correr_regla(cap)
        self.assertEqual(len(h), 1)
        self.assertEqual(len(cap.findings), 1)
        for texto in ("TeamViewer", "AnyDesk", "RustDesk", "tcp/5938", "net.anydesk.com", "Internet"):
            self.assertIn(texto, h[0]["evidencia"])
        self.assertIn("mitre-ics", h[0]["referencias"])
        self.assertIn("T0822", h[0]["referencias"]["mitre-ics"])
        self.assertIn("SR 1.13", h[0]["referencias"]["iec62443"])

    def test_un_indicador_por_cliente_herramienta_metodo_e_indicador(self):
        cap = captura(dns=["a.teamviewer.com", "a.teamviewer.com", "b.teamviewer.com"])
        self.assertEqual([x["indicador"] for x in ar.de_captura(cap)], ["a.teamviewer.com", "b.teamviewer.com"])

    def test_dominios_trampa_y_443_solo_no_disparan(self):
        cap = captura(dns=["teamviewer.com.example.net", "noteamviewer.com"], sni=["anydesk.com.example.net"],
                      flujos=[flujo(CLI, "198.51.100.13", 443), flujo(CLI, "198.51.100.14", 80)])
        self.assertEqual(ar.de_captura(cap), [])
        self.assertEqual(correr_regla(cap), [])

    def test_severidad_alta_con_cliente_ot_y_media_con_cliente_it(self):
        flujos = [flujo(CLI, "203.0.113.70", 5938)]
        self.assertEqual(correr_regla(captura("Nivel 2", flujos=flujos))[0]["severidad"], "Alta")
        self.assertEqual(correr_regla(captura("Nivel 1-2", flujos=flujos))[0]["severidad"], "Alta")
        self.assertEqual(correr_regla(captura("Nivel 4", flujos=flujos))[0]["severidad"], "Media")
        self.assertEqual(correr_regla(captura("", flujos=flujos))[0]["severidad"], "Media")
        self.assertEqual(correr_regla(captura("Nivel 2-3", flujos=flujos))[0]["severidad"], "Media")

    def test_severidad_alta_si_el_conducto_llega_a_una_zona_ot(self):
        cap = captura("Nivel 4", flujos=[flujo(CLI, "10.80.1.20", 21116)])
        cap.hosts["aa:2"] = host("10.80.1.20", "Nivel 1")
        h = correr_regla(cap)[0]
        self.assertEqual(h["severidad"], "Alta")
        self.assertIn("interno", h["evidencia"])

    def test_indicador_sin_verificar_se_marca(self):
        cap = captura(flujos=[flujo(CLI, "203.0.113.90", 8041)])
        (x,) = ar.de_captura(cap)
        self.assertEqual(x["estado"], "sin verificar")
        self.assertIn("indicador sin verificar: confirmar con el dueno del equipo", correr_regla(cap)[0]["evidencia"])
        verificado = correr_regla(captura(flujos=[flujo(CLI, "203.0.113.70", 5938)]))[0]
        self.assertNotIn("sin verificar", verificado["evidencia"])

    def test_hasta_diez_activos_en_la_evidencia(self):
        cap = captura()
        cap.flows = {}
        for i in range(1, 13):
            f = flujo(f"10.80.2.{i}", "203.0.113.70", 5938)
            cap.flows[(f["src"], f["dst"], f["dport"], f["l4"])] = f
        ev = correr_regla(cap)[0]["evidencia"]
        self.assertIn("12 activos", ev)
        self.assertIn("10.80.2.10 ", ev)
        self.assertNotIn("10.80.2.11 ", ev)
        self.assertIn("2 mas", ev)

    def test_dns_resuelto_da_destino_y_conductos(self):
        cap = captura(dns=["x.teamviewer.com"], flujos=[flujo(CLI, "203.0.113.50", 443, nbytes=900)])
        cap.dns_eventos.append({"t": 1_700_000_005.5, "src": "10.80.1.53", "dst": CLI, "id": "1", "resp": True,
                                "nombre": "x.teamviewer.com", "tipo": "A", "rcode": "NOERROR",
                                "respuestas": [("x.teamviewer.com", "A", "203.0.113.50", 60)]})
        (x,) = ar.de_captura(cap)
        self.assertEqual((x["destino"], x["destino_ip"], x["conductos"]), ("Internet", "203.0.113.50", 1))


class ExportacionTest(unittest.TestCase):
    ASSETS = {"a1": {"ips": {"10.10.1.10"}, "purdue": "Nivel 2", "nombre": "HMI-1"},
              "ext": {"ips": {"203.0.113.5"}, "purdue": "Externo", "nombre": "203.0.113.5"}}

    def test_dominios_y_puertos_de_una_exportacion(self):
        dominios = [{"cliente": "a1", "servidor": "ext", "dominio": "x.teamviewer.com", "bytes": 7,
                     "fecha": "2026-11-02"}]
        conductos = [{"src": "a1", "dst": "ext", "l4": "tcp", "port": "6568", "bytes": 50, "primera": "2026-11-02",
                      "ultima": "2026-11-03"},
                     {"src": "a1", "dst": "ext", "l4": "tcp", "port": "443", "bytes": 5, "primera": "", "ultima": ""}]
        inds = ar.de_exportacion("exportacion X", dominios, conductos, self.ASSETS)
        self.assertEqual([(x["herramienta"], x["metodo"], x["indicador"], x["destino"], x["ot"]) for x in inds],
                         [("AnyDesk", "puerto", "tcp/6568", "Internet", True),
                          ("TeamViewer", "dominio exportado", "x.teamviewer.com", "Internet", True)])
        self.assertEqual(inds[0]["activo"], "HMI-1")
        self.assertEqual(inds[0]["fuente"], "exportacion X")


class DestinoDeMuchosPuertosTest(unittest.TestCase):
    """T8b: un indicador solo por puerto hacia un destino que 'sirve' >100 puertos no es evidencia."""

    def _datos(self, n_puertos, con_dns=False):
        assets = {"srv": {"ips": {"10.20.0.5"}, "purdue": "Nivel 3", "nombre": "SRV"},
                  "pub": {"ips": {"203.0.113.9"}, "purdue": "Externo", "nombre": "203.0.113.9"}}
        conductos = []
        for i in range(1, 4):
            assets[f"c{i}"] = {"ips": {f"10.10.1.{i}"}, "purdue": "Nivel 2", "nombre": f"HMI-{i}"}
            conductos.append({"src": f"c{i}", "dst": "srv", "l4": "tcp", "port": "5938", "bytes": 1,
                              "primera": "", "ultima": ""})
        conductos += [{"src": "c1", "dst": "srv", "l4": "tcp", "port": str(20000 + i), "bytes": 1,
                       "primera": "", "ultima": ""} for i in range(n_puertos - 1)]
        conductos.append({"src": "c1", "dst": "pub", "l4": "tcp", "port": "21116", "bytes": 1,
                          "primera": "", "ultima": ""})
        dominios = [{"cliente": "c2", "servidor": "srv", "dominio": "x.teamviewer.com", "bytes": 1,
                     "fecha": ""}] if con_dns else []
        return ar.de_exportacion("exportacion X", dominios, conductos, assets)

    def test_destino_de_150_puertos_se_descarta(self):
        inds = self._datos(150)
        por = {(x["ip"], x["indicador"]): x for x in inds}
        d = [x for x in inds if x["destino_ip"] == "10.20.0.5"]
        self.assertTrue(d)
        for x in d:
            self.assertEqual(x["estado"], "descartado")
            self.assertEqual(x["nota"], "destino con 150 puertos distintos: no concluyente "
                                        "(sentido invertido, NAT o escaneo)")
        pub = por[("10.10.1.1", "tcp/21116")]
        self.assertEqual((pub["estado"], pub["nota"]), ("verificado", ""))
        cap = Capture(Path("exportacion X"))
        rar.hallazgo(cap, inds)
        self.assertEqual(len(cap.findings), 1)
        ev = cap.findings[0]["evidencia"]
        self.assertIn("203.0.113.9", ev)
        self.assertNotIn("10.20.0.5", ev)
        self.assertEqual(cap.findings[0]["severidad"], "Alta")      # HMI nivel 2 -> pub

    def test_solo_descartados_no_hay_hallazgo(self):
        inds = [x for x in self._datos(150) if x["destino_ip"] == "10.20.0.5"]
        cap = Capture(Path("exportacion X"))
        rar.hallazgo(cap, inds)
        self.assertEqual(cap.findings, [])

    def test_con_100_puertos_o_menos_entra(self):
        inds = self._datos(ar.PUERTOS_SERVIDOR_MAX)
        self.assertTrue(all(x["estado"] == "verificado" and x["nota"] == "" for x in inds))

    def test_indicador_por_nombre_no_se_descarta(self):
        inds = self._datos(150, con_dns=True)
        nombre = [x for x in inds if x["metodo"] == "dominio exportado"]
        self.assertEqual([(x["estado"], x["nota"]) for x in nombre], [("verificado", "")])

    def test_captura_descarta_con_el_conteo_de_todas_las_capturas(self):
        cap = captura(flujos=[flujo(CLI, "10.20.0.5", 5938)])
        otra = captura(flujos=[flujo("10.80.1.11", "10.20.0.5", 30000 + i) for i in range(150)])
        self.assertEqual(ar.de_captura(cap)[0]["estado"], "verificado")      # sola, no alcanza
        muchos = ar.destinos_de_muchos_puertos(ar.puertos_por_destino(
            p for c in (cap, otra) for p in ar._pares_captura(c)))
        self.assertEqual(ar.de_captura(cap, muchos)[0]["estado"], "descartado")


@unittest.skipUnless(shutil.which("tshark") and HAY_SCAPY, "requiere tshark y scapy")
class AccesoRemotoE2ETest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import gen_pcaps as g

        from ot_assess import i18n
        from ot_assess.cli import main

        cls.tmp = Path(tempfile.mkdtemp())
        pcaps = cls.tmp / "pcaps"
        pcaps.mkdir()
        cls.pcaps = pcaps
        g.guardar(g.punto_t8(), pcaps / "t8_it.pcap")
        g.guardar(g.punto_t8(con_ot=True), pcaps / "t8_ot.pcap")
        g.guardar(g.punto_t8_trampa(), pcaps / "t8_trampa.pcap")
        g.guardar(g.punto_a(), pcaps / "viejo_a.pcap")
        g.guardar(g.punto_b(), pcaps / "viejo_b.pcap")
        g.guardar(g.punto_c(), pcaps / "viejo_c.pcap")
        g.guardar(g.punto_d(), pcaps / "viejo_d.pcap")
        i18n.FALTANTES.clear()
        cls.rc = main([str(pcaps), "-o", str(cls.tmp / "es"), "--cache", str(cls.tmp / "cache")])
        cls.ind = cls._csv(cls.tmp / "es" / "acceso_remoto.csv")
        cls.hall = [r for r in cls._csv(cls.tmp / "es" / "hallazgos.csv") if r["titulo"] == T_HALLAZGO]
        i18n.FALTANTES.clear()
        main([str(pcaps), "-o", str(cls.tmp / "en"), "--idioma", "en"])
        cls.faltantes_en = set(i18n.FALTANTES)
        i18n.usar("es")
        cls.main = staticmethod(main)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    @staticmethod
    def _csv(path):
        with open(path, newline="", encoding="utf-8-sig") as fh:
            return list(csv.DictReader(fh))

    def test_cuatro_indicadores_y_un_solo_hallazgo_por_captura(self):
        filas = [r for r in self.ind if r["fuente"] == "t8_it.pcap"]
        self.assertEqual(sorted((r["herramienta"], r["metodo"], r["indicador"]) for r in filas), [
            ("AnyDesk", "SNI", "net.anydesk.com"), ("RustDesk", "puerto", "tcp/21116"),
            ("TeamViewer", "DNS", "master3.teamviewer.com"), ("TeamViewer", "puerto", "tcp/5938")])
        self.assertEqual([r["captura"] for r in self.hall].count("t8_it.pcap"), 1)
        for r in filas:
            self.assertEqual((r["ip"], r["estado_indicador"]), ("10.80.1.10", "verificado"))
            self.assertTrue(r["primera"] and r["ultima"], r)
        dns = next(r for r in filas if r["metodo"] == "DNS")
        self.assertEqual((dns["destino"], dns["destino_ip"]), ("Internet", "203.0.113.50"))
        sni = next(r for r in filas if r["metodo"] == "SNI")
        self.assertEqual((sni["destino_ip"], sni["conductos"]), ("203.0.113.60", "1"))

    def test_severidad_media_con_cliente_it_y_alta_con_cliente_ot(self):
        sev = {r["captura"]: r["severidad"] for r in self.hall}
        self.assertEqual(sev["t8_it.pcap"], "Media")
        self.assertEqual(sev["t8_ot.pcap"], "Alta")

    def test_trampas_y_capturas_existentes_no_generan_el_hallazgo(self):
        self.assertEqual({r["captura"] for r in self.hall}, {"t8_it.pcap", "t8_ot.pcap"})
        self.assertEqual([r for r in self.ind if r["fuente"] not in ("t8_it.pcap", "t8_ot.pcap")], [])

    def test_ingles_sin_textos_faltantes(self):
        self.assertEqual(sorted(self.faltantes_en), [])

    def test_con_cache_las_salidas_son_iguales(self):
        out = self.tmp / "es2"
        self.assertEqual(self.main([str(self.pcaps), "-o", str(out), "--cache", str(self.tmp / "cache")]), 0)
        for n in ("acceso_remoto.csv", "hallazgos.csv"):
            self.assertEqual((out / n).read_text(encoding="utf-8-sig"),
                             (self.tmp / "es" / n).read_text(encoding="utf-8-sig"), n)


class ExportacionE2ETest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import gen_exports as ge

        from ot_assess.cli import main

        cls.tmp = Path(tempfile.mkdtemp())
        xd = ge.xdome(cls.tmp)
        com = ge.xd_escribir_comunicaciones(cls.tmp / "com_t8.csv", [
            ge.xd_fila("10.10.1.10", "203.0.113.5", "From A to B", 443, "TLS 1.2", nbytes=7, tipo_a="HMI",
                       ambito="Internet (External)", dominios="cdn.example.com, x.teamviewer.com"),
            ge.xd_fila("10.10.1.10", "203.0.113.6", "From A to B", 443, "TLS 1.2", nbytes=9,
                       ambito="Internet (External)", dominios="teamviewer.com.example.net, noteamviewer.com"),
            ge.xd_fila("10.10.1.10", "203.0.113.7", "From A to B", 8041, "N/A", nbytes=11,
                       ambito="Internet (External)", dominios="N/A")])
        cls.out = cls.tmp / "diag"
        cls.rc = main(["diagrama", "--activos", str(xd["inventario"]), "--enlaces", str(com), "-o", str(cls.out),
                       "--cliente", "Prueba"])

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_hallazgo_y_csv_desde_side_b_domains(self):
        self.assertEqual(self.rc, 0)
        with open(self.out / "acceso_remoto.csv", newline="", encoding="utf-8-sig") as fh:
            filas = list(csv.DictReader(fh))
        self.assertEqual(sorted((r["herramienta"], r["metodo"], r["indicador"], r["estado_indicador"]) for r in filas),
                         [("ScreenConnect (ConnectWise Control)", "puerto", "8041", "sin verificar"),
                          ("TeamViewer", "dominio exportado", "x.teamviewer.com", "verificado")])
        self.assertEqual({r["ip"] for r in filas}, {"10.10.1.10"})
        self.assertTrue(all(r["destino"] == "Internet" for r in filas))
        with open(self.out / "hallazgos.csv", newline="", encoding="utf-8-sig") as fh:
            hall = [r for r in csv.DictReader(fh) if r["titulo"] == T_HALLAZGO]
        self.assertEqual(len(hall), 1)
        self.assertEqual(hall[0]["severidad"], "Alta")          # HMI = Nivel 2
        self.assertIn("indicador sin verificar", hall[0]["evidencia"])


if __name__ == "__main__":
    unittest.main()
