"""Pruebas de los registros DNS (DNS-a). El e2e requiere tshark y scapy."""
from __future__ import annotations

import csv
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))
sys.path.insert(0, str(RAIZ / "tests"))

try:
    import scapy  # noqa: F401
    HAY_SCAPY = True
except ImportError:
    HAY_SCAPY = False

from ot_assess import perfil, registros_dns as rd  # noqa: E402
from ot_assess.detail import dns as colector  # noqa: E402


def fila(r, nombre, tipo):
    return next(x for x in r if x[0] == nombre and x[1] == tipo)


def ev(t, src, dst, id_, nombre, tipo="A", resp=False, rcode="", respuestas=()):
    return {"t": t, "src": src, "dst": dst, "id": id_, "resp": resp, "nombre": nombre,
            "tipo": tipo, "rcode": rcode, "respuestas": list(respuestas)}


def corrida(eventos, nombres=(), dominios=None):
    cap = SimpleNamespace(name="a.pcap", dns_eventos=list(eventos), nombres_servidor=list(nombres))
    return SimpleNamespace(caps=[cap], perfil={"dominios_internos": dominios} if dominios else {})


class AlineacionTest(unittest.TestCase):
    def test_autoridad_y_adicional_no_desalinean(self):
        campos = {"dns.count.answers": "2", "dns.resp.name": "www.x.com|cdn.x.net|x.net|ns.x.net",
                  "dns.resp.type": "5|1|2|1", "dns.resp.ttl": "300|60|900|900",
                  "dns.cname": "cdn.x.net", "dns.a": "1.2.3.4|9.9.9.9", "dns.ns": "ns.x.net"}
        r = colector.respuestas(lambda k: campos.get(k, ""))
        self.assertEqual(r, [("www.x.com", "CNAME", "cdn.x.net", 300),
                             ("cdn.x.net", "A", "1.2.3.4", 60)])

    def test_tipo_y_rcode_numero_o_texto(self):
        self.assertEqual(colector.tipo_dns("28"), "AAAA")
        self.assertEqual(colector.tipo_dns("AAAA"), "AAAA")
        self.assertEqual(colector.tipo_dns("99"), "99")
        self.assertEqual(colector.rcode_dns("3"), "NXDOMAIN")
        self.assertEqual(colector.rcode_dns("Refused"), "REFUSED")


class TablasTest(unittest.TestCase):
    def setUp(self):
        c, s = "10.0.0.5", "10.0.0.53"
        self.res = corrida([
            ev(1, c, s, "1", "a.x.com"),
            ev(2, s, c, "1", "a.x.com", resp=True, rcode="NOERROR", respuestas=[
                ("a.x.com", "CNAME", "b.x.com", 300), ("b.x.com", "A", "1.2.3.4", 60)]),
            ev(3, c, s, "2", "a.x.com"),                      # sin respuesta
            ev(4, c, s, "3", "n.x.com"),
            ev(5, s, c, "3", "n.x.com", resp=True, rcode="NXDOMAIN"),
            ev(6, c, "8.8.8.8", "4", "5.0.0.10.in-addr.arpa", "PTR"),
            ev(7, "8.8.8.8", c, "4", "5.0.0.10.in-addr.arpa", "PTR", True, "NOERROR",
               [("5.0.0.10.in-addr.arpa", "PTR", "Host.Planta.Local", 10)]),
        ], nombres=[{"fuente": "TLS SNI", "ip": "1.2.3.4", "nombre": "a.x.com"}])

    def test_registros(self):
        r = rd.registros(self.res)
        f = fila(r, "a.x.com", "A")
        self.assertEqual(f[2:8], [2, 1, 1, "NOERROR 1", 60, "CNAME b.x.com; A 1.2.3.4"])
        self.assertEqual(f[10:12], ["1970-01-01T00:00:01Z", "1970-01-01T00:00:03Z"])
        self.assertEqual(f[12], "externo")
        self.assertEqual(fila(r, "n.x.com", "A")[5], "NXDOMAIN 1")
        self.assertEqual(r[0][0], "a.x.com")        # mas consultas primero

    def test_resoluciones(self):
        r = {(x[0], x[1], x[2]): x[3] for x in rd.resoluciones(self.res)}
        self.assertEqual(r[("1.2.3.4", "a.x.com", "DNS A")], 1)
        self.assertEqual(r[("1.2.3.4", "b.x.com", "DNS A")], 1)     # nombre del CNAME
        self.assertEqual(r[("10.0.0.5", "host.planta.local", "DNS PTR")], 1)
        self.assertEqual(r[("1.2.3.4", "a.x.com", "TLS SNI")], 1)
        self.assertNotIn(("1.2.3.4", "n.x.com", "DNS A"), r)

    def test_servidores(self):
        s = {x[0]: x for x in rd.servidores(self.res)}
        self.assertEqual(s["10.0.0.53"][1:6], ["interno", 3, 2, "NOERROR 1; NXDOMAIN 1", 1])
        self.assertEqual(s["8.8.8.8"][1], "publico")

    def test_ambito(self):
        a = rd.ambito_nombre
        self.assertEqual(a("x.planta.local"), "interno")
        self.assertEqual(a("impresora"), "interno")
        self.assertEqual(a("www.example.com"), "externo")
        self.assertEqual(a("srv.corp.example", ("corp.example",)), "interno")
        self.assertEqual(a("srv.corp.example"), "externo")
        self.assertEqual(a("5.0.0.10.in-addr.arpa"), "interno")
        self.assertEqual(a("4.3.2.1.in-addr.arpa"), "externo")
        self.assertEqual(a("x.notcorp"), "externo")

    def test_dominios_internos_del_perfil(self):
        res = corrida([ev(1, "10.0.0.5", "10.0.0.53", "1", "h.corp.example")],
                      dominios=["corp.example"])
        self.assertEqual(rd.registros(res)[0][12], "interno")


class NombreDeIpTest(unittest.TestCase):
    def test_orden_de_fuente_y_maximo_dos(self):
        c, s = "10.0.0.5", "10.0.0.53"
        res = corrida(
            [ev(1, c, s, "1", "a.example.com"),
             ev(2, s, c, "1", "a.example.com", resp=True, respuestas=[("a.example.com", "A", "1.1.1.1", 60)]),
             ev(3, s, c, "2", "b.example.com", resp=True, respuestas=[("b.example.com", "A", "1.1.1.1", 60)]),
             ev(4, s, c, "3", "b.example.com", resp=True, respuestas=[("b.example.com", "A", "1.1.1.1", 60)])],
            nombres=[{"fuente": "TLS SNI", "ip": "1.1.1.1", "nombre": "sni.example.com"},
                     {"fuente": "HTTP Host", "ip": "2.2.2.2", "nombre": "h.example.com"}])
        n = rd.nombre_de_ip(res)
        self.assertEqual(n["1.1.1.1"], "b.example.com; a.example.com")   # el mas visto primero; SNI queda fuera
        self.assertEqual(n["2.2.2.2"], "h.example.com")

    def test_seccion_sin_dns(self):
        self.assertIsNone(rd.seccion(corrida([])))

    def test_seccion_recorta_y_remite(self):
        ev_ = [ev(i, "10.0.0.5", "10.0.0.53", str(i), f"h{i}.example.com") for i in range(25)]
        ev_.append(ev(99, "10.0.0.53", "10.0.0.5", "0", "h0.example.com", resp=True,
                      respuestas=[("h0.example.com", "TXT", "x" * 200, 5)]))
        s = rd.seccion(corrida(ev_))
        self.assertEqual(len(s["nombres"]), 20)
        self.assertTrue(s["mas"])
        self.assertTrue(any(len(f[5]) == 80 and f[5].endswith("...") for f in s["nombres"]))


class PerfilTest(unittest.TestCase):
    def cargar(self, extra):
        base = {"version": 1, "cliente": "C", "marcos": [{"clave": "iec62443"}]}
        base.update(extra)
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, True)
        (d / "p.json").write_text(json.dumps(base), encoding="utf-8")
        return perfil.cargar(d / "p.json")

    def test_valido_se_normaliza(self):
        p = self.cargar({"dominios_internos": [" Planta.Local", ".corp.example"]})
        self.assertEqual(p["dominios_internos"], ["planta.local", "corp.example"])

    def test_invalido_falla(self):
        for malo in ("planta.local", [1], [""], [" . "]):
            with self.assertRaises(SystemExit, msg=repr(malo)):
                self.cargar({"dominios_internos": malo})


@unittest.skipUnless(shutil.which("tshark") and HAY_SCAPY, "requiere tshark y scapy")
class E2ETest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import gen_pcaps
        from ot_assess.cli import main
        cls.tmp = Path(tempfile.mkdtemp())
        pcaps = cls.tmp / "pcaps"
        pcaps.mkdir()
        gen_pcaps.guardar(gen_pcaps.punto_dns(), pcaps / "dns.pcap")
        cls.rc = main([str(pcaps), "-o", str(cls.tmp / "out")])

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def leer(self, nombre):
        with open(self.tmp / "out" / nombre, newline="", encoding="utf-8-sig") as fh:
            return list(csv.reader(fh))

    def test_encabezados(self):
        self.assertEqual(self.leer("dns_registros.csv")[0], rd.COL_REGISTROS)
        self.assertEqual(self.leer("dns_resoluciones.csv")[0], rd.COL_RESOLUCIONES)
        self.assertEqual(self.leer("dns_servidores.csv")[0], rd.COL_SERVIDORES)
        self.assertEqual(",".join(rd.COL_RESOLUCIONES), "ip,nombre,fuente,veces,capturas")

    def test_registros(self):
        r = {(x[0], x[1]): x for x in self.leer("dns_registros.csv")[1:]}
        www = r[("www.example.com", "A")]
        self.assertEqual(www[2:8], ["1", "1", "0", "NOERROR 1", "60",
                                    "CNAME cdn.example.net; A 93.184.216.34"])
        self.assertEqual(r[("v6.example.com", "AAAA")][7], "AAAA 2001:db8::1")
        self.assertEqual(r[("20.1.10.10.in-addr.arpa", "PTR")][7], "PTR plc.planta.local")
        self.assertEqual(r[("20.1.10.10.in-addr.arpa", "PTR")][12], "interno")
        self.assertEqual(r[("nada.example.com", "A")][5], "NXDOMAIN 1")
        self.assertEqual(r[("nada.example.com", "A")][7], "")        # el SOA es autoridad
        self.assertEqual(r[("refused.example.org", "A")][5], "REFUSED 1")
        self.assertEqual(r[("perdida.example.com", "A")][2:5], ["1", "0", "1"])
        self.assertTrue(www[10].endswith("Z"))

    def test_resoluciones(self):
        r = {(x[0], x[1], x[2]) for x in self.leer("dns_resoluciones.csv")[1:]}
        for esperado in (("93.184.216.34", "www.example.com", "DNS A"),
                         ("93.184.216.34", "cdn.example.net", "DNS A"),
                         ("2001:db8::1", "v6.example.com", "DNS AAAA"),
                         ("10.10.1.20", "plc.planta.local", "DNS PTR"),
                         ("93.184.216.34", "www.example.com", "TLS SNI")):
            self.assertIn(esperado, r)

    def test_hojas_dns_en_el_libro(self):
        import re
        import zipfile
        with zipfile.ZipFile(self.tmp / "out" / "reporte_ot.xlsx") as z:
            hojas = re.findall(r'<sheet name="([^"]+)"', z.read("xl/workbook.xml").decode("utf-8"))
        for h in ("DNS registros", "DNS resoluciones", "DNS servidores"):
            self.assertIn(h, hojas)

    def test_seccion_en_los_reportes(self):
        import zipfile
        html = (self.tmp / "out" / "reporte_ot.html").read_text(encoding="utf-8")
        md = (self.tmp / "out" / "reporte_ot.md").read_text(encoding="utf-8")
        with zipfile.ZipFile(self.tmp / "out" / "informe_ot.docx") as z:
            docx = z.read("word/document.xml").decode("utf-8")
        for texto in (html, md, docx):
            self.assertIn("Resolucion de nombres (DNS)", texto)
            self.assertIn("www.example.com", texto)

    def test_columna_nombre_dns(self):
        com = self.leer("comunicaciones.csv")
        j = com[0].index("nombre_dns")
        self.assertIn("nombre_dns", self.leer("inventario.csv")[0])
        i = com[0].index("destino_ip")
        nombres = [f[j] for f in com[1:] if f[i] == "93.184.216.34"]
        self.assertTrue(nombres)
        self.assertIn("www.example.com", nombres[0])

    def test_servidores(self):
        s = {x[0]: x for x in self.leer("dns_servidores.csv")[1:]}
        self.assertEqual(s["10.10.1.53"][1], "interno")
        self.assertEqual(s["8.8.8.8"][1], "publico")


@unittest.skipUnless(shutil.which("tshark") and HAY_SCAPY, "requiere tshark y scapy")
class SinDnsTest(unittest.TestCase):
    def test_sin_trafico_dns(self):
        import gen_pcaps
        import zipfile
        from ot_assess.cli import main
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        (tmp / "pcaps").mkdir()
        gen_pcaps.guardar(gen_pcaps.punto_d(), tmp / "pcaps" / "d.pcap")
        main([str(tmp / "pcaps"), "-o", str(tmp / "out")])
        with zipfile.ZipFile(tmp / "out" / "informe_ot.docx") as z:
            docx = z.read("word/document.xml").decode("utf-8")
        for texto in ((tmp / "out" / "reporte_ot.html").read_text(encoding="utf-8"),
                      (tmp / "out" / "reporte_ot.md").read_text(encoding="utf-8"), docx):
            self.assertIn("No se observo trafico DNS.", texto)


if __name__ == "__main__":
    unittest.main()
