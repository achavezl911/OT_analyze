"""Pruebas de las reglas de DNS (DNS-b). Las unitarias no requieren tshark; el e2e si."""
from __future__ import annotations

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

from ot_assess import rules  # noqa: E402
from ot_assess.detail import dns as colector  # noqa: E402
from ot_assess.rules import dns as rdns  # noqa: E402
from ot_assess.standards import ESTANDARES, MITRE  # noqa: E402

C, S = "10.0.0.5", "10.0.0.53"


def q(src, dst, nombre, tipo="A", id_="1"):
    return {"t": 1.0, "src": src, "dst": dst, "id": id_, "resp": False, "nombre": nombre,
            "tipo": tipo, "rcode": "", "respuestas": []}


def r(cli, srv, nombre, rcode="NOERROR", id_="1"):
    return {"t": 1.0, "src": srv, "dst": cli, "id": id_, "resp": True, "nombre": nombre,
            "tipo": "A", "rcode": rcode, "respuestas": []}


def correr(eventos=(), flows=None, dominios=()):
    cap = SimpleNamespace(name="a.pcap", dns_eventos=list(eventos), flows=flows or {},
                          findings=[], dominios_internos=tuple(dominios))
    for regla in (rdns.dns_wpad, rdns.dns_publico, rdns.dns_dominios_internet, rdns.dns_fallas,
                  rdns.dns_nxdomain, rdns.dns_tunel, rdns.dns_transferencia_zona, rdns.dns_dot):
        regla(cap)
    return cap.findings


def titulos(f):
    return [x["titulo"] for x in f]


def par(i, rcode, cli=C, srv=S):
    """Consulta con su respuesta (id propio)."""
    return [q(cli, srv, f"n{i}.planta.local", id_=str(i)),
            r(cli, srv, f"n{i}.planta.local", rcode, id_=str(i))]


class ReglasTest(unittest.TestCase):
    def test_wpad(self):
        f = correr([q(C, S, "wpad"), q(C, S, "wpad.planta.local"), q(C, S, "mywpad.x.local")])
        self.assertEqual(titulos(f), ["Busqueda de proxy WPAD por DNS"])
        self.assertIn("2 consultas", f[0]["evidencia"])
        self.assertEqual(correr([q(C, S, "mywpad.planta.local")]), [])

    def test_publico(self):
        f = correr([q(C, "8.8.8.8", "x.planta.local")])
        self.assertEqual(titulos(f), ["Consultas DNS a servidores publicos"])
        self.assertEqual(correr([q(C, S, "x.planta.local")]), [])

    def test_dominios_internet(self):
        f = correr([q(C, S, "www.example.com"), q(C + "1", S, "www.example.com"),
                    q(C, S, "x.planta.local")])
        self.assertEqual(titulos(f), ["Resolucion de dominios de Internet desde la red"])
        self.assertIn("www.example.com (2 consultas", f[0]["evidencia"])
        self.assertEqual(correr([q(C, S, "x.planta.local")]), [])

    def test_dominios_internos_del_perfil(self):
        ev = [q(C, S, "srv.corp.example"), q(C, S, "www.example.com")]
        self.assertIn("srv.corp.example", correr(ev)[0]["evidencia"])
        f = correr(ev, dominios=("corp.example",))
        self.assertNotIn("srv.corp.example", f[0]["evidencia"])
        self.assertEqual(correr(ev[:1], dominios=("corp.example",)), [])

    def test_nxdomain_singular(self):
        ev = sum((par(i, "NXDOMAIN") for i in range(50)), [])
        self.assertIn("1 cliente:", correr(ev)[0]["evidencia"])

    def test_evidencia_limitada_a_10(self):
        f = correr([q(C, S, f"h{i}.example.com") for i in range(13)])
        self.assertIn("y 3 mas", f[0]["evidencia"])

    def test_fallas_por_rcode(self):
        ev = sum((par(i, "SERVFAIL") for i in range(20)), []) + \
            sum((par(i, "NOERROR") for i in range(20, 60)), [])
        self.assertIn("Fallas de resolucion DNS", titulos(correr(ev)))     # 20 de 60 = 33 %
        ev = sum((par(i, "SERVFAIL") for i in range(19)), []) + \
            sum((par(i, "NOERROR") for i in range(19, 40)), [])
        self.assertNotIn("Fallas de resolucion DNS", titulos(correr(ev)))  # 19 < 20
        ev = sum((par(i, "REFUSED") for i in range(20)), []) + \
            sum((par(i, "NOERROR") for i in range(20, 200)), [])
        self.assertNotIn("Fallas de resolucion DNS", titulos(correr(ev)))  # 20 de 200 = 10 %

    def test_fallas_sin_respuesta(self):
        ev = [q(C, S, "x.planta.local", id_=str(i)) for i in range(20)]
        self.assertIn("Fallas de resolucion DNS", titulos(correr(ev)))
        ev = [q(C, S, "x.planta.local", id_=str(i)) for i in range(19)]
        self.assertNotIn("Fallas de resolucion DNS", titulos(correr(ev)))
        ev = [q(C, S, "x.planta.local", id_=str(i)) for i in range(20)] + \
            sum((par(100 + i, "NOERROR") for i in range(200)), [])
        self.assertNotIn("Fallas de resolucion DNS", titulos(correr(ev)))  # 20 de 220 < 10 %

    def test_nxdomain_absoluto_y_porcentaje(self):
        ev = sum((par(i, "NXDOMAIN") for i in range(50)), []) + \
            sum((par(i, "NOERROR") for i in range(50, 500)), [])
        self.assertIn("Cliente con muchas respuestas NXDOMAIN", titulos(correr(ev)))
        ev = sum((par(i, "NXDOMAIN") for i in range(49)), []) + \
            sum((par(i, "NOERROR") for i in range(49, 500)), [])
        self.assertNotIn("Cliente con muchas respuestas NXDOMAIN", titulos(correr(ev)))
        ev = sum((par(i, "NXDOMAIN") for i in range(6)), []) + \
            sum((par(i, "NOERROR") for i in range(6, 20)), [])           # 6 de 20 = 30 %
        self.assertIn("Cliente con muchas respuestas NXDOMAIN", titulos(correr(ev)))
        ev = sum((par(i, "NXDOMAIN") for i in range(5)), []) + \
            sum((par(i, "NOERROR") for i in range(5, 20)), [])           # 25 %
        self.assertNotIn("Cliente con muchas respuestas NXDOMAIN", titulos(correr(ev)))
        ev = sum((par(i, "NXDOMAIN") for i in range(5)), []) + \
            sum((par(i, "NOERROR") for i in range(5, 19)), [])           # 5 de 19: pocas respuestas
        self.assertNotIn("Cliente con muchas respuestas NXDOMAIN", titulos(correr(ev)))

    def test_tunel(self):
        self.assertIn("Posible tunel DNS", titulos(correr([q(C, S, "a" * 51 + ".x.com")])))
        self.assertNotIn("Posible tunel DNS", titulos(correr([q(C, S, "a" * 50 + ".x.com")])))
        subs = [q(C, S, f"s{i}.t.example.com") for i in range(101)]
        self.assertIn("Posible tunel DNS", titulos(correr(subs)))
        self.assertNotIn("Posible tunel DNS", titulos(correr(subs[:100])))
        txt = [q(C, S, "x.planta.local", "TXT", str(i)) for i in range(50)]
        self.assertIn("Posible tunel DNS", titulos(correr(txt)))
        self.assertNotIn("Posible tunel DNS", titulos(correr(txt[:49])))
        nulo = [q(C, S, "x.planta.local", "10", str(i)) for i in range(50)]
        self.assertIn("Posible tunel DNS", titulos(correr(nulo)))

    def test_transferencia_zona(self):
        for tipo in ("AXFR", "IXFR"):
            self.assertIn("Intento de transferencia de zona DNS",
                          titulos(correr([q(C, S, "planta.local", tipo)])))
        self.assertNotIn("Intento de transferencia de zona DNS",
                         titulos(correr([q(C, S, "planta.local", "SOA")])))

    def test_dot(self):
        flujo = {"src": C, "dst": "1.1.1.1", "dport": "853", "l4": "tcp", "pkts": 4}
        self.assertEqual(titulos(correr(flows={("k",): flujo})), ["DNS cifrado sin visibilidad (DoT)"])
        udp = dict(flujo, l4="udp")
        self.assertEqual(correr(flows={("k",): udp}), [])
        self.assertEqual(correr(flows={("k",): dict(flujo, dport="443")}), [])

    def test_registradas_y_orden(self):
        nombres = [f.__name__ for f in rules.RULES]
        self.assertIn("dns_wpad", nombres)
        self.assertIn("dns_dot", nombres)


class ReferenciasTest(unittest.TestCase):
    TITULOS = {
        "Busqueda de proxy WPAD por DNS": (
            "T0830 Adversary-in-the-Middle", "SR 3.1 Integridad de las comunicaciones; SR 7.7 Funcionalidad minima",
            "CIP-007 R1 (puertos y servicios)", "CM-7 (funcionalidad minima); SC-8 (integridad de la transmision)",
            "PR.PS-01 (gestion de configuracion); PR.IR-01 (proteccion de redes)"),
        "Consultas DNS a servidores publicos": (
            "T0869 Standard Application Layer Protocol", "SR 5.1 Segmentacion de red; SR 5.2 Proteccion del limite de zona",
            "CIP-005 R1 (perimetro de seguridad electronica)", "SC-7 (proteccion de limites); SC-21 (resolucion recursiva segura)",
            "PR.IR-01 (proteccion de redes)"),
        "Resolucion de dominios de Internet desde la red": (
            "", "SR 5.1 Segmentacion de red; SR 5.2 Proteccion del limite de zona",
            "CIP-005 R1 (perimetro de seguridad electronica)", "SC-7 (proteccion de limites); AC-4 (control de flujo de informacion)",
            "ID.AM-03 (flujos de red autorizados); PR.IR-01 (proteccion de redes)"),
        "Fallas de resolucion DNS": (
            "", "SR 7.6 Ajustes de configuracion de red y seguridad", "",
            "CM-6 (parametros de configuracion); SC-22 (arquitectura del servicio de nombres)",
            "PR.PS-01 (gestion de configuracion)"),
        "Cliente con muchas respuestas NXDOMAIN": (
            "", "SR 6.2 Monitoreo continuo", "CIP-007 R4 (monitoreo de eventos de seguridad)",
            "SI-4 (monitoreo del sistema)", "DE.CM-01 (monitoreo de redes); DE.AE-02 (analisis de eventos)"),
        "Posible tunel DNS": (
            "T0869 Standard Application Layer Protocol", "SR 6.2 Monitoreo continuo; SR 5.2 Proteccion del limite de zona",
            "CIP-007 R4 (monitoreo de eventos de seguridad); CIP-015 (monitoreo interno de red)",
            "SI-4 (monitoreo del sistema); SC-7 (proteccion de limites)",
            "DE.CM-01 (monitoreo de redes); DE.AE-02 (analisis de eventos)"),
        "Intento de transferencia de zona DNS": (
            "T0888 Remote System Information Discovery; T0846 Remote System Discovery",
            "SR 2.1 Aplicacion de autorizacion", "CIP-005 R1 (perimetro de seguridad electronica)",
            "AC-3 (aplicacion del acceso); CM-7 (funcionalidad minima)",
            "PR.AA-05 (permisos de acceso); DE.CM-01 (monitoreo de redes)"),
        "DNS cifrado sin visibilidad (DoT)": (
            "", "SR 6.2 Monitoreo continuo", "CIP-005 R1 (perimetro de seguridad electronica)",
            "SC-7 (proteccion de limites); SI-4 (monitoreo del sistema)", "DE.CM-01 (monitoreo de redes)"),
    }

    def test_cinco_marcos(self):
        from ot_assess.standards import referencias
        claves = [MITRE.clave] + [e.clave for e in ESTANDARES.values()]
        self.assertEqual(sorted(claves), sorted(["mitre-ics", "iec62443", "nerc-cip",
                                                 "nist-800-82", "nist-csf"]))
        orden = ["mitre-ics", "iec62443", "nerc-cip", "nist-800-82", "nist-csf"]
        for titulo, esperado in self.TITULOS.items():
            ref = referencias(titulo)
            for clave, txt in zip(orden, esperado):
                self.assertEqual(ref.get(clave, ""), txt, f"{titulo} / {clave}")


class ColectorTest(unittest.TestCase):
    def test_multicast_y_puertos_excluidos(self):
        es = colector._es_multicast_dns
        self.assertTrue(es(lambda k: {"udp.dstport": "5353"}.get(k, "")))
        self.assertTrue(es(lambda k: {"udp.srcport": "5355"}.get(k, "")))
        self.assertTrue(es(lambda k: {"ip.dst": "224.0.0.252"}.get(k, "")))
        self.assertTrue(es(lambda k: {"ipv6.dst": "ff02::fb"}.get(k, "")))
        self.assertFalse(es(lambda k: {"ip.dst": "10.0.0.53", "udp.dstport": "53"}.get(k, "")))


@unittest.skipUnless(shutil.which("tshark") and HAY_SCAPY, "requiere tshark y scapy")
class E2ETest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import gen_pcaps
        from ot_assess.cli import main
        cls.tmp = Path(tempfile.mkdtemp())
        pcaps = cls.tmp / "pcaps"
        pcaps.mkdir()
        gen_pcaps.guardar(gen_pcaps.punto_dns_hallazgos(), pcaps / "dnsh.pcap")
        cls.rc = main([str(pcaps), "-o", str(cls.tmp / "out")])
        cls.salida = cls.tmp / "out"

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_hallazgos_y_multicast(self):
        import csv
        csvs = list(self.salida.glob("*.csv"))
        self.assertTrue(csvs)
        with open(self.salida / "dns_servidores.csv", newline="", encoding="utf-8-sig") as fh:
            servidores = [x[0] for x in csv.reader(fh)][1:]
        self.assertNotIn("224.0.0.251", servidores)
        self.assertIn("10.10.1.53", servidores)
        txt = "".join(p.read_text(encoding="utf-8-sig") for p in csvs)
        for titulo in ("Busqueda de proxy WPAD por DNS", "Consultas DNS a servidores publicos",
                       "Intento de transferencia de zona DNS", "DNS cifrado sin visibilidad (DoT)",
                       "Resolucion de dominios de Internet desde la red"):
            self.assertIn(titulo, txt)


if __name__ == "__main__":
    unittest.main()
