"""P3: puertos de MQTT, KNX, HART-IP, CODESYS V2, Beckhoff ADS y DLMS/COSEM."""
from __future__ import annotations

import csv
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))

try:
    from scapy.all import Ether, IP, TCP, Raw, wrpcap
    HAY_SCAPY = True
except ImportError:
    HAY_SCAPY = False

from ot_assess.util import port_info

ESPERADOS = {
    (1883, "tcp"): "MQTT",
    (8883, "tcp"): "MQTT sobre TLS",
    (3671, "udp"): "KNXnet/IP (EIBnet/IP)",
    (5094, "tcp"): "HART-IP",
    (5094, "udp"): "HART-IP",
    (2455, "tcp"): "CODESYS V2 / WAGO-IO-SYSTEM",
    (2455, "udp"): "CODESYS V2 / WAGO-IO-SYSTEM",
    (48898, "tcp"): "Beckhoff ADS/AMS",
    (48899, "udp"): "Beckhoff ADS descubrimiento",
    (8016, "tcp"): "Beckhoff Secure ADS",
    (4059, "tcp"): "DLMS/COSEM",
    (4059, "udp"): "DLMS/COSEM",
}


class PuertosP3Test(unittest.TestCase):
    def test_port_info_devuelve_nombre_y_categoria_ot(self):
        for (puerto, proto), nombre in ESPERADOS.items():
            self.assertEqual(port_info(str(puerto), proto), (nombre, "ot"), (puerto, proto))


@unittest.skipUnless(shutil.which("tshark") and HAY_SCAPY, "requiere tshark y scapy")
class ComunicacionesP3Test(unittest.TestCase):
    def test_flujos_aparecen_como_conducto_ot(self):
        from ot_assess.cli import main

        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        pcaps, out = tmp / "pcaps", tmp / "out"
        pcaps.mkdir()
        pk = []
        for sport, dport in ((40001, 48898), (40002, 1883)):
            e = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
            ip = IP(src="10.9.0.1", dst="10.9.0.2")
            pk.append(e / ip / TCP(sport=sport, dport=dport, flags="S", seq=1))
            pk.append(Ether(src="02:00:00:00:00:02", dst="02:00:00:00:00:01") /
                      IP(src="10.9.0.2", dst="10.9.0.1") /
                      TCP(sport=dport, dport=sport, flags="SA", seq=1, ack=2))
            pk.append(e / ip / TCP(sport=sport, dport=dport, flags="PA", seq=2, ack=2) / Raw(b"\x00" * 8))
        wrpcap(str(pcaps / "p3.pcap"), pk)
        self.assertEqual(main([str(pcaps), "-o", str(out)]), 0)
        with open(out / "comunicaciones.csv", newline="", encoding="utf-8-sig") as fh:
            filas = {r["puerto"]: r for r in csv.DictReader(fh) if r["origen_ip"] == "10.9.0.1"}
        for puerto, nombre in (("48898", "Beckhoff ADS/AMS"), ("1883", "MQTT")):
            self.assertIn(puerto, filas)
            self.assertEqual(filas[puerto]["servicio"], nombre)
            self.assertEqual(filas[puerto]["categoria"], "ot")


if __name__ == "__main__":
    unittest.main()
