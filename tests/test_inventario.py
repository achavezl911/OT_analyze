"""Reglas sobre inventario y conductos importados (sin captura). Solo biblioteca estandar."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ot_assess.rules.inventario import AVISO, evaluar_inventario  # noqa: E402


def _activo(nombre, ip="10.0.0.1", **kw):
    a = {"mac": nombre, "ips": {ip}, "nombre": nombre, "vendor": "", "modelo": "", "firmware": "",
         "tipo_texto": "", "purdue": "", "zona": ""}
    a.update(kw)
    return {nombre: a}


def _conducto(src="10.0.0.1", dst="10.0.0.2", port="502", servicio="modbus", categoria="control", l4="tcp"):
    return {"src": src, "dst": dst, "l4": l4, "port": port, "servicio": servicio, "categoria": categoria}


def _por_titulo(hallazgos, fragmento):
    return [h for h in hallazgos if fragmento in h["titulo"]]


class EvidenciaPublicasTest(unittest.TestCase):
    def _evidencia(self, activos, conducto):
        h = evaluar_inventario(activos, [conducto], "xDome")
        return _por_titulo(h, "IP publicas")[0]["evidencia"]

    def test_muestra_ip_y_nombre_no_la_mac(self):
        a = _activo("PC-7", ip="10.0.0.7", mac="00:0c:29:00:00:07")
        a["PC-7"]["alias"] = {"00:0c:29:00:00:07"}
        ev = self._evidencia(a, _conducto(src="00:0c:29:00:00:07", dst="146.112.255.101"))
        self.assertIn("10.0.0.7 (PC-7) -> 146.112.255.101", ev)
        self.assertNotIn("00:0c", ev)

    def test_mac_solo_si_no_hay_ip(self):
        a = _activo("PC-7", mac="00:0c:29:00:00:07")
        a["PC-7"]["ips"] = set()
        a["PC-7"]["alias"] = {"00:0c:29:00:00:07"}
        ev = self._evidencia(a, _conducto(src="00:0c:29:00:00:07", dst="146.112.255.101"))
        self.assertIn("00:0c:29:00:00:07 -> 146.112.255.101", ev)


class InventarioTest(unittest.TestCase):
    def test_sin_casos_no_hay_hallazgos(self):
        h = evaluar_inventario(_activo("PLC-1", modelo="S7-1500"), [_conducto()], "Nozomi")
        self.assertEqual(h, [])
        self.assertEqual(evaluar_inventario({}, [], "Nozomi"), [])

    def test_gestion_sin_cifrar(self):
        h = evaluar_inventario({}, [_conducto(port="23", servicio="telnet", categoria="claro"),
                                    _conducto(dst="10.0.0.3", port="23", servicio="telnet", categoria="claro")],
                               "Claroty")
        f = _por_titulo(h, "Protocolos de gestion sin cifrar")
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["severidad"], "Media")
        self.assertIn("telnet: 2 conductos", f[0]["evidencia"])
        self.assertTrue(f[0]["evidencia"].endswith(AVISO))
        self.assertEqual(f[0]["captura"], "exportacion Claroty")

    def test_gestion_por_puerto_aunque_categoria_otra(self):
        h = evaluar_inventario({}, [_conducto(port="23", servicio="-", categoria="otro")], "Dragos")
        self.assertEqual(len(_por_titulo(h, "Protocolos de gestion sin cifrar")), 1)

    def test_software_obsoleto(self):
        h = evaluar_inventario(_activo("HMI-1", tipo_texto="Windows XP SP3"), [], "Nozomi")
        f = _por_titulo(h, "Software o sistema operativo fuera de soporte")
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["severidad"], "Alta")
        self.assertIn("HMI-1: Windows XP", f[0]["evidencia"])
        self.assertTrue(f[0]["evidencia"].endswith(AVISO))

    def test_ip_publicas(self):
        h = evaluar_inventario({}, [_conducto(dst="8.8.8.8", port="53", servicio="dns", categoria="otro")], "Nozomi")
        f = _por_titulo(h, "Trafico con direcciones IP publicas")
        self.assertEqual(len(f), 1)
        self.assertIn("10.0.0.1 -> 8.8.8.8", f[0]["evidencia"])

    def test_privadas_y_basura_no_rompen(self):
        malos = [_conducto(src="no-es-ip", dst=""), _conducto(src=None, dst="192.168.1.1"),
                 _conducto(src="10.1.1.1", dst="224.0.0.1", port="x")]
        self.assertEqual(evaluar_inventario({}, malos, "generico"), [])

    def test_referencias_heredadas(self):
        h = evaluar_inventario(
            _activo("HMI-1", tipo_texto="Windows XP"),
            [_conducto(port="23", servicio="telnet", categoria="claro"), _conducto(dst="8.8.8.8")], "Nozomi")
        self.assertEqual([f["titulo"] for f in h], [
            "Protocolos de gestion sin cifrar en uso (segun la exportacion)",
            "Software o sistema operativo fuera de soporte (segun el inventario)",
            "Trafico con direcciones IP publicas desde la red OT (segun la exportacion)"])
        for f in h:
            self.assertIn("iec62443", f["referencias"])
            self.assertIn("mitre-ics", f["referencias"])
            self.assertTrue(f["titulo"].isascii() and f["evidencia"].isascii())


if __name__ == "__main__":
    unittest.main()
