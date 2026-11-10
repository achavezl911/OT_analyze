"""V1b (D90): fabricante, modelo y firmware que el equipo reporta en su propio protocolo OT (CIP, Modbus MEI, S7 SZL,
PROFINET DCP), sin sondeo activo. Todo sintetico: IP 192.0.2.0/24, productos inventados; solo los ID 1 (Rockwell) y 42
(Siemens) son reales. Unitarias sin tshark; extremo a extremo con tshark y scapy (pcaps de gen_pcaps.py)."""
from __future__ import annotations

import contextlib
import csv
import io
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))
sys.path.insert(0, str(RAIZ / "tests"))

try:
    import scapy  # noqa: F401
    HAY_SCAPY = True
except ImportError:
    HAY_SCAPY = False

from ot_assess import cli
from ot_assess import consolidate as cons
from ot_assess import inventario_normalizado as inv
from ot_assess.cli import main
from ot_assess.detail import identity as ident
from ot_assess.fields import DETAIL_FIELDS, DETAIL_FILTER_PARTS
from ot_assess.model import Capture

NUEVOS_CAMPOS = {
    "enip.lir.vendor", "enip.lir.name", "enip.lir.revision", "cip.id.vendor_id", "cip.id.product_name",
    "cip.id.major_rev", "cip.id.minor_rev", "modbus.object_id", "modbus.object_str_value",
    "s7comm.szl.xy11.0001.anz", "s7comm.szl.xy11.0001.index", "s7comm.szl.xy11.0001.ausbg",
    "s7comm.szl.xy11.0001.ausbe", "s7comm.szl.001c.0001.name", "s7comm.szl.001c.0002.name", "pn_dcp.service_type",
    "pn_dcp.suboption_device_devicevendorvalue", "pn_dcp.suboption_device_nameofstation",
    "pn_dcp.suboption_vendor_id", "pn_dcp.suboption_ip_ip"}


def _leer(path):
    with open(path, newline="", encoding="utf-8-sig") as fh:
        return list(csv.DictReader(fh))


def _por_ip(out):
    return {f["ips"].split(";")[0]: f for f in _leer(Path(out) / "inventario_normalizado.csv")}


class UnitariasTest(unittest.TestCase):
    def test_tabla_de_fabricantes(self):
        self.assertEqual(ident._fabricante("cip", 1), "Rockwell Automation")
        self.assertEqual(ident._fabricante("profinet", 42), "Siemens")
        self.assertEqual(ident._fabricante("cip", 9999), "CIP vendor 9999")
        self.assertEqual(ident._fabricante("profinet", 7), "PROFINET vendor 7")

    def test_version_de_rockwell_y_comparacion_numerica(self):
        self.assertEqual(ident._version(20, 11), "20.011")
        self.assertEqual(ident._version(None, 1), "")
        self.assertEqual(inv._norm("firmware", "20.011"), inv._norm("firmware", "20.11"))

    def test_campos_y_filtro_nuevos_estan_declarados(self):
        self.assertTrue(NUEVOS_CAMPOS <= set(DETAIL_FIELDS))
        self.assertIn("cip.id.vendor_id", DETAIL_FILTER_PARTS)

    def _captura(self, ots, cdp=False, ips=("192.0.2.9",)):
        c = Capture(Path("a.pcap"))
        h = c.host("02:00:00:00:00:09", "")
        h["ips"] |= set(ips)
        h["vendor"] = "OUI Fabricante"
        if cdp:
            c.identity.append({"ip": "", "mac": "02:00:00:00:00:09", "tipo": "CDP",
                               "valor": "sw / cisco WS-X", "detalle": "Version 12.2(55)SE"})
        for ip, tipo, ot in ots:
            c.identity.append({"ip": ip, "mac": "02:00:00:00:00:09", "tipo": tipo, "valor": "x", "detalle": "",
                               "ot": ot})
        return c

    def test_precedencia_cdp_luego_ot_y_fabricante_ot_sobre_oui(self):
        ot = {"fabricante": "Acme", "modelo": "PLC-1", "firmware": "1.0", "nombre": "est-1"}
        assets, _ = cons.merge_assets([self._captura([("192.0.2.9", "CIP Identity", ot)])])
        a = next(iter(assets.values()))
        self.assertEqual((a["vendor"], a["modelo"], a["firmware"], a["nombre"]), ("Acme", "PLC-1", "1.0", "est-1"))
        self.assertEqual(a["fuente_ot"]["modelo"], ("CIP Identity", "a.pcap"))
        assets, _ = cons.merge_assets([self._captura([("192.0.2.9", "CIP Identity", ot)], cdp=True)])
        a = next(iter(assets.values()))
        self.assertEqual((a["vendor"], a["modelo"], a["firmware"]), ("Acme", "cisco WS-X", "12.2(55)SE"))
        self.assertNotIn("modelo", a["fuente_ot"])

    def test_sin_identidad_ot_no_cambia_nada(self):
        assets, _ = cons.merge_assets([self._captura([], cdp=True)])
        a = next(iter(assets.values()))
        self.assertEqual((a["vendor"], a["modelo"], a["firmware"], a["fuente_ot"]),
                         ("OUI Fabricante", "cisco WS-X", "12.2(55)SE", {}))

    def test_mac_enrutada_deja_la_identidad_en_su_ip(self):
        ips = tuple(f"192.0.2.{i}" for i in range(101, 107))
        ot = {"fabricante": "Acme", "modelo": "PLC-1", "firmware": "1.0", "nombre": "est-1"}
        assets, _ = cons.merge_assets([self._captura([("192.0.2.103", "CIP Identity", ot)], ips=ips)])
        a = next(iter(assets.values()))
        self.assertEqual((a["vendor"], a["modelo"], a["firmware"]), ("OUI Fabricante", "", ""))
        self.assertEqual(a["ot_por_ip"]["192.0.2.103"]["modelo"], "PLC-1")
        self.assertNotIn("est-1", a["hostnames"])


@unittest.skipUnless(shutil.which("tshark") and HAY_SCAPY, "requiere tshark y scapy")
class CapturasE2ETest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import gen_pcaps as g
        from test_vuln_firmware import csaf
        cls.tmp = Path(tempfile.mkdtemp())
        cls.ent = cls.tmp / "pcaps"
        cls.ent.mkdir()
        g.guardar(g.punto_identidad_ot(), cls.ent / "identidad.pcap")
        cls.solo_pet = cls.tmp / "peticiones"
        cls.solo_pet.mkdir()
        g.guardar(g.punto_identidad_ot(solo_peticiones=True), cls.solo_pet / "peticiones.pcap")
        avisos = cls.tmp / "avisos"
        avisos.mkdir()
        (avisos / "a.json").write_text(json.dumps(csaf("ICSA-99-50", {"CVE-2099-15001": (9.8, [], [])})),
                                       encoding="utf-8")
        cls.avisos = avisos
        cls.out = cls.correr("o", cls.ent, "--avisos-ics", str(avisos))
        cls.inv = _por_ip(cls.out)

    @classmethod
    def correr(cls, nombre, entrada, *extra):
        out = cls.tmp / nombre
        with contextlib.redirect_stdout(io.StringIO()):
            rc = main([str(entrada), "-o", str(out), *extra])
        assert rc == 0, rc
        return out

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_cip_listidentity(self):
        f = self.inv["192.0.2.50"]
        self.assertEqual((f["fabricante"], f["modelo"], f["firmware"]),
                         ("Rockwell Automation", "1756-L71/B LOGIX5571", "20.011"))
        for campo in ("fabricante", "modelo", "firmware"):
            self.assertEqual(f[campo + "_fuente"], "captura:identidad.pcap (CIP Identity)")
        fila = [i for i in _leer(self.out / "identidad.csv") if i["tipo"] == "CIP Identity"
                and i["origen_ip"] == "192.0.2.50"]
        self.assertEqual(len(fila), 1)
        self.assertEqual(fila[0]["valor"], "1756-L71/B LOGIX5571")

    def test_la_peticion_sola_no_crea_identidad(self):
        out = self.correr("o_pet", self.solo_pet)
        tipos = {i["tipo"] for i in _leer(out / "identidad.csv")}
        self.assertFalse(tipos & {"CIP Identity", "Modbus MEI", "S7 SZL", "PROFINET DCP"}, tipos)
        for f in _leer(out / "inventario_normalizado.csv"):
            self.assertEqual((f["modelo"], f["firmware"]), ("", ""))
            self.assertNotIn("(", f["fabricante_fuente"])      # el fabricante, si hay, es el del OUI

    def test_modbus_mei_gana_al_oui_y_cruza_con_los_avisos(self):
        f = self.inv["192.0.2.51"]
        self.assertEqual((f["fabricante"], f["modelo"], f["firmware"]), ("Acme Automation", "PLC-5000", "V2.3.0"))
        self.assertEqual(f["fabricante_fuente"], "captura:identidad.pcap (Modbus MEI)")
        filas = _leer(self.out / "vulnerabilidades_firmware.csv")
        self.assertEqual([(x["ip"], x["cve"], x["estado"]) for x in filas],
                         [("192.0.2.51", "CVE-2099-15001", "version afectada")])

    def test_profinet_dcp(self):
        f = self.inv["192.0.2.60"]
        self.assertEqual((f["fabricante"], f["modelo"], f["nombre"], f["firmware"]),
                         ("Siemens", "PX-1500", "estacion-px1", ""))
        self.assertEqual(f["modelo_fuente"], "captura:identidad.pcap (PROFINET DCP)")

    def test_s7_szl(self):
        f = self.inv["192.0.2.70"]
        self.assertEqual((f["modelo"], f["nombre"], f["firmware"], f["fabricante"]),
                         ("6XX7 123-4AB56-0XY7", "PLC-SINTETICO", "V2.9.5", ""))
        self.assertEqual(f["modelo_fuente"], "captura:identidad.pcap (S7 SZL)")

    def test_mac_enrutada_solo_la_ip_que_respondio_trae_modelo(self):
        con_modelo = {ip for ip, f in self.inv.items() if ip.startswith("192.0.2.10") and f["modelo"]}
        self.assertEqual(con_modelo, {"192.0.2.103"})
        f = self.inv["192.0.2.103"]
        self.assertEqual((f["fabricante"], f["modelo"], f["firmware"]), ("Rockwell Automation", "1756-L83E", "33.015"))
        self.assertEqual(self.inv["192.0.2.101"]["fabricante"], "")

    def test_misma_mac_cdp_y_cip_el_modelo_es_el_de_cdp(self):
        f = self.inv["192.0.2.80"]
        self.assertEqual(f["modelo"], "cisco WS-C9999-24T")
        self.assertEqual(f["modelo_fuente"], "captura:identidad.pcap")
        self.assertEqual(f["fabricante"], "CIP vendor 9999")       # ID que no esta en la tabla
        self.assertEqual(f["firmware"], "1.002")

    def test_cache_previa_con_otros_campos_se_relee(self):
        cache = self.tmp / "cache"
        viejos = [x for x in DETAIL_FIELDS if x not in NUEVOS_CAMPOS]
        with mock.patch.object(cli, "DETAIL_FIELDS", viejos):
            out = self.correr("o_c0", self.ent, "--cache", str(cache))
        self.assertFalse({i["tipo"] for i in _leer(out / "identidad.csv")} & {"CIP Identity", "Modbus MEI"})
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main([str(self.ent), "-o", str(self.tmp / "o_c1"), "--cache", str(cache)])
        self.assertEqual(rc, 0)
        self.assertIn("0 de 1 capturas desde cache", buf.getvalue())
        self.assertEqual(_por_ip(self.tmp / "o_c1")["192.0.2.50"]["modelo"], "1756-L71/B LOGIX5571")
        buf = io.StringIO()      # y la identidad OT sobrevive a la cache
        with contextlib.redirect_stdout(buf):
            main([str(self.ent), "-o", str(self.tmp / "o_c2"), "--cache", str(cache)])
        self.assertIn("1 de 1 capturas desde cache", buf.getvalue())
        self.assertEqual(_por_ip(self.tmp / "o_c2")["192.0.2.50"]["modelo"], "1756-L71/B LOGIX5571")


class S7ModuloTest(unittest.TestCase):
    class _Rc:
        def __init__(self, d):
            self.d = d

        def get(self, campo):
            return self.d.get(campo, "")

    def test_mlfb_del_indice_1_y_firmware_solo_con_la_v(self):
        rc = self._Rc({"s7comm.szl.xy11.0001.index": "0x0006|0x0001|0x0007",
                       "s7comm.szl.xy11.0001.anz": "6XX7 000-0AA00-0AA0|6XX7 123-4AB56-0XY7|",
                       "s7comm.szl.xy11.0001.ausbg": "1|1|22018", "s7comm.szl.xy11.0001.ausbe": "0|0|2309"})
        self.assertEqual(ident._s7_modulo(rc), ("6XX7 123-4AB56-0XY7", "V2.9.5"))
        rc.d["s7comm.szl.xy11.0001.ausbg"] = "1|1|2"      # sin la 'V' no se inventa una version
        self.assertEqual(ident._s7_modulo(rc), ("6XX7 123-4AB56-0XY7", ""))
        self.assertEqual(ident._s7_modulo(self._Rc({})), ("", ""))

    def test_fabricante_s7_solo_con_numero_de_pedido_de_siemens(self):
        self.assertEqual(ident._fabricante_s7("6ES7 315-2EH14-0AB0"), "Siemens")
        self.assertEqual(ident._fabricante_s7("6AG1 511-1AK02-2AB0"), "Siemens")
        self.assertEqual(ident._fabricante_s7("6XX7 123-4AB56-0XY7"), "")
        self.assertEqual(ident._fabricante_s7(""), "")


if __name__ == "__main__":
    unittest.main()
