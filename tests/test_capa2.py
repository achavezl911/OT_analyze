"""T10a (D72): ataques de capa 2 y bucles vistos en una captura pasiva. Datos sinteticos (scapy).

Cada escenario es una captura propia; un solo main() las analiza todas. Correr con
`python -m unittest discover -s tests -p test_capa2.py` o `python tests/test_capa2.py`.
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

from ot_assess import bucles
from ot_assess.model import Capture
from ot_assess.rules import ataques_l2 as r2

T_DHCP = "Mas de un servidor DHCP respondiendo en el segmento"
T_RAIZ = "Cambio del puente raiz de STP durante la captura"
T_BPDU = "BPDU enviadas por un equipo que no es switch"
T_VLAN = "Indicios de salto de VLAN (doble etiqueta o DTP)"
T_HA = "Redundancia de puerta de enlace (HSRP/VRRP) sin autenticacion"
T_RA = "Anuncios de router IPv6 no esperados"
T_MAC = "Posible inundacion de la tabla MAC del switch"
T_BUCLE = "Indicios de bucle de capa 2 o de enrutamiento"
TODOS = (T_DHCP, T_RAIZ, T_BPDU, T_VLAN, T_HA, T_RA, T_MAC, T_BUCLE)


def captura(**l2x) -> Capture:
    cap = Capture(Path("x.pcap"))
    cap.l2x = l2x
    return cap


class ReglasTest(unittest.TestCase):
    """Reglas sobre evidencia fabricada: umbrales y casos que una captura no arma facil."""

    def _titulos(self, cap):
        cap.findings.clear()
        for regla in (r2.dhcp_no_autorizado, r2.cambio_raiz_stp, r2.bpdu_equipo_final, r2.salto_vlan,
                      r2.ha_sin_autenticacion, r2.ra_no_esperado, r2.inundacion_mac, r2.bucle_l2):
            regla(cap)
        return [h["titulo"] for h in cap.findings]

    def test_sin_evidencia_no_hay_hallazgos(self):
        self.assertEqual(self._titulos(captura()), [])

    def test_un_solo_servidor_dhcp_no_dispara(self):
        e = {"ip": "10.0.0.2", "macs": {"aa"}, "ofertas": 1, "acks": 1, "clientes": {"cc"}, "t": 1.0, "frame": "1"}
        self.assertEqual(self._titulos(captura(dhcp={"10.0.0.2": e})), [])
        self.assertEqual(self._titulos(captura(dhcp={"10.0.0.2": e, "10.0.0.9": dict(e, ip="10.0.0.9")})), [T_DHCP])

    def test_solo_duplicados_o_solo_tcn_no_disparan_bucle(self):
        cap = captura(bucle={"rachas": [], "ttl_n": 0, "ttl_ejemplos": [], "ttl_primero": 0.0,
                             "i11_total": 0, "i11_max": 0, "i11_en": 0})
        cap.info = {"Number of duplicate packets": "40"}
        self.assertEqual(self._titulos(cap), [])
        cap.info, cap.stp_tc = {}, 50
        self.assertEqual(self._titulos(cap), [])
        cap.info = {"Number of duplicate packets": "40"}
        self.assertEqual(self._titulos(cap), [])              # ni juntos: hace falta un indicio propio
        cap.l2x["bucle"]["i11_max"] = bucles.ICMP11_RAFAGA
        ev = self._titulos(cap)
        self.assertEqual(ev, [T_BUCLE])
        self.assertIn("paquetes duplicados", cap.findings[0]["evidencia"])
        self.assertIn("cambios de topologia STP: 50", cap.findings[0]["evidencia"])

    def test_ttl_por_debajo_del_umbral_no_dispara(self):
        b = {"rachas": [], "ttl_n": bucles.LAZO_TTL_PAQUETES - 1, "ttl_ejemplos": [["a", "b", 64, 61, 1.0]],
             "ttl_primero": 1.0, "i11_total": 0, "i11_max": bucles.ICMP11_RAFAGA - 1, "i11_en": 0}
        self.assertEqual(self._titulos(captura(bucle=b)), [])
        self.assertEqual(self._titulos(captura(bucle=dict(b, ttl_n=bucles.LAZO_TTL_PAQUETES))), [T_BUCLE])
        self.assertEqual(self._titulos(captura(bucle=dict(b, i11_max=bucles.ICMP11_RAFAGA))), [T_BUCLE])

    def test_vigia_cuenta_ttl_solo_si_baja_de_forma_estricta(self):
        v = bucles.Vigia()
        idx = {f: i for i, f in enumerate(["ip.src", "ip.dst", "ip.proto", "ip.id", "ip.ttl", "ip.len"])}
        for k in range(bucles.LAZO_TTL_PAQUETES):
            for ttl in (64, 64, 63, 63, 62):                 # repetidos y solo tres valores: no es bucle
                v._ttl(["a", "b", "17", f"0x{k + 1:04x}", str(ttl), "40"], idx, 1.0)
        self.assertEqual(v.ttl_n, 0)
        for k in range(bucles.LAZO_TTL_PAQUETES):
            for ttl in range(64, 64 - bucles.LAZO_TTL_VISTAS, -1):
                v._ttl(["a", "b", "17", f"0x{k + 100:04x}", str(ttl), "40"], idx, 1.0)
        self.assertEqual(v.ttl_n, bucles.LAZO_TTL_PAQUETES)

    def test_inundacion_cuenta_ventana_arranque_y_paquetes_por_mac(self):
        cap = Capture(Path("x.pcap"))
        cap.ventana = [1000.0, 2000.0]

        def hosts(n, desde, tx=1):
            cap.hosts = {f"m{i}": {"first": desde + i * 10.0 / n, "tx_pkts": tx} for i in range(n)}
        hosts(r2.MAC_NUEVAS_POR_VENTANA, 1100.0)
        self.assertIsNotNone(r2._ventana_de_macs(cap))
        hosts(r2.MAC_NUEVAS_POR_VENTANA - 1, 1100.0)
        self.assertIsNone(r2._ventana_de_macs(cap))
        hosts(r2.MAC_NUEVAS_POR_VENTANA, 1000.0 + r2.ARRANQUE_S - 5)       # dentro del arranque
        self.assertIsNone(r2._ventana_de_macs(cap))
        hosts(r2.MAC_NUEVAS_POR_VENTANA, 1100.0, tx=50)                    # equipos que hablan mucho
        self.assertIsNone(r2._ventana_de_macs(cap))


@unittest.skipUnless(shutil.which("tshark") and HAY_SCAPY, "requiere tshark y scapy")
class CapasE2ETest(unittest.TestCase):
    ESCENARIOS = {
        "dhcp_dos": ("punto_t10_dhcp", {}, {T_DHCP}),
        "dhcp_uno": ("punto_t10_dhcp", {"dos": False}, set()),
        "stp_raiz": ("punto_t10_stp", {"cambio_raiz": True}, {T_RAIZ}),
        "stp_estable": ("punto_t10_stp", {}, set()),
        "stp_final": ("punto_t10_stp", {"equipo_final": True}, {T_BPDU}),
        "vlan_ambos": ("punto_t10_vlan", {}, {T_VLAN}),
        "vlan_doble": ("punto_t10_vlan", {"dtp": False}, {T_VLAN}),
        "vlan_dtp": ("punto_t10_vlan", {"doble": False}, {T_VLAN}),
        "ha": ("punto_t10_ha", {}, {T_HA}),
        "ra_host": ("punto_t10_ra", {"origen": "host", "ipv6_en_uso": True}, {T_RA}),
        "ra_router": ("punto_t10_ra", {"origen": "router", "ipv6_en_uso": True}, set()),
        "ra_router_sin_ipv6": ("punto_t10_ra", {"origen": "router"}, {T_RA}),
        "mac_inunda": ("punto_t10_macflood", {}, {T_MAC}),
        "mac_pocas": ("punto_t10_macflood", {"n": 50}, set()),
        "mac_arranque": ("punto_t10_macflood", {"n": 250, "arranque": True}, set()),
        "bucle_todo": ("punto_t10_bucle", {}, {T_BUCLE}),
        "bucle_ttl": ("punto_t10_bucle", {"icmp11": False, "tormenta": False}, {T_BUCLE}),
        "bucle_icmp": ("punto_t10_bucle", {"ttl": False, "tormenta": False}, {T_BUCLE}),
        "bucle_tormenta": ("punto_t10_bucle", {"ttl": False, "icmp11": False}, {T_BUCLE}),
        "bucle_nada": ("punto_t10_bucle", {"ttl": False, "icmp11": False, "tormenta": False}, set()),
        "bucle_ttl_corto": ("punto_t10_bucle", {"icmp11": False, "tormenta": False, "ttl_vistas": 3}, set()),
    }

    @classmethod
    def setUpClass(cls):
        import gen_pcaps as g

        from ot_assess import i18n
        from ot_assess.cli import main

        cls.tmp = Path(tempfile.mkdtemp())
        cls.pcaps = cls.tmp / "pcaps"
        cls.pcaps.mkdir()
        for nombre, (fn, kw, _) in cls.ESCENARIOS.items():
            g.guardar_t(getattr(g, fn)(**kw), cls.pcaps / f"{nombre}.pcap")
        for nombre in ("punto_a", "punto_b", "punto_c", "punto_d"):
            g.guardar(getattr(g, nombre)(), cls.pcaps / f"viejo_{nombre[-1]}.pcap")
        for nombre, fn in (("t8", g.punto_t8), ("t9", g.punto_t9)):
            g.guardar(fn(), cls.pcaps / f"viejo_{nombre}.pcap")
        g.guardar_t(g.punto_t5_periodico(), cls.pcaps / "viejo_t5.pcap")
        i18n.FALTANTES.clear()
        cls.rc = main([str(cls.pcaps), "-o", str(cls.tmp / "es"), "--cache", str(cls.tmp / "cache")])
        cls.hall = cls._csv(cls.tmp / "es" / "hallazgos.csv")
        i18n.FALTANTES.clear()
        main([str(cls.pcaps), "-o", str(cls.tmp / "en"), "--idioma", "en"])
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

    def _nuevos(self, captura):
        return {r["titulo"] for r in self.hall if r["captura"] == f"{captura}.pcap" and r["titulo"] in TODOS}

    def _fila(self, captura, titulo):
        return next(r for r in self.hall if r["captura"] == f"{captura}.pcap" and r["titulo"] == titulo)

    def test_cada_escenario_dispara_lo_esperado_y_nada_mas(self):
        self.assertEqual(self.rc, 0)
        for nombre, (_, _, esperado) in self.ESCENARIOS.items():
            self.assertEqual(self._nuevos(nombre), esperado, nombre)

    def test_dhcp_evidencia_servidores_y_clientes(self):
        ev = self._fila("dhcp_dos", T_DHCP)["evidencia"]
        self.assertIn("10.10.1.2", ev)
        self.assertIn("10.10.1.99", ev)
        self.assertIn("2 servidores y 3 clientes", ev)
        self.assertEqual(self._fila("dhcp_dos", T_DHCP)["severidad"], "Alta")

    def test_stp_cambio_de_raiz_y_bpdu_desde_equipo_final(self):
        ev = self._fila("stp_raiz", T_RAIZ)["evidencia"]
        self.assertIn("32768/00:0d:65:10:00:01", ev)
        self.assertIn("4096/00:0d:65:10:00:02", ev)
        fila = self._fila("stp_final", T_BPDU)
        self.assertIn("02:00:00:10:00:01", fila["evidencia"])
        self.assertIn("10.10.1.50", fila["evidencia"])
        self.assertEqual(fila["severidad"], "Alta")

    def test_vlan_doble_etiqueta_y_dtp(self):
        ev = self._fila("vlan_ambos", T_VLAN)["evidencia"]
        self.assertIn("doble etiqueta 802.1Q 100/200: 4 tramas", ev)
        self.assertIn("DTP desde 00:0d:65:10:00:01", ev)
        self.assertNotIn("DTP", self._fila("vlan_doble", T_VLAN)["evidencia"])
        self.assertNotIn("doble etiqueta", self._fila("vlan_dtp", T_VLAN)["evidencia"])

    def test_hsrp_texto_claro_vrrp_sin_autenticacion_y_prioridad_255(self):
        fila = self._fila("ha", T_HA)
        self.assertIn("HSRP grupo 1: autenticacion texto", fila["evidencia"])
        self.assertIn("prioridad 255 desde 10.10.1.77", fila["evidencia"])
        self.assertIn("VRRP grupo 5: autenticacion ninguna", fila["evidencia"])
        self.assertEqual(fila["severidad"], "Media")

    def test_ra_motivo_segun_el_caso(self):
        self.assertIn("no es un equipo de red", self._fila("ra_host", T_RA)["evidencia"])
        self.assertIn("la red no usa IPv6 para nada mas", self._fila("ra_router_sin_ipv6", T_RA)["evidencia"])

    def test_bucle_lista_cada_indicio_con_su_momento(self):
        ev = self._fila("bucle_todo", T_BUCLE)["evidencia"]
        self.assertIn("difusion o multicast sostenido", ev)
        self.assertIn("TTL decreciente", ev)
        self.assertIn("rafaga de ICMP time exceeded: 60 en un segundo", ev)
        self.assertIn("2023-11-14T", ev)                          # el instante de la captura sintetica
        self.assertIn("difusion", self._fila("bucle_tormenta", T_BUCLE)["evidencia"])
        self.assertNotIn("TTL", self._fila("bucle_tormenta", T_BUCLE)["evidencia"])
        self.assertEqual(self._fila("bucle_todo", T_BUCLE)["severidad"], "Alta")

    def test_inundacion_mac_en_alta(self):
        fila = self._fila("mac_inunda", T_MAC)
        self.assertEqual(fila["severidad"], "Alta")
        self.assertIn("MAC de origen nuevas en 10 s", fila["evidencia"])

    def test_las_capturas_existentes_no_disparan_nada_nuevo(self):
        viejos = {r["titulo"] for r in self.hall if r["captura"].startswith("viejo_")}
        self.assertEqual(viejos & set(TODOS), set())

    def test_referencias_en_los_cinco_marcos_sin_decir_cumple(self):
        for titulo in TODOS:
            fila = next((r for r in self.hall if r["titulo"] == titulo), None)
            if fila is None:
                continue
            self.assertNotRegex(fila["evidencia"].lower(), r"\bcumple\b")

    def test_ingles_sin_textos_faltantes(self):
        self.assertEqual(sorted(self.faltantes_en), [])

    def test_con_cache_las_salidas_son_iguales(self):
        out = self.tmp / "es2"
        self.assertEqual(self.main([str(self.pcaps), "-o", str(out), "--cache", str(self.tmp / "cache")]), 0)
        self.assertEqual((out / "hallazgos.csv").read_text(encoding="utf-8-sig"),
                         (self.tmp / "es" / "hallazgos.csv").read_text(encoding="utf-8-sig"))


if __name__ == "__main__":
    unittest.main()
