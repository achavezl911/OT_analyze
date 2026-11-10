"""T9 (D71): canales que evaden la inspeccion (DoH, DoQ, Tor, VPN, tuneles, proxies). Datos sinteticos.

Las IP de Tor de estas pruebas son ficticias (bloque de documentacion) y los archivos de relays se generan
aqui: la lista real nunca esta en el repositorio. Correr con `python -m unittest tests.test_evasion` o
`python tests/test_evasion.py`.
"""
from __future__ import annotations

import csv
import datetime
import json
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

from ot_assess import evasion as ev
from ot_assess import indicadores as ind
from ot_assess.model import Capture
from ot_assess.rules import evasion as rev

T_DNS = "DNS cifrado hacia resolvedores externos (DoH o DoQ)"
T_CANAL = "Canal anonimizador o tunel hacia Internet (Tor, VPN o proxy)"
CLI = "10.80.1.10"
TOR = "203.0.113.105"
HOY = datetime.date(2026, 11, 6)


def host(ip, purdue=""):
    return {"mac": "aa:" + ip, "ips": {ip}, "purdue": purdue, "hostnames": set()}


def flujo(src, dst, dport, l4="tcp", nbytes=100, proto=""):
    return {"src": src, "dst": dst, "dport": str(dport), "l4": l4, "pkts": 2, "bytes": nbytes,
            "first": 1_700_000_000.0, "last": 1_700_000_010.0, "proto": proto, "sports": set()}


def captura(purdue="", dns=(), sni=(), flujos=(), relays=None):
    cap = Capture(Path("x.pcap"))
    cap.hosts = {"aa:1": host(CLI, purdue)}
    cap.dns_eventos = [{"t": 1_700_000_005.0, "src": CLI, "dst": "10.80.1.53", "id": "1", "resp": False,
                        "nombre": n, "tipo": "A", "rcode": "", "respuestas": []} for n in dns]
    cap.nombres_servidor = [{"fuente": "TLS SNI", "ip": "203.0.113.60", "nombre": n, "src": CLI,
                             "t": 1_700_000_006.0} for n in sni]
    cap.flows = {(f["src"], f["dst"], f["dport"], f["l4"]): f for f in flujos}
    cap.tor_relays = relays
    return cap


def relays(*ips):
    return {"ips": frozenset(ips), "archivo": "r.txt", "fecha": "", "total": len(ips), "avisos": [], "entrada": {}}


def correr(cap):
    rev.evasion_canales(cap)
    return {f["titulo"]: f for f in cap.findings if f["titulo"] in (T_DNS, T_CANAL)}


def indicadores(cap, rel=None):
    return [(x["tipo"], x["metodo"], x["indicador"]) for x in ev.de_captura(cap, rel)]


class DohDoqTest(unittest.TestCase):
    def test_doh_por_sni_y_por_dns_con_variantes_de_cloudflare(self):
        cap = captura(dns=["mozilla.cloudflare-dns.com", "dns.quad9.net"], sni=["dns.google"])
        self.assertEqual(sorted(indicadores(cap)), [
            ("doh", "DNS", "dns.quad9.net"), ("doh", "DNS", "mozilla.cloudflare-dns.com"),
            ("doh", "SNI", "dns.google")])

    def test_estado_verificado_solo_en_google_cloudflare_y_quad9(self):
        cap = captura(dns=["dns.google", "cloudflare-dns.com", "dns.quad9.net", "doh.opendns.com", "dns.nextdns.io",
                           "doh.cleanbrowsing.org", "dns.adguard-dns.com"])
        est = {x["indicador"]: x["estado"] for x in ev.de_captura(cap)}
        self.assertEqual(sorted(k for k, v in est.items() if v == "verificado"),
                         ["cloudflare-dns.com", "dns.google", "dns.quad9.net"])
        self.assertEqual(len(est), 7)

    def test_443_hacia_ip_de_resolvedor_publico_tcp_y_udp(self):
        cap = captura(flujos=[flujo(CLI, "1.1.1.1", 443), flujo(CLI, "8.8.4.4", 443, "udp"),
                              flujo(CLI, "2606:4700:4700::1111", 443), flujo(CLI, "9.9.9.9", 80),
                              flujo(CLI, "1.1.1.2", 443)])
        self.assertEqual(sorted(i[2] for i in indicadores(cap)),
                         ["tcp/443 hacia 1.1.1.1", "tcp/443 hacia 2606:4700:4700::1111", "udp/443 hacia 8.8.4.4"])
        self.assertTrue(all(i[0] == "doh" and i[1] == "IP y puerto" for i in indicadores(cap)))

    def test_ips_publicadas_de_los_tres_proveedores(self):
        for ip in ("8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112",
                   "2001:4860:4860::8888", "2606:4700:4700::1001", "2620:fe::fe", "2620:fe::9"):
            self.assertIn(ip, ev.IPS_RESOLVEDORES, ip)

    def test_doq_udp_853_solo_hacia_internet(self):
        cap = captura(flujos=[flujo(CLI, "203.0.113.5", 853, "udp"), flujo(CLI, "10.1.1.1", 853, "udp")])
        self.assertEqual(indicadores(cap), [("doq", "puerto", "udp/853")])

    def test_dot_tcp_853_no_se_duplica(self):
        cap = captura(flujos=[flujo(CLI, "203.0.113.5", 853)])
        self.assertEqual(indicadores(cap), [])
        from ot_assess.rules import dns as rdns
        rdns.dns_dot(cap)
        self.assertEqual([f["titulo"] for f in cap.findings], ["DNS cifrado sin visibilidad (DoT)"])
        self.assertEqual(correr(cap), {})

    def test_canario_de_firefox_es_indicio_y_va_como_nota(self):
        cap = captura(dns=["use-application-dns.net"])
        self.assertEqual(indicadores(cap), [("canario_doh", "DNS", "use-application-dns.net")])
        self.assertEqual(correr(cap), {})                       # solo canario: no hay hallazgo
        cap = captura(dns=["use-application-dns.net"], sni=["dns.google"])
        h = correr(cap)[T_DNS]
        self.assertIn("dominio canario de Firefox", h["evidencia"])
        self.assertIn("no prueba que lo use", h["evidencia"])
        self.assertNotIn("DoH por DNS use-application-dns.net", h["evidencia"])

    def test_dominios_trampa_no_disparan(self):
        cap = captura(dns=["dns.google.example.net", "nodns.google", "cloudflare-dns.com.evil.net"],
                      flujos=[flujo(CLI, "198.51.100.13", 443)])
        self.assertEqual(indicadores(cap), [])


class TorTest(unittest.TestCase):
    def test_conducto_hacia_ip_de_la_lista_es_tor(self):
        cap = captura(flujos=[flujo(CLI, TOR, 443), flujo(CLI, "203.0.113.200", 443)])
        self.assertEqual(indicadores(cap, relays(TOR)), [("tor", "lista de relays Tor", TOR)])
        self.assertEqual(indicadores(cap), [])

    def test_ipv6_de_la_lista_se_normaliza(self):
        cap = captura(flujos=[flujo(CLI, "2001:db8:0:0:0:0:0:77", 443)])
        self.assertEqual(len(ev.de_captura(cap, relays("2001:db8::77"))), 1)

    def test_9001_y_9030_sin_lista_son_indicio_sin_verificar(self):
        cap = captura(flujos=[flujo(CLI, "203.0.113.4", 9001), flujo(CLI, "203.0.113.5", 9030),
                              flujo(CLI, "10.0.0.4", 9001)])
        inds = ev.de_captura(cap)
        self.assertEqual([(x["indicador"], x["estado"]) for x in inds],
                         [("tcp/9001", "sin verificar"), ("tcp/9030", "sin verificar")])
        self.assertIn("sin verificar", correr(cap)[T_CANAL]["evidencia"])

    def test_con_lista_el_puerto_por_defecto_ya_no_cuenta(self):
        cap = captura(flujos=[flujo(CLI, "203.0.113.4", 9001)])
        self.assertEqual(indicadores(cap, relays(TOR)), [])


class CargaDeRelaysTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def _w(self, nombre, contenido):
        p = self.tmp / nombre
        p.write_text(contenido if isinstance(contenido, str) else json.dumps(contenido), encoding="utf-8")
        return p

    def test_texto_una_ip_por_linea(self):
        r = ev.cargar_relays(self._w("t.txt", "# salidas\n203.0.113.1\n\n 203.0.113.2 \n2001:db8::5\nbasura\n"), HOY)
        self.assertEqual(sorted(r["ips"]), ["2001:db8::5", "203.0.113.1", "203.0.113.2"])
        self.assertEqual(r["fecha"], "")
        self.assertEqual(len(r["avisos"]), 1)
        self.assertIn("no trae fecha", r["avisos"][0])
        self.assertEqual(len(r["entrada"]["sha256"]), 64)

    def test_onionoo_summary_ipv4_e_ipv6(self):
        doc = {"relays_published": "2026-11-05 10:00:00",
               "relays": [{"n": "a", "a": ["203.0.113.1", "2001:db8::1"]}, {"n": "b", "a": ["203.0.113.2"]}]}
        r = ev.cargar_relays(self._w("s.json", doc), HOY)
        self.assertEqual(sorted(r["ips"]), ["2001:db8::1", "203.0.113.1", "203.0.113.2"])
        self.assertEqual((r["fecha"], r["avisos"]), ("2026-11-05", []))

    def test_onionoo_details_or_addresses_con_puerto(self):
        doc = {"relays_published": "2026-11-05 10:00:00",
               "relays": [{"or_addresses": ["203.0.113.1:9001", "[2001:db8::2]:9001"]},
                          {"or_addresses": ["203.0.113.3:443"]}]}
        r = ev.cargar_relays(self._w("d.json", doc), HOY)
        self.assertEqual(sorted(r["ips"]), ["2001:db8::2", "203.0.113.1", "203.0.113.3"])

    def test_lista_de_mas_de_siete_dias_avisa(self):
        doc = {"relays_published": "2026-10-20 10:00:00", "relays": [{"a": ["203.0.113.1"]}]}
        r = ev.cargar_relays(self._w("v.json", doc), HOY)
        self.assertEqual(len(r["avisos"]), 1)
        self.assertIn("2026-10-20", r["avisos"][0])
        doc["relays_published"] = "2026-10-30 00:00:00"        # exactamente 7 dias: sin aviso
        self.assertEqual(ev.cargar_relays(self._w("v2.json", doc), HOY)["avisos"], [])

    def test_formatos_invalidos_y_limites(self):
        for nombre, contenido in (("a.json", "{no es json"), ("b.json", {"x": 1}), ("c.txt", "nada\n"),
                                  ("d.json", {"relays": []})):
            with self.assertRaises(SystemExit, msg=nombre):
                ev.cargar_relays(self._w(nombre, contenido), HOY)
        with self.assertRaises(SystemExit):
            ev.cargar_relays(self.tmp / "no_existe.txt", HOY)
        viejo = ev.MAX_BYTES_RELAYS
        try:
            ev.MAX_BYTES_RELAYS = 10
            with self.assertRaisesRegex(SystemExit, "pasa de"):
                ev.cargar_relays(self._w("g.txt", "203.0.113.1\n" * 5), HOY)
        finally:
            ev.MAX_BYTES_RELAYS = viejo
        viejo = ev.MAX_RELAYS
        try:
            ev.MAX_RELAYS = 2
            r = ev.cargar_relays(self._w("h.txt", "203.0.113.1\n203.0.113.2\n203.0.113.3\n203.0.113.4\n"), HOY)
            self.assertEqual(len(r["ips"]), 2)
            self.assertTrue(any("pasa de 2 direcciones" in a for a in r["avisos"]))
        finally:
            ev.MAX_RELAYS = viejo

    def test_preparar_deja_la_entrada_para_el_entorno(self):
        class A:
            tor_relays = None
        a = A()
        self.assertIsNone(ev.preparar(a))
        self.assertIsNone(a.tor_entrada)
        a.tor_relays = str(self._w("t.txt", "203.0.113.1\n"))
        r = ev.preparar(a)
        self.assertEqual(a.tor_entrada["archivo"], "t.txt")
        self.assertEqual(set(a.tor_entrada), {"archivo", "sha256", "tamano"})
        self.assertEqual(r["total"], 1)


class VpnTunelProxyTest(unittest.TestCase):
    def test_puertos_y_protocolos_hacia_ip_publica(self):
        pub = "203.0.113.7"
        cap = captura(flujos=[
            flujo(CLI, pub, 1194, "udp"), flujo(CLI, pub, 1194), flujo(CLI, pub, 4500, "udp"),
            flujo(CLI, pub, 500, "udp"), flujo(CLI, pub, 1701, "udp"), flujo(CLI, pub, 1723),
            flujo(CLI, pub, 51820, "udp"), flujo(CLI, pub, "", "", proto="GRE"),
            flujo(CLI, "203.0.113.8", "", "", proto="ESP"), flujo(CLI, pub, 1080), flujo(CLI, pub, 3128),
            flujo(CLI, pub, 8080)])
        got = sorted((x["tipo"], x["metodo"], x["indicador"]) for x in ev.de_captura(cap))
        self.assertEqual(got, sorted([
            ("vpn", "puerto", "udp/1194"), ("vpn", "puerto", "tcp/1194"), ("vpn", "puerto", "udp/4500"),
            ("vpn", "puerto", "udp/500"), ("vpn", "puerto", "udp/1701"), ("vpn", "puerto", "tcp/1723"),
            ("vpn", "puerto", "udp/51820"), ("tunel", "protocolo", "GRE"), ("tunel", "protocolo", "ESP"),
            ("proxy", "puerto", "tcp/1080"), ("proxy", "puerto", "tcp/3128")]))

    def test_los_mismos_hacia_ip_privada_no_salen(self):
        priv = "10.99.0.7"
        cap = captura(flujos=[
            flujo(CLI, priv, 1194, "udp"), flujo(CLI, priv, 4500, "udp"), flujo(CLI, priv, 1723),
            flujo(CLI, "192.168.0.9", 1080), flujo(CLI, priv, 9001), flujo(CLI, priv, 853, "udp"),
            flujo(CLI, priv, "", "", proto="GRE"), flujo(CLI, "172.16.0.3", "", "", proto="ESP")])
        self.assertEqual(ev.de_captura(cap), [])

    def test_estados(self):
        pub = "203.0.113.7"
        cap = captura(flujos=[flujo(CLI, pub, 1194, "udp"), flujo(CLI, pub, 51820, "udp"),
                              flujo(CLI, pub, 3128), flujo(CLI, pub, 1080)])
        est = {x["indicador"]: x["estado"] for x in ev.de_captura(cap)}
        self.assertEqual(est, {"udp/1194": "verificado", "udp/51820": "sin verificar", "tcp/3128": "sin verificar",
                               "tcp/1080": "verificado"})

    def test_dominios_de_vpn_comercial_con_limite_de_etiqueta(self):
        cap = captura(dns=["api.nordvpn.com", "nordvpn.com.evil.net", "nonordvpn.com"], sni=["protonvpn.com"])
        self.assertEqual(sorted(indicadores(cap)), [("vpn", "DNS", "api.nordvpn.com"), ("vpn", "SNI", "protonvpn.com")])
        for d in ("nordvpn.com", "expressvpn.com", "surfshark.com", "privateinternetaccess.com", "mullvad.net",
                  "windscribe.com", "protonvpn.com", "tunnelbear.com", "cyberghostvpn.com", "hotspotshield.com"):
            self.assertEqual(ev.entrada_de_nombre(d)["tipo"], "vpn", d)
            self.assertEqual(ev.entrada_de_nombre(d)["estado"], "sin verificar", d)

    def test_destino_de_muchos_puertos_se_descarta_con_nota(self):
        flujos = [flujo(CLI, "203.0.113.9", 1080)] + [flujo(CLI, "203.0.113.9", 20000 + i)
                                                      for i in range(ind.PUERTOS_SERVIDOR_MAX)]
        x = ev.de_captura(captura(flujos=flujos))[0]
        self.assertEqual(x["estado"], "descartado")
        self.assertIn("101 puertos distintos: no concluyente", x["nota"])
        cap = captura(flujos=flujos)
        self.assertEqual(correr(cap), {})                       # solo descartados: sin hallazgo


class SeveridadTest(unittest.TestCase):
    def test_canal_alta_con_cliente_ot_y_media_con_cliente_it(self):
        fl = [flujo(CLI, "203.0.113.7", 1194, "udp")]
        self.assertEqual(correr(captura("Nivel 2", flujos=fl))[T_CANAL]["severidad"], "Alta")
        self.assertEqual(correr(captura("Nivel 3", flujos=fl))[T_CANAL]["severidad"], "Media")
        self.assertEqual(correr(captura("", flujos=fl))[T_CANAL]["severidad"], "Media")

    def test_dns_media_con_cliente_ot_y_baja_con_cliente_it(self):
        fl = [flujo(CLI, "1.1.1.1", 443)]
        self.assertEqual(correr(captura("Nivel 1", flujos=fl))[T_DNS]["severidad"], "Media")
        self.assertEqual(correr(captura("Nivel 3", flujos=fl))[T_DNS]["severidad"], "Baja")

    def test_el_conducto_que_llega_a_una_zona_ot_sube_la_severidad(self):
        cap = Capture(Path("exportacion X"))
        assets = {"a1": {"ips": {"10.10.3.10"}, "purdue": "Nivel 3", "nombre": "SRV"},
                  "p1": {"ips": {"10.10.1.5"}, "purdue": "Nivel 1", "nombre": "PLC"},
                  "ext": {"ips": {"203.0.113.9"}, "purdue": "Externo", "nombre": "x"}}
        conductos = [{"src": "a1", "dst": "ext", "l4": "tcp", "port": "1080", "bytes": 1, "primera": "", "ultima": ""},
                     {"src": "a1", "dst": "ext", "l4": "tcp", "port": "9001", "bytes": 1, "primera": "", "ultima": ""}]
        inds = ev.de_exportacion("exportacion X", [], conductos, assets)
        rev.hallazgo(cap, inds)
        self.assertEqual(cap.findings[0]["severidad"], "Media")
        for x in inds:                                            # el destino es de Nivel 1: el conducto cruza a OT
            x["ot"] = True
        cap = Capture(Path("exportacion X"))
        rev.hallazgo(cap, inds)
        self.assertEqual(cap.findings[0]["severidad"], "Alta")

    def test_evidencia_hasta_diez_clientes_con_tipo_metodo_destino_y_estado(self):
        cap = captura()
        cap.flows = {}
        for i in range(12):
            f = flujo(f"10.80.2.{i + 1}", "203.0.113.7", 1194, "udp", nbytes=50 + i)
            cap.flows[(f["src"], f["dst"], f["dport"], f["l4"])] = f
        h = correr(cap)[T_CANAL]
        self.assertIn("12 equipos", h["evidencia"])
        self.assertEqual(h["evidencia"].count("VPN por puerto udp/1194"), 10)
        self.assertIn(" y 2 mas", h["evidencia"])
        self.assertIn("destino Internet (203.0.113.7)", h["evidencia"])
        self.assertIn("indicador verificado", h["evidencia"])
        self.assertIn("Encrypted Client Hello", correr(captura(sni=["dns.google"]))[T_DNS]["recomendacion"])
        self.assertIn("puentes Tor ofuscados", h["recomendacion"])

    def test_los_dos_hallazgos_son_independientes(self):
        cap = captura(sni=["dns.google"], flujos=[flujo(CLI, "203.0.113.7", 1194, "udp")])
        self.assertEqual(sorted(correr(cap)), sorted([T_DNS, T_CANAL]))


class ExportacionTest(unittest.TestCase):
    ASSETS = {"a1": {"ips": {"10.10.1.10"}, "purdue": "Nivel 2", "nombre": "HMI-1"},
              "ext": {"ips": {"203.0.113.5"}, "purdue": "Externo", "nombre": "203.0.113.5"},
              "priv": {"ips": {"10.20.0.5"}, "purdue": "Nivel 3", "nombre": "SRV"},
              "tor": {"ips": {TOR}, "purdue": "Externo", "nombre": TOR},
              "dns": {"ips": {"1.1.1.1"}, "purdue": "Externo", "nombre": "1.1.1.1"}}

    @staticmethod
    def c(dst, l4, port, src="a1"):
        return {"src": src, "dst": dst, "l4": l4, "port": port, "bytes": 5, "primera": "2026-11-02",
                "ultima": "2026-11-03"}

    def test_dominios_puertos_protocolos_y_lista(self):
        dominios = [{"cliente": "a1", "servidor": "ext", "dominio": "dns.google", "bytes": 7, "fecha": "2026-11-02"},
                    {"cliente": "a1", "servidor": "ext", "dominio": "nordvpn.com.evil.net", "bytes": 7, "fecha": ""}]
        conductos = [self.c("ext", "udp", "1194"), self.c("ext", "udp", "853"), self.c("ext", "gre", ""),
                     self.c("ext", "tcp", "1080"), self.c("priv", "udp", "1194"), self.c("priv", "gre", ""),
                     self.c("tor", "tcp", "443"), self.c("dns", "tcp", "443"), self.c("ext", "tcp", "443")]
        inds = ev.de_exportacion("exportacion X", dominios, conductos, self.ASSETS, relays(TOR))
        self.assertEqual(sorted((x["tipo"], x["metodo"], x["indicador"]) for x in inds), sorted([
            ("doh", "dominio exportado", "dns.google"), ("vpn", "puerto", "udp/1194"), ("doq", "puerto", "udp/853"),
            ("tunel", "protocolo", "GRE"), ("proxy", "puerto", "tcp/1080"), ("tor", "lista de relays Tor", TOR),
            ("doh", "IP y puerto", "tcp/443 hacia 1.1.1.1")]))
        self.assertTrue(all(x["destino"] == "Internet" and x["ot"] for x in inds))
        self.assertEqual(inds[0]["activo"], "HMI-1")

    def test_sin_lista_el_9001_a_un_externo_es_indicio(self):
        inds = ev.de_exportacion("exportacion X", [], [self.c("ext", "tcp", "9001")], self.ASSETS)
        self.assertEqual([(x["tipo"], x["estado"]) for x in inds], [("tor", "sin verificar")])


class CatalogoTest(unittest.TestCase):
    def test_cada_entrada_tiene_fuente_estado_y_tipo(self):
        for e in ev.CATALOGO:
            self.assertIn(e["estado"], ("verificado", "sin verificar"), e["herramienta"])
            self.assertTrue(e["fuente"], e["herramienta"])
            self.assertIn(e["tipo"], ("doh", "doq", "tor", "vpn", "tunel", "proxy"), e["herramienta"])

    def test_catalogo_no_trae_listas_reales_de_tor(self):
        self.assertLess(len(json.dumps(ev.CATALOGO)), 20000)
        self.assertNotIn("8080", json.dumps([e["puertos"] for e in ev.CATALOGO]))


@unittest.skipUnless(shutil.which("tshark") and HAY_SCAPY, "requiere tshark y scapy")
class EvasionE2ETest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import gen_pcaps as g

        from ot_assess import i18n
        from ot_assess.cli import main

        cls.tmp = Path(tempfile.mkdtemp())
        pcaps = cls.tmp / "pcaps"
        pcaps.mkdir()
        cls.pcaps = pcaps
        g.guardar(g.punto_t9(), pcaps / "t9_it.pcap")
        g.guardar(g.punto_t9(con_ot=True), pcaps / "t9_ot.pcap")
        g.guardar(g.punto_t9_trampa(), pcaps / "t9_trampa.pcap")
        g.guardar(g.punto_a(), pcaps / "viejo_a.pcap")
        g.guardar(g.punto_b(), pcaps / "viejo_b.pcap")
        g.guardar(g.punto_c(), pcaps / "viejo_c.pcap")
        g.guardar(g.punto_d(), pcaps / "viejo_d.pcap")
        cls.relays = cls.tmp / "relays.txt"
        cls.relays.write_text(f"{g.T9_TOR}\n", encoding="utf-8")
        cls.relays_json = cls.tmp / "relays.json"
        cls.relays_json.write_text(json.dumps({"relays_published": "2020-01-01 00:00:00",
                                               "relays": [{"a": [g.T9_TOR, "2001:db8::9"]}]}), encoding="utf-8")
        i18n.FALTANTES.clear()
        cls.rc = main([str(pcaps), "-o", str(cls.tmp / "es"), "--cache", str(cls.tmp / "cache")])
        cls.sin_lista = cls._csv(cls.tmp / "es" / "evasion.csv")
        cls.hall_sin = cls._hall(cls.tmp / "es")
        cls.rc2 = main([str(pcaps), "-o", str(cls.tmp / "lista"), "--tor-relays", str(cls.relays),
                        "--cache", str(cls.tmp / "cache")])
        cls.con_lista = cls._csv(cls.tmp / "lista" / "evasion.csv")
        i18n.FALTANTES.clear()
        main([str(pcaps), "-o", str(cls.tmp / "en"), "--idioma", "en", "--tor-relays", str(cls.relays_json)])
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

    @classmethod
    def _hall(cls, carpeta):
        return [r for r in cls._csv(carpeta / "hallazgos.csv") if r["titulo"] in (T_DNS, T_CANAL)]

    def _filas(self, filas, fuente="t9_it.pcap"):
        return sorted((r["tipo"], r["metodo"], r["indicador"]) for r in filas if r["fuente"] == fuente)

    def test_columnas_de_evasion_csv(self):
        with open(self.tmp / "es" / "evasion.csv", newline="", encoding="utf-8-sig") as fh:
            self.assertEqual(next(csv.reader(fh)), ev.COLUMNAS)

    def test_doh_doq_canario_vpn_tunel_y_proxy_sin_lista(self):
        self.assertEqual(self._filas(self.sin_lista), sorted([
            ("canario_doh", "DNS", "use-application-dns.net"), ("vpn", "DNS", "nordvpn.com"),
            ("doh", "SNI", "dns.google"), ("doh", "IP y puerto", "tcp/443 hacia 1.1.1.1"),
            ("doq", "puerto", "udp/853"), ("tor", "puerto", "tcp/9001"), ("vpn", "puerto", "udp/1194"),
            ("vpn", "puerto", "udp/4500"), ("vpn", "puerto", "tcp/1723"), ("vpn", "puerto", "udp/51820"),
            ("tunel", "protocolo", "GRE"), ("tunel", "protocolo", "ESP"), ("proxy", "puerto", "tcp/1080"),
            ("proxy", "puerto", "tcp/3128")]))

    def test_dot_sigue_saliendo_solo_por_dns_dot(self):
        for r in self.sin_lista:
            self.assertNotEqual(r["indicador"], "tcp/853")
        titulos = [r["titulo"] for r in self._csv(self.tmp / "es" / "hallazgos.csv") if r["captura"] == "t9_it.pcap"]
        self.assertEqual(titulos.count("DNS cifrado sin visibilidad (DoT)"), 1)

    def test_con_lista_tor_sale_por_la_lista_y_no_por_el_puerto(self):
        tor = [(r["metodo"], r["indicador"], r["estado_indicador"]) for r in self.con_lista
               if r["fuente"] == "t9_it.pcap" and r["tipo"] == "tor"]
        self.assertEqual(tor, [("lista de relays Tor", "203.0.113.105", "verificado")])

    def test_columnas_de_una_fila(self):
        r = next(x for x in self.sin_lista if x["indicador"] == "udp/1194" and x["fuente"] == "t9_it.pcap")
        self.assertEqual((r["ip"], r["tipo"], r["herramienta_o_servicio"], r["estado_indicador"], r["destino"],
                          r["destino_ip"], r["ambito"], r["conductos"]),
                         ("10.80.1.10", "vpn", "OpenVPN", "verificado", "Internet", "203.0.113.106", "IT", "1"))
        self.assertTrue(r["primera"] and r["ultima"] and int(r["bytes"]) > 0)

    def test_severidades_por_captura(self):
        sev = {(r["captura"], r["titulo"]): r["severidad"] for r in self.hall_sin}
        self.assertEqual(sev[("t9_it.pcap", T_CANAL)], "Media")
        self.assertEqual(sev[("t9_ot.pcap", T_CANAL)], "Alta")
        self.assertEqual(sev[("t9_it.pcap", T_DNS)], "Baja")
        self.assertEqual(sev[("t9_ot.pcap", T_DNS)], "Media")

    def test_trampas_y_capturas_existentes_no_generan_hallazgos(self):
        self.assertEqual({r["captura"] for r in self.hall_sin}, {"t9_it.pcap", "t9_ot.pcap"})
        self.assertEqual([r for r in self.sin_lista if r["fuente"] not in ("t9_it.pcap", "t9_ot.pcap")], [])

    def test_ingles_sin_textos_faltantes(self):
        self.assertEqual(sorted(self.faltantes_en), [])

    def test_con_cache_las_salidas_son_iguales(self):
        out = self.tmp / "es2"
        self.assertEqual(self.main([str(self.pcaps), "-o", str(out), "--cache", str(self.tmp / "cache")]), 0)
        for n in ("evasion.csv", "hallazgos.csv"):
            self.assertEqual((out / n).read_text(encoding="utf-8-sig"),
                             (self.tmp / "es" / n).read_text(encoding="utf-8-sig"), n)

    def test_el_entorno_registra_la_lista_sin_ruta_absoluta(self):
        doc = json.loads((self.tmp / "lista" / "resultado.json").read_text(encoding="utf-8"))
        e = doc["entorno"]["tor_relays"]
        self.assertEqual(e["archivo"], "relays.txt")
        self.assertEqual(len(e["sha256"]), 64)
        self.assertNotIn(str(self.tmp), json.dumps(e))
        sin = json.loads((self.tmp / "es" / "resultado.json").read_text(encoding="utf-8"))
        self.assertIsNone(sin["entorno"]["tor_relays"])


@unittest.skipUnless(shutil.which("tshark") and HAY_SCAPY, "requiere tshark y scapy")
class ExportacionE2ETest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import gen_exports as ge

        from ot_assess.cli import main

        cls.tmp = Path(tempfile.mkdtemp())
        xd = ge.xdome(cls.tmp)
        cls.relays = cls.tmp / "relays.txt"
        cls.relays.write_text("203.0.113.7\n", encoding="utf-8")
        com = ge.xd_escribir_comunicaciones(cls.tmp / "com_t9.csv", [
            ge.xd_fila("10.10.1.10", "203.0.113.5", "From A to B", 443, "TLS 1.2", nbytes=7, tipo_a="HMI",
                       ambito="Internet (External)", dominios="cdn.example.com, dns.google"),
            ge.xd_fila("10.10.1.10", "203.0.113.6", "From A to B", 1194, "N/A", nbytes=9,
                       ambito="Internet (External)", dominios="N/A"),
            ge.xd_fila("10.10.1.10", "203.0.113.7", "From A to B", 443, "TLS 1.2", nbytes=11,
                       ambito="Internet (External)", dominios="N/A"),
            ge.xd_fila("10.10.1.10", "203.0.113.8", "From A to B", 1080, "N/A", nbytes=11,
                       ambito="Internet (External)", dominios="N/A")])
        cls.out = cls.tmp / "diag"
        cls.rc = main(["diagrama", "--activos", str(xd["inventario"]), "--enlaces", str(com), "-o", str(cls.out),
                       "--cliente", "Prueba", "--tor-relays", str(cls.relays)])

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_hallazgos_csv_y_entorno_desde_exportaciones(self):
        self.assertEqual(self.rc, 0)
        with open(self.out / "evasion.csv", newline="", encoding="utf-8-sig") as fh:
            lector = csv.DictReader(fh)
            self.assertEqual(lector.fieldnames, ev.COLUMNAS)
            filas = list(lector)
        got = sorted((r["tipo"], r["metodo"], r["indicador"]) for r in filas)
        self.assertIn(("doh", "dominio exportado", "dns.google"), got)
        self.assertIn(("tor", "lista de relays Tor", "203.0.113.7"), got)
        self.assertIn(("proxy", "puerto", "1080"), got)        # xDome no trae el transporte: solo el puerto
        self.assertIn(("vpn", "puerto", "1194"), got)
        self.assertEqual({r["tipo"] for r in filas}, {"doh", "tor", "proxy", "vpn"}, got)
        self.assertEqual({r["ip"] for r in filas}, {"10.10.1.10"})
        with open(self.out / "hallazgos.csv", newline="", encoding="utf-8-sig") as fh:
            hall = {r["titulo"]: r for r in csv.DictReader(fh) if r["titulo"] in (T_DNS, T_CANAL)}
        self.assertEqual(sorted(hall), sorted([T_DNS, T_CANAL]))
        self.assertEqual(hall[T_CANAL]["severidad"], "Alta")       # HMI = Nivel 2
        self.assertEqual(hall[T_DNS]["severidad"], "Media")


if __name__ == "__main__":
    unittest.main()
