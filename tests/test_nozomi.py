"""Pruebas del perfil Nozomi con exportaciones sinteticas (D74): Assets, Nodes, Sessions, Links y CVE por nodo.

Los encabezados son los de una Guardian real; los valores son inventados (IP de documentacion, MAC locales).
"""
from __future__ import annotations

import contextlib
import csv
import datetime
import io
import json
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))

from ot_assess import avisos_cisa as ac
from ot_assess import vulnerabilidades as vu
from ot_assess.cli import main
from ot_assess.importers import importar, plataformas
from ot_assess.report.xlsx import escribir_xlsx

ASSETS = ["name", "type", "os_or_firmware", "os", "firmware_version", "ip", "vendor", "serial_number", "vlan_id",
          "mac_address", "mac_vendor", "roles", "protocols", "created_at", "last_activity_time", "is_ai_enriched"]
NODES = ["address", "roles", "ip", "vlan_id", "mac_address", "sent_bytes", "received_bytes",
         "tcp_retransmission_percent", "links_count", "protocols"]
SESSIONS = ["status", "from", "to", "protocol", "transport_protocol", "from_port", "to_port", "throughput_speed",
            "transferred_bytes", "transferred_packets", "first_activity_time", "last_activity_time"]
LINKS = ["from", "to", "protocol", "last_activity_time", "alerts", "throughput_speed", "transferred_bytes",
         "transferred_packets", "tcp_retransmission_percent", "is_learned"]
CVES = ["node_id", "cve", "cve_score", "cve_epss_score", "cwe_id", "cwe_name", "cve_creation_time", "time",
        "matching_cpes", "likelihood", "resolved", "cve_source", "cve_is_kev"]

PLC, SRV, SW, MACIP = "02:00:5e:00:00:10", "02:00:5e:00:00:01", "02:00:5e:00:00:30", "02:00:5e:10:00:01"

FILAS_ASSETS = [   # name, type, ..., ip, ..., vlan_id, mac, ..., roles, protocols
    ["plc1", "OT_device", "-", "-", "1.2", "192.0.2.10", "Acme", "", "10", PLC, "Acme", "producer", "s7comm",
     "", "", "0"],
    ["srv1", "'-", "", "", "", "192.0.2.1, 192.0.2.2", "", "", "10, 20", SRV, "", "web_server, other", "http",
     "", "", "0"],
    ["v6host", "computer", "", "Windows 10", "", "2001:db8::5", "", "", "10", "", "", "other", "", "", "", "0"],
    ["sw1", "switch", "", "", "", "", "", "", "10", SW, "", "other", "", "", "", "0"],
]
FILAS_NODES = [    # address, roles, ip, vlan_id, mac, sent, received, retrans, links, protocols
    [PLC, "producer", "192.0.2.10", "10", PLC, "1", "1", "0", "1", "s7comm"],
    [f"{MACIP}@169.254.1.1", "other", "169.254.1.1", "", MACIP, "1", "1", "0", "1", ""],
    ["224.0.0.251", "other", "224.0.0.251", "", "01:00:5e:00:00:fb", "1", "1", "0", "1", "mdns"],
    ["255.255.255.255", "other", "255.255.255.255", "", "ff:ff:ff:ff:ff:ff", "1", "1", "0", "1", "dhcp"],
    ["ff02::1:2", "other", "ff02::1:2", "", "33:33:00:01:00:02", "1", "1", "0", "1", "dhcpv6"],
    ["192.0.2.255", "other", "192.0.2.255", "", "", "1", "1", "0", "1", "netbios-ns"],
    ["192.0.2.40", "other", "192.0.2.40", "", "", "1", "1", "0", "1", ""],
]
T0, T1 = 46300.25, 46301.75      # numeros de serie de Excel
FILAS_SESSIONS = [
    ["ACTIVE", "192.0.2.1", "192.0.2.10", "s7comm", "tcp", 50123, 102, "1", 100, 10, T0, T1],
    ["CLOSED", "192.0.2.2", "192.0.2.10", "s7comm", "tcp", 50999, 102, "1", 100, 10, T0, T1],
    ["ACTIVE", f"{MACIP}@169.254.1.1", "192.0.2.1", "http", "tcp", 40000, 80, "1", 50, 5, T0, T1],
    ["ACTIVE", "192.0.2.10", "224.0.0.251", "mdns", "udp", 5353, 5353, "1", 50, 5, T0, T1],
    ["ACTIVE", "192.0.2.10", "255.255.255.255", "dhcp", "udp", 68, 67, "1", 50, 5, T0, T1],
    ["ACTIVE", "192.0.2.40", "ff02::1:2", "dhcpv6", "udp", 546, 547, "1", 50, 5, T0, T1],
    ["ACTIVE", "192.0.2.1", "192.0.2.255", "netbios-ns", "udp", 137, 137, "1", 50, 5, T0, T1],
    ["ACTIVE", SW, "01:80:c2:00:00:00", "stp", "ethernet", "", "", "1", 50, 5, T0, T1],
]
FILAS_LINKS = [["192.0.2.1", "192.0.2.10", "s7comm", T1, "0", "1", 100, 10, "0", "1"]]
FILAS_CVES = [
    [PLC, "CVE-2024-0001", "9.8", "0.5", "CWE-1", "x", T0, T0, "cpe:2.3:o:acme:plc", "1", "0", "nvd", "1"],
    [PLC, "CVE-2024-0002", "7.5", "0.1", "CWE-2", "x", T0, T0, "cpe:2.3:o:acme:plc", "1", "1", "nvd", "0"],
    ["02:00:5e:99:99:99", "CVE-2024-0003", "5.0", "0.0", "CWE-3", "x", T0, T0, "", "1", "0", "nvd", "0"],
]


def csv_en(ruta, cab, filas):
    with open(ruta, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(cab)
        w.writerows(filas)
    return str(ruta)


class NozomiBase(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.assets = csv_en(self.d / "assets.csv", ASSETS, FILAS_ASSETS)
        self.nodes = csv_en(self.d / "nodes.csv", NODES, FILAS_NODES)
        self.sessions = csv_en(self.d / "sessions.csv", SESSIONS, FILAS_SESSIONS)
        self.links = csv_en(self.d / "links.csv", LINKS, FILAS_LINKS)
        self.cves = csv_en(self.d / "cves.csv", CVES, FILAS_CVES)
        # Nodes primero: los datos de Assets deben mandar aunque se den despues
        self.imp = importar([self.nodes, self.assets], [self.sessions])

    def por_nombre(self, nombre):
        return next(a for a in self.imp.assets.values() if a["nombre"] == nombre)


class ImportacionTest(NozomiBase):
    def test_perfil_detectado_en_las_cinco(self):
        for cab in (ASSETS, NODES, SESSIONS, LINKS, CVES):
            from ot_assess.importers import perfiles as pf
            if cab is CVES:
                continue                    # el CVE por nodo no es una tabla del importador
            self.assertEqual(pf.detectar_perfil(cab), "nozomi", cab[:3])

    def test_puerto_es_el_del_servidor(self):          # (1)
        k = next(k for k in self.imp.conduits if k["dst"] == self.por_nombre("plc1")["mac"])
        self.assertEqual((k["port"], k["l4"]), ("102", "tcp"))
        self.assertEqual(self.imp.mapeos["enlaces"]["puerto"], "to_port")
        self.assertFalse(any(k["port"] in ("50123", "50999") for k in self.imp.conduits))

    def test_mac_arroba_ip(self):                      # (2)
        a = next(a for a in self.imp.assets.values() if MACIP in a["alias"])
        self.assertEqual(a["mac"], MACIP)
        self.assertIn("169.254.1.1", a["ips"])
        self.assertTrue(any(k["src"] == MACIP for k in self.imp.conduits))

    def test_multicast_y_broadcast_no_son_equipos(self):    # (3)
        dsts = {k["dst"] for k in self.imp.conduits} | {k["src"] for k in self.imp.conduits}
        for x in ("224.0.0.251", "255.255.255.255", "ff02::1:2", "192.0.2.255", "01:80:c2:00:00:00"):
            self.assertNotIn(x, dsts)
            self.assertFalse(any(x in a["ips"] or x == a["mac"] for a in self.imp.assets.values()), x)
        self.assertEqual(self.imp.resumen["difusion"],
                         {"dhcp": 1, "dhcpv6": 1, "mdns": 1, "netbios-ns": 1, "stp": 1})
        self.assertFalse(any("no coinciden" in a for a in self.imp.advertencias), self.imp.advertencias)
        self.assertTrue(any("multicast o broadcast" in a for a in self.imp.advertencias))
        self.assertEqual(self.imp.resumen["extremos_no_resueltos"], 0)

    def test_inventario_completo_sin_usar_vlan_como_id(self):    # (4) y (6)
        self.assertEqual(len(self.imp.assets), 6)
        v6 = self.por_nombre("v6host")
        self.assertEqual(v6["ips"], {"2001:db8::5"})
        sw = self.por_nombre("sw1")
        self.assertEqual((sw["mac"], sw["ips"]), (SW, set()))
        self.assertEqual(sw["tipo"], "red")
        self.assertFalse(any(k in ("10", "20", "10, 20") for k in self.imp.assets))
        srv = self.por_nombre("srv1")
        self.assertEqual(srv["ips"], {"192.0.2.1", "192.0.2.2"})
        self.assertEqual(srv["vlans"], {"10", "20"})
        # sesiones desde ambas IP del mismo equipo llegan al mismo origen
        self.assertEqual({k["src"] for k in self.imp.conduits if k["dst"] == self.por_nombre("plc1")["mac"]},
                         {srv["mac"]})

    def test_tipo_desde_roles_si_type_vacio(self):     # (5)
        self.assertEqual(self.por_nombre("srv1")["tipo"], "servidor")
        self.assertEqual(self.por_nombre("srv1")["tipo_texto"], "web_server")
        self.assertEqual(self.por_nombre("v6host")["tipo"], "host")
        self.assertEqual(self.por_nombre("plc1")["firmware"], "1.2")
        self.assertEqual(self.por_nombre("v6host")["so"], "Windows 10")

    def test_assets_y_nodes_con_la_misma_mac_son_un_activo(self):    # (6)
        plcs = [a for a in self.imp.assets.values() if PLC in a["alias"]]
        self.assertEqual(len(plcs), 1)
        self.assertEqual(plcs[0]["nombre"], "plc1")
        self.assertEqual(plcs[0]["protocolos"], {"s7comm"})

    def test_periodo_desde_numeros_de_excel(self):     # (8)
        base = datetime.datetime(1899, 12, 30)
        esperado = {"desde": (base + datetime.timedelta(days=T0)).strftime("%Y-%m-%d %H:%M"),
                    "hasta": (base + datetime.timedelta(days=T1)).strftime("%Y-%m-%d %H:%M"),
                    "zona": "sin zona horaria"}
        self.assertEqual(self.imp.resumen["periodo"], esperado)
        self.assertTrue(esperado["desde"].startswith("2026-"))

    def test_links_como_enlaces_avisa_que_no_hay_puerto(self):    # (9)
        imp = importar([self.assets, self.nodes], [self.links])
        self.assertTrue(any("links.csv" in a and "sin puerto" in a for a in imp.advertencias), imp.advertencias)
        self.assertEqual(imp.resumen["periodo"]["hasta"], self.imp.resumen["periodo"]["hasta"])
        self.assertTrue(all(not k["port"] for k in imp.conduits))
        sin = importar([self.assets, self.nodes], [self.sessions])
        self.assertFalse(any("sin puerto" in a for a in sin.advertencias))

    def test_xlsx_con_numeros(self):
        ruta = Path(escribir_xlsx(self.d / "sessions.xlsx", [("Nozomi query export", SESSIONS, FILAS_SESSIONS)]))
        imp = importar([self.assets, self.nodes], [str(ruta)])
        self.assertEqual(imp.perfil, "nozomi")
        k = next(k for k in imp.conduits if k["port"] == "102")
        self.assertEqual(k["l4"], "tcp")
        self.assertEqual(imp.resumen["periodo"], self.imp.resumen["periodo"])
        self.assertEqual(len(imp.conduits), len(self.imp.conduits))


RTR, HOST = "02:00:00:00:00:01", "02:00:00:00:00:20"
PUBLICAS = ("198.51.100.0/24", "203.0.113.0/24")      # documentacion RFC 5737 como "Internet" simulado


class EnrutamientoTest(unittest.TestCase):
    """Los equipos remotos aparecen en Nodes con la MAC del router: no se pegan a el (D74)."""

    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        p = mock.patch.object(plataformas, "_PUBLICAS_FORZADAS", PUBLICAS)
        p.start()
        self.addCleanup(p.stop)
        pub = [f"198.51.100.{i}" for i in range(1, 4)] + [f"203.0.113.{i}" for i in range(1, 4)]
        priv = [f"10.9.9.{i}" for i in range(1, 4)]
        assets = [
            ["rt1", "router", "", "", "", "192.0.2.1", "", "", "10", RTR, "", "dhcp_server", "", "", "", "0"],
            ["h1", "computer", "", "", "", "192.0.2.20", "", "", "10", HOST, "", "other", "", "", "", "0"],
        ]
        nodes = [[f"{RTR}@{ip}", "other", ip, "", RTR, "1", "1", "0", "1", "http"] for ip in pub + priv]
        nodes += [[f"{RTR}@192.0.2.1", "dhcp_server", "192.0.2.1", "", RTR, "1", "1", "0", "1", ""],
                  [f"{RTR}@fe80::1", "other", "fe80::1", "", RTR, "1", "1", "0", "1", ""],
                  [f"{HOST}@fe80::20", "other", "fe80::20", "", HOST, "1", "1", "0", "1", ""],
                  [f"{HOST}@192.0.2.20", "other", "192.0.2.20", "", HOST, "1", "1", "0", "1", ""]]
        sesiones = [["ACTIVE", "10.9.9.1", "192.0.2.1", "http", "tcp", 40000, 80, "1", 50, 5, T0, T1]]
        self.nodes_f = csv_en(self.d / "nodes.csv", NODES, nodes)
        self.assets_f = csv_en(self.d / "assets.csv", ASSETS, assets)
        self.sessions_f = csv_en(self.d / "sessions.csv", SESSIONS, sesiones)
        self.imp = importar([self.nodes_f, self.assets_f], [self.sessions_f])

    def activo(self, nombre):
        return next(a for a in self.imp.assets.values() if a["nombre"] == nombre)

    def test_router_conserva_solo_sus_ip(self):        # (1)
        rt = self.activo("rt1")
        self.assertEqual(rt["ips"], {"192.0.2.1", "fe80::1"})
        todas = set().union(*(a["ips"] for a in self.imp.assets.values()))
        self.assertFalse(any(i.startswith(("198.51.100.", "203.0.113.")) for i in todas))
        for i in ("10.9.9.1", "10.9.9.2", "10.9.9.3"):
            a = next(a for a in self.imp.assets.values() if i in a["ips"])
            self.assertIsNot(a, rt)
            self.assertEqual((a["ips"], _mac_valida(a["mac"])), ({i}, False))
        self.assertTrue(any("9 direcciones de Nodes comparten la MAC de un equipo de enrutamiento (1 MAC)" in a
                            for a in self.imp.advertencias), self.imp.advertencias)
        self.assertEqual(self.imp.resumen["mac_enrutamiento"], {"direcciones": 9, "macs": 1})

    def test_host_normal_sigue_unido(self):            # (2)
        h = self.activo("h1")
        self.assertEqual(h["ips"], {"192.0.2.20", "fe80::20"})
        self.assertEqual(len([a for a in self.imp.assets.values() if HOST in a["alias"]]), 1)

    def test_cve_del_router_sigue_en_el_router(self):  # (3)
        cve = csv_en(self.d / "cves.csv", CVES, [[RTR, "CVE-2024-0009", "9.8", "0.5", "CWE-1", "x", T0, T0,
                                                  "", "1", "0", "nvd", "0"]])
        cruces = vu.cruzar(vu.cargar(cve), self.imp.assets)
        self.assertEqual(cruces[0]["activo"], self.activo("rt1")["mac"])


def _mac_valida(t):
    return bool(re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", t))


class VulnerabilidadesNozomiTest(NozomiBase):
    def cruces(self, ruta=None):
        vulns = vu.cargar(ruta or self.cves)
        cruces = vu.cruzar(vulns, self.imp.assets)
        return vulns, cruces

    def test_cve_por_nodo(self):                       # (7)
        vulns, cruces = self.cruces()
        self.assertEqual([c["activo"] is not None for c in cruces], [True, True, False])
        self.assertEqual([v["estado"] for v in vulns], ["abierta", "mitigada", "abierta"])
        self.assertEqual([v["severidad"] for v in vulns], ["Critica", "Alta", "Media"])
        self.assertEqual(vulns[0]["epss"], 0.5)
        kev = ac.kev_efectivo(cruces, None)
        self.assertEqual([c["kev"] for c in cruces], ["si", "no", "no"])
        self.assertIsNotNone(kev)
        self.assertEqual(ac.en_kev_abiertas(cruces), 1)         # la resuelta no cuenta
        self.assertIn("1 de 3", vu.aviso_sin_activo(cruces, "cves.csv"))

    def test_cve_por_nodo_en_xlsx(self):
        ruta = Path(escribir_xlsx(self.d / "cves.xlsx", [("Nozomi query export", CVES, FILAS_CVES)]))
        _vulns, cruces = self.cruces(str(ruta))
        self.assertEqual([c["activo"] is not None for c in cruces], [True, True, False])

    def test_extremo_a_extremo(self):
        out = self.d / "salida"
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main(["diagrama", "--activos", self.assets, self.nodes, "--enlaces", self.sessions,
                       "--vulnerabilidades", self.cves, "-o", str(out), "--solo-diagramas"])
        self.assertEqual(rc, 0)
        texto = buf.getvalue()
        self.assertIn("Plataforma: Nozomi Networks", texto)
        self.assertIn("periodo de la exportacion", texto)
        self.assertIn("1 de 3 filas de vulnerabilidades no unen", texto)
        datos = json.loads((out / "importacion.json").read_text(encoding="utf-8"))
        self.assertEqual(datos["resumen"]["periodo"]["zona"], "sin zona horaria")
        self.assertEqual(datos["vulnerabilidades"]["asociadas"], 2)
        self.assertEqual(datos["vulnerabilidades"]["kev"]["abiertas_en_kev"], 1)
        with open(out / "vulnerabilidades.csv", encoding="utf-8-sig") as fh:
            filas = list(csv.DictReader(fh))
        self.assertIn("epss", filas[0])
        self.assertEqual(sorted(f["kev"] for f in filas), ["no", "no", "si"])


if __name__ == "__main__":
    unittest.main()
