"""CAMPOS1 (D141): campos minimos por salida (activos, flujos, direccionamiento, matriz de segmentacion, fuentes de
log). Sintetico.

El modo captura requiere tshark y scapy (se omite sin ellos); el resto corre sin ellos.
"""
from __future__ import annotations

import contextlib
import csv
import io
import json
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import ClassVar

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))
sys.path.insert(0, str(RAIZ / "tests"))

import gen_exports
from test_cobertura_captura import LEE_CAPTURAS, escribir
from test_estado1 import _xlsx_hojas
from test_rm1 import _error, _perfil
from test_zonas import _inventario_xdome

from ot_assess import campos_minimos as cm
from ot_assess import i18n
from ot_assess.cli import main as main_completo
from ot_assess.cli_diagrama import main as main_diagrama
from ot_assess.model import Capture

ISO = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
T1, T2, T3, T4 = 1_700_000_000, 1_700_000_100, 1_700_001_000, 1_700_001_500


def _csv(path):
    with open(path, newline="", encoding="utf-8-sig") as fh:
        return list(csv.DictReader(fh))


def _iso(ts):
    from datetime import datetime, timezone
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


ZONAS = [{"nombre": "Corp", "redes": ["10.0.0.0/24"], "dominio": "IT"},
         {"nombre": "Campo", "redes": ["10.1.0.0/24"]},
         {"nombre": "Borde", "redes": ["10.2.0.0/24"], "dmz": True},
         {"nombre": "Mix", "redes": ["10.3.0.0/24"]}]


# --------------------------------------------------------------------------- #
# Perfil
# --------------------------------------------------------------------------- #

class PerfilTest(unittest.TestCase):
    def test_valido_y_normalizado(self):
        p = _perfil({"zonas": ZONAS, "campos_minimos": {
            "sitio": "Planta_1-A", "as_of": "2026-03-01T12:00:00+02:00",
            "duenos": [{"red": "10.0.0.0/24", "dueno": " Redes "}],
            "politica_esperada": [{"origen": "Corp", "destino": "*", "politica": " denegar "},
                                  {"origen": "*", "destino": "*", "politica": "x"}]}})
        c = p["campos_minimos"]
        self.assertEqual(c["sitio"], "Planta_1-A")
        self.assertEqual(c["as_of"], "2026-03-01T10:00:00Z")
        self.assertEqual(c["duenos"], [{"red": "10.0.0.0/24", "dueno": "Redes"}])
        self.assertEqual(c["politica_esperada"][0], {"origen": "Corp", "destino": "*", "politica": "denegar"})
        self.assertEqual(p["zonas"][0]["dominio"], "IT")
        self.assertEqual(_perfil({"campos_minimos": {}})["campos_minimos"], {})
        self.assertEqual(_perfil({"campos_minimos": {"as_of": "2026-03-01T12:00:00Z"}})["campos_minimos"]["as_of"],
                         "2026-03-01T12:00:00Z")

    def test_dominio_de_zona_solo_se_conserva_con_la_clave(self):
        self.assertNotIn("dominio", _perfil({"zonas": ZONAS})["zonas"][0])
        self.assertEqual(_perfil({"zonas": ZONAS, "campos_minimos": {}})["zonas"][0]["dominio"], "IT")

    def test_cada_error(self):
        pol = {"origen": "Corp", "destino": "Campo", "politica": "p"}
        casos = [("lista", "debe ser un objeto"), ({"otra": 1}, "clave desconocida"),
                 ({"sitio": ""}, "sitio"), ({"sitio": "a b"}, "sitio"), ({"sitio": "x" * 41}, "sitio"),
                 ({"sitio": 3}, "sitio"),
                 ({"as_of": "2026-03-01"}, "as_of"), ({"as_of": "2026-03-01T12:00:00"}, "as_of"),
                 ({"as_of": "2026-13-01T12:00:00Z"}, "as_of"), ({"as_of": 5}, "as_of"),
                 ({"as_of": "2026-03-01T12:00:00+25:00"}, "as_of"),
                 ({"duenos": "x"}, "duenos"), ({"duenos": [{"red": "10.0.0.0/24"}]}, "necesita"),
                 ({"duenos": [{"red": "10.0.0.1/24", "dueno": "a"}]}, "CIDR"),
                 ({"duenos": [{"red": "nada", "dueno": "a"}]}, "CIDR"),
                 ({"duenos": [{"red": "10.0.0.0/24", "dueno": ""}]}, "1 a 100"),
                 ({"duenos": [{"red": "10.0.0.0/24", "dueno": "x" * 101}]}, "1 a 100"),
                 ({"duenos": [{"red": "10.0.0.0/24", "dueno": "a", "otro": 1}]}, "clave desconocida"),
                 ({"duenos": [{"red": "10.0.0.0/24", "dueno": "a"}] * 2}, "repetida"),
                 ({"duenos": [{"red": f"10.{i // 256}.{i % 256}.0/24", "dueno": "a"} for i in range(501)]}, "0 a 500"),
                 ({"politica_esperada": "x"}, "politica_esperada"),
                 ({"politica_esperada": [{"origen": "Corp", "destino": "Campo"}]}, "necesita"),
                 ({"politica_esperada": [{**pol, "origen": "Otra"}]}, "no es una zona del perfil"),
                 ({"politica_esperada": [{**pol, "destino": "Otra"}]}, "no es una zona del perfil"),
                 ({"politica_esperada": [{**pol, "politica": ""}]}, "1 a 60"),
                 ({"politica_esperada": [{**pol, "politica": "x" * 61}]}, "1 a 60"),
                 ({"politica_esperada": [pol, pol]}, "repetido"),
                 ({"politica_esperada": [pol] * 2501}, "0 a 2500")]
        for v, frag in casos:
            with self.subTest(v=v if len(str(v)) < 80 else str(v)[:80]):
                self.assertIn(frag, _error({"zonas": ZONAS, "campos_minimos": v}))
        for v in ("OT ", "ot", "Planta", 3, ""):
            with self.subTest(dominio=v):
                zs = [{"nombre": "Z", "redes": ["10.9.0.0/24"], "dominio": v}]
                self.assertIn("IT, OT o DMZ", _error({"zonas": zs, "campos_minimos": {}}))
                self.assertIn("IT, OT o DMZ", _error({"zonas": zs}))      # se valida aunque falte la clave
        self.assertIn("no es una zona del perfil", _error({"campos_minimos": {"politica_esperada": [
            {"origen": "Corp", "destino": "*", "politica": "x"}]}}))      # sin zonas en el perfil


# --------------------------------------------------------------------------- #
# Dominio
# --------------------------------------------------------------------------- #

class DominioTest(unittest.TestCase):
    PERFIL: ClassVar[dict] = {"zonas": [{"nombre": "Corp", "redes": ["10.0.0.0/24"], "dominio": "IT"},
                        {"nombre": "Borde", "redes": ["10.2.0.0/24"], "dmz": True},
                        {"nombre": "OtraOT", "redes": ["10.7.0.0/24"], "dominio": "OT", "dmz": True},
                        {"nombre": "Libre", "redes": ["10.8.0.0/24"]}]}

    def d(self, zona, purdue=""):
        return cm.dominio_de({"zona_asignada": zona, "purdue": purdue}, self.PERFIL)

    def test_zona_declarada_gana_a_dmz_y_a_purdue(self):
        self.assertEqual(self.d("Corp", "Nivel 1"), "IT")
        self.assertEqual(self.d("OtraOT", "Nivel 4"), "OT")

    def test_dmz_gana_a_purdue(self):
        self.assertEqual(self.d("Borde", "Nivel 1"), "DMZ")

    def test_por_purdue(self):
        for nivel, esperado in (("Nivel 4", "IT"), ("Nivel 5", "IT"), ("Nivel 3.5", "DMZ"), ("Nivel 3", "OT"),
                                ("Nivel 2", "OT"), ("Nivel 1", "OT"), ("Nivel 0", "OT"), ("Nivel 1-2", "OT"),
                                ("Nivel 2-3", "OT"), ("Nivel 3-4", "sin dato"), ("Infraestructura", "sin dato"),
                                ("", "sin dato"), ("Nivel 7", "sin dato"), ("Externo", "sin dato")):
            with self.subTest(nivel=nivel):
                self.assertEqual(self.d("Libre", nivel), esperado)
                self.assertEqual(self.d("Subred 10.9.0.0/24", nivel), esperado)

    def test_sin_activo(self):
        self.assertEqual(cm.dominio_de(None, self.PERFIL), "sin dato")
        self.assertEqual(cm.dominio_de({}, {}), "sin dato")


# --------------------------------------------------------------------------- #
# Calculo sobre un modelo armado a mano
# --------------------------------------------------------------------------- #

def _activo(mac, ip, zona, purdue="", ultima=""):
    return {"mac": mac, "ips": {ip}, "zona_asignada": zona, "origen_zona": "perfil", "purdue": purdue,
            **({"ultima": ultima} if ultima else {})}


def _conducto(src, dst, l4, port, servicio, nbytes, pkts, caps=("c1.pcap",)):
    return {"src": src, "dst": dst, "l4": l4, "port": port, "servicio": servicio, "bytes": nbytes, "pkts": pkts,
            "capturas": set(caps)}


def _flujo(src, dst, l4, dport, first, last):
    return {"src": src, "dst": dst, "l4": l4, "dport": dport, "first": first, "last": last}


def _modelo(campos=None, **extra):
    perfil = {"sitio": "Sitio del perfil", "zonas": [dict(z) for z in ZONAS],
              "campos_minimos": campos if campos is not None else {}}
    activos = [_activo("m1", "10.0.0.1", "Corp", "Nivel 4"), _activo("m2", "10.1.0.10", "Campo", "Nivel 1"),
               _activo("m3", "10.2.0.5", "Borde"), _activo("m4", "10.3.0.5", "Mix", "Nivel 1"),
               _activo("m5", "10.3.0.6", "Mix", "Nivel 4"),
               _activo("m6", "10.4.0.5", "Subred 10.4.0.0/24"),
               _activo("m7", "10.5.0.5", "Subred 10.5.0.0/24", "Nivel 4")]
    assets = {a["mac"]: a for a in activos}
    c1, c2 = Capture(Path("c1.pcap")), Capture(Path("c2.pcap"))
    for c, f in ((c1, _flujo("10.0.0.1", "10.1.0.10", "tcp", "502", T1, T2)),
                 (c2, _flujo("10.0.0.1", "10.1.0.10", "tcp", "502", T3, T4)),
                 (c1, _flujo("10.1.0.10", "10.2.0.5", "udp", "514", T2, T3)),
                 (c1, _flujo("10.1.0.10", "10.2.0.5", "udp", "162", T1, T1))):
        c.flows[(f["src"], f["dst"], f["dport"], f["l4"])] = f
    c1.ventana, c2.ventana = [T1, T3], [T3, T4]
    conductos = [_conducto("10.0.0.1", "10.1.0.10", "tcp", "502", "Modbus", 300, 6, ("c1.pcap", "c2.pcap")),
                 _conducto("10.0.0.1", "10.2.0.5", "tcp", "443", "TLS", 10, 1),
                 _conducto("10.1.0.10", "10.4.0.5", "tcp", "44818", "EtherNet/IP", 20, 2),
                 _conducto("10.0.0.1", "10.5.0.5", "tcp", "445", "SMB", 30, 3),
                 _conducto("10.1.0.10", "10.2.0.5", "udp", "514", "Syslog", 1000, 10),
                 _conducto("10.1.0.10", "10.2.0.5", "udp", "162", "Trampas SNMP", 500, 5),
                 _conducto("10.1.0.10", "8.8.8.8", "tcp", "6514", "Syslog TLS", 7, 1),
                 _conducto("10.1.0.10", "10.0.0.1", "udp", "5000", "otro", 99, 9)]
    inventario = {"filas": [{"id": "A-1", "campos": {"ips": {"valor": "10.0.0.1"}}},
                            {"id": "A-2", "campos": {"ips": {"valor": "10.1.0.10;10.1.0.11"}}},
                            {"id": "A-3", "campos": {"ips": {"valor": "10.2.0.5"}}},
                            {"id": "A-9", "campos": {"ips": {"valor": "10.99.0.1"}}}]}
    zonas = {"filas": [{"zona": z, "origen": "perfil"} for z in ("Corp", "Campo", "Borde", "Mix")]
             + [{"zona": "Subred 10.4.0.0/24", "origen": "subred"}, {"zona": "Subred 10.5.0.0/24", "origen": "subred"}]}
    dr = {"filas": [{"red": r} for r in ("10.0.0.0/24", "10.1.0.0/24", "10.2.0.0/24", "10.3.0.0/24", "10.4.0.0/24",
                                         "10.0.5.0/24")]}
    fl = {"filas": [{"ips": ["10.0.0.1"]}, {"ips": ["10.1.0.10", "10.1.0.11"]}, {"ips": ["10.2.0.5"]}]}
    base = {"perfil": perfil, "assets": assets, "conduits": conductos, "caps": [c1, c2],
            "inventario_normalizado": inventario, "direccionamiento": dr, "fuentes_log": fl, "zonas": zonas,
            "manifiesto": {}}
    base.update(extra)
    return SimpleNamespace(**base)


def _tabla(res, archivo):
    cab, filas = cm.calcular(res)["tablas"][archivo]
    return [dict(zip(cab, f)) for f in filas]


class CalculoTest(unittest.TestCase):
    def setUp(self):
        i18n.usar("es")
        self.addCleanup(i18n.usar, "es")

    def test_activos_primera_y_ultima_vez_exactas_y_dominio(self):
        f = _tabla(_modelo(), "inventario_normalizado.csv")
        self.assertEqual([(x["sitio"], x["dominio"], x["primera_vez_visto"], x["ultima_vez_visto"]) for x in f],
                         [("Sitio del perfil", "IT", _iso(T1), _iso(T4)),
                          ("Sitio del perfil", "OT", _iso(T1), _iso(T4)),
                          ("Sitio del perfil", "DMZ", _iso(T1), _iso(T3)),
                          ("Sitio del perfil", "sin dato", "", "")])
        self.assertTrue(all(x["as_of"] == _iso(T4) for x in f))

    def test_sitio_de_la_clave_y_as_of_declarado(self):
        res = _modelo({"sitio": "S9", "as_of": "2026-03-01T18:00:00Z"})
        f = _tabla(res, "inventario_normalizado.csv")[0]
        self.assertEqual((f["sitio"], f["as_of"]), ("S9", "2026-03-01T18:00:00Z"))
        sin = _modelo()
        sin.perfil.pop("sitio")
        self.assertEqual(_tabla(sin, "inventario_normalizado.csv")[0]["sitio"], "")

    def test_ultima_vez_de_la_plataforma_en_modo_diagrama(self):
        res = _modelo(caps=[])
        res.assets["m1"]["ultima"] = "2026-02-01 10:11:12"
        res.assets["m2"]["ultima"] = "no es fecha"
        f = _tabla(res, "inventario_normalizado.csv")
        self.assertEqual((f[0]["primera_vez_visto"], f[0]["ultima_vez_visto"]), ("", "2026-02-01T10:11:12Z"))
        self.assertEqual((f[1]["primera_vez_visto"], f[1]["ultima_vez_visto"]), ("", ""))
        self.assertTrue(ISO.match(f[0]["as_of"]))          # sin captura: la hora de la corrida

    def test_flujos_ids_tiempos_dataset_y_cruce(self):
        res = _modelo({"sitio": "S"}, manifiesto={"filas": [
            {"dataset_id": "DS-A", "archivos": ["c1.pcap"]}, {"dataset_id": "DS-B", "archivos": ["c2.pcap", "c3.pcap"]},
            {"dataset_id": "DS-C", "archivos": []}]})
        f = _tabla(res, "comunicaciones.csv")
        self.assertEqual([x["cruza_it_ot"] for x in f],
                         ["si", "no", "sin dato", "no", "no", "no", "sin dato", "si"])
        m = f[0]
        self.assertEqual((m["origen_id"], m["destino_id"], m["primera_vez_visto"], m["ultima_vez_visto"]),
                         ("A-1", "A-2", _iso(T1), _iso(T4)))
        self.assertEqual((m["dataset_id"], m["origen_dominio"], m["destino_dominio"]), ("DS-A;DS-B", "IT", "OT"))
        self.assertEqual((f[1]["destino_id"], f[1]["destino_dominio"], f[1]["dataset_id"]), ("A-3", "DMZ", "DS-A"))
        self.assertEqual((f[2]["destino_id"], f[2]["destino_dominio"]), ("", "sin dato"))     # sin activo en el inventario
        self.assertEqual((f[4]["primera_vez_visto"], f[4]["ultima_vez_visto"]), (_iso(T2), _iso(T3)))
        self.assertEqual((f[5]["primera_vez_visto"], f[5]["ultima_vez_visto"]), (_iso(T1), _iso(T1)))
        self.assertEqual((f[6]["origen_dominio"], f[6]["destino_dominio"], f[6]["destino_id"]), ("OT", "sin dato", ""))
        self.assertEqual((f[1]["primera_vez_visto"], f[1]["ultima_vez_visto"]), ("", ""))     # sin flujo en la captura

    def test_sin_manifiesto_el_dataset_va_vacio(self):
        self.assertEqual({x["dataset_id"] for x in _tabla(_modelo(), "comunicaciones.csv")}, {""})

    def test_direccionamiento_dueno_y_dominio(self):
        res = _modelo({"duenos": [{"red": "10.0.0.0/16", "dueno": "TI"}, {"red": "10.0.0.0/24", "dueno": "Redes"},
                                  {"red": "10.1.0.0/24", "dueno": "Planta"}]})
        f = _tabla(res, "direccionamiento_ip.csv")
        self.assertEqual([("", x["dominio"], x["dueno"]) for x in f],
                         [("", "IT", "Redes"), ("", "OT", "Planta"), ("", "DMZ", "PENDIENTE"),
                          ("", "mixto", "PENDIENTE"), ("", "sin dato", "PENDIENTE"), ("", "sin dato", "TI")])
        self.assertEqual({x["sitio"] for x in f}, {"Sitio del perfil"})

    def test_fuentes_log_destinos_y_volumen(self):
        f = _tabla(_modelo(), "fuentes_log.csv")
        self.assertEqual((f[0]["destinos"], f[0]["volumen_bytes"], f[0]["volumen_paquetes"]), ("", 0, 0))
        self.assertEqual((f[1]["destinos"], f[1]["volumen_bytes"], f[1]["volumen_paquetes"]),
                         ("8.8.8.8:6514;10.2.0.5:162;10.2.0.5:514", 1507, 16))
        self.assertEqual((f[2]["destinos"], f[2]["volumen_bytes"], f[2]["volumen_paquetes"]), ("", 0, 0))

    def test_matriz_observados_no_observados_y_politica(self):
        res = _modelo({"politica_esperada": [
            {"origen": "Corp", "destino": "Campo", "politica": "permitir Modbus"},
            {"origen": "Corp", "destino": "*", "politica": "denegar"},
            {"origen": "*", "destino": "Borde", "politica": "solo syslog"},
            {"origen": "*", "destino": "*", "politica": "base"}]})
        filas = cm.calcular(res)["matriz"]
        m = {(f[0], f[1]): f for f in filas}
        n = 7        # 6 zonas de la tabla + Internet
        self.assertEqual(len(filas), n * n)
        self.assertEqual(m[("Corp", "Campo")], ["Corp", "Campo", "si", "Modbus", 1, 300, "permitir Modbus"])
        self.assertEqual(m[("Corp", "Borde")], ["Corp", "Borde", "si", "TLS", 1, 10, "denegar"])       # exacta > "*"
        self.assertEqual(m[("Campo", "Borde")], ["Campo", "Borde", "si", "Syslog;Trampas SNMP", 2, 1500,
                                                 "solo syslog"])
        self.assertEqual(m[("Mix", "Mix")], ["Mix", "Mix", "no", "", 0, 0, "base"])
        self.assertEqual(m[("Campo", "Internet")][2:6], ["si", "Syslog TLS", 1, 7])
        self.assertEqual(sum(1 for f in filas if f[2] == "si"), 7)
        self.assertEqual(cm.calcular(res)["json"]["conteos"]["pares_observados"], 7)
        sin = cm.calcular(_modelo())["matriz"]
        self.assertEqual({f[6] for f in sin}, {"sin declarar"})

    def test_matriz_grande_solo_observados_o_con_politica(self):
        res = _modelo({"politica_esperada": [{"origen": "Mix", "destino": "Corp", "politica": "p"},
                                             {"origen": "*", "destino": "Corp", "politica": "q"}]})
        res.zonas["filas"] += [{"zona": f"Subred 10.{100 + i}.0.0/24", "origen": "subred"} for i in range(100)]
        with contextlib.redirect_stdout(io.StringIO()) as sal:
            filas = cm.calcular(res)["matriz"]
            cm.calcular(res)
        self.assertEqual(sal.getvalue().count("campos_minimos: 107 zonas"), 1)      # un solo aviso por corrida
        self.assertEqual(len(filas), 7 + 1)          # 7 observados + la exacta Mix -> Corp
        self.assertIn(["Mix", "Corp", "no", "", 0, 0, "p"], filas)

    def test_ampliar_agrega_al_final_y_sin_clave_no_toca(self):
        res = _modelo()
        tablas = [("inventario_normalizado.csv", "H", ["id"], [["A-1"], ["A-2"], ["A-3"], ["A-9"]]),
                  ("comunicaciones.csv", "C", ["origen"], [["x"]] * 8), ("otra.csv", "O", ["a"], [["1"]])]
        out = cm.ampliar(res, tablas)
        self.assertEqual(out[0][2], ["id", *cm.COL_INVENTARIO])
        self.assertEqual(out[0][3][0][0], "A-1")
        self.assertEqual(out[1][2], ["origen", *cm.COL_COMUNICACIONES])
        self.assertEqual(out[2], tablas[2])
        self.assertEqual((out[-1][0], out[-1][1]), ("matriz_segmentacion.csv", "Matriz de segmentacion"))
        otra = _modelo()
        del otra.perfil["campos_minimos"]
        self.assertIs(cm.ampliar(otra, tablas), tablas)
        # una tabla cuyas filas no calzan con el modelo se deja como esta
        self.assertEqual(cm.ampliar(res, [("comunicaciones.csv", "C", ["origen"], [["x"]])])[0][2], ["origen"])

    def test_ingles_valores_fijos(self):
        i18n.usar("en")
        res = _modelo({"politica_esperada": []})
        f = _tabla(res, "comunicaciones.csv")
        self.assertEqual({x["cruza_it_ot"] for x in f}, {"yes", "no", "no data"})
        self.assertEqual(_tabla(res, "direccionamiento_ip.csv")[3]["dominio"], "mixed")
        self.assertEqual(_tabla(res, "direccionamiento_ip.csv")[1]["dueno"], "PENDING")
        self.assertEqual({f[2] for f in cm.calcular(res)["matriz"]}, {"yes", "no"})
        self.assertEqual({f[6] for f in cm.calcular(res)["matriz"]}, {"not declared"})
        self.assertEqual(i18n.t("Matriz de segmentacion"), "Segmentation matrix")
        for c in (*cm.COL_INVENTARIO, *cm.COL_COMUNICACIONES, *cm.COL_DIRECCIONAMIENTO, *cm.COL_FUENTES,
                  *cm.COL_MATRIZ):
            i18n.t(c)
        self.assertEqual(i18n.FALTANTES, set())
        self.assertEqual([i18n.t(c) for c in ("origen_id", "cruza_it_ot", "dueno", "volumen_bytes")],
                         ["source_id", "crosses_it_ot", "owner", "volume_bytes"])

    def test_json(self):
        j = cm.para_json(_modelo({"sitio": "S1"}))
        self.assertEqual((j["sitio"], j["as_of"]), ("S1", _iso(T4)))
        self.assertEqual(j["conteos"], {"activos_con_primera_vez": 3, "flujos_cruzan_it_ot": 2,
                                        "subredes_por_dominio": {"DMZ": 1, "IT": 1, "OT": 1, "mixto": 1,
                                                                 "sin dato": 2},
                                        "pares_observados": 7})
        self.assertEqual(j["tablas"], ["comunicaciones.csv", "direccionamiento_ip.csv", "fuentes_log.csv",
                                       "inventario_normalizado.csv", "matriz_segmentacion.csv"])


# --------------------------------------------------------------------------- #
# Corridas completas
# --------------------------------------------------------------------------- #

def _udp(src_mac, dst_mac, ip_s, ip_d, sport, dport, t, carga=b"x" * 20):
    from scapy.all import IP, UDP, Ether, Raw
    p = Ether(src=src_mac, dst=dst_mac) / IP(src=ip_s, dst=ip_d) / UDP(sport=sport, dport=dport) / Raw(carga)
    p.time = t
    return p


def _tcp(src_mac, dst_mac, ip_s, ip_d, sport, dport, t, flags="PA", carga=b"x" * 12):
    from scapy.all import IP, TCP, Ether, Raw
    p = Ether(src=src_mac, dst=dst_mac) / IP(src=ip_s, dst=ip_d) / TCP(sport=sport, dport=dport, flags=flags) / Raw(carga)
    p.time = t
    return p


MAC_A, MAC_B, MAC_C, MAC_D = (f"02:00:00:d1:00:0{i}" for i in range(1, 5))
IP_A, IP_B, IP_C, IP_D = "10.10.1.5", "10.20.1.10", "10.30.1.50", "10.20.1.77"
PERFIL_CAP = {"zonas": [{"nombre": "Corp", "redes": ["10.10.1.0/24"], "dominio": "IT"},
                        {"nombre": "Planta", "redes": ["10.20.1.0/24"]},
                        {"nombre": "Borde", "redes": ["10.30.1.0/24"], "dmz": True}]}


class CapturaTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        a, b = cls.tmp / "pA", cls.tmp / "pB"
        # pA: A habla Modbus con B y envia syslog a C; D habla con B por UDP. pB: Modbus otra vez y trampa de B a C
        escribir([_tcp(MAC_A, MAC_B, IP_A, IP_B, 40000, 502, T1), _tcp(MAC_B, MAC_A, IP_B, IP_A, 502, 40000, T1 + 1),
                  _udp(MAC_A, MAC_C, IP_A, IP_C, 5514, 514, T1 + 2), _udp(MAC_A, MAC_C, IP_A, IP_C, 5514, 514, T1 + 9),
                  _udp(MAC_D, MAC_B, IP_D, IP_B, 6000, 5000, T1 + 3)], a / "a1.pcap")
        escribir([_tcp(MAC_A, MAC_B, IP_A, IP_B, 40001, 502, T3), _tcp(MAC_B, MAC_A, IP_B, IP_A, 502, 40001, T3 + 1),
                  _udp(MAC_B, MAC_C, IP_B, IP_C, 5162, 162, T3 + 5), _udp(MAC_B, MAC_C, IP_B, IP_C, 5162, 162, T4)],
                 b / "b1.pcap")
        cls.n = 0

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def setUp(self):
        i18n.usar("es")
        self.addCleanup(i18n.usar, "es")

    def correr(self, extra=None, **perfil):
        type(self).n += 1
        p = self.tmp / f"perfil{self.n}.json"
        cfg = {"version": 1, "cliente": "ACME", "marcos": [{"clave": "iec62443"}], **PERFIL_CAP, **perfil}
        if extra is not None:
            cfg["campos_minimos"] = extra
        p.write_text(json.dumps(cfg), encoding="utf-8")
        out = self.tmp / f"out{self.n}"
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main_completo([str(self.tmp / "pA"), str(self.tmp / "pB"), "-o", str(out),
                                            "--perfil", str(p)]), 0)
        i18n.usar("es")
        return out

    @LEE_CAPTURAS
    def test_captura_completa(self):
        man = {"sitios": ["S1"], "datasets": [{"sitio": "S1", "punto": "a1.pcap"}, {"sitio": "S1", "punto": "b1.pcap"}]}
        o = self.correr({"sitio": "PLANTA-1"}, manifiesto=man)
        ds = {f["punto_o_archivos"]: f["dataset_id"] for f in _csv(o / "manifiesto.csv")}
        self.assertEqual(len(ds), 2)
        # activos
        inv = _csv(o / "inventario_normalizado.csv")
        por_ip = {f["ips"]: f for f in inv}
        self.assertEqual(list(inv[0])[-5:], cm.COL_INVENTARIO)
        a, b, c, d = (por_ip[i] for i in (IP_A, IP_B, IP_C, IP_D))
        self.assertEqual((a["sitio"], a["dominio"], a["primera_vez_visto"], a["ultima_vez_visto"]),
                         ("PLANTA-1", "IT", _iso(T1), _iso(T3 + 1)))
        self.assertEqual((b["dominio"], b["primera_vez_visto"], b["ultima_vez_visto"]), ("OT", _iso(T1), _iso(T4)))
        self.assertEqual((c["dominio"], c["primera_vez_visto"], c["ultima_vez_visto"]), ("DMZ", _iso(T1 + 2), _iso(T4)))
        self.assertEqual((d["dominio"], d["primera_vez_visto"], d["ultima_vez_visto"]),
                         ("sin dato", _iso(T1 + 3), _iso(T1 + 3)))
        self.assertEqual({f["as_of"] for f in inv}, {_iso(T4)})                  # el ultimo paquete de la corrida
        # flujos
        com = {(f["origen_ip"], f["destino_ip"], f["puerto"]): f for f in _csv(o / "comunicaciones.csv")}
        self.assertEqual(list(_csv(o / "comunicaciones.csv")[0])[-8:], cm.COL_COMUNICACIONES)
        mb = com[(IP_A, IP_B, "502")]
        self.assertEqual((mb["origen_id"], mb["destino_id"]), (a["id"], b["id"]))
        self.assertEqual((mb["origen_dominio"], mb["destino_dominio"], mb["cruza_it_ot"]), ("IT", "OT", "si"))
        self.assertEqual(mb["dataset_id"], f"{ds['a1.pcap']};{ds['b1.pcap']}")
        self.assertEqual((mb["primera_vez_visto"], mb["ultima_vez_visto"]), (_iso(T1), _iso(T3)))
        sl = com[(IP_A, IP_C, "514")]
        self.assertEqual((sl["primera_vez_visto"], sl["ultima_vez_visto"], sl["dataset_id"], sl["cruza_it_ot"]),
                         (_iso(T1 + 2), _iso(T1 + 9), ds["a1.pcap"], "no"))
        tr = com[(IP_B, IP_C, "162")]
        self.assertEqual((tr["primera_vez_visto"], tr["ultima_vez_visto"], tr["dataset_id"], tr["cruza_it_ot"]),
                         (_iso(T3 + 5), _iso(T4), ds["b1.pcap"], "no"))
        self.assertEqual(com[(IP_D, IP_B, "5000")]["cruza_it_ot"], "sin dato")
        # direccionamiento
        dr = {f["red"]: f for f in _csv(o / "direccionamiento_ip.csv")}
        self.assertEqual((dr["10.10.1.0/24"]["sitio"], dr["10.10.1.0/24"]["dominio"], dr["10.10.1.0/24"]["dueno"]),
                         ("PLANTA-1", "IT", "PENDIENTE"))
        self.assertEqual(dr["10.30.1.0/24"]["dominio"], "DMZ")
        self.assertEqual(dr["10.20.1.0/24"]["dominio"], "OT")        # B es OT y D no se conoce: cuenta lo conocido
        # fuentes de log
        fl = {f["ip"]: f for f in _csv(o / "fuentes_log.csv")}
        self.assertEqual((fl[IP_A]["destinos"], fl[IP_A]["volumen_paquetes"]), (f"{IP_C}:514", "2"))
        self.assertEqual((fl[IP_B]["destinos"], fl[IP_B]["volumen_paquetes"]), (f"{IP_C}:162", "2"))
        self.assertEqual((fl[IP_C]["destinos"], fl[IP_C]["volumen_bytes"], fl[IP_C]["volumen_paquetes"]), ("", "0", "0"))
        # matriz
        mat = {(f["zona_origen"], f["zona_destino"]): f for f in _csv(o / "matriz_segmentacion.csv")}
        self.assertEqual(mat[("Corp", "Planta")]["observado"], "si")
        self.assertNotEqual(mat[("Corp", "Borde")]["servicios"], "")
        self.assertEqual(mat[("Borde", "Corp")]["observado"], "no")
        # json
        j = json.loads((o / "resultado.json").read_text(encoding="utf-8"))["campos_minimos"]
        self.assertEqual((j["sitio"], j["as_of"]), ("PLANTA-1", _iso(T4)))
        self.assertEqual(j["conteos"]["flujos_cruzan_it_ot"], sum(f["cruza_it_ot"] == "si" for f in _csv(o / "comunicaciones.csv")))
        self.assertGreaterEqual(j["conteos"]["flujos_cruzan_it_ot"], 1)
        self.assertIn("matriz_segmentacion.csv", j["tablas"])

    @LEE_CAPTURAS
    def test_sitio_del_perfil_as_of_declarado_y_dominio_de_dmz(self):
        o = self.correr({"as_of": "2030-01-02T03:04:05Z"}, sitio="Planta Norte")
        inv = _csv(o / "inventario_normalizado.csv")
        self.assertEqual({(f["sitio"], f["as_of"]) for f in inv}, {("Planta Norte", "2030-01-02T03:04:05Z")})
        self.assertEqual({f["dataset_id"] for f in _csv(o / "comunicaciones.csv")}, {""})      # sin "manifiesto"

    @LEE_CAPTURAS
    def test_sin_la_clave_las_salidas_no_cambian(self):
        sin = self.correr(None)
        con_dominio = self.correr(None, zonas=[{**z, "dominio": "OT"} for z in PERFIL_CAP["zonas"]])
        con = self.correr({})
        self.assertFalse((sin / "matriz_segmentacion.csv").exists())
        self.assertFalse((con_dominio / "matriz_segmentacion.csv").exists())
        self.assertNotIn("campos_minimos", json.loads((sin / "resultado.json").read_text(encoding="utf-8")))
        for n in ("inventario_normalizado.csv", "comunicaciones.csv", "direccionamiento_ip.csv", "fuentes_log.csv",
                  "resultado.json", "reporte_ot.html"):
            with self.subTest(archivo=n):
                self.assertEqual(self._normal(con_dominio / n), self._normal(sin / n))
                if n.endswith(".csv"):      # con la clave, lo de hoy queda en las mismas posiciones
                    a, b = _lineas(sin / n), _lineas(con / n)
                    self.assertEqual([f[:len(a[0])] for f in b], a)
                    self.assertGreater(len(b[0]), len(a[0]))

    @staticmethod
    def _normal(ruta):
        txt = Path(ruta).read_text(encoding="utf-8-sig")
        txt = re.sub(r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})?", "<fecha>", txt)
        txt = re.sub(r"[0-9a-f]{40,64}", "<sha>", txt)
        txt = re.sub(r"\d{1,2}:\d{2}(:\d{2})?", "<hora>", txt)
        return re.sub(r"out\d+|perfil\d+", "<dir>", txt)

    @LEE_CAPTURAS
    def test_ingles(self):
        o = self.correr({"politica_esperada": [{"origen": "Corp", "destino": "*", "politica": "x"}]}, idioma="en")
        com = _csv(o / "comunicaciones.csv")
        self.assertEqual(list(com[0])[-8:], ["source_id", "destination_id", "first_seen", "last_seen", "dataset_id",
                                             "source_domain", "destination_domain", "crosses_it_ot"])
        self.assertEqual({f["crosses_it_ot"] for f in com} - {"yes", "no", "no data"}, set())
        self.assertIn("yes", {f["crosses_it_ot"] for f in com})
        self.assertEqual(list(_csv(o / "matriz_segmentacion.csv")[0]),
                         ["source zone", "destination zone", "observed", "services", "conduits", "bytes",
                          "expected_policy"])
        self.assertIn("PENDING", {f["owner"] for f in _csv(o / "direccionamiento_ip.csv")})
        self.assertIn("not declared", {f["expected_policy"] for f in _csv(o / "matriz_segmentacion.csv")})


MAC_R = "02:00:00:d1:00:09"
IPS_R = ("10.10.1.20", "10.10.1.21", "10.20.1.90", "10.30.1.60", "10.30.1.61")      # Corp (IT), Planta, Borde (dmz)


class EnrutadorTest(unittest.TestCase):
    """Captura detras de un enrutador: las IP de varias zonas llegan con una sola MAC y merge_assets las junta en un
    activo cuya zona es la de una sola de ellas. El dominio, los ids y la matriz van por IP (como el inventario
    presentado, D105), no por la zona del activo agrupado."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        pq = []
        for i, ip in enumerate(IPS_R):
            pq += [_tcp(MAC_R, MAC_B, ip, IP_B, 41000 + i, 502, T1 + i), _tcp(MAC_B, MAC_R, IP_B, ip, 502, 41000 + i, T1 + i)]
        escribir(pq, cls.tmp / "pR" / "r1.pcap")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    @LEE_CAPTURAS
    def test_dominio_y_matriz_por_ip_detras_de_un_enrutador(self):
        i18n.usar("es")
        self.addCleanup(i18n.usar, "es")
        p = self.tmp / "perfil.json"
        p.write_text(json.dumps({"version": 1, "cliente": "ACME", "marcos": [{"clave": "iec62443"}], **PERFIL_CAP,
                                 "campos_minimos": {}}), encoding="utf-8")
        out = self.tmp / "out"
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main_completo([str(self.tmp / "pR"), "-o", str(out), "--perfil", str(p)]), 0)
        inv = {f["ips"]: f for f in _csv(out / "inventario_normalizado.csv")}
        self.assertTrue(all(ip in inv for ip in IPS_R))                 # el inventario ya parte la MAC por IP
        self.assertEqual([inv[ip]["dominio"] for ip in ("10.10.1.20", "10.30.1.60", "10.30.1.61")], ["IT", "DMZ", "DMZ"])
        com = {f["origen_ip"]: f for f in _csv(out / "comunicaciones.csv") if f["destino_ip"] == IP_B}
        self.assertEqual((com["10.30.1.60"]["origen_dominio"], com["10.10.1.20"]["origen_dominio"]), ("DMZ", "IT"))
        self.assertEqual(com["10.30.1.60"]["origen_id"], inv["10.30.1.60"]["id"])
        mat = {(f["zona_origen"], f["zona_destino"]): f for f in _csv(out / "matriz_segmentacion.csv")}
        # sin saludo TCP, cada respuesta de B es su propio conducto: cada par sale tambien de vuelta
        self.assertEqual({k: mat[k]["conductos"] for k in (("Corp", "Planta"), ("Borde", "Planta"), ("Planta", "Corp"),
                                                          ("Planta", "Borde"), ("Planta", "Planta"))},
                         {("Corp", "Planta"): "2", ("Borde", "Planta"): "2", ("Planta", "Corp"): "2",
                          ("Planta", "Borde"): "2", ("Planta", "Planta"): "2"})
        self.assertEqual(mat[("Corp", "Borde")]["observado"], "no")


def _lineas(path):
    with open(path, newline="", encoding="utf-8-sig") as fh:
        return list(csv.reader(fh))


class DiagramaTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        cls.com = gen_exports.xd_escribir_comunicaciones(cls.tmp / "com.csv", [
            gen_exports.xd_fila("10.10.1.10", "10.10.2.20", "From A to B", 502, "Modbus", tipo_a="HMI", tipo_b="PLC")])
        cls.inv = _inventario_xdome(cls.tmp / "inv.csv", [("HMI-1", "10.10.1.10", "Operacion"),
                                                          ("PLC-1", "10.10.2.20", "Campo")])
        cls.n = 0

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def setUp(self):
        i18n.usar("es")
        self.addCleanup(i18n.usar, "es")

    def correr(self, extra=None, **perfil):
        type(self).n += 1
        p = self.tmp / f"perfil{self.n}.json"
        cfg = {"version": 1, "cliente": "ACME", "marcos": [{"clave": "iec62443"}],
               "zonas": [{"nombre": "Oficina", "redes": ["10.10.1.0/24"], "dominio": "IT"},
                         {"nombre": "Proceso", "redes": ["10.10.2.0/24"], "dominio": "OT"}], **perfil}
        if extra is not None:
            cfg["campos_minimos"] = extra
        p.write_text(json.dumps(cfg), encoding="utf-8")
        out = self.tmp / f"out{self.n}"
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main_diagrama(["--activos", str(self.inv), "--enlaces", str(self.com), "--formato",
                                            "xdome", "-o", str(out), "--perfil", str(p)]), 0)
        i18n.usar("es")
        return out

    def test_columnas_matriz_y_direccionamiento(self):
        o = self.correr({"sitio": "S1", "duenos": [{"red": "10.10.0.0/16", "dueno": "Planta"}],
                         "politica_esperada": [{"origen": "Oficina", "destino": "Proceso", "politica": "solo Modbus"}]})
        inv = _csv(o / "inventario_normalizado.csv")
        self.assertEqual(list(inv[0])[-5:], cm.COL_INVENTARIO)
        self.assertEqual({(f["sitio"], f["primera_vez_visto"]) for f in inv}, {("S1", "")})
        self.assertTrue(all(ISO.match(f["ultima_vez_visto"]) or not f["ultima_vez_visto"] for f in inv))
        self.assertEqual(sorted(f["dominio"] for f in inv), ["IT", "OT"])
        self.assertTrue(all(ISO.match(f["as_of"]) for f in inv))
        com = _csv(o / "comunicaciones.csv")
        self.assertEqual(list(com[0])[-8:], cm.COL_COMUNICACIONES)
        self.assertEqual((com[0]["cruza_it_ot"], com[0]["primera_vez_visto"], com[0]["dataset_id"]), ("si", "", ""))
        self.assertTrue(com[0]["origen_id"].startswith("A-"))
        dr = _csv(o / "direccionamiento_ip.csv")
        self.assertEqual({(f["red"], f["dominio"], f["dueno"]) for f in dr},
                         {("10.10.1.0/24", "IT", "Planta"), ("10.10.2.0/24", "OT", "Planta")})
        mat = {(f["zona_origen"], f["zona_destino"]): f for f in _csv(o / "matriz_segmentacion.csv")}
        self.assertEqual((mat[("Oficina", "Proceso")]["observado"], mat[("Oficina", "Proceso")]["politica_esperada"],
                          mat[("Oficina", "Proceso")]["conductos"]), ("si", "solo Modbus", "1"))
        self.assertEqual(mat[("Proceso", "Oficina")]["politica_esperada"], "sin declarar")
        hojas, _ = _xlsx_hojas(o / "reporte_ot.xlsx")
        self.assertIn("Matriz de segmentacion", hojas)
        j = json.loads((o / "resultado.json").read_text(encoding="utf-8"))["campos_minimos"]
        self.assertEqual(j["conteos"]["flujos_cruzan_it_ot"], 1)

    def test_sin_la_clave_nada_cambia(self):
        sin, con = self.correr(None), self.correr({})
        self.assertFalse((sin / "matriz_segmentacion.csv").exists())
        for n in ("inventario_normalizado.csv", "comunicaciones.csv", "direccionamiento_ip.csv"):
            a, b = _lineas(sin / n), _lineas(con / n)
            self.assertEqual([f[:len(a[0])] for f in b], a, n)
        hojas, _ = _xlsx_hojas(sin / "reporte_ot.xlsx")
        self.assertNotIn("Matriz de segmentacion", hojas)

    def test_solo_estado_incluye_la_matriz_con_la_politica_esperada(self):
        o = self.correr({"politica_esperada": [{"origen": "Oficina", "destino": "Proceso", "politica": "x"}]},
                        solo_estado={})
        copia = o / "estado" / "matriz_segmentacion.csv"
        self.assertTrue(copia.is_file())
        self.assertEqual(list(_csv(copia)[0]), cm.COL_MATRIZ)
        self.assertEqual(_lineas(copia), _lineas(o / "matriz_segmentacion.csv"))
        sin = self.correr(None, solo_estado={})
        self.assertFalse((sin / "estado" / "matriz_segmentacion.csv").exists())

    def test_ingles(self):
        o = self.correr({}, idioma="en")
        self.assertEqual(list(_csv(o / "direccionamiento_ip.csv")[0])[-3:], ["site", "domain", "owner"])
        self.assertEqual({f["crosses_it_ot"] for f in _csv(o / "comunicaciones.csv")}, {"yes"})
        hojas, _ = _xlsx_hojas(o / "reporte_ot.xlsx")
        self.assertIn("Segmentation matrix", hojas)


if __name__ == "__main__":
    unittest.main()
