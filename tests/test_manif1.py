"""MANIF1 (D139): manifiesto por dataset y plan de captura contra lo capturado. Sintetico.

El modo captura requiere tshark y scapy (se omite sin ellos); el resto corre sin ellos.
"""
from __future__ import annotations

import contextlib
import csv
import hashlib
import io
import json
import shutil
import struct
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from typing import ClassVar

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))
sys.path.insert(0, str(RAIZ / "tests"))

import gen_exports
from test_cobertura_captura import LEE_CAPTURAS, T0, escribir, lecturas
from test_rm1 import _error, _perfil
from test_zonas import _inventario_xdome

from ot_assess import i18n
from ot_assess import manifiesto as mf
from ot_assess.cli import main as main_completo
from ot_assess.cli_diagrama import main as main_diagrama


def _csv(path):
    with open(path, newline="", encoding="utf-8-sig") as fh:
        return list(csv.DictReader(fh))


def _man(**extra):
    return {"sitios": ["S1", "S2"], "datasets": [{"sitio": "S1", "punto": "A"}], **extra}


def _cada(archivos):
    return [{"archivo": a, "sha256": hashlib.sha256(a.encode()).hexdigest(), "bytes": 1, "_ruta": a}
            for a in archivos]


# --- pcapng a mano ---------------------------------------------------------------------------------------- #

def _bloque(tipo, cuerpo, fin="<"):
    cuerpo += b"\0" * (-len(cuerpo) % 4)
    largo = 12 + len(cuerpo)
    return struct.pack(fin + "II", tipo, largo) + cuerpo + struct.pack(fin + "I", largo)


def _isb(iface, ifdrop=None, osdrop=None, fin="<"):
    cuerpo = struct.pack(fin + "III", iface, 0, 0)
    for codigo, v in ((5, ifdrop), (6, osdrop)):
        if v is not None:
            cuerpo += struct.pack(fin + "HHQ", codigo, 8, v)
    return _bloque(5, cuerpo + struct.pack(fin + "HH", 0, 0), fin)


def pcapng(paquetes=(), isbs=(), fin="<"):
    out = _bloque(0x0A0D0D0A, struct.pack(fin + "IHHq", 0x1A2B3C4D, 1, 0, -1), fin)
    out += _bloque(1, struct.pack(fin + "HHI", 1, 0, 65535), fin)
    for p in paquetes:
        datos, ts = bytes(p), int(float(p.time) * 1e6)
        out += _bloque(6, struct.pack(fin + "IIIII", 0, ts >> 32, ts & 0xFFFFFFFF, len(datos), len(datos)) + datos,
                       fin)
    return out + b"".join(isbs)


class PerdidasPcapngTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def leer(self, datos: bytes):
        p = self.tmp / "x.pcapng"
        p.write_bytes(datos)
        return mf.perdidas_pcapng(p)

    def test_suma_ifdrop_y_osdrop_el_ultimo_isb_de_cada_interfaz(self):
        self.assertEqual(self.leer(pcapng(isbs=[_isb(0, 2), _isb(0, 5, 1), _isb(1, 10)])), 16)
        self.assertEqual(self.leer(pcapng(isbs=[_isb(0, 4, 3)])), 7)

    def test_big_endian(self):
        self.assertEqual(self.leer(pcapng(isbs=[_isb(0, 4, 3, ">")], fin=">")), 7)

    def test_sin_dato_nunca_error(self):
        self.assertIsNone(self.leer(pcapng()))                                  # sin ISB
        self.assertIsNone(self.leer(pcapng(isbs=[_isb(0)])))                    # ISB sin contadores de perdida
        self.assertIsNone(self.leer(b"\xd4\xc3\xb2\xa1" + b"\0" * 40))          # pcap clasico
        self.assertIsNone(self.leer(b""))
        self.assertIsNone(self.leer(pcapng(isbs=[_isb(0, 5)])[:-6]))            # truncado
        self.assertIsNone(self.leer(pcapng(isbs=[_isb(0, 5)]) + b"\0\0\0"))     # cola incompleta
        self.assertIsNone(mf.perdidas_pcapng(self.tmp / "no_existe"))


class PerfilTest(unittest.TestCase):
    def test_valido_y_normalizado(self):
        p = _perfil({"manifiesto": _man(
            zona_presentacion={"etiqueta": "CST", "desfase": "-06:00"}, procesado_por=" Ana ",
            datasets=[{"sitio": "S1", "punto": " A ", "id": "ds.1_a-b", "no_ve": ["VLAN 30"],
                       "inicio_utc": "2026-03-01T10:00:00-06:00", "fin_utc": "2026-03-01T18:00:00Z"},
                      {"sitio": "S2", "archivos": ["a.csv", "b.csv", "a.csv"]}],
            plan={"dias_por_punto": 3, "puntos": [{"sitio": "S1", "punto": "A"}],
                  "muestras": [{"nombre": "m", "sitios": ["S1", "S2"], "total": 5}]})})["manifiesto"]
        self.assertEqual(p["procesado_por"], "Ana")
        d0, d1 = p["datasets"]
        self.assertEqual((d0["punto"], d0["inicio_utc"], d0["fin_utc"]), ("A", "2026-03-01T16:00:00Z", "2026-03-01T18:00:00Z"))
        self.assertEqual(d1["archivos"], ["a.csv", "b.csv"])
        self.assertEqual(p["plan"]["dias_por_punto"], 3.0)

    def test_errores(self):
        ds = {"sitio": "S1", "punto": "A"}
        largo = "x" * 201
        casos = [
            ("lista", "debe ser un objeto"), ({"otra": 1, **_man()}, "desconocida"),
            ({"datasets": [ds]}, "sitios"), ({"sitios": [], "datasets": [ds]}, "sitios"),
            ({"sitios": ["a b"], "datasets": [ds]}, "sitios"), ({"sitios": ["S" * 41], "datasets": [ds]}, "sitios"),
            ({"sitios": [f"S{i}" for i in range(201)], "datasets": [ds]}, "1 a 200"),
            ({"sitios": ["S1"]}, "datasets"), ({"sitios": ["S1"], "datasets": []}, "datasets"),
            ({"sitios": ["S1"], "datasets": [ds] * 501}, "1 a 500"),
            (_man(datasets=[{"sitio": "ZZ", "punto": "A"}]), "no esta en"),
            (_man(datasets=[{"punto": "A"}]), "no esta en"),
            (_man(datasets=[{"sitio": "S1"}]), "necesita 'punto'"),
            (_man(datasets=[{**ds, "otro": 1}]), "desconocida"),
            (_man(datasets=[{**ds, "id": "a b"}]), "caracteres de"),
            (_man(datasets=[{**ds, "id": "x" * 65}]), "caracteres de"),
            (_man(datasets=[{**ds, "id": "X"}, {**ds, "id": "X"}]), "repetidos"),
            (_man(datasets=[{**ds, "sensor": largo}]), "1 a 200"), (_man(datasets=[{**ds, "sensor": ""}]), "1 a 200"),
            (_man(datasets=[{**ds, "no_ve": ["a"] * 101}]), "0 a 100"),
            (_man(datasets=[{**ds, "no_ve": [3]}]), "texto"), (_man(datasets=[{**ds, "no_ve": "a"}]), "lista"),
            (_man(datasets=[{"sitio": "S1", "archivos": []}]), "1 a 200"),
            (_man(datasets=[{"sitio": "S1", "archivos": ["a"] * 201}]), "1 a 200"),
            (_man(datasets=[{"sitio": "S1", "archivos": ["dir/a.csv"]}]), "sin ruta"),
            (_man(datasets=[{**ds, "inicio_utc": "ayer"}]), "ISO 8601"),
            (_man(datasets=[{**ds, "inicio_utc": "2026-03-01T10:00:00"}]), "Z u offset"),
            (_man(datasets=[{**ds, "inicio_utc": "2026-03-01T10:00:00Z", "fin_utc": "2026-03-01T09:00:00Z"}]),
             "anterior"),
            (_man(zona_presentacion={"etiqueta": "X", "desfase": "-12:30"}), "desfase"),
            (_man(zona_presentacion={"etiqueta": "X", "desfase": "+14:30"}), "desfase"),
            (_man(zona_presentacion={"etiqueta": "X", "desfase": "6"}), "desfase"),
            (_man(zona_presentacion={"etiqueta": "X", "desfase": "+05:75"}), "desfase"),
            (_man(zona_presentacion={"etiqueta": "", "desfase": "+01:00"}), "1 a 40"),
            (_man(zona_presentacion={"etiqueta": "X" * 41, "desfase": "+01:00"}), "1 a 40"),
            (_man(procesado_por="x" * 101), "1 a 100"),
            (_man(plan={"dias_por_punto": 0.4}), "0.5 a 60"), (_man(plan={"dias_por_punto": 61}), "0.5 a 60"),
            (_man(plan={"dias_por_punto": True}), "0.5 a 60"),
            (_man(plan={"puntos": [{"sitio": "S1", "punto": "A"}]}), "obligatorio"),
            (_man(plan={"dias_por_punto": 1, "puntos": [{"sitio": "ZZ", "punto": "A"}]}), "no esta en"),
            (_man(plan={"dias_por_punto": 1, "puntos": [{"sitio": "S1", "punto": "A"}] * 501}), "0 a 500"),
            (_man(plan={"dias_por_punto": 1, "muestras": [{"nombre": "m", "sitios": ["S1", "S2"], "total": 1}]}),
             "total"),
            (_man(plan={"dias_por_punto": 1, "muestras": [{"nombre": "m", "sitios": ["ZZ"], "total": 4}]}),
             "no esta en"),
            (_man(plan={"dias_por_punto": 1, "muestras": [{"nombre": "m", "sitios": ["S1"], "total": "4"}]}),
             "total"),
            (_man(plan={"dias_por_punto": 1, "muestras": [{"nombre": "m", "sitios": ["S1"], "total": 1}] * 51}),
             "0 a 50"),
            (_man(plan={"otra": 1}), "desconocida")]
        for v, frag in casos:
            self.assertIn(frag, _error({"manifiesto": v}), v)


class DatasetIdTest(unittest.TestCase):
    def test_estable_independiente_del_orden_y_la_ruta(self):
        ds = {"sitio": "S1", "punto": "A"}
        a = mf.dataset_id(ds, ["bb", "aa", "cc"])
        self.assertEqual(a, mf.dataset_id({"sitio": "S2", "punto": "otro"}, ["cc", "aa", "bb"]))
        esperado = "DS-" + hashlib.sha256(b"aa\nbb\ncc").hexdigest()[:12].upper()
        self.assertEqual(a, esperado)
        self.assertNotEqual(a, mf.dataset_id(ds, ["aa", "bb", "cd"]))
        self.assertEqual(mf.dataset_id({**ds, "id": "MIO-1"}, ["aa"]), "MIO-1")

    def test_sin_archivos_sale_de_lo_declarado(self):
        a = mf.dataset_id({"sitio": "S1", "punto": "A"}, [])
        self.assertTrue(a.startswith("DS-") and len(a) == 15)
        self.assertEqual(a, mf.dataset_id({"sitio": "S1", "punto": "A"}, []))
        self.assertNotEqual(a, mf.dataset_id({"sitio": "S2", "punto": "A"}, []))


def _cobertura(punto, inicio, fin, huecos=0, perdida=0.0, rutas=()):
    return {"puntos": [{"punto": punto, "paths": [str(r) for r in rutas], "m": {
        "inicio": inicio, "fin": fin, "huecos": huecos, "perdida_pct": perdida}}]}


class ConstruirTest(unittest.TestCase):
    """Sin tshark: cobertura y SHA-256 armados a mano."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.a1, self.a2 = self.tmp / "p" / "a1.pcap", self.tmp / "p" / "a2.pcap"
        self.a1.parent.mkdir()
        self.a1.write_bytes(b"1")
        self.a2.write_bytes(b"22")
        self.caps = [(self.a1, "11"), (self.a2, "22")]

    def man(self, **extra):
        return {"manifiesto": mf.validar(_man(**extra), self.fallo, self.objeto)}

    @staticmethod
    def fallo(msg):
        raise AssertionError(msg)

    @staticmethod
    def objeto(v, donde, permitidas):
        return v

    def test_sin_la_clave_nada(self):
        self.assertEqual(mf.construir({}, {}, self.caps, []), {})
        self.assertEqual(mf.construir(None, {}, [], []), {})
        self.assertFalse(mf.hay({}))
        self.assertEqual(mf.tablas({}), [])
        self.assertEqual(mf.nota_no_ve({}), [])

    def test_ventana_medida_zona_que_cruza_la_medianoche_y_declarada_distinta(self):
        cob = _cobertura("p", T0, T0 + 5400, 2, 0.5, [self.a1, self.a2])
        perfil = self.man(zona_presentacion={"etiqueta": "UTC+2", "desfase": "+02:00"}, procesado_por="Ana",
                          datasets=[{"sitio": "S1", "punto": "p", "sensor": "SPAN-1", "fuentes_espejadas": ["VLAN 10", "VLAN 20"],
                                     "inicio_utc": "2023-11-14T10:00:00Z", "fin_utc": "2023-11-14T12:00:00Z"}])
        m = mf.construir(perfil, cob, self.caps, [])
        f = m["filas"][0]
        self.assertEqual((f["inicio_utc"], f["fin_utc"]), ("2023-11-14T22:13:20Z", "2023-11-14T23:43:20Z"))
        self.assertEqual(f["origen_ventana"], mf.DISTINTA)
        self.assertEqual((f["inicio_local"], f["fin_local"]), ("2023-11-15 00:13:20 UTC+2", "2023-11-15 01:43:20 UTC+2"))
        self.assertTrue(any("difiere" in a for a in m["avisos"]))
        fila = dict(zip(mf.COLUMNAS, mf.fila_tabla(f)))
        self.assertEqual((fila["dias"], fila["huecos"], fila["perdida_tcp_pct"], fila["archivos_n"]),
                         ("0.1", 2, "0.50", 2))
        self.assertEqual(fila["sha256"], "a1.pcap:11;a2.pcap:22")
        self.assertEqual((fila["perdidas_pcapng"], fila["estado"], fila["version"], fila["procesado_por"]),
                         (i18n.t("sin dato"), "con datos", f["version"], "Ana"))
        self.assertEqual(f["archivos_sha"][1], {"archivo": "a2.pcap", "sha256": "22", "bytes": 2})

    def test_ventana_declarada_cercana_no_avisa_y_sin_zona_no_hay_hora_local(self):
        cob = _cobertura("p", T0, T0 + 5400, rutas=[self.a1, self.a2])
        perfil = self.man(datasets=[{"sitio": "S1", "punto": "p", "inicio_utc": "2023-11-14T22:30:00Z",
                                     "fin_utc": "2023-11-15T00:00:00Z"}])
        m = mf.construir(perfil, cob, self.caps, [])
        self.assertEqual(m["filas"][0]["origen_ventana"], mf.MEDIDA)
        self.assertEqual((m["filas"][0]["inicio_local"], m["avisos"]), ("", []))

    def test_sin_datos_en_la_corrida_avisa_y_no_es_error(self):
        perfil = self.man(datasets=[{"sitio": "S1", "punto": "otro"}, {"sitio": "S2", "archivos": ["x.csv"]}])
        m = mf.construir(perfil, _cobertura("p", T0, T0 + 10, rutas=[self.a1]), self.caps, [])
        self.assertEqual([f["estado"] for f in m["filas"]], [mf.SIN_DATOS, mf.SIN_DATOS])
        self.assertEqual(sum("sin datos en esta corrida" in a for a in m["avisos"]), 2)
        self.assertTrue(any("sin dataset declarado: p" in a for a in m["avisos"]))
        self.assertEqual(m["conteos"], {"datasets": 2, "con_datos": 0, "sin_datos": 2, "sitios": 2})
        self.assertEqual(m["filas"][0]["archivos_n"], 0)

    def test_plan_completo_parcial_pendiente_no_planeado_y_muestra(self):
        cob = {"puntos": [
            {"punto": "completo", "paths": [str(self.a1)], "m": {"inicio": T0, "fin": T0 + 3 * 86400, "huecos": 0,
                                                                  "perdida_pct": 0.0}},
            {"punto": "parcial", "paths": [str(self.a2)], "m": {"inicio": T0, "fin": T0 + 86400, "huecos": 0,
                                                                 "perdida_pct": 0.0}},
            {"punto": "extra", "paths": [str(self.a1)], "m": {"inicio": T0, "fin": T0 + 86400, "huecos": 0,
                                                   "perdida_pct": 0.0}}]}
        perfil = self.man(
            datasets=[{"sitio": "S1", "punto": "completo"}, {"sitio": "S1", "punto": "parcial"},
                      {"sitio": "S2", "punto": "extra"}],
            plan={"dias_por_punto": 3, "puntos": [{"sitio": "S1", "punto": "completo"},
                                                  {"sitio": "S1", "punto": "parcial"},
                                                  {"sitio": "S2", "punto": "falta"}],
                  "muestras": [{"nombre": "Norte", "sitios": ["S1", "S2"], "total": 5}]})
        m = mf.construir(perfil, cob, self.caps, [])
        estados = {(x["sitio"], x["punto"]): x["estado"] for x in m["plan"]["filas"]}
        self.assertEqual(estados, {("S1", "completo"): "completo", ("S1", "parcial"): "parcial",
                                   ("S2", "falta"): "pendiente", ("S2", "extra"): "no planeado"})
        self.assertEqual(m["plan"]["muestras"][0]["capturados"], 2)
        tab = {a: (c, f) for a, _h, c, f in mf.tablas(m)}
        filas = tab[mf.ARCHIVO_PLAN][1]
        self.assertEqual(filas[-1][0], "muestra Norte: capturados 2 de 5 (planeados 2)")
        self.assertEqual(filas[1][:4] + filas[1][5:], ["S1", "parcial", "si", "si", "3.0", "1.0", "parcial"])
        self.assertEqual(filas[2][:4], ["S2", "falta", "si", "no"])
        self.assertEqual(filas[3][:4], ["S2", "extra", "no", "si"])
        s = mf.seccion(m)
        self.assertEqual(s["plan"]["muestras"], ["muestra Norte: capturados 2 de 5 (planeados 2)"])

    def test_nota_no_ve(self):
        cob = _cobertura("p", T0, T0 + 10, rutas=[self.a1])
        m = mf.construir(self.man(datasets=[{"sitio": "S1", "punto": "p", "no_ve": ["VLAN 30", "red de campo"]},
                                            {"sitio": "S1", "punto": "q", "no_ve": ["VLAN 99"]}]),
                         cob, self.caps, [])
        self.assertEqual(mf.nota_no_ve(m), ["Ausencia de un flujo no es inexistencia: el punto p no ve VLAN 30, red de campo."])

    def test_diagrama_ventana_declarada_y_sha(self):
        e1, e2 = self.tmp / "inv.csv", self.tmp / "com.csv"
        e1.write_bytes(b"inv")
        e2.write_bytes(b"com")
        perfil = self.man(datasets=[{"sitio": "S1", "archivos": ["com.csv", "inv.csv"], "inicio_utc": "2026-03-01T00:00:00Z",
                                     "fin_utc": "2026-03-03T12:00:00Z"},
                                    {"sitio": "S1", "archivos": ["inv.csv"]}, {"sitio": "S2", "archivos": ["falta.csv"]}])
        m = mf.construir(perfil, {}, [], [(e1, "h1"), (e2, "h2")])
        f = m["filas"][0]
        self.assertEqual(f["origen_ventana"], mf.DECLARADA)
        fila = dict(zip(mf.COLUMNAS, mf.fila_tabla(f)))
        self.assertEqual((fila["dias"], fila["archivos_n"], fila["huecos"], fila["perdida_tcp_pct"]), ("2.5", 2, "", ""))
        self.assertEqual(fila["sha256"], "com.csv:h2;inv.csv:h1")
        self.assertEqual(f["archivos_sha"][0]["bytes"], 3)
        self.assertEqual(m["filas"][1]["inicio_utc"], "")                       # sin ventana declarada: sin hora
        self.assertEqual(m["filas"][2]["estado"], mf.SIN_DATOS)
        self.assertEqual(f["dataset_id"], "DS-" + hashlib.sha256(b"h1\nh2").hexdigest()[:12].upper())


@LEE_CAPTURAS
class CapturaTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        a, b = cls.tmp / "sensorA", cls.tmp / "sensorB"
        cls.pcapng = a / "a1.pcapng"
        a.mkdir()
        b.mkdir()
        cls.pcapng.write_bytes(pcapng(lecturas(n=10), [_isb(0, 2), _isb(0, 5, 1)]))
        escribir(lecturas(n=20, desde=10), a / "a2.pcap")
        escribir(lecturas(n=20), b / "b1.pcap")
        escribir(lecturas(n=20), b / "b2.pcap")
        cls.n = 0

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def setUp(self):
        i18n.usar("es")
        self.addCleanup(i18n.usar, "es")

    def correr(self, man=None, **extra):
        type(self).n += 1
        p = self.tmp / f"perfil{self.n}.json"
        cfg = {"version": 1, "cliente": "ACME", "marcos": [{"clave": "iec62443"}], **extra}
        if man is not None:
            cfg["manifiesto"] = man
        p.write_text(json.dumps(cfg), encoding="utf-8")
        out = self.tmp / f"out{self.n}"
        sal = io.StringIO()
        with contextlib.redirect_stdout(sal), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main_completo([str(self.tmp / "sensorA"), str(self.tmp / "sensorB"), "-o", str(out),
                                            "--perfil", str(p)]), 0)
        self.consola = sal.getvalue()
        i18n.usar("es")
        return out

    MAN: ClassVar[dict] = {"sitios": ["S1", "S2"], "procesado_por": "Ana",
           "zona_presentacion": {"etiqueta": "UTC+2", "desfase": "+02:00"},
           "datasets": [
               {"sitio": "S1", "punto": "sensorA", "sensor": "SPAN-A", "fuentes_espejadas": ["VLAN 10"],
                "no_ve": ["VLAN 30"], "inicio_utc": "2023-11-14T10:00:00Z", "fin_utc": "2023-11-14T12:00:00Z"},
               {"sitio": "S1", "punto": "sensorB", "id": "B-1", "perdidas_declaradas": "SPAN: 0 descartes"},
               {"sitio": "S2", "punto": "sensorC"}],
           "plan": {"dias_por_punto": 1, "puntos": [{"sitio": "S1", "punto": "sensorA"},
                                                    {"sitio": "S1", "punto": "sensorB"},
                                                    {"sitio": "S2", "punto": "sensorC"}],
                    "muestras": [{"nombre": "Todas", "sitios": ["S1", "S2"], "total": 4}]}}

    def test_manifiesto_de_dos_puntos(self):
        o = self.correr(self.MAN)
        filas = {f["sitio"] + f["punto_o_archivos"]: f for f in _csv(o / mf.ARCHIVO)}
        self.assertEqual(list(_csv(o / mf.ARCHIVO)[0]), mf.COLUMNAS)
        a, b, c = filas["S1sensorA"], filas["S1sensorB"], filas["S2sensorC"]
        sha = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in self.tmp.glob("sensor*/*.pcap*")}
        self.assertEqual(a["sha256"], ";".join(f"{n}:{sha[n]}" for n in ("a1.pcapng", "a2.pcap")))
        self.assertEqual((a["inicio_utc"], a["origen_ventana"], a["inicio_local"]),
                         ("2023-11-14T22:13:17Z", "medida (declarada distinta)", "2023-11-15 00:13:17 UTC+2"))
        self.assertEqual((a["huecos"], a["perdida_tcp_pct"], a["perdidas_pcapng"], a["archivos_n"], a["dias"]),
                         ("0", "0.00", "6", "2", "0.1"))
        self.assertEqual((b["dataset_id"], b["perdidas_pcapng"], b["perdidas_declaradas"], b["origen_ventana"]),
                         ("B-1", "sin dato", "SPAN: 0 descartes", "medida"))
        self.assertTrue(a["dataset_id"].startswith("DS-") and len(a["dataset_id"]) == 15)
        self.assertEqual((c["estado"], c["archivos_n"], c["inicio_utc"]), ("sin datos en esta corrida", "0", ""))
        self.assertEqual((a["fuentes_espejadas"], a["no_ve"], a["sensor"], a["procesado_por"]),
                         ("VLAN 10", "VLAN 30", "SPAN-A", "Ana"))
        self.assertIn("difiere", self.consola)
        self.assertIn("sin datos en esta corrida", self.consola)
        # un JSON por dataset con archivos, sha256 y bytes
        j = json.loads((o / f"manifiesto_{a['dataset_id']}.json").read_text(encoding="utf-8"))
        self.assertEqual([x["archivo"] for x in j["archivos"]], ["a1.pcapng", "a2.pcap"])
        self.assertEqual(j["archivos"][0]["bytes"], self.pcapng.stat().st_size)
        self.assertTrue((o / "manifiesto_B-1.json").is_file())
        # plan
        plan = {(f["sitio"], f["punto"]): f for f in _csv(o / mf.ARCHIVO_PLAN) if f["punto"]}
        self.assertEqual(plan[("S1", "sensorA")]["estado"], "parcial")      # 0.05 d capturados de 1 planeado
        self.assertEqual(plan[("S2", "sensorC")]["estado"], "pendiente")
        self.assertTrue(_csv(o / mf.ARCHIVO_PLAN)[-1]["sitio"].startswith("muestra Todas: capturados 1 de 4 (planeados 2)"))
        # resultado.json, secciones, hoja y docx
        r = json.loads((o / "resultado.json").read_text(encoding="utf-8"))["manifiesto"]
        self.assertEqual(r["conteos"], {"datasets": 3, "con_datos": 2, "sin_datos": 1, "sitios": 2})
        self.assertEqual(r["filas"][0]["archivos"][0]["sha256"], sha["a1.pcapng"])
        self.assertEqual(r["plan"]["muestras"][0]["capturados"], 1)
        for n in ("reporte_ot.html", "reporte_ot.md"):
            texto = (o / n).read_text(encoding="utf-8")
            self.assertIn(mf.TITULO, texto, n)
            self.assertIn(mf.TITULO_PLAN, texto, n)
            self.assertIn("Ausencia de un flujo no es inexistencia: el punto sensorA no ve VLAN 30.", texto, n)
        for nombre, esperado in (("reporte_ot.xlsx", mf.HOJA_PLAN), ("informe_ot.docx", mf.TITULO)):
            with zipfile.ZipFile(o / nombre) as z:
                texto = " ".join(z.read(x).decode("utf-8", "ignore") for x in z.namelist() if x.endswith(".xml"))
            self.assertIn(esperado, texto, nombre)

    def test_dataset_id_no_depende_de_la_carpeta(self):
        o = self.correr({"sitios": ["S1"], "datasets": [{"sitio": "S1", "punto": "sensorB"}]})
        antes = _csv(o / mf.ARCHIVO)[0]["dataset_id"]
        copia = self.tmp / "otra_carpeta" / "renombrada"
        shutil.copytree(self.tmp / "sensorB", copia)
        type(self).n += 1
        p = self.tmp / f"perfil{self.n}.json"
        p.write_text(json.dumps({"version": 1, "cliente": "ACME", "marcos": [{"clave": "iec62443"}],
                                 "manifiesto": {"sitios": ["S1"], "datasets": [{"sitio": "S1", "punto": "renombrada"}]}}),
                     encoding="utf-8")
        out = self.tmp / f"out{self.n}"
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            main_completo([str(copia / "b2.pcap"), str(copia / "b1.pcap"), "-o", str(out), "--perfil", str(p)])
        i18n.usar("es")
        self.assertEqual(_csv(out / mf.ARCHIVO)[0]["dataset_id"], antes)

    def test_sin_la_clave_las_salidas_no_cambian(self):
        sin = self.correr(None)
        con = self.correr({"sitios": ["S1"], "datasets": [{"sitio": "S1", "punto": "sensorA", "no_ve": ["VLAN 30"]}]})
        self.assertEqual([p.name for p in sin.glob("manifiesto*")] + [p.name for p in sin.glob("plan_captura*")], [])
        self.assertEqual((sin / "hallazgos.csv").read_bytes(), (con / "hallazgos.csv").read_bytes())
        self.assertNotIn("manifiesto", json.loads((sin / "resultado.json").read_text(encoding="utf-8")))
        for n in ("reporte_ot.html", "reporte_ot.md", "resultado.json"):
            texto = (sin / n).read_text(encoding="utf-8")
            self.assertNotIn("Manifiesto de datos", texto, n)
            self.assertNotIn("Ausencia de un flujo", texto, n)
        self.assertTrue((con / "manifiesto.csv").is_file())
        self.assertFalse((con / "plan_captura.csv").exists())

    def test_ingles(self):
        o = self.correr(self.MAN, idioma="en")
        filas = _csv(o / mf.ARCHIVO)
        self.assertIn("pcapng_losses", filas[0])
        self.assertEqual(filas[1]["status"], "with data")
        self.assertEqual(filas[2]["status"], "no data in this run")
        self.assertEqual(filas[1]["pcapng_losses"], "no data")
        self.assertEqual(filas[0]["window_source"], "measured (declared differs)")
        plan = _csv(o / mf.ARCHIVO_PLAN)
        self.assertEqual(plan[0]["status"], "partial")
        self.assertTrue(plan[-1]["site"].startswith("sample Todas: captured 1 of 4 (planned 2)"))
        h = (o / "reporte_ot.html").read_text(encoding="utf-8")
        self.assertIn("Data manifest", h)
        self.assertIn("Absence of a flow is not non-existence: point sensorA does not see VLAN 30.", h)


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

    def correr(self, man=None, argumentos=(), **extra):
        type(self).n += 1
        p = self.tmp / f"perfil{self.n}.json"
        cfg = {"version": 1, "cliente": "ACME", "marcos": [{"clave": "iec62443"}], **extra}
        if man is not None:
            cfg["manifiesto"] = man
        p.write_text(json.dumps(cfg), encoding="utf-8")
        out = self.tmp / f"out{self.n}"
        sal = io.StringIO()
        with contextlib.redirect_stdout(sal), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main_diagrama(["--activos", str(self.inv), "--enlaces", str(self.com), "--formato",
                                            "xdome", "-o", str(out), "--perfil", str(p), *argumentos]), 0)
        self.consola = sal.getvalue()
        i18n.usar("es")
        return out

    MAN: ClassVar[dict] = {"sitios": ["S1", "S2"],
           "datasets": [{"sitio": "S1", "archivos": ["inv.csv", "com.csv"], "sensor": "xDome",
                         "inicio_utc": "2026-03-01T00:00:00Z", "fin_utc": "2026-03-04T00:00:00Z",
                         "no_ve": ["red de campo"]},
                        {"sitio": "S2", "archivos": ["otro.csv"]}],
           "plan": {"dias_por_punto": 3, "muestras": [{"nombre": "Todas", "sitios": ["S1", "S2"], "total": 3}]}}

    def test_exportes_con_ventana_declarada_y_sha256(self):
        o = self.correr(self.MAN)
        filas = _csv(o / mf.ARCHIVO)
        sha = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in (self.com, self.inv)}
        f = filas[0]
        self.assertEqual({x.split(":")[0]: x.split(":")[1] for x in f["sha256"].split(";")}, sha)
        self.assertEqual((f["origen_ventana"], f["inicio_utc"], f["dias"], f["archivos_n"], f["huecos"],
                          f["perdida_tcp_pct"], f["perdidas_pcapng"], f["estado"]),
                         ("declarada", "2026-03-01T00:00:00Z", "3.0", "2", "", "", "sin dato", "con datos"))
        self.assertEqual(f["punto_o_archivos"], "inv.csv;com.csv")
        self.assertEqual(f["dataset_id"], "DS-" + hashlib.sha256("\n".join(sorted(sha.values())).encode())
                         .hexdigest()[:12].upper())
        self.assertEqual(filas[1]["estado"], "sin datos en esta corrida")
        self.assertIn("faltan archivos: otro.csv", self.consola)
        self.assertTrue((o / f"manifiesto_{f['dataset_id']}.json").is_file())
        plan = _csv(o / mf.ARCHIVO_PLAN)
        self.assertEqual(plan[0]["sitio"], "muestra Todas: capturados 1 de 3 (planeados 2)")
        for n in ("reporte_ot.html", "reporte_ot.md"):
            ps = list(o.glob(n))
            if ps:
                texto = ps[0].read_text(encoding="utf-8")
                self.assertIn(mf.TITULO, texto, n)
                self.assertIn("el punto " + f["dataset_id"] + " no ve red de campo", texto, n)

    def test_exportes_de_vulnerabilidades_entran_en_el_dataset(self):
        vul = self.tmp / "vul.csv"
        vul.write_text("ip,cve,severidad,cvss,estado,producto,version,fuente\n"
                       "10.10.2.20,CVE-2099-0001,High,7.5,open,Firmware,1.0,Escaner\n", encoding="utf-8")
        man = {"sitios": ["S1"], "datasets": [{"sitio": "S1", "archivos": ["inv.csv", "com.csv", "vul.csv"],
                                               "inicio_utc": "2026-03-01T00:00:00Z", "fin_utc": "2026-03-02T00:00:00Z"}]}
        f = _csv(self.correr(man, ["--vulnerabilidades", str(vul)]) / mf.ARCHIVO)[0]
        self.assertEqual((f["estado"], f["archivos_n"]), ("con datos", "3"))
        self.assertIn("vul.csv:" + hashlib.sha256(vul.read_bytes()).hexdigest(), f["sha256"].split(";"))
        self.assertNotIn("faltan archivos", self.consola)

    def test_sin_la_clave_nada_cambia(self):
        sin, con = self.correr(None), self.correr(self.MAN)
        self.assertEqual([p.name for p in sin.glob("manifiesto*")] + [p.name for p in sin.glob("plan_captura*")], [])
        self.assertEqual((sin / "hallazgos_importados.csv").read_bytes(), (con / "hallazgos_importados.csv").read_bytes())
        self.assertNotIn("manifiesto", json.loads((sin / "resultado.json").read_text(encoding="utf-8")))
        for p in sin.iterdir():
            if p.suffix in (".html", ".md", ".csv", ".json"):
                self.assertNotIn("Manifiesto de datos", p.read_text(encoding="utf-8-sig"), p.name)
                self.assertNotIn("Ausencia de un flujo", p.read_text(encoding="utf-8-sig"), p.name)


if __name__ == "__main__":
    unittest.main()
