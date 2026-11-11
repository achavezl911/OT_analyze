"""M2 (D46): varias fuentes de flujos con nombre: union sin duplicar, procedencia y cobertura. Datos sinteticos."""
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

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))
sys.path.insert(0, str(RAIZ / "tests"))

import gen_exports as ge
from test_firewalls_integracion import _sesion

from ot_assess import fuentes as fu
from ot_assess.cli import main
from ot_assess.importers import importar

D1, D2 = "2026-11-02", "2026-11-03"
HMI, PLC, SRV, LAB = "10.10.1.10", "10.10.2.20", "10.10.3.30", "10.10.4.40"
RUTAS = ("S*  0.0.0.0 0.0.0.0 [1/0] via 192.0.2.1, outside\n"
         "C   10.10.1.0 255.255.255.0 is directly connected, inside\n"
         "C   10.10.2.0 255.255.255.0 is directly connected, campo\n"
         "C   10.10.3.0 255.255.255.0 is directly connected, dmz\n"
         "C   10.10.4.0 255.255.255.0 is directly connected, lab\n")
REGLAS = "access-list CSM_FW_ACL_ advanced permit ip any any rule-id 1\n"


def _inv(nombre, ip, mac):
    return ["Ethernet", nombre, ip, mac, "Acme", "Net1", "OT", "Operator", "Acme", "HMI", "H100", "Windows", "10",
            "2026-11-02", "Low", 10, "N/A", "No", "N/A", "N/A", "N/A"]


def _escribir(carpeta: Path, nombre: str, filas: list) -> Path:
    return ge.xd_escribir_comunicaciones(carpeta / nombre, filas)


def _fila(b, dia=D1, nbytes=100, puerto=502, a=HMI, **kw):
    return ge.xd_fila(a, b, "From A to B", puerto, "Modbus", dia, nbytes, **kw)


class FuentesTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        ge.escribir_xlsx(cls.tmp / "inv.xlsx", [ge.XD_INVENTARIO,
                                                _inv("HMI-1", HMI, "aa:bb:cc:00:00:01"),
                                                _inv("PLC-1", PLC, "aa:bb:cc:00:00:02"),
                                                _inv("SRV-1", SRV, "aa:bb:cc:00:00:03"),
                                                _inv("LAB-1", LAB, "aa:bb:cc:00:00:04")])
        cls.inv = cls.tmp / "inv.xlsx"
        cls.fw = cls.tmp / "fw.txt"
        cls.fw.write_text(_sesion(
            RUTAS, "access-list CSM_FW_ACL_ advanced permit ip ifc inside any ifc campo any rule-id 1\n"
                   "access-list CSM_FW_ACL_ advanced permit ip ifc inside any ifc dmz any rule-id 2\n"),
            encoding="utf-8")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _imp(self, nombre, fuentes):
        d = self.tmp / nombre
        d.mkdir(exist_ok=True)
        rutas = {n: [str(_escribir(d, f"{n}_{i}.csv", filas)) for i, filas in enumerate(lotes)]
                 for n, lotes in fuentes.items()}
        return importar([str(self.inv)], [], "auto", None, "auto", rutas)

    def test_mismo_dia_maximo_entre_fuentes(self):
        imp = self._imp("t1", {"A": [[_fila(PLC, nbytes=100)]], "B": [[_fila(PLC, nbytes=120)]]})
        self.assertEqual(len(imp.conduits), 1)
        k = imp.conduits[0]
        self.assertEqual((k["bytes"], k["fuentes"], k["dias"]), (120, ["A", "B"], 1))

    def test_dias_distintos_suma_de_maximos(self):
        imp = self._imp("t2", {"A": [[_fila(PLC, D1, 100), _fila(PLC, D2, 50)]],
                               "B": [[_fila(PLC, D1, 120)]]})
        k = imp.conduits[0]
        self.assertEqual((k["bytes"], k["dias"], k["primera"], k["ultima"]), (170, 2, D1, D2))
        self.assertEqual(imp.fuentes["resumen"][0]["unicos"], 0)
        self.assertEqual([x["compartidos"] for x in imp.fuentes["resumen"]], [1, 1])
        self.assertEqual(imp.fuentes["resumen"][1]["primera"], D1)

    def test_fuente_unica_en_su_conducto_y_sin_fecha(self):
        imp = self._imp("t3", {"A": [[_fila(PLC, "", 70)]], "B": [[_fila(SRV, D1, 5, 445)]]})
        self.assertEqual(sorted((k["fuentes"], k["bytes"]) for k in imp.conduits), [(["A"], 70), (["B"], 5)])
        sin_fecha = self._imp("t3b", {"A": [[_fila(PLC, "", 70)]], "B": [[_fila(PLC, "", 90)]]}).conduits[0]
        self.assertEqual(sin_fecha["bytes"], 90)       # maximo de los totales de cada fuente

    def test_misma_fuente_varios_archivos_fila_repetida_una_vez(self):
        rep = _fila(PLC, D1, 100)
        imp = self._imp("t4", {"A": [[rep, _fila(PLC, D2, 10)], [rep]]})
        self.assertEqual(imp.conduits[0]["bytes"], 110)
        self.assertTrue(any("1 filas repetidas exactas" in a and "'A'" in a for a in imp.advertencias))

    def test_mismo_dia_en_dos_archivos_vale_el_maximo(self):
        # dos exportaciones "X to any" y "Y to any" traen el mismo flujo: no se suman (D46, por archivo)
        imp = self._imp("t5", {"A": [[_fila(PLC, D1, 100)], [_fila(PLC, D1, 40)]]})
        self.assertEqual(imp.conduits[0]["bytes"], 100)
        self.assertFalse(any("repetidas" in a for a in imp.advertencias))

    def test_filas_distintas_del_mismo_dia_en_un_archivo_se_suman(self):
        imp = self._imp("t5b", {"A": [[_fila(PLC, D1, 100), _fila(PLC, D1, 40)]]})
        self.assertEqual(imp.conduits[0]["bytes"], 140)

    def test_mismo_archivo_en_dos_fuentes_no_es_repeticion(self):
        imp = self._imp("t6", {"A": [[_fila(PLC, D1, 100)]], "B": [[_fila(PLC, D1, 100)]]})
        self.assertEqual(imp.conduits[0]["bytes"], 100)
        self.assertFalse(any("repetidas" in a for a in imp.advertencias))

    def test_separar_y_carpeta(self):
        d = self.tmp / "carpeta"
        d.mkdir()
        _escribir(d, "uno.csv", [_fila(PLC)])
        _escribir(d, "dos.csv", [_fila(SRV, nbytes=1)])
        (d / "otro.txt").write_text("x", encoding="utf-8")
        f = fu.separar([f"IT={d}", f"IT={d / 'uno.csv'}"])
        self.assertEqual(list(f), ["IT"])
        self.assertEqual([Path(x).name for x in f["IT"]], ["dos.csv", "uno.csv", "uno.csv"])
        with self.assertRaises(ValueError):
            fu.separar(["Uno=no/existe"])
        with self.assertRaises(ValueError):
            fu.separar(["Datos del cliente"])      # el texto del encabezado va en --fuente, no aqui

    def _cli(self, nombre, *extra):
        out = self.tmp / nombre
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main(["diagrama", "--activos", str(self.inv), "-o", str(out), *extra])
        self.assertEqual(rc, 0)
        return out, buf.getvalue()

    @staticmethod
    def _csv(p):
        with open(p, newline="", encoding="utf-8-sig") as fh:
            return list(csv.DictReader(fh))

    def _fuentes_cli(self):
        d = self.tmp / "cli"
        d.mkdir(exist_ok=True)
        a = _escribir(d, "a.csv", [_fila(PLC, D1, 100)])
        b = _escribir(d, "b.csv", [_fila(PLC, D1, 120), _fila(SRV, D1, 5, 445)])
        return [f"IT={a}", f"OT={b}"]

    def test_cobertura_por_interfaz_y_hallazgo(self):
        out, _ = self._cli("c1", "--firewall", str(self.fw), *[x for f in self._fuentes_cli() for x in ("--fuente-flujos", f)])
        cob = {(f["segmento"], f["fuente"]): f for f in self._csv(out / "fuentes_cobertura.csv")}
        self.assertEqual(cob[("inside", "IT")]["conductos_vistos"], "1")
        self.assertEqual(cob[("inside", "OT")]["conductos_vistos"], "2")
        self.assertEqual(cob[("inside", "OT")]["solo_esta_fuente"], "1")
        self.assertEqual((cob[("dmz", "IT")]["conductos_vistos"], cob[("dmz", "OT")]["solo_esta_fuente"]), ("0", "1"))
        self.assertEqual(cob[("campo", "IT")]["equipos_vistos"], "1")
        self.assertEqual({f["conductos_vistos"] for (s, _f), f in cob.items() if s == "lab"}, {"0"})
        res = {f["fuente"]: f for f in self._csv(out / "fuentes_resumen.csv")}
        self.assertEqual((res["IT"]["conductos"], res["IT"]["unicos_de_la_fuente"], res["IT"]["compartidos"]),
                         ("1", "0", "1"))
        self.assertEqual((res["OT"]["conductos"], res["OT"]["unicos_de_la_fuente"]), ("2", "1"))
        hall = [h for h in json.loads((out / "importacion.json").read_text(encoding="utf-8"))["hallazgos"]
                if "sin cobertura" in h["titulo"]]
        self.assertEqual(len(hall), 1)
        self.assertEqual(hall[0]["severidad"], "Informativa")
        self.assertIn("lab", hall[0]["evidencia"])
        self.assertNotIn("dmz,", hall[0]["evidencia"])
        self.assertEqual(len(hall[0]["referencias"]) , 5)      # los seis marcos menos MITRE, sin referencia

    def test_cruces_del_firewall_llevan_fuentes(self):
        out, _ = self._cli("c2", "--firewall", str(self.fw), *[x for f in self._fuentes_cli() for x in ("--fuente-flujos", f)])
        det = self._csv(out / "firewall_cruces_detalle.csv")
        por_dst = {f["ip_destino"]: f["fuentes"] for f in det}
        self.assertEqual(por_dst[PLC], "IT; OT")
        self.assertEqual(por_dst[SRV], "OT")
        agr = {f["puerto"]: f["fuentes"] for f in self._csv(out / "firewall_cruces.csv")}
        self.assertEqual(agr, {"502": "IT; OT", "445": "OT"})

    def test_sin_fuente_nada_cambia(self):
        d = self.tmp / "sf"
        d.mkdir(exist_ok=True)
        a = _escribir(d, "a.csv", [_fila(PLC, D1, 100), _fila(SRV, D1, 5, 445)])
        out, _ = self._cli("c3", "--firewall", str(self.fw), "--enlaces", str(a))
        self.assertFalse((out / "fuentes_cobertura.csv").exists())
        self.assertFalse((out / "fuentes_resumen.csv").exists())
        self.assertNotIn("fuentes", self._csv(out / "firewall_cruces_detalle.csv")[0])
        self.assertNotIn("fuentes", json.loads((out / "importacion.json").read_text(encoding="utf-8")))
        imp = importar([str(self.inv)], [str(a)])
        self.assertTrue(all("fuentes" not in k for k in imp.conduits))
        self.assertEqual(imp.fuentes, {})

    def test_enlaces_y_fuente_se_suman(self):
        d = self.tmp / "mix"
        d.mkdir(exist_ok=True)
        a = _escribir(d, "a.csv", [_fila(PLC, D1, 100)])
        b = _escribir(d, "b.csv", [_fila(PLC, D1, 120)])
        out, _ = self._cli("c4", "--enlaces", str(a), "--fuente-flujos", f"Sensor2={b}")
        res = {f["fuente"] for f in self._csv(out / "fuentes_resumen.csv")}
        self.assertEqual(res, {"principal", "Sensor2"})


try:
    import scapy  # noqa: F401
    HAY_SCAPY = True
except ImportError:
    HAY_SCAPY = False


def _clave(ip_a, ip_b, l4, puerto):
    return (frozenset((ip_a, ip_b)), l4, str(puerto))


@unittest.skipUnless(shutil.which("tshark") and HAY_SCAPY, "requiere tshark y scapy")
class CapturasComoFuenteTest(unittest.TestCase):
    """M2b: --fuente-flujos acepta capturas y las trata como un archivo mas de su fuente."""

    @classmethod
    def setUpClass(cls):
        import gen_pcaps
        cls.tmp = Path(tempfile.mkdtemp())
        sys.argv = ["gen", str(cls.tmp / "pcaps")]
        gen_pcaps.main()
        cls.pcap = cls.tmp / "pcaps" / "punto_a.pcap"

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_captura_sola_da_los_mismos_conductos_que_el_cli_de_capturas(self):
        out = self.tmp / "cap"
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main([str(self.pcap), "-o", str(out)]), 0)
        with open(out / "comunicaciones.csv", newline="", encoding="utf-8-sig") as fh:
            esperado = {}
            for f in csv.DictReader(fh):
                c = _clave(f["origen_ip"], f["destino_ip"], f["l4"], f["puerto"])
                esperado[c] = esperado.get(c, 0) + int(f["paquetes"])
        imp = importar([], [], "auto", None, "auto", {"FW": [str(self.pcap)]})
        obtenido = {}
        for k in imp.conduits:
            c = _clave(k["src"], k["dst"], k["l4"], k["port"])
            obtenido[c] = obtenido.get(c, 0) + k["pkts"]
        self.assertTrue(esperado)
        self.assertEqual(obtenido, esperado)
        self.assertTrue(all(k["fuentes"] == ["FW"] and k["primera"] for k in imp.conduits))
        self.assertEqual(imp.fuentes["resumen"][0]["tipo"], "captura")

    def _un_conducto(self):
        regs, _av = fu.procesar_capturas([str(self.pcap)])
        # con servicio deducido del puerto (sin nombre propio de tshark): lo que una exportacion sin protocolo trae igual
        return max((x for x in regs[str(self.pcap)] if not x["servicio"]), key=lambda x: x["bytes"])

    def test_exportacion_y_captura_el_mismo_dia_cuentan_una_vez(self):
        r = self._un_conducto()
        d = self.tmp / "ex"
        d.mkdir()
        csv_ = _escribir(d, "e.csv", [ge.xd_fila(r["src"], r["dst"], "Bidirectional" if r["bidireccional"] else "From A to B", r["port"], r["l4"].upper(), r["dia"],
                                                 r["bytes"] + 5000)])
        imp = importar([], [], "auto", None, "auto", {"Claroty": [str(csv_)], "FW": [str(self.pcap)]})
        k = [k for k in imp.conduits if _clave(k["src"], k["dst"], k["l4"], k["port"]) ==
             _clave(r["src"], r["dst"], r["l4"], r["port"]) and k["bytes"] > 0]
        self.assertEqual(len(k), 1)
        self.assertEqual((k[0]["bytes"], k[0]["fuentes"]), (r["bytes"] + 5000, ["Claroty", "FW"]))
        tipos = {x["fuente"]: x["tipo"] for x in imp.fuentes["resumen"]}
        self.assertEqual(tipos, {"Claroty": "exportacion", "FW": "captura"})

    def test_carpeta_con_captura_y_csv_es_mixta(self):
        r = self._un_conducto()
        d = self.tmp / "mixta"
        d.mkdir()
        shutil.copy(self.pcap, d / "punto_a.pcap")
        _escribir(d, "e.csv", [ge.xd_fila(HMI, PLC, "Bidirectional", 502, "N/A", D1, 10)])
        f = fu.separar([f"X={d}"])
        self.assertEqual([Path(x).name for x in f["X"]], ["e.csv", "punto_a.pcap"])
        imp = importar([], [], "auto", None, "auto", f)
        self.assertEqual(imp.fuentes["resumen"][0]["tipo"], "mixta")
        self.assertTrue(any(k["src"] == r["src"] for k in imp.conduits))

    def test_deteccion_por_cabecera_sin_extension(self):
        sin_ext = self.tmp / "captura_sin_extension"
        shutil.copy(self.pcap, sin_ext)
        self.assertTrue(fu.es_captura(sin_ext))


class SinTsharkTest(unittest.TestCase):
    def test_sin_tshark_avisa_y_el_resto_sale(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            falsa = tmp / "x.pcap"
            falsa.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\0" * 20)
            csv_ = _escribir(tmp, "e.csv", [_fila(PLC)])
            imp = importar([], [], "auto", None, "auto", {"IT": [str(csv_)], "FW": [str(falsa)]},
                           str(tmp / "no_existe"))
            self.assertEqual(len(imp.conduits), 1)
            self.assertTrue(any("sin tshark" in a for a in imp.advertencias))
            self.assertEqual({x["fuente"]: x["tipo"] for x in imp.fuentes["resumen"]},
                             {"IT": "exportacion", "FW": "captura"})
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class IdentidadEntreFuentesTest(unittest.TestCase):
    """M2c (D46): el mismo flujo en dos fuentes es un conducto aunque falte el l4 o el protocolo se nombre distinto."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        ge.escribir_xlsx(self.tmp / "inv.xlsx", [ge.XD_INVENTARIO, _inv("HMI-1", HMI, "aa:bb:cc:00:00:01"),
                                                _inv("PLC-1", PLC, "aa:bb:cc:00:00:02")])

    def _imp(self, exportaciones, capturas=None):
        """exportaciones: {fuente: [filas]}; capturas: {fuente: [registros]} (simula tshark sin necesitarlo)."""
        from unittest import mock
        rutas = {n: [str(_escribir(self.tmp, f"{n}.csv", filas))] for n, filas in exportaciones.items()}
        regs = {}
        for n, rs in (capturas or {}).items():
            p = self.tmp / f"{n}.pcap"
            p.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\0" * 20)
            rutas.setdefault(n, []).append(str(p))
            regs[str(p)] = [dict({"servicio": "", "bidireccional": False, "pkts": 1, "dia": D1}, **r) for r in rs]
        with mock.patch("ot_assess.fuentes.procesar_capturas", return_value=(regs, [])):
            return importar([str(self.tmp / "inv.xlsx")], [], "auto", None, "auto", rutas)

    def _cap(self, l4="tcp", port="443", servicio="HTTPS", by=500):
        return {"src": HMI, "dst": PLC, "l4": l4, "port": port, "servicio": servicio, "bytes": by}

    def _ex(self, proto, puerto=443, by=100, dia=D1):
        return ge.xd_fila(HMI, PLC, "From A to B", puerto, proto, dia, by)

    def test_captura_y_exportacion_sin_l4_son_un_conducto(self):
        imp = self._imp({"XD": [self._ex("TLS")]}, {"FW": [self._cap()]})
        self.assertEqual(len(imp.conduits), 1)
        k = imp.conduits[0]
        self.assertEqual((k["l4"], k["servicio"], k["protocolos"], k["fuentes"]),
                         ("tcp", "TLS", ["HTTPS", "TLS"], ["FW", "XD"]))
        self.assertEqual(k["bytes"], 500)       # mismo dia: maximo entre fuentes

    def test_varios_nombres_de_una_fuente_se_unen_con_la_captura(self):
        imp = self._imp({"XD": [self._ex("TLS", by=100), self._ex("TLS 1.2", by=200)]},
                        {"FW": [self._cap(by=50)]})
        self.assertEqual(len(imp.conduits), 1)
        k = imp.conduits[0]
        self.assertEqual(k["protocolos"], ["HTTPS", "TLS", "TLS 1.2"])
        self.assertEqual(k["bytes"], 300)       # suma dentro del archivo; maximo contra la captura

    def test_tcp_y_udp_conocidos_en_el_mismo_puerto_son_distintos(self):
        imp = self._imp({"XD": [self._ex("DNS", 53)]}, {"FW": [self._cap("tcp", "53", "DNS"),
                                                                self._cap("udp", "53", "DNS")]})
        self.assertEqual(sorted(k["l4"] for k in imp.conduits if k["l4"]), ["tcp", "udp"])
        self.assertEqual(len(imp.conduits), 3)      # el DNS sin l4 es ambiguo: no se une a ninguno

    def test_dentro_de_una_fuente_no_se_unen(self):
        imp = self._imp({"XD": [self._ex("TLS"), self._ex("TLS 1.2")]})
        self.assertEqual(sorted(k["servicio"] for k in imp.conduits), ["TLS", "TLS 1.2"])
        imp = self._imp({"XD": [self._ex("TLS"), self._ex("TLS 1.2")], "B": [self._ex("Modbus", 502)]})
        self.assertEqual(len(imp.conduits), 3)

    def test_sin_fuente_flujos_nada_cambia(self):
        csv_ = _escribir(self.tmp, "e.csv", [self._ex("TLS"), self._ex("TLS 1.2")])
        imp = importar([str(self.tmp / "inv.xlsx")], [str(csv_)], "auto", None, "auto")
        self.assertEqual(len(imp.conduits), 2)
        self.assertTrue(all("protocolos" not in k and "fuentes" not in k for k in imp.conduits))

    def test_mismo_dia_en_dos_fuentes_toma_el_maximo(self):
        imp = self._imp({"XD": [self._ex("TLS", by=900)]}, {"FW": [self._cap(by=500)]})
        self.assertEqual([k["bytes"] for k in imp.conduits], [900])


if __name__ == "__main__":
    unittest.main()
