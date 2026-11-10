"""Z1b (D51): conductos entre zonas (ZCR), brechas, diagrama y hallazgos. Datos sinteticos."""
from __future__ import annotations

import contextlib
import csv
import io
import shutil
import sys
import tempfile
import time
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from types import SimpleNamespace
from typing import ClassVar

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))
sys.path.insert(0, str(RAIZ / "tests"))

import gen_exports
from test_firewalls_integracion import RUTAS, _contraste, _sesion
from test_firewalls_topologia import _cadena
from test_zonas import _activo, _inventario_xdome

from ot_assess import conductos_zcr as zc
from ot_assess import i18n, remediacion
from ot_assess import zonas as zo
from ot_assess.cli_diagrama import main as main_diagrama
from ot_assess.diagram import diagrama_zcr
from ot_assess.firewalls import cisco
from ot_assess.firewalls import integracion as fi
from ot_assess.model import Capture
from ot_assess.standards import ESTANDARES, MITRE


def _k(src, dst, port=443, l4="tcp", **kw):
    return dict({"src": src, "dst": dst, "l4": l4, "port": str(port), "servicio": "-", "bytes": 100}, **kw)


def _perfil(zonas):
    return {"zonas": zonas}


def _armar(ips: dict, zonas, conductos, firewall=None, zonas_fw=None):
    """ips: nombre -> (ip, purdue). Devuelve (assets, zonas de Z1a, zcr)."""
    assets = {n: _activo(ip, purdue=p) for n, (ip, p) in ips.items()}
    zon = zo.asignar(assets, _perfil(zonas), None, firewall, zonas_fw)
    return assets, zon, zc.construir(assets, conductos, zon, firewall)


class AgrupacionTest(unittest.TestCase):
    ZONAS: ClassVar[list] = [{"nombre": "A", "redes": ["10.1.0.0/24"]}, {"nombre": "B", "redes": ["10.2.0.0/24"]},
                             {"nombre": "C", "redes": ["10.3.0.0/24"]}]
    IPS: ClassVar[dict] = {"a1": ("10.1.0.5", ""), "a2": ("10.1.0.6", ""), "b1": ("10.2.0.5", ""), "c1": ("10.3.0.5", "")}

    def test_ambos_sentidos_un_conducto_y_dentro_de_zona_no_cuenta(self):
        cond = [_k("10.1.0.5", "10.2.0.5"), _k("10.2.0.5", "10.1.0.6", 502),
                _k("10.1.0.5", "10.1.0.6", 22)]            # el ultimo es dentro de A
        _a, _z, zcr = _armar(self.IPS, self.ZONAS, cond)
        self.assertEqual(len(zcr["filas"]), 1)
        f = zcr["filas"][0]
        self.assertEqual((f["id"], f["zona_a"], f["zona_b"], f["conductos"], f["ab"], f["ba"]),
                         ("C-01", "A", "B", 2, 1, 1))
        self.assertEqual(zcr["internos"], 1)
        self.assertEqual((f["activos_a"], f["activos_b"]), (2, 1))
        fila = zc.fila_tabla(f)
        self.assertEqual(fila[4], "1 a->b, 1 b->a")
        self.assertEqual(fila[5], "tcp/443 (1), tcp/502 (1)")
        self.assertEqual(fila[9], "sin datos de firewall")

    def test_ids_estables_y_ordenados_por_conductos_y_nombre(self):
        cond = [_k("10.3.0.5", "10.2.0.5"), _k("10.1.0.5", "10.3.0.5"), _k("10.1.0.6", "10.3.0.5", 80),
                _k("10.2.0.5", "10.1.0.5")]
        r1 = _armar(self.IPS, self.ZONAS, cond)[2]
        r2 = _armar(self.IPS, self.ZONAS, list(cond))[2]
        ids = [(f["id"], f["zona_a"], f["zona_b"], f["conductos"]) for f in r1["filas"]]
        self.assertEqual(ids, [("C-01", "A", "C", 2), ("C-02", "A", "B", 1), ("C-03", "B", "C", 1)])
        self.assertEqual(ids, [(f["id"], f["zona_a"], f["zona_b"], f["conductos"]) for f in r2["filas"]])

    def test_sin_zonas_no_hay_conductos_zcr(self):
        self.assertEqual(zc.construir({}, [_k("1.1.1.1", "2.2.2.2")], {}), {})
        self.assertFalse(zc.hay({}))


class BrechasTest(unittest.TestCase):
    def brechas(self, ips, zonas, cond, **kw):
        zcr = _armar(ips, zonas, cond, **kw)[2]
        return {f["id"]: f["brechas"] for f in zcr["filas"]}, zcr

    def test_rdp_entre_zonas_es_servicio_de_riesgo(self):
        zonas = [{"nombre": "A", "redes": ["10.1.0.0/24"]}, {"nombre": "B", "redes": ["10.2.0.0/24"]}]
        b, _zcr = self.brechas({"a": ("10.1.0.5", ""), "b": ("10.2.0.5", "")}, zonas, [_k("10.1.0.5", "10.2.0.5", 3389)])
        self.assertIn(zc.B_RIESGO, b["C-01"])
        b2, _ = self.brechas({"a": ("10.1.0.5", ""), "b": ("10.2.0.5", "")}, zonas, [_k("10.1.0.5", "10.2.0.5", 4840)])
        self.assertNotIn(zc.B_RIESGO, b2["C-01"])

    def test_nivel_1_con_internet_salta_niveles(self):
        zonas = [{"nombre": "Campo", "redes": ["10.1.0.0/24"]}]
        b, zcr = self.brechas({"plc": ("10.1.0.5", "Nivel 1")}, zonas, [_k("10.1.0.5", "8.8.8.8", 443)])
        self.assertIn(zc.B_SALTA, b["C-01"])
        self.assertEqual((zcr["filas"][0]["zona_a"], zcr["filas"][0]["zona_b"]), ("Campo", "Internet"))
        # niveles contiguos: no salta
        zonas = [{"nombre": "A", "redes": ["10.1.0.0/24"]}, {"nombre": "B", "redes": ["10.2.0.0/24"]}]
        b, _ = self.brechas({"a": ("10.1.0.5", "Nivel 1"), "b": ("10.2.0.5", "Nivel 2-3")}, zonas,
                            [_k("10.1.0.5", "10.2.0.5")])
        self.assertNotIn(zc.B_SALTA, b["C-01"])

    def test_sl_t_distinto_e_inferida(self):
        zonas = [{"nombre": "A", "redes": ["10.1.0.0/24"], "sl_t": "SL3"},
                 {"nombre": "B", "redes": ["10.2.0.0/24"], "sl_t": "SL1"},
                 {"nombre": "C", "redes": ["10.3.0.0/24"], "sl_t": "SL3", "inferida": True}]
        ips = {"a": ("10.1.0.5", ""), "b": ("10.2.0.5", ""), "c": ("10.3.0.5", "")}
        b, zcr = self.brechas(ips, zonas, [_k("10.1.0.5", "10.2.0.5"), _k("10.1.0.5", "10.3.0.5")])
        self.assertEqual(b["C-01"], [zc.B_SL])
        self.assertEqual(b["C-02"], [zc.B_INFERIDA])
        txt = zc.fila_tabla(zcr["filas"][0])
        self.assertIn("debe disenarse para el SL-T mayor (SL3)", txt[-1])
        self.assertEqual(txt[13], "SL3 / SL1")
        self.assertNotIn("cumple", txt[-1].lower())

    def test_sin_firewall_observado_y_alta(self):
        """A (Nivel 1) y B (Nivel 4) estan detras de la misma interfaz del FW-SCADA: ningun firewall en el camino."""
        zonas = [{"nombre": "A", "redes": ["10.30.1.0/24"]}, {"nombre": "B", "redes": ["10.30.2.0/24"]},
                 {"nombre": "Corp", "redes": ["10.10.0.0/16"]}]
        ips = {"a": ("10.30.1.5", "Nivel 1"), "b": ("10.30.2.5", "Nivel 4"), "c": ("10.10.1.5", "Nivel 4")}
        cond = [_k("10.30.1.5", "10.30.2.5", 4840), _k("10.30.1.5", "10.10.1.5", 4840)]
        assets = {n: _activo(ip, purdue=p) for n, (ip, p) in ips.items()}
        _rutas, fw = fi.integrar_modelos(_cadena(), ["it.txt", "dmz.txt", "scada.txt"], assets, cond)
        zon = zo.asignar(assets, _perfil(zonas), None, fw)
        zcr = zc.construir(assets, cond, zon, fw)
        por = {(f["zona_a"], f["zona_b"]): f for f in zcr["filas"]}
        ab, ac = por[("A", "B")], por[("A", "Corp")]
        self.assertIn(zc.B_SIN_FW, ab["brechas"])
        self.assertEqual((ab["firewalls"], ab["estado_fw"]), ([], "ninguno observado"))
        self.assertNotIn(zc.B_SIN_FW, ac["brechas"])
        self.assertEqual(ac["firewalls"], ["FW-DMZ", "FW-IT", "FW-SCADA"])
        self.assertEqual(zc.fila_tabla(ab)[9], "ninguno observado")
        cap = Capture(Path("conductos entre zonas"))
        zc.agregar_hallazgos(cap, zcr)
        f = {x["titulo"]: x for x in cap.findings}
        self.assertEqual(f[zc.TIT_SIN_FW]["severidad"], "Alta")      # Nivel 1 <-> Nivel 4
        self.assertIn("C-01", f[zc.TIT_SIN_FW]["evidencia"])
        # sin el cruce de nivel 1 con nivel 4, queda en Media
        ips["a"] = ("10.30.1.5", "Nivel 3")
        assets2 = {n: _activo(ip, purdue=p) for n, (ip, p) in ips.items()}
        zon2 = zo.asignar(assets2, _perfil(zonas), None, fw)
        cap2 = Capture(Path("x"))
        zc.agregar_hallazgos(cap2, zc.construir(assets2, cond, zon2, fw))
        self.assertEqual({x["titulo"]: x["severidad"] for x in cap2.findings}[zc.TIT_SIN_FW], "Media")

    def test_un_firewall_regla_y_propuesta(self):
        reglas = ("access-list CSM_FW_ACL_ line 1 extended permit tcp 10.10.1.0 255.255.255.0 any eq 80 "
                  "rule-id 7\n")
        zonas = [{"nombre": "Dentro", "redes": ["10.10.1.0/24"]}, {"nombre": "Fuera", "redes": ["10.10.9.0/24"]}]
        ips = {"a": ("10.10.1.5", ""), "b": ("10.10.9.5", "")}
        cond = [_k("10.10.1.5", "10.10.9.5", 80)]
        d = _contraste(reglas, cond)
        _a, _z, zcr = _armar(ips, zonas, cond, firewall=d)
        f = zcr["filas"][0]
        self.assertEqual(len(f["firewalls"]), 1)
        self.assertTrue(f["reglas"] and f["reglas"][0].startswith("7"), f["reglas"])


class ZonasFwTest(unittest.TestCase):
    def test_zonas_fw_renombra_la_zona_de_firewall(self):
        fw = cisco.analizar_texto(_sesion(RUTAS, ""))
        cond = [_k("10.10.1.5", "10.10.9.5", 80)]
        ips = {"a": ("10.10.1.5", ""), "b": ("10.10.9.5", "")}

        def correr(zonas_fw):
            assets = {n: _activo(ip, purdue=p) for n, (ip, p) in ips.items()}
            rutas = fi._rutas(fw, "fw.txt", assets, cond)
            d = fi.contrastar(fw, cond, "fw.txt", [])
            zon = zo.asignar(assets, {}, rutas, d, zonas_fw)
            return zon, zc.construir(assets, cond, zon, d)

        zon, zcr = correr(None)
        self.assertEqual({(f["zona_a"], f["zona_b"]) for f in zcr["filas"]}, {("dmz", "inside")})
        zon, zcr = correr({("fw.txt", "inside"): "IT"})
        self.assertEqual({(f["zona_a"], f["zona_b"]) for f in zcr["filas"]}, {("IT", "dmz")})
        self.assertIn("IT", [f["zona"] for f in zon["filas"]])


def _diez_zonas():
    zonas = [{"nombre": f"Z{i}", "redes": [f"10.0.{i}.0/24"]} for i in range(10)]
    ips = {f"h{i}": (f"10.0.{i}.5", "") for i in range(10)}
    cond = [_k(f"10.0.{i}.5", f"10.0.{j}.5", 1000 + i * 10 + j) for i in range(10) for j in range(i + 1, 10)]
    return zonas, ips, cond


class DiagramaTest(unittest.TestCase):
    def setUp(self):
        i18n.usar("es")
        zonas, ips, cond = _diez_zonas()
        self.zcr = _armar(ips, zonas, cond)[2]
        self.d = diagrama_zcr(self.zcr)

    def test_45_conductos_dibuja_40_y_la_nota(self):
        self.assertEqual(len(self.zcr["filas"]), 45)
        self.assertIn("40 conductos", self.d.nota)
        self.assertIn("5 mas", self.d.nota)
        svg = ET.fromstring(self.d.svg)
        self.assertEqual(sum(1 for g in svg.iter("{http://www.w3.org/2000/svg}g") if g.get("class") == "ot-e"), 40)
        self.assertIn("C-01", self.d.svg)
        self.assertNotIn("C-41", self.d.svg)
        self.assertEqual(sum(1 for ln in self.d.mermaid.splitlines() if "|" in ln and "--" in ln), 40)
        celdas = list(ET.fromstring(self.d.drawio).iter("mxCell"))
        self.assertEqual(sum(c.get("edge") == "1" for c in celdas), 40)
        self.assertEqual(sum(c.get("vertex") == "1" for c in celdas), 10 * 2)      # cajas + bandas

    def test_etiquetas_de_linea_y_estilo_con_brechas(self):
        self.assertIn("C-01", self.d.mermaid)
        self.assertIn("conductos entre zonas", zc.NOTA.lower())
        # con brechas (zonas inferidas) la linea es continua; la leyenda lo explica
        self.assertIn("Con brechas marcadas", self.d.svg)

    def test_sin_conductos_no_hay_diagrama(self):
        self.assertIsNone(diagrama_zcr({}))

    def test_rendimiento_44000_conductos_25_zonas(self):
        zonas = [{"nombre": f"Z{i}", "redes": [f"10.{i}.0.0/16"]} for i in range(25)]
        cond = [_k(f"10.{i % 25}.{(i // 25) % 200}.{i % 250}", f"10.{(i * 7 + 1) % 25}.{i % 200}.9", 1000 + i % 500)
                for i in range(44000)]
        assets = {c[k]: _activo(c[k]) for c in cond for k in ("src", "dst")}
        zon = zo.asignar(assets, _perfil(zonas), None, None)
        t0 = time.time()
        zcr = zc.construir(assets, cond, zon, None)
        diagrama_zcr(zcr)
        zc.filas_tabla(zcr)
        self.assertLess(time.time() - t0, 30)
        self.assertTrue(zcr["filas"])


class HallazgosTest(unittest.TestCase):
    def setUp(self):
        i18n.usar("es")
        self.addCleanup(i18n.usar, "es")
        zonas = [{"nombre": "A", "redes": ["10.30.1.0/24"]}, {"nombre": "B", "redes": ["10.30.2.0/24"]}]
        ips = {"a": ("10.30.1.5", "Nivel 1"), "b": ("10.30.2.5", "Nivel 4")}
        self.cond = [_k("10.30.1.5", "10.30.2.5", 3389)]
        assets = {n: _activo(ip, purdue=p) for n, (ip, p) in ips.items()}
        _r, fw = fi.integrar_modelos(_cadena(), ["it.txt", "dmz.txt", "scada.txt"], assets, self.cond)
        zon = zo.asignar(assets, _perfil(zonas), None, fw)
        self.zcr = zc.construir(assets, self.cond, zon, fw)
        self.cap = Capture(Path("conductos entre zonas"))
        zc.agregar_hallazgos(self.cap, self.zcr)
        self.f = {x["titulo"]: x for x in self.cap.findings}

    def test_tres_hallazgos_con_referencias_en_los_cinco_marcos(self):
        self.assertEqual(set(self.f), {zc.TIT_SIN_FW, zc.TIT_RIESGO, zc.TIT_SALTA})
        for tit, x in self.f.items():
            self.assertIn("(segun las zonas del analisis)", tit)
            self.assertEqual(set(x["referencias"]) - {MITRE.clave}, {e.clave for e in ESTANDARES.values()})
            self.assertIn("ZCR 3", x["referencias"]["iec62443"])
            self.assertIn("SR 5.2", x["referencias"]["iec62443"])
            self.assertIn("AC-4", x["referencias"]["nist-800-82"])
            self.assertIn("CIP-005 R1", x["referencias"]["nerc-cip"])
            self.assertIn("PR.IR-01", x["referencias"]["nist-csf"])
            for txt in (x["evidencia"], x["recomendacion"], x["por_que_importa"]):
                self.assertNotIn("cumple", txt.lower())
        self.assertIn("T0886", self.f[zc.TIT_RIESGO]["referencias"][MITRE.clave])
        self.assertNotIn(MITRE.clave, self.f[zc.TIT_SIN_FW]["referencias"])
        self.assertNotIn(MITRE.clave, self.f[zc.TIT_SALTA]["referencias"])
        self.assertEqual(self.f[zc.TIT_RIESGO]["severidad"], "Media")
        self.assertEqual(self.f[zc.TIT_SALTA]["severidad"], "Media")

    def test_evidencia_acotada_a_20(self):
        zonas, ips, cond = _diez_zonas()
        zcr = _armar(ips, zonas, cond)[2]
        for f in zcr["filas"]:
            f["brechas"] = [zc.B_RIESGO]
        cap = Capture(Path("x"))
        zc.agregar_hallazgos(cap, zcr)
        ev = cap.findings[0]["evidencia"]
        self.assertIn("Conductos: 45.", ev)
        self.assertEqual(ev.count("C-"), 20)

    def test_entran_al_plan_de_remediacion(self):
        res = SimpleNamespace(caps=[], extras=[self.cap], assets={}, perfil={})
        self.assertEqual({x["titulo"] for x in remediacion.plan(res)}, set(self.f))

    def test_en_ingles_sin_faltantes(self):
        i18n.usar("en")
        i18n.FALTANTES.clear()
        cap = Capture(Path("conductos entre zonas"))
        zc.agregar_hallazgos(cap, self.zcr)
        for x in cap.findings:
            for k in ("titulo", "evidencia", "por_que_importa", "recomendacion", "categoria"):
                i18n.t(x[k])
            for ref in x["referencias"].values():
                for pieza in ref.split("; "):
                    i18n.t(pieza)
        zc.filas_tabla(self.zcr)
        zc.tabla_reporte(self.zcr)
        zc.resumen_texto(self.zcr)
        i18n.t(zc.NOTA)
        for f in self.zcr["filas"]:
            f["brechas"] = list(zc.BRECHAS)
            f["sl_mayor"] = "SL2"
            f["propuesta"] = {"permitir": 1, "revisar": 1, "bloquear": 1}
        zc.filas_tabla(self.zcr)
        d = diagrama_zcr(self.zcr)
        self.assertFalse(i18n.FALTANTES, sorted(i18n.FALTANTES))
        self.assertEqual(i18n.t(zc.TIT_SIN_FW)[:12], "Zone-to-zone")
        self.assertTrue(d.titulo.isascii() and d.descripcion.isascii())


class SalidasTest(unittest.TestCase):
    def setUp(self):
        i18n.usar("es")
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_exportacion_de_plataforma_escribe_csv_diagrama_y_seccion(self):
        com = gen_exports.xd_escribir_comunicaciones(self.tmp / "com.csv", [
            gen_exports.xd_fila("10.10.1.10", "10.10.2.20", "From A to B", 502, "Modbus", tipo_a="HMI", tipo_b="PLC"),
            gen_exports.xd_fila("10.10.1.10", "10.10.3.30", "From A to B", 445, "N/A")])
        inv = _inventario_xdome(self.tmp / "inv.csv", [("HMI-1", "10.10.1.10", "Operacion"),
                                                       ("PLC-1", "10.10.2.20", "Campo"),
                                                       ("SRV-1", "10.10.3.30", "Campo")])
        out = self.tmp / "out"
        with contextlib.redirect_stdout(io.StringIO()):
            rc = main_diagrama(["--activos", str(inv), "--enlaces", str(com), "--formato", "xdome", "-o", str(out)])
        self.assertEqual(rc, 0)
        filas = list(csv.DictReader(open(out / "conductos_zcr.csv", encoding="utf-8-sig")))
        self.assertEqual(list(filas[0]), zc.COLUMNAS)
        self.assertEqual([(f["id"], f["zona_a"], f["zona_b"], f["conductos"]) for f in filas],
                         [("C-01", "Campo", "Operacion", "2")])
        for ext in ("svg", "mmd", "drawio"):
            self.assertTrue((out / f"{zc.SLUG}.{ext}").exists(), ext)
        h = (out / "diagramas.html").read_text(encoding="utf-8")
        self.assertIn("<h2>Zonas y conductos</h2>", h)
        self.assertIn("C-01", h)
        hall = (out / "hallazgos_importados.csv").read_text(encoding="utf-8-sig")
        self.assertIn("servicios de riesgo", hall)       # 445 compartir archivos


if __name__ == "__main__":
    unittest.main()
