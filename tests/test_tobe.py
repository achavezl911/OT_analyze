"""T1a (D85): arquitectura TO-BE (allowlist zona x zona, matriz y diagrama). Datos sinteticos."""
from __future__ import annotations

import contextlib
import csv
import io
import json
import shutil
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import ClassVar

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))
sys.path.insert(0, str(RAIZ / "tests"))

import gen_exports
from test_conductos_zcr import _armar, _k
from test_zonas import _inventario_xdome

from ot_assess import i18n, perfil
from ot_assess import tobe as tb
from ot_assess.cli_diagrama import main as main_diagrama
from ot_assess.diagram import Opciones, diagrama_tobe
from ot_assess.standards import ESTANDARES

ZONAS: ClassVar[list] = [
    {"nombre": "Empresa", "redes": ["10.4.0.0/24"]}, {"nombre": "Control", "redes": ["10.1.0.0/24"]},
    {"nombre": "Supervision", "redes": ["10.2.0.0/24"]}, {"nombre": "Operaciones", "redes": ["10.3.0.0/24"]},
    {"nombre": "Operaciones B", "redes": ["10.5.0.0/24"]}, {"nombre": "Interna", "redes": ["10.6.0.0/24"]}]
IPS: ClassVar[dict] = {
    "it": ("10.4.0.5", "Nivel 4"), "plc": ("10.1.0.5", "Nivel 1"), "hmi": ("10.2.0.5", "Nivel 2"),
    "op1": ("10.3.0.5", "Nivel 3"), "op2": ("10.5.0.5", "Nivel 3"), "pc": ("10.6.0.5", "Nivel 3")}


def _tobe(conductos, zonas=ZONAS, ips=IPS, hallazgos=(), perfil_extra=None):
    assets, zon, zcr = _armar(ips, zonas, conductos)
    pf = {"zonas": zonas, **(perfil_extra or {})}
    return tb.construir(assets, conductos, zon, zcr, None, hallazgos, pf), zcr


def _fila(r, servicio, origen=None):
    xs = [f for f in r["filas"] if f["servicio"] == servicio and (origen is None or f["zona_origen"] == origen)]
    assert len(xs) == 1, xs
    return xs[0]


class DecisionTest(unittest.TestCase):
    def test_internet_hacia_interna_y_dns_publico_y_ot_hacia_internet_se_bloquean(self):
        r, _z = _tobe([_k("151.101.1.1", "10.1.0.5", 502), _k("10.3.0.5", "8.8.8.8", 53, "udp"),
                       _k("10.1.0.5", "1.1.1.1", 443)])
        f = _fila(r, "tcp/502")
        self.assertEqual((f["decision"], f["zona_origen"], f["zona_destino"]), (tb.D_BLOQUEAR, "Internet", "Control"))
        self.assertEqual(f["motivo"][0], tb.M_INTERNET_ENTRA)
        dns = _fila(r, "udp/53")
        self.assertEqual((dns["decision"], dns["motivo"][0]), (tb.D_BLOQUEAR, tb.M_DNS))
        ot = _fila(r, "tcp/443", "Control")
        self.assertEqual((ot["decision"], ot["motivo"][0]), (tb.D_BLOQUEAR, tb.M_OT_SALE))

    def test_it_a_control_por_rdp_va_por_dmz_con_servidor_de_salto(self):
        r, _z = _tobe([_k("10.4.0.5", "10.1.0.5", 3389)])
        f = r["filas"][0]
        self.assertEqual(f["decision"], tb.D_DMZ)
        self.assertEqual(f["motivo"][1]["s"], tb.S_SALTO)
        self.assertIn("servidor de salto", tb._motivo(f))

    def test_it_a_control_por_historiador_va_por_dmz_con_replica(self):
        r, _z = _tobe([_k("10.4.0.5", "10.1.0.5", 5450, servicio="OSIsoft PI"), _k("10.1.0.5", "10.4.0.5", 8530)])
        self.assertEqual(_fila(r, "tcp/5450")["motivo"][1]["s"], tb.S_HISTORIADOR)
        self.assertIn("replica del historiador", tb._motivo(_fila(r, "tcp/5450")))
        self.assertEqual(_fila(r, "tcp/8530")["motivo"][1]["s"], tb.S_PARCHES)
        self.assertEqual(_fila(r, "tcp/8530")["zona_origen"], "Control")      # en cualquier sentido

    def test_otro_servicio_usa_servicio_intermedio_generico(self):
        r, _z = _tobe([_k("10.4.0.5", "10.1.0.5", 9999, servicio="x")])
        self.assertEqual(r["filas"][0]["motivo"][1]["s"], tb.S_OTRO)

    def test_telnet_entre_zonas_de_nivel_3_se_revisa(self):
        r, _z = _tobe([_k("10.3.0.5", "10.5.0.5", 23)])
        f = r["filas"][0]
        self.assertEqual((f["decision"], f["motivo"][0]), (tb.D_REVISAR, tb.M_RIESGO))
        self.assertIn("acceso remoto", tb._motivo(f))

    def test_modbus_de_nivel_2_a_1_visto_varios_dias_se_permite_con_pares_observados(self):
        r, _z = _tobe([_k("10.2.0.5", "10.1.0.5", 502, dias=4)])
        f = r["filas"][0]
        self.assertEqual((f["decision"], f["dias"]), (tb.D_PERMITIR, 4))
        self.assertEqual((f["activos_origen"], f["activos_destino"]), (["10.2.0.5"], ["10.1.0.5"]))

    def test_un_solo_dia_y_puerto_alto_se_revisan(self):
        r, _z = _tobe([_k("10.2.0.5", "10.1.0.5", 502, dias=1), _k("10.3.0.5", "10.5.0.5", 40123)])
        self.assertEqual(_fila(r, "tcp/502")["motivo"][0], tb.M_UN_DIA)
        self.assertEqual(_fila(r, "tcp/40123")["motivo"][0], tb.M_ALTO)

    def test_dentro_de_una_zona_no_entra_y_la_unidad_es_zona_zona_servicio(self):
        r, _z = _tobe([_k("10.3.0.5", "10.5.0.5", 502), _k("10.3.0.5", "10.5.0.5", 502), _k("10.3.0.5", "10.3.0.5", 22)])
        self.assertEqual(len(r["filas"]), 1)
        self.assertEqual(r["filas"][0]["conductos"], 2)
        self.assertEqual(r["internos"], 1)             # el conducto dentro de Operaciones se cuenta aparte

    def test_orden_bloquear_dmz_revisar_permitir(self):
        r, _z = _tobe([_k("10.2.0.5", "10.1.0.5", 502, dias=3), _k("10.3.0.5", "10.5.0.5", 23),
                       _k("10.4.0.5", "10.1.0.5", 3389), _k("151.101.1.1", "10.1.0.5", 502)])
        self.assertEqual([f["decision"] for f in r["filas"]], [tb.D_BLOQUEAR, tb.D_DMZ, tb.D_REVISAR, tb.D_PERMITIR])

    def test_respuesta_de_sesion_no_genera_fila(self):
        assets, zon, zcr = _armar(IPS, ZONAS, [_k("10.2.0.5", "10.1.0.5", 502), _k("10.1.0.5", "10.2.0.5", 49000)])
        fw = {"hostname": "fw", "resultados": [{"resultado": "permitido"}, {"resultado": "respuesta"}]}
        r = tb.construir(assets, [_k("10.2.0.5", "10.1.0.5", 502), _k("10.1.0.5", "10.2.0.5", 49000)], zon, zcr, fw, (),
                         {"zonas": ZONAS})
        self.assertEqual([f["servicio"] for f in r["filas"]], ["tcp/502"])

    def test_sentido_real_del_firewall(self):
        conductos = [_k("10.1.0.5", "10.2.0.5", 502)]
        assets, zon, zcr = _armar(IPS, ZONAS, conductos)
        fw = {"hostname": "fw", "resultados": [{"resultado": "permitido", "sentido": "invertido"}]}
        r = tb.construir(assets, conductos, zon, zcr, fw, (), {"zonas": ZONAS})
        self.assertEqual((r["filas"][0]["zona_origen"], r["filas"][0]["zona_destino"]), ("Supervision", "Control"))

    def test_sin_conductos_entre_zonas_queda_vacio(self):
        r = _tobe([_k("10.3.0.5", "10.3.0.5", 502)])[0]
        self.assertEqual((r["filas"], r["vacio"], r["respuestas_probables"]), ([], True, 0))
        self.assertFalse(tb.hay(r))
        self.assertTrue(tb.hay_seccion(r))
        self.assertEqual(tb.tablas(r), [])
        self.assertIn("Sin comunicacion observada entre zonas distintas", tb.aviso(r))

    def test_dns_hacia_puerto_efimero_es_respuesta_probable_y_hacia_53_es_fila(self):
        r, _z = _tobe([_k("10.3.0.5", "10.1.0.5", 53000, "udp", servicio="DNS"),
                       _k("10.3.0.5", "10.1.0.5", 53, "udp", servicio="DNS"),
                       _k("10.3.0.5", "10.1.0.5", 5353, "udp", servicio="mDNS")])
        self.assertEqual(sorted(f["servicio"] for f in r["filas"]), ["udp/53", "udp/5353"])
        self.assertEqual(r["respuestas_probables"], 1)
        self.assertIn("respuestas probables", tb.nota_texto(r))
        self.assertEqual(tb.para_json(r)["respuestas_probables"], 1)

    def test_puerto_dinamico_con_conducto_inverso_a_puerto_de_servidor_es_respuesta(self):
        r, _z = _tobe([_k("10.3.0.5", "10.1.0.5", 50000), _k("10.1.0.5", "10.3.0.5", 1433)])
        self.assertEqual([f["servicio"] for f in r["filas"]], ["tcp/1433"])
        self.assertEqual(r["respuestas_probables"], 1)
        r, _z = _tobe([_k("10.3.0.5", "10.1.0.5", 50000)])
        f = _fila(r, "tcp/50000")
        self.assertEqual((f["decision"], f["motivo"][0], r["respuestas_probables"]), (tb.D_REVISAR, tb.M_ALTO, 0))

    def test_servicio_sin_puerto_se_revisa_nunca_se_permite(self):
        c = _k("10.3.0.5", "10.1.0.5", "", "", dias=3)
        r, _z = _tobe([c])
        f = _fila(r, "ip")
        self.assertEqual((f["decision"], f["motivo"][0]), (tb.D_REVISAR, tb.M_SIN_PUERTO))


class DmzTest(unittest.TestCase):
    COND: ClassVar[list] = [_k("10.4.0.5", "10.1.0.5", 3389), _k("10.2.0.5", "10.1.0.5", 502, dias=3)]

    def test_sin_zona_dmz_se_propone_una(self):
        r, _z = _tobe(self.COND)
        self.assertTrue(r["dmz_propuesta"])
        self.assertEqual(r["dmz"], tb.DMZ_PROPUESTA)
        self.assertIn(tb.DMZ_PROPUESTA, tb.nota_texto(r))
        g = tb.grafo(r)
        self.assertIn(tb.DMZ_PROPUESTA, {n.id for n in g.nodos})
        self.assertIn("(propuesta)", diagrama_tobe(r).svg)

    def test_sin_filas_por_dmz_no_se_propone(self):
        r, _z = _tobe([_k("10.2.0.5", "10.1.0.5", 502, dias=3)])
        self.assertFalse(r["dmz_propuesta"])
        self.assertEqual(r["dmz"], "")

    def test_perfil_dmz_true_usa_esa_zona(self):
        zonas = [*ZONAS, {"nombre": "Servicios", "redes": ["10.9.0.0/24"], "dmz": True}]
        ips = {**IPS, "srv": ("10.9.0.5", "Nivel 3.5")}
        r, _z = _tobe(self.COND, zonas, ips)
        self.assertEqual((r["dmz"], r["dmz_propuesta"]), ("Servicios", False))
        ids = {n.id for n in tb.grafo(r).nodos}
        self.assertIn("Servicios", ids)

    def test_nombre_con_dmz_sin_distinguir_mayusculas(self):
        zonas = [*ZONAS, {"nombre": "zona dMz planta", "redes": ["10.9.0.0/24"]}]
        r, _z = _tobe(self.COND, zonas, {**IPS, "srv": ("10.9.0.5", "Nivel 3.5")})
        self.assertEqual((r["dmz"], r["dmz_propuesta"]), ("zona dMz planta", False))

    def test_trafico_con_la_dmz_no_se_envia_otra_vez_por_la_dmz(self):
        zonas = [*ZONAS, {"nombre": "DMZ", "redes": ["10.9.0.0/24"]}]
        ips = {**IPS, "srv": ("10.9.0.5", "Nivel 1")}                      # aunque el equipo sea de nivel bajo
        r, _z = _tobe([_k("10.4.0.5", "10.9.0.5", 443)], zonas, ips)
        self.assertEqual(r["filas"][0]["decision"], tb.D_PERMITIR)

    def test_perfil_valida_el_booleano(self):
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, True)
        base = {"version": 1, "cliente": "C", "marcos": [{"clave": "iec62443"}]}
        for valor, esperado in ((True, True), ("si", None)):
            (d / "p.json").write_text(json.dumps(dict(base, zonas=[
                {"nombre": "Z", "redes": ["10.0.0.0/24"], "dmz": valor}])), encoding="utf-8")
            if esperado is None:
                with self.assertRaises(SystemExit) as cm:
                    perfil.cargar(d / "p.json")
                self.assertIn("'dmz' debe ser true o false", str(cm.exception))
            else:
                self.assertTrue(perfil.cargar(d / "p.json")["zonas"][0]["dmz"])


class HallazgosMatrizTest(unittest.TestCase):
    def test_ids_hallazgo_trae_el_de_servicios_de_riesgo_de_esos_equipos(self):
        from ot_assess import conductos_zcr as zc
        from ot_assess.model import Capture
        conductos = [_k("10.3.0.5", "10.5.0.5", 23), _k("10.2.0.5", "10.1.0.5", 502, dias=3)]
        assets, zon, zcr = _armar(IPS, ZONAS, conductos)
        cap = Capture(Path("conductos entre zonas"))
        zc.agregar_hallazgos(cap, zcr)
        riesgo = next(h for h in cap.findings if h["titulo"] == zc.TIT_RIESGO)
        otro = {"id": "H-aaaaaa", "titulo": "Otro asunto", "categoria": "Higiene", "severidad": "Baja",
                "activos": ["10.3.0.5"]}
        r = tb.construir(assets, conductos, zon, zcr, None, [*cap.findings, otro], {"zonas": ZONAS})
        telnet = _fila(r, "tcp/23")
        ids = {frozenset((f["zona_a"], f["zona_b"])): f["id"] for f in zcr["filas"]}
        self.assertIn(riesgo["id"], telnet["ids_hallazgo"])
        self.assertNotIn("H-aaaaaa", telnet["ids_hallazgo"])       # fuera de la familia de segmentacion
        self.assertTrue(riesgo["id"].startswith("H-"))
        self.assertTrue(riesgo["id"] in tb.fila_tabla(telnet)[10])
        self.assertEqual(tb.fila_tabla(telnet)[0], ids[frozenset(("Operaciones", "Operaciones B"))])

    def test_maximo_cinco_ids(self):
        hs = [{"id": f"H-00000{i}", "titulo": f"Conducto {i}", "categoria": "Segmentacion", "severidad": "Media",
               "activos": ["10.3.0.5"]} for i in range(8)]
        r, _z = _tobe([_k("10.3.0.5", "10.5.0.5", 502, dias=3)], hallazgos=hs)
        self.assertEqual(len(r["filas"][0]["ids_hallazgo"]), 5)

    def test_suma_de_la_matriz_igual_a_filas_y_cuadricula(self):
        r, _z = _tobe([_k("10.2.0.5", "10.1.0.5", 502, dias=3), _k("10.2.0.5", "10.1.0.5", 44818, dias=3),
                       _k("10.3.0.5", "10.5.0.5", 23), _k("10.4.0.5", "10.1.0.5", 3389),
                       _k("151.101.1.1", "10.1.0.5", 502)])
        total = sum(m[c] for m in r["matriz"] for c in tb.COL_MATRIZ[2:])
        self.assertEqual(total, len(r["filas"]))
        cab, filas = tb.cuadricula(r)
        self.assertEqual(cab[0], "Origen \\ Destino")
        celda = next(c for fila in filas if fila[0] == "Supervision" for c in fila[1:] if c)
        self.assertEqual(celda, "P 2")
        self.assertTrue(any("B 1" in c for fila in filas for c in fila[1:]))
        self.assertEqual(len(tb.filas_matriz(r)), len(r["matriz"]))


class DiagramaTest(unittest.TestCase):
    def test_dibuja_permitir_y_dos_tramos_por_dmz_y_no_bloquear_ni_revisar(self):
        r, _z = _tobe([_k("10.2.0.5", "10.1.0.5", 502, dias=3), _k("10.4.0.5", "10.1.0.5", 3389),
                       _k("151.101.1.1", "10.1.0.5", 4840), _k("10.3.0.5", "10.5.0.5", 23)])
        g = tb.grafo(r)
        pares = {(e.a, e.b): e for e in g.aristas}
        self.assertEqual(len(g.aristas), 3)             # Supervision-Control, Empresa-DMZ, DMZ-Control
        dmz = [e for e in g.aristas if e.discontinua]
        self.assertEqual(len(dmz), 2)
        self.assertTrue(all(tb.DMZ_PROPUESTA in (e.a, e.b) for e in dmz))      # origen -> DMZ y DMZ -> destino
        self.assertFalse(pares[("Supervision", "Control")].discontinua)
        d = diagrama_tobe(r, Opciones(estandar=ESTANDARES["iec62443"], titulo="T", cliente="C", fuente="F"))
        self.assertEqual(d.slug, "diagrama_tobe")
        for texto in (d.svg, d.svg_completo):
            ET.fromstring(texto)
        self.assertIn("Segmentacion propuesta (TO-BE)", d.svg_completo)
        self.assertIn("no es un diseno de ingenieria", d.nota)
        self.assertNotIn("Internet", d.svg)               # la fila bloquear (Internet -> Control) no se dibuja
        self.assertNotIn("Operaciones", d.svg)            # la fila revisar tampoco
        self.assertIn("1 a bloquear y 1 a revisar", d.svg)
        self.assertIn("stroke-dasharray", d.svg)
        self.assertIn("flowchart", d.mermaid)
        ET.fromstring(d.drawio)

    def test_sin_aristas_no_hay_diagrama(self):
        r, _z = _tobe([_k("151.101.1.1", "10.1.0.5", 502)])
        self.assertIsNone(diagrama_tobe(r))

    def test_maximo_40_aristas_con_aviso(self):
        zonas = [{"nombre": f"Z{i:02d}", "redes": [f"10.{i}.0.0/24"]} for i in range(1, 52)]
        ips = {f"h{i}": (f"10.{i}.0.5", "Nivel 3") for i in range(1, 52)}
        cond = [_k("10.1.0.5", f"10.{i}.0.5", 502, dias=3) for i in range(2, 52)]
        r, _z = _tobe(cond, zonas, ips)
        self.assertEqual(len(tb.grafo(r).aristas), 40)
        self.assertIn("40 aristas", tb.nota_diagrama(r))
        self.assertIn("10 mas", tb.nota_diagrama(r))


class SalidasTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def correr(self, *extra, una_zona=False):
        com = gen_exports.xd_escribir_comunicaciones(self.tmp / "com.csv", [
            gen_exports.xd_fila("10.10.1.10", "10.10.2.20", "From A to B", 502, "Modbus", tipo_a="HMI", tipo_b="PLC"),
            gen_exports.xd_fila("10.10.1.10", "10.10.2.20", "From A to B", 502, "Modbus", "2026-11-03",
                                tipo_a="HMI", tipo_b="PLC"),
            gen_exports.xd_fila("10.10.1.10", "10.10.3.30", "From A to B", 445, "N/A")])
        zonas = ("Operacion",) * 3 if una_zona else ("Operacion", "Campo", "Planta")
        inv = _inventario_xdome(self.tmp / "inv.csv", [("HMI-1", "10.10.1.10", zonas[0]),
                                                       ("PLC-1", "10.10.2.20", zonas[1]),
                                                       ("SRV-1", "10.10.3.30", zonas[2])])
        out = self.tmp / "out"
        with contextlib.redirect_stdout(io.StringIO()):
            rc = main_diagrama(["--activos", str(inv), "--enlaces", str(com), "--formato", "xdome", "-o", str(out),
                                *extra])
        self.assertEqual(rc, 0)
        return out

    def test_diagrama_escribe_allowlist_matriz_diagrama_y_resultado(self):
        out = self.correr()
        with open(out / tb.ARCHIVO_ALLOW, encoding="utf-8-sig") as fh:
            filas = list(csv.DictReader(fh))
        self.assertEqual(list(filas[0]), tb.COLUMNAS)
        self.assertEqual(sorted((f["servicio"], f["decision"]) for f in filas),
                         [("445", "revisar"), ("502", "permitir")])
        self.assertTrue(all(f[c] == "" for f in filas for c in tb.COLUMNAS[-4:]))
        self.assertTrue((out / tb.ARCHIVO_ALLOW).read_bytes().startswith(b"\xef\xbb\xbf"))
        with open(out / tb.ARCHIVO_MATRIZ, encoding="utf-8-sig") as fh:
            matriz = list(csv.DictReader(fh))
        self.assertEqual(list(matriz[0]), tb.COL_MATRIZ)
        for ext in ("svg", "mmd", "drawio"):
            self.assertTrue((out / f"{tb.SLUG}.{ext}").exists(), ext)
        svg = (out / f"{tb.SLUG}.svg").read_text(encoding="utf-8")
        self.assertIn("502", svg)
        self.assertNotIn("445", svg)                       # revisar no se dibuja
        res = json.loads((out / "resultado.json").read_text(encoding="utf-8"))
        self.assertEqual(len(res["tobe"]["filas"]), 2)
        self.assertEqual(sum(m["permitir"] + m["revisar"] for m in res["tobe"]["matriz"]), 2)
        for patron in ("*.md", "*.html"):
            self.assertIn("Arquitectura TO-BE", "".join(p.read_text(encoding="utf-8") for p in out.glob(patron)))

    def test_sin_conductos_entre_zonas_la_seccion_dice_por_que_y_no_hay_csv(self):
        out = self.correr(una_zona=True)
        for nombre in (tb.ARCHIVO_ALLOW, tb.ARCHIVO_MATRIZ, f"{tb.SLUG}.svg"):
            self.assertFalse((out / nombre).exists(), nombre)
        res = json.loads((out / "resultado.json").read_text(encoding="utf-8"))
        self.assertEqual(res["tobe"]["filas"], [])
        self.assertIn("Sin comunicacion observada entre zonas distintas", res["tobe"]["nota"])
        for patron in ("*.md", "*.html"):
            txt = "".join(p.read_text(encoding="utf-8") for p in out.glob(patron))
            self.assertIn("Arquitectura TO-BE", txt)
            self.assertIn("Sin comunicacion observada entre zonas distintas", txt)

    def test_en_ingles_sin_faltantes_y_con_catalogo(self):
        i18n.usar("en")
        self.addCleanup(i18n.usar, "es")
        i18n.FALTANTES.clear()
        r, _z = _tobe([_k("10.2.0.5", "10.1.0.5", 502, dias=3), _k("10.4.0.5", "10.1.0.5", 3389),
                       _k("10.4.0.5", "10.1.0.5", 5450), _k("10.4.0.5", "10.1.0.5", 8530),
                       _k("10.4.0.5", "10.1.0.5", 9999), _k("151.101.1.1", "10.1.0.5", 502),
                       _k("10.3.0.5", "8.8.8.8", 53, "udp"), _k("10.1.0.5", "1.1.1.1", 443),
                       _k("10.3.0.5", "10.5.0.5", 23), _k("10.3.0.5", "10.5.0.5", 40123),
                       _k("10.2.0.5", "10.1.0.5", 44818, dias=1)])
        tb.filas_tabla(r)
        tb.filas_matriz(r)
        tb.seccion(r)
        tb.para_json(r)
        tb.nota_diagrama(r)
        v = _tobe([_k("10.3.0.5", "10.3.0.5", 502)])[0]
        v["respuestas_probables"] = 2
        tb.seccion_vacia(v)
        tb.aviso(v)
        tb.nota_texto(dict(r, respuestas_probables=2))
        diagrama_tobe(r, Opciones(estandar=ESTANDARES["iec62443"], titulo="T", cliente="C", fuente="F"))
        self.assertEqual(i18n.FALTANTES, set())
        self.assertEqual(tb.fila_tabla(_fila(r, "tcp/3389"))[4], "via DMZ")
        self.assertIn("jump server", tb.fila_tabla(_fila(r, "tcp/3389"))[5])
        self.assertIn("block", tb.resumen_texto(r))
        self.assertIn("P = allow", tb.seccion(r)["leyenda"])


if __name__ == "__main__":
    unittest.main()
