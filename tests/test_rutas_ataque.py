"""A1 (D52): rutas de ataque por alcanzabilidad sobre los conductos observados. Datos sinteticos."""
from __future__ import annotations

import contextlib
import csv
import io
import shutil
import sys
import tempfile
import time
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from typing import ClassVar

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))
sys.path.insert(0, str(RAIZ / "tests"))


import gen_exports
from test_conductos_zcr import _k
from test_zonas import _activo, _inventario_xdome

from ot_assess import conductos_zcr as zc
from ot_assess import i18n, remediacion
from ot_assess import rutas_ataque as ra
from ot_assess import zonas as zo
from ot_assess.cli_diagrama import main as main_diagrama
from ot_assess.model import Capture
from ot_assess.standards import ESTANDARES, MITRE

ZONAS = [{"nombre": "DMZ", "redes": ["10.1.0.0/24"]}, {"nombre": "SCADA", "redes": ["10.2.0.0/24"]},
         {"nombre": "Campo", "redes": ["10.3.0.0/24"]}, {"nombre": "IT Corp", "redes": ["10.9.0.0/24"]},
         {"nombre": "Planta", "redes": ["10.8.0.0/24"]}]
IPS = {"dmz": "10.1.0.5", "scada": "10.2.0.5", "scada2": "10.2.0.6", "plc": "10.3.0.5", "plc2": "10.3.0.6",
       "it": "10.9.0.5", "pl": "10.8.0.5"}
ROLES = {"plc": "Controlador", "plc2": "Controlador"}
EXT = "8.8.8.8"


def _fw(*resultados):
    return {"hostname": "FW1", "resultados": [r if isinstance(r, dict) else {"resultado": r, "regla": ""}
                                              for r in resultados]}


def _armar(conductos, firewall=None, origenes=(), objetivos=(), zonas=ZONAS, roles=ROLES, ips=IPS):
    assets = {n: _activo(ip, role=roles.get(n, "")) for n, ip in ips.items()}
    perfil = {"zonas": zonas}
    zon = zo.asignar(assets, perfil, None, firewall)
    zcr = zc.construir(assets, conductos, zon, firewall)
    return ra.construir(assets, conductos, zon, firewall, perfil, zcr, origenes, objetivos)


CADENA = [_k(EXT, "10.1.0.5", 443), _k("10.1.0.5", "10.2.0.5", 3389), _k("10.2.0.5", "10.3.0.5", 502)]


class CaminosTest(unittest.TestCase):
    def test_internet_dmz_scada_plc_tres_saltos_con_acceso_remoto(self):
        r = _armar(CADENA)
        filas = [f for f in r["filas"] if f["origen"] == "Internet"]
        self.assertEqual(len(filas), 1)
        f = filas[0]
        self.assertEqual((f["objetivo"], f["saltos"], f["acceso_remoto"], f["criticidad"]),
                         ("10.3.0.5", 3, "si", "Critica"))
        self.assertEqual(f["camino"], "8.8.8.8 (Internet) -[tcp/443]-> 10.1.0.5 (DMZ) -[tcp/3389]-> "
                                      "10.2.0.5 (SCADA) -[tcp/502]-> 10.3.0.5 (Campo)")
        self.assertTrue(f["conductos_zcr"].startswith("C-"))
        self.assertEqual(r["origenes"][0]["alcanzables"], 1)

    def test_el_firewall_que_niega_un_salto_corta_el_camino(self):
        r = _armar(CADENA, _fw("permitido", "denegado_observado", "permitido"))
        self.assertEqual(r["filas"], [])
        r = _armar(CADENA, _fw("permitido", "sin_regla", "permitido"))
        self.assertEqual(r["filas"], [])
        r = _armar(CADENA, _fw("permitido", "permitido", "no_cruza"))     # sin datos de cruce: no niega
        self.assertEqual(len(r["filas"]), 1)

    def test_reglas_del_firewall_en_la_fila_y_en_los_puntos(self):
        fw = _fw({"resultado": "permitido", "regla": "R1", "regla_nombre": "web"},
                 {"resultado": "permitido", "regla": "R2", "regla_nombre": "rdp"},
                 {"resultado": "permitido", "regla": "R3", "regla_nombre": "modbus"})
        f = _armar(CADENA, fw)["filas"][0]
        self.assertEqual(f["reglas_firewall"], "R1 web; R2 rdp; R3 modbus")
        r = _armar(CADENA, fw)
        self.assertIn(("regla", "R2 rdp", 1), [(p["tipo"], p["nombre"], p["caminos"]) for p in r["puntos"]])

    def test_sentido_invertido_usa_el_sentido_real(self):
        c = [_k(EXT, "10.1.0.5", 443), _k("10.2.0.5", "10.1.0.5", 3389), _k("10.2.0.5", "10.3.0.5", 502)]
        fw = _fw("permitido", {"resultado": "permitido", "regla": "", "sentido": "invertido"}, "permitido")
        self.assertEqual(len(_armar(c, fw)["filas"]), 1)
        self.assertEqual(_armar(c)["filas"], [])

    def test_las_respuestas_no_crean_aristas(self):
        c = [*CADENA, _k("10.3.0.5", "10.2.0.5", 50000)]       # vuelta de scada -> plc:502
        _n, adj = ra._grafo({n: _activo(ip) for n, ip in IPS.items()}, c, {})
        self.assertNotIn("plc", adj)
        self.assertEqual(sorted(adj["scada"]), ["plc"])
        _n, adj = ra._grafo({n: _activo(ip) for n, ip in IPS.items()}, c,
                            _fw("permitido", "permitido", "permitido", "respuesta"))
        self.assertNotIn("plc", adj)
        # sin la vuelta de servicio, un puerto alto si es un servicio y crea la arista
        _n, adj = ra._grafo({n: _activo(ip) for n, ip in IPS.items()}, [_k("10.3.0.5", "10.2.0.5", 50000)], {})
        self.assertIn("scada", adj["plc"])

    def test_internet_sin_entrada_se_dice(self):
        r = _armar(CADENA[1:])
        self.assertEqual(r["origenes"][0]["origenes"], 0)
        self.assertIn("Internet no tiene camino de entrada observado", ra.resumen_texto(r))

    def test_saliente_a_internet_no_es_entrada(self):
        r = _armar([_k("10.1.0.5", EXT, 443), *CADENA[1:]])
        self.assertEqual(r["origenes"][0]["origenes"], 0)
        self.assertEqual(r["filas"], [])


class OrigenesTest(unittest.TestCase):
    C: ClassVar[list] = [_k("10.9.0.5", "10.2.0.5", 3389), _k("10.2.0.5", "10.3.0.5", 502),
                         _k("10.8.0.5", "10.2.0.6", 22), _k("10.2.0.6", "10.3.0.6", 502)]

    def test_origen_it_por_defecto_por_el_nombre_de_la_zona(self):
        r = _armar(self.C)
        self.assertEqual([o["origen"] for o in r["origenes"]], ["Internet", "IT Corp"])
        f = r["filas"]
        self.assertEqual([(x["origen"], x["objetivo"], x["saltos"]) for x in f], [("IT Corp", "10.3.0.5", 2)])

    def test_opcion_origen_ataque_reemplaza_el_defecto(self):
        r = _armar(self.C, origenes=("Planta",))
        self.assertEqual([o["origen"] for o in r["origenes"]], ["Internet", "Planta"])
        self.assertEqual([(x["origen"], x["objetivo"]) for x in r["filas"]], [("Planta", "10.3.0.6")])
        r = _armar(self.C, origenes=("IT Corp", "Planta"))
        self.assertEqual(len(r["filas"]), 2)

    def test_zona_inexistente_avisa(self):
        self.assertTrue(_armar(self.C, origenes=("Nada",))["avisos"])

    def test_objetivo_ataque_agrega_los_activos_de_la_zona(self):
        r = _armar(self.C, objetivos=("SCADA",))
        self.assertEqual({x["objetivo"] for x in r["filas"]}, {"10.3.0.5", "10.2.0.5"})

    def test_es_origen_it_por_tokens(self):
        self.assertTrue(all(ra._es_origen_it(x) for x in ("IT", "Red IT", "CORP-LAN", "Corporativa", "internet")))
        self.assertFalse(any(ra._es_origen_it(x) for x in ("Capital", "Planta", "DMZ")))


class LimiteTest(unittest.TestCase):
    def test_seis_saltos_y_cuenta_los_que_quedan_fuera(self):
        ips = {f"h{i}": f"10.7.0.{i + 10}" for i in range(6)}
        ips.update({"it": "10.9.0.5", "cerca": "10.3.0.6", "lejos": "10.3.0.5"})
        cadena = ["it"] + [f"h{i}" for i in range(5)]               # it -> h0 (1) ... h4 (5)
        c = [_k(ips[a], ips[b], 502) for a, b in zip(cadena, cadena[1:])]
        c += [_k(ips["h4"], ips["cerca"], 502),                      # cerca: 6 saltos, cabe
              _k(ips["h4"], ips["h5"], 502), _k(ips["h5"], ips["lejos"], 502)]    # lejos: 7 saltos, fuera
        roles = {"cerca": "Controlador", "lejos": "Controlador"}
        r = _armar(c, roles=roles, ips=ips, zonas=[{"nombre": "IT", "redes": ["10.9.0.0/24"]},
                                                    {"nombre": "Medio", "redes": ["10.7.0.0/24"]},
                                                    {"nombre": "OT", "redes": ["10.3.0.0/24"]}])
        o = next(x for x in r["origenes"] if x["origen"] == "IT")
        self.assertEqual([(f["objetivo"], f["saltos"]) for f in r["filas"] if f["origen"] == "IT"],
                         [("10.3.0.6", 6)])
        self.assertEqual((o["alcanzables"], o["fuera"]), (1, 1))
        self.assertIn("1 mas quedan a mas de 6 saltos", ra.resumen_texto(r))


class PuntosTest(unittest.TestCase):
    C: ClassVar[list] = [_k(EXT, "10.1.0.5", 443), _k("10.1.0.5", "10.2.0.5", 3389), _k("10.1.0.5", "10.2.0.6", 3389),
                         _k("10.2.0.5", "10.3.0.5", 502), _k("10.2.0.6", "10.3.0.6", 502)]

    def test_el_intermedio_comun_va_primero(self):
        r = _armar(self.C)
        self.assertEqual(len(r["filas"]), 2)
        activos = [p for p in r["puntos"] if p["tipo"] == "activo"]
        self.assertEqual((activos[0]["nombre"], activos[0]["caminos"]), ("10.1.0.5 (DMZ)", 2))
        self.assertEqual({p["caminos"] for p in activos[1:]}, {1})
        self.assertEqual([p["nombre"] for p in activos[1:]], ["10.2.0.5 (SCADA)", "10.2.0.6 (SCADA)"])
        zcrs = [p for p in r["puntos"] if p["tipo"] == "conducto ZCR"]
        self.assertTrue(zcrs and zcrs[0]["caminos"] == 2)
        cab, filas = ra.tabla_puntos(r)
        self.assertEqual(filas[0][1], "10.1.0.5 (DMZ)")
        self.assertEqual(len(cab), 3)

    def test_salida_determinista(self):
        self.assertEqual(_armar(self.C)["filas"][0]["camino"], _armar(list(self.C))["filas"][0]["camino"])
        self.assertEqual(_armar(self.C)["puntos"], _armar(self.C)["puntos"])

    def test_rendimiento_9000_activos_44000_conductos(self):
        n = 9000
        assets = {f"a{i}": _activo(f"10.{(i >> 8) & 255}.{i & 255}.1", role="Controlador" if i % 50 == 0 else "")
                  for i in range(n)}
        conds = []
        for i in range(44000):
            a, b = (i * 7919) % n, (i * 104729 + 13) % n
            if a != b:
                conds.append(_k(f"10.{(a >> 8) & 255}.{a & 255}.1", f"10.{(b >> 8) & 255}.{b & 255}.1", 502 + i % 3))
        conds.append(_k(EXT, "10.0.0.1", 3389))
        perfil = {"zonas": [{"nombre": "IT", "redes": ["10.0.0.0/10"]}, {"nombre": "OT", "redes": ["10.64.0.0/10"]}]}
        zon = zo.asignar(assets, perfil, None, None)
        t0 = time.time()
        r = ra.construir(assets, conds, zon, None, perfil, None)
        self.assertLess(time.time() - t0, 60)
        self.assertTrue(r["filas"])


class HallazgoTest(unittest.TestCase):
    def _h(self, conductos, **kw):
        cap = Capture(Path("rutas de ataque"))
        ra.agregar_hallazgos(cap, _armar(conductos, **kw))
        return cap.findings

    def test_alta_desde_internet(self):
        f = self._h(CADENA)
        self.assertEqual([x["severidad"] for x in f], ["Alta"])
        self.assertEqual(f[0]["titulo"], ra.TIT)
        self.assertIn("8.8.8.8 (Internet)", f[0]["evidencia"])

    def test_alta_desde_it_en_dos_saltos_con_acceso_remoto(self):
        f = self._h([_k("10.9.0.5", "10.2.0.5", 3389), _k("10.2.0.5", "10.3.0.5", 502)])
        self.assertEqual([x["severidad"] for x in f], ["Alta"])

    def test_media_si_el_camino_de_it_es_largo_o_sin_acceso_remoto(self):
        f = self._h([_k("10.9.0.5", "10.2.0.5", 502), _k("10.2.0.5", "10.3.0.5", 502)])
        self.assertEqual([x["severidad"] for x in f], ["Media"])
        f = self._h([_k("10.9.0.5", "10.1.0.5", 443), _k("10.1.0.5", "10.2.0.5", 3389),
                     _k("10.2.0.5", "10.3.0.5", 502)])
        self.assertEqual([x["severidad"] for x in f], ["Media"])

    def test_ninguno_sin_caminos(self):
        self.assertEqual(self._h([_k("10.2.0.5", "10.3.0.5", 502)]), [])
        self.assertEqual(self._h(CADENA, firewall=_fw("permitido", "denegado_observado", "permitido")), [])

    def test_referencias_en_los_cinco_marcos_plan_e_ingles(self):
        f = self._h(CADENA)[0]
        refs = f["referencias"]
        self.assertEqual(set(refs), {e.clave for e in ESTANDARES.values()} | {MITRE.clave})
        self.assertIn("SR 5.2", refs["iec62443"])
        self.assertIn("ZCR 5.x", refs["iec62443"])
        self.assertIn("RA-3", refs["nist-800-82"])
        self.assertIn("CIP-005 R2", refs["nerc-cip"])
        self.assertIn("ID.RA-04", refs["nist-csf"])
        self.assertIn("T0866", refs[MITRE.clave])
        for txt in (f["evidencia"], f["recomendacion"], f["por_que_importa"]):
            self.assertNotIn("cumple", txt.lower())
        cap = Capture(Path("rutas de ataque"))
        cap.findings.append(f)
        res = SimpleNamespace(caps=[], extras=[cap], assets={}, perfil={})
        self.assertEqual([x["titulo"] for x in remediacion.plan(res)], [ra.TIT])
        i18n.usar("en")
        self.addCleanup(i18n.usar, "es")
        i18n.FALTANTES.clear()
        cap2 = Capture(Path("rutas de ataque"))
        r = _armar(CADENA)
        ra.agregar_hallazgos(cap2, r)
        for x in cap2.findings:
            for k in ("titulo", "evidencia", "por_que_importa", "recomendacion", "categoria"):
                i18n.t(x[k])
            for ref in x["referencias"].values():
                for pieza in ref.split("; "):
                    i18n.t(pieza)
        ra.tabla_caminos(r)
        ra.tabla_puntos(r)
        ra.resumen_texto(r)
        i18n.t(ra.NOTA)
        i18n.t(ra.TITULO)
        r = _armar(CADENA[1:])
        ra.resumen_texto(r)
        self.assertFalse(i18n.FALTANTES, sorted(i18n.FALTANTES))
        self.assertEqual(i18n.t(ra.TIT)[:16], "Critical assets ")


class SalidasTest(unittest.TestCase):
    def setUp(self):
        i18n.usar("es")
        self.addCleanup(i18n.usar, "es")
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_exportacion_de_plataforma_escribe_hojas_y_hallazgo(self):
        com = gen_exports.xd_escribir_comunicaciones(self.tmp / "com.csv", [
            gen_exports.xd_fila("10.10.1.10", "10.10.2.20", "From A to B", 3389, "RDP", tipo_a="HMI", tipo_b="PLC"),
            gen_exports.xd_fila("10.10.2.20", "10.10.3.30", "From A to B", 502, "Modbus", tipo_a="PLC", tipo_b="PLC")])
        inv = _inventario_xdome(self.tmp / "inv.csv", [("HMI-1", "10.10.1.10", "Operacion"),
                                                       ("PLC-1", "10.10.2.20", "Campo"),
                                                       ("PLC-2", "10.10.3.30", "Planta")])
        out = self.tmp / "out"
        with contextlib.redirect_stdout(io.StringIO()):
            rc = main_diagrama(["--activos", str(inv), "--enlaces", str(com), "--formato", "xdome", "-o", str(out),
                                "--origen-ataque", "Operacion", "--objetivo-ataque", "Planta"])
        self.assertEqual(rc, 0)
        filas = list(csv.DictReader(open(out / "rutas_ataque.csv", encoding="utf-8-sig")))
        self.assertEqual(list(filas[0]), ra.COLUMNAS)
        self.assertTrue(any(f["origen"] == "Operacion" and f["objetivo"] == "10.10.3.30" and f["saltos"] == "2"
                            and f["acceso_remoto"] == "si" for f in filas), filas)
        pts = list(csv.DictReader(open(out / "rutas_ataque_puntos.csv", encoding="utf-8-sig")))
        self.assertEqual(list(pts[0]), ra.COLUMNAS_PUNTOS)
        self.assertEqual(pts[0]["tipo"], "activo")
        self.assertIn(ra.TIT, (out / "hallazgos_importados.csv").read_text(encoding="utf-8-sig"))


try:
    import scapy  # noqa: F401
    HAY_SCAPY = True
except ImportError:
    HAY_SCAPY = False


@unittest.skipUnless(shutil.which("tshark") and HAY_SCAPY, "requiere tshark y scapy")
class PipelineTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import gen_pcaps

        from ot_assess.cli import main
        cls.tmp = Path(tempfile.mkdtemp())
        pcaps = cls.tmp / "pcaps"
        sys.argv = ["gen", str(pcaps)]
        gen_pcaps.main()
        perfil = cls.tmp / "perfil.json"
        perfil.write_text('{"version": 1, "cliente": "C", "marcos": [{"clave": "iec62443"}], "zonas": ['
                          '{"nombre": "IT", "redes": ["10.10.1.30/32"]}, '
                          '{"nombre": "Campo", "redes": ["10.10.1.40/32", "10.10.1.1/32"]}]}', encoding="utf-8")
        ataque = ["--origen-ataque", "IT", "--objetivo-ataque", "Campo"]
        with contextlib.redirect_stdout(io.StringIO()):
            main([str(pcaps), "-o", str(cls.tmp / "es"), "--perfil", str(perfil), "--idioma", "es", *ataque])
            main([str(pcaps), "-o", str(cls.tmp / "en"), "--perfil", str(perfil), "--idioma", "en", *ataque])
        i18n.usar("es")

    @classmethod
    def tearDownClass(cls):
        i18n.FALTANTES.clear()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_hojas_y_secciones(self):
        o = self.tmp / "es"
        self.assertTrue((o / "rutas_ataque.csv").exists())
        self.assertTrue((o / "rutas_ataque_puntos.csv").exists())
        for n, marca in (("reporte_ot.html", "<h3>Rutas de ataque</h3>"), ("reporte_ot.md", "### Rutas de ataque")):
            texto = (o / n).read_text(encoding="utf-8")
            self.assertIn(marca, texto, n)
            self.assertIn("no una prueba de explotacion", texto, n)
        with zipfile.ZipFile(o / "informe_ot.docx") as zf:
            self.assertIn("Rutas de ataque", zf.read("word/document.xml").decode("utf-8"))
        h = (self.tmp / "en" / "reporte_ot.html").read_text(encoding="utf-8")
        self.assertIn("<h3>Attack paths</h3>", h)
        self.assertNotIn("no una prueba", h)


if __name__ == "__main__":
    unittest.main()
