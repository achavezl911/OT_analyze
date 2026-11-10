"""M3a: politica propuesta por firewall (D47). Texto sintetico de FTD y conductos sinteticos."""
from __future__ import annotations

import contextlib
import csv
import io
import ipaddress
import re
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path
from typing import ClassVar

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))
sys.path.insert(0, str(RAIZ / "tests"))

import gen_exports
from test_firewalls_integracion import RUTAS, _sesion
from test_firewalls_topologia import _c as _conectada
from test_firewalls_topologia import _cadena, _i

from ot_assess import i18n
from ot_assess.cli import main
from ot_assess.firewalls import cisco
from ot_assess.firewalls import integracion as fi
from ot_assess.firewalls import politica as po
from ot_assess.firewalls.modelo import Firewall, Regla

PERMITE_TODO = "access-list CSM_FW_ACL_ advanced permit ip any any rule-id 1\n"
VALIDO = re.compile(r"^[A-Za-z0-9_.\-]{1,64}$")


def _k(src, dst, port=443, dias=5, l4="tcp", **kw):
    c = {"src": src, "dst": dst, "l4": l4, "port": str(port), "servicio": "-", "bytes": 100, "dias": dias,
         "primera": "2024-10-01", "ultima": f"2024-10-{max(dias or 1, 1):02d}"}
    c.update(kw)
    return c


def _activo(ip, nivel="", nombre="", tipo=""):
    return {"ips": {ip}, "purdue": nivel, "nombre": nombre, "tipo_texto": tipo}


def _pol(reglas, conductos, assets=None, zonas=None, hits=""):
    """Politica del unico firewall de una sesion FTD sintetica."""
    fw = cisco.analizar_texto(_sesion(RUTAS, reglas, hits))
    assets = assets or {}
    d = fi.contrastar(fw, conductos, "fw.txt", [], assets)
    return po.construir_todo(["FW1"], ["fw.txt"], [fw], [d], conductos, assets, fi._ip_de(assets),
                             zonas)["firewalls"][0]


def _texto(p, regla):
    """Fila de politica_propuesta de una regla como dict."""
    return dict(zip(po.COL_PROPUESTA, po.filas_propuesta(p)[p["reglas"].index(regla)]))


class ClasificacionTest(unittest.TestCase):
    def test_escaneo_desde_internet_va_a_bloqueados_sin_regla(self):
        p = _pol(PERMITE_TODO, [_k("45.33.32.156", "10.10.1.5", 3389), _k("45.33.32.156", "10.10.1.6", 3389)])
        self.assertEqual(p["reglas"], [])
        self.assertEqual(len(p["bloqueados"]), 1)
        b = p["bloqueados"][0]
        self.assertEqual((b["interfaz_entrada"], b["interfaz_salida"]), ("outside", "inside"))
        self.assertEqual((b["origenes"], b["destinos"], b["conductos"]), (1, 2, 2))
        self.assertEqual(b["razon"], po.R_ENTRANTE)

    def test_dns_externo_se_bloquea_y_pide_dns_interno(self):
        p = _pol(PERMITE_TODO, [_k("10.10.1.5", "8.8.8.8", 53, l4="udp")])
        self.assertEqual(p["reglas"], [])
        self.assertIn("DNS interno", p["bloqueados"][0]["razon"])

    def test_denegado_hoy_sigue_negado_y_no_genera_regla(self):
        reglas = "access-list CSM_FW_ACL_ advanced deny tcp any any eq 135 rule-id 50\n" + PERMITE_TODO
        p = _pol(reglas, [_k("10.10.9.5", "10.10.1.5", 135)])
        self.assertEqual(p["reglas"], [])
        self.assertEqual(p["bloqueados"][0]["razon"], po.R_DENEGADO)

    def test_rdp_entre_interfaces_es_revisar_con_acceso_remoto(self):
        p = _pol(PERMITE_TODO, [_k("10.10.9.5", "10.10.1.5", 3389)])
        self.assertEqual(len(p["reglas"]), 1)
        r = p["reglas"][0]
        self.assertEqual(r["decision"], po.D_REVISAR)
        self.assertEqual(r["razones"], ["acceso remoto"])
        self.assertEqual((r["ifo"], r["ifd"]), ("dmz", "inside"))

    def test_varias_razones_se_listan_juntas(self):
        p = _pol(PERMITE_TODO, [_k("10.10.9.5", "10.10.1.5", 23, dias=1)])
        self.assertEqual(p["reglas"][0]["razones"], ["acceso remoto", "texto claro", "visto un solo dia"])

    def test_trafico_permitido_con_servicio_y_dias_es_permitir(self):
        p = _pol(PERMITE_TODO, [_k("10.10.9.5", "10.10.1.5", 443, dias=2)])
        self.assertEqual(p["reglas"][0]["decision"], po.D_PERMITIR)
        self.assertEqual(p["reglas"][0]["razones"], [])
        sin_fecha = _pol(PERMITE_TODO, [_k("10.10.9.5", "10.10.1.5", 443, dias=None)])
        self.assertEqual(sin_fecha["reglas"][0]["decision"], po.D_PERMITIR)

    def test_un_solo_dia_es_revisar(self):
        p = _pol(PERMITE_TODO, [_k("10.10.9.5", "10.10.1.5", 443, dias=1)])
        self.assertEqual((p["reglas"][0]["decision"], p["reglas"][0]["razones"]),
                         (po.D_REVISAR, ["visto un solo dia"]))

    def test_hacia_internet_usa_any_internet_y_es_revisar(self):
        p = _pol(PERMITE_TODO, [_k("10.10.1.5", "8.8.8.8", 443), _k("10.10.1.5", "1.1.1.1", 443)])
        self.assertEqual(len(p["reglas"]), 1)
        r = p["reglas"][0]
        self.assertEqual(r["decision"], po.D_REVISAR)
        self.assertEqual(r["destino"].nombres, ["ANY_INTERNET"])
        self.assertIn("hacia Internet", r["razones"])
        self.assertEqual([o for o in p["objetos"] if o["valor"] == "0.0.0.0/0" and o["nombre"] != "ANY_INTERNET"], [])

    def test_respuesta_de_sesion_no_genera_regla_y_se_cuenta(self):
        conductos = [_k("10.10.9.5", "10.10.1.5", 443), _k("10.10.1.5", "10.10.9.5", 50123)]
        reglas = ("access-list CSM_FW_ACL_ advanced permit tcp host 10.10.9.5 host 10.10.1.5 eq 443 rule-id 1\n"
                  "access-list CSM_FW_ACL_ advanced deny ip any any rule-id 2\n")
        p = _pol(reglas, conductos)
        self.assertEqual(p["resumen"]["respuestas"], 1)
        self.assertEqual(len(p["reglas"]), 1)
        self.assertEqual(p["reglas"][0]["conductos"], 1)


class OTTest(unittest.TestCase):
    CONDUCTO: ClassVar[list] = [_k("10.10.9.10", "10.10.1.20", 502)]

    def test_hmi_a_plc_entre_interfaces_ot_es_permitir(self):
        assets = {"h": _activo("10.10.9.10", "Nivel 2"), "p": _activo("10.10.1.20", "Nivel 1")}
        r = _pol(PERMITE_TODO, self.CONDUCTO, assets)["reglas"][0]
        self.assertEqual((r["decision"], r["razones"]), (po.D_PERMITIR, []))

    def test_protocolo_ot_hacia_interfaz_no_ot_es_revisar(self):
        assets = {"h": _activo("10.10.9.10", "Nivel 2"), "p": _activo("10.10.1.20", "Nivel 1"),
                  "e": _activo("10.10.9.50", "Nivel 4"), "f": _activo("10.10.9.51", "Nivel 5")}
        r = _pol(PERMITE_TODO, self.CONDUCTO, assets)["reglas"][0]     # dmz queda con mayoria de IT
        self.assertEqual((r["decision"], r["razones"]), (po.D_REVISAR, ["protocolo OT"]))

    def test_sin_niveles_cualquier_protocolo_ot_que_cruce_es_revisar(self):
        r = _pol(PERMITE_TODO, self.CONDUCTO)["reglas"][0]
        self.assertEqual((r["decision"], r["razones"]), (po.D_REVISAR, ["protocolo OT"]))


def _origenes(n, puerto=443):
    return [_k(f"10.10.9.{11 + i}", "10.10.1.5", puerto) for i in range(n)]


class AgrupacionTest(unittest.TestCase):
    def test_doce_origenes_son_un_grupo_y_nueve_son_hosts(self):
        g = _pol(PERMITE_TODO, _origenes(12))["reglas"]
        self.assertEqual(len(g), 1)
        self.assertEqual(len(g[0]["origen"].nombres), 1)
        self.assertTrue(g[0]["origen"].nombres[0].startswith("G_dmz_"))
        p = _pol(PERMITE_TODO, _origenes(9))
        r = p["reglas"][0]
        self.assertEqual(len(r["origen"].nombres), 9)
        self.assertTrue(all(n.startswith("H_") for n in r["origen"].nombres))
        self.assertEqual(r["destino"].nombres, ["H_10_10_1_5"])

    def test_el_grupo_lista_sus_miembros_en_objetos(self):
        p = _pol(PERMITE_TODO, _origenes(12))
        grupo = next(o for o in p["objetos"] if o["tipo"] == "grupo")
        self.assertEqual(len(grupo["miembros"].split(";")), 12)

    def test_dos_servicios_con_los_mismos_pares_son_una_regla(self):
        p = _pol(PERMITE_TODO, [_k("10.10.9.5", "10.10.1.5", 443), _k("10.10.9.5", "10.10.1.5", 25)])
        self.assertEqual(len(p["reglas"]), 1)
        r = p["reglas"][0]
        self.assertEqual(r["svs"], [("TCP", 25), ("TCP", 443)])
        self.assertTrue(r["servicios"].startswith("SG_"))
        sg = next(o for o in p["objetos"] if o["tipo"] == "grupo_servicio")
        self.assertEqual(sg["miembros"], "S_TCP_25;S_TCP_443")

    def test_no_se_permiten_pares_que_no_se_vieron(self):
        conductos = [_k("10.10.9.5", "10.10.1.5", 443), _k("10.10.9.6", "10.10.1.6", 443)]
        p = _pol(PERMITE_TODO, conductos)
        self.assertEqual(len(p["reglas"]), 2)

    def test_cobertura_de_24_usa_la_red(self):
        assets = {str(i): _activo(f"10.10.9.{11 + i}") for i in range(12)}
        p = _pol(PERMITE_TODO, _origenes(12), assets)
        r = p["reglas"][0]
        self.assertEqual(r["origen"].nombres, ["N_10_10_9_0_24"])
        self.assertIn("10.10.9.0/24", _texto(p, r)["justificacion"])
        self.assertEqual(next(o for o in p["objetos"] if o["nombre"] == "N_10_10_9_0_24")["valor"], "10.10.9.0/24")

    def test_cobertura_menor_al_80_se_queda_en_grupo(self):
        assets = {str(i): _activo(f"10.10.9.{11 + i}") for i in range(100)}
        r = _pol(PERMITE_TODO, _origenes(12), assets)["reglas"][0]
        self.assertTrue(r["origen"].nombres[0].startswith("G_"))

    def test_orden_de_especificas_a_amplias(self):
        conductos = _origenes(12) + [_k("10.10.9.99", "10.10.1.6", 22, dias=5)]
        p = _pol(PERMITE_TODO, conductos)
        self.assertEqual([r["orden"] for r in p["reglas"]], [1, 2])
        self.assertLess(p["reglas"][0]["tam"], p["reglas"][1]["tam"])
        self.assertTrue(p["reglas"][0]["nombre"].startswith("1_dmz_a_inside_"))


class ComparacionTest(unittest.TestCase):
    REGLAS = (
        "access-list CSM_FW_ACL_ advanced permit tcp host 10.10.9.5 host 10.10.1.5 eq 443 rule-id 268435457\n"
        "access-list CSM_FW_ACL_ advanced permit tcp host 10.10.9.7 host 10.10.1.7 eq 21 rule-id 268435458\n"
        "access-list CSM_FW_ACL_ advanced permit tcp host 10.10.9.8 host 10.10.1.8 eq 23 rule-id 268435459\n"
        "access-list CSM_FW_ACL_ advanced deny tcp any any eq 135 rule-id 268435460\n"
        "access-list CSM_FW_ACL_ advanced permit ip any any rule-id 268435461\n")
    HITS = ("FW1# show rule hits\n"
            "RuleID        Hit Count   First Hit Time(UTC)        Last Hit Time(UTC)\n"
            "268435457     12          10:01:02 Oct 5 2024        11:22:33 Nov 3 2024\n"
            "268435458     5           10:01:02 Oct 5 2024        11:22:33 Nov 3 2024\n"
            "268435460     3           10:01:02 Oct 5 2024        11:22:33 Nov 3 2024\n")
    CONDUCTOS: ClassVar[list] = [_k("10.10.9.5", "10.10.1.5", 443), _k("10.10.9.6", "10.10.1.6", 25),
                 _k("10.10.9.9", "10.10.1.9", 135)]

    def setUp(self):
        self.p = _pol(self.REGLAS, self.CONDUCTOS, hits=self.HITS)
        self.est = {f["regla_actual"]: f for f in self.p["comparacion"]}

    def test_estados(self):
        e = {k: v["estado"] for k, v in self.est.items()}
        self.assertEqual(e["268435457"], po.E_REEMPLAZADA)
        self.assertEqual(e["268435461"], po.E_ACOTAR)
        self.assertEqual(e["268435458"], po.E_VALIDAR)
        self.assertEqual(e["268435459"], po.E_ELIMINAR)
        self.assertEqual(e["268435460"], po.E_MANTENER)

    def test_reemplazada_y_acotar_indican_las_reglas_propuestas(self):
        nombres = {r["nombre"] for r in self.p["reglas"]}
        self.assertEqual(len(nombres), 2)
        self.assertIn(self.est["268435457"]["reglas_propuestas"], nombres)
        self.assertIn(self.est["268435461"]["reglas_propuestas"], nombres)

    def test_validar_no_propone_eliminar(self):
        self.assertEqual(self.est["268435458"]["estado"], "validar antes de eliminar")
        fila = next(f for f in po.filas_comparacion(self.p) if f[0] == "268435458")
        self.assertIn("5 aciertos", fila[-1])

    def test_regla_de_denegar_sin_conductos_se_sustituye_por_la_accion_por_defecto(self):
        p = _pol(self.REGLAS, [_k("10.10.9.5", "10.10.1.5", 443)], hits=self.HITS)
        self.assertEqual({f["regla_actual"]: f["estado"] for f in p["comparacion"]}["268435460"], po.E_BLOQUEO)


class CadenaTest(unittest.TestCase):
    @staticmethod
    def _integrar(fws, conductos, zonas=None):
        return fi.integrar_modelos(fws, [f.hostname + ".txt" for f in fws], {}, conductos, zonas)[1]

    def test_un_conducto_permitido_genera_regla_en_los_tres_firewalls(self):
        res = self._integrar(_cadena(), [_k("10.10.0.5", "10.30.1.5", 443)])
        pol = res["politica"]
        self.assertTrue(pol["multiple"])
        self.assertEqual([p["id"] for p in pol["firewalls"]], ["FW-IT", "FW-DMZ", "FW-SCADA"])
        for p in pol["firewalls"]:
            self.assertEqual(len(p["reglas"]), 1, p["id"])
            self.assertEqual(p["reglas"][0]["decision"], po.D_PERMITIR)
        self.assertEqual([(p["reglas"][0]["ifo"], p["reglas"][0]["ifd"]) for p in pol["firewalls"]],
                         [("corp", "dmz"), ("it", "scada"), ("dmz", "scada")])

    def test_camino_incompleto_se_marca(self):
        fws = _cadena()
        fws[2].rutas = [r for r in fws[2].rutas if r.tipo != "defecto"]     # FW-SCADA ya no ubica 10.20.x
        res = self._integrar(fws, [_k("10.30.1.5", "10.20.1.5", 443)])
        p = {x["id"]: x for x in res["politica"]["firewalls"]}
        self.assertEqual(p["FW-DMZ"]["resumen"]["caminos_incompletos"], 1)
        just = po.filas_propuesta(p["FW-DMZ"])[0][-1]
        self.assertIn("camino incompleto", just)
        self.assertIn("FW-SCADA", just)
        self.assertEqual(p["FW-IT"]["resumen"]["caminos_incompletos"], 0)

    def test_archivos_con_prefijo_por_firewall(self):
        res = self._integrar(_cadena(), [_k("10.10.0.5", "10.30.1.5", 443)])
        archivos = [a for a, _h, _c, _f in po.tablas(res["politica"])]
        self.assertIn("FW-IT_politica_propuesta.csv", archivos)
        self.assertIn("FW-SCADA_politica_bloqueados.csv", archivos)
        hojas = [str(h) for _a, h, _c, _f in po.tablas(res["politica"])]
        self.assertIn("FW-DMZ Politica comparacion", hojas)


class NombresYZonasTest(unittest.TestCase):
    def test_nombres_validos_y_sin_colisiones(self):
        assets = {"a": _activo("10.10.9.5", nombre="PLC Línea #1 (norte)"),
                  "b": _activo("10.10.9.6", nombre="PLC Línea #1 (norte)"),
                  "c": _activo("10.10.9.7", nombre="X" * 100)}
        conductos = [_k("10.10.9.5", "10.10.1.5", 443), _k("10.10.9.6", "10.10.1.5", 443, dias=1),
                     _k("10.10.9.7", "10.10.1.5", 443, dias=5), _k("10.10.9.5", "10.10.1.5", 25),
                     _k("10.10.9.6", "10.10.1.5", 25)] + _origenes(12, 8443)
        p = _pol(PERMITE_TODO, conductos, assets)
        nombres = [o["nombre"] for o in p["objetos"]] + [r["nombre"] for r in p["reglas"]]
        for n in nombres:
            self.assertRegex(n, VALIDO)
        objetos = [o["nombre"] for o in p["objetos"]]
        self.assertEqual(len(objetos), len(set(objetos)))
        self.assertEqual(len({r["nombre"] for r in p["reglas"]}), len(p["reglas"]))
        plc = [n for n in objetos if n.startswith("H_PLC_L")]
        self.assertEqual(len(plc), 2)
        self.assertTrue(any(n.endswith("_2") for n in plc))
        self.assertTrue(all(len(n) <= 64 for n in objetos))
        self.assertTrue(any(len(n) == 64 for n in objetos))

    def test_zonas_fw_se_aplica(self):
        zonas = {("fw1", "dmz"): "Z_DMZ", ("fw1", "inside"): "Z_OT"}
        r = _pol(PERMITE_TODO, [_k("10.10.9.5", "10.10.1.5", 443)], zonas=zonas)["reglas"][0]
        self.assertEqual((r["zo"], r["zd"]), ("Z_DMZ", "Z_OT"))

    def test_sin_zonas_fw_propone_sz_nameif_con_aviso(self):
        p = _pol(PERMITE_TODO, [_k("10.10.9.5", "10.10.1.5", 443)])
        r = p["reglas"][0]
        self.assertEqual((r["zo"], r["zd"]), ("SZ_dmz", "SZ_inside"))
        self.assertEqual(len(p["avisos"]), 2)
        self.assertIn("SZ_dmz", po.texto_aviso("FW1", p["avisos"][0], False))

    def test_el_aviso_llega_a_los_avisos_del_firewall(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        f = tmp / "fw.txt"
        f.write_text(_sesion(RUTAS, PERMITE_TODO), encoding="utf-8")
        _r, fw = fi.integrar([str(f)], {}, [_k("10.10.9.5", "10.10.1.5", 443)])
        self.assertTrue(any("SZ_dmz" in a for a in fw["avisos"]))
        z = tmp / "zonas.csv"
        z.write_text("firewall,interfaz,zona\nFW1,dmz,Z_DMZ\nfw1,INSIDE,Z_OT\n", encoding="utf-8")
        zonas = po.cargar_zonas(str(z))
        _r, fw = fi.integrar([str(f)], {}, [_k("10.10.9.5", "10.10.1.5", 443)], zonas)
        self.assertFalse(any("SZ_" in a for a in fw["avisos"]))
        self.assertEqual(fw["politica"]["firewalls"][0]["reglas"][0]["zo"], "Z_DMZ")

    def test_cargar_zonas_exige_columnas(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        z = tmp / "z.csv"
        z.write_text("a,b\n1,2\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            po.cargar_zonas(str(z))


class RendimientoTest(unittest.TestCase):
    def test_44000_conductos_y_30_pares_de_interfaces(self):
        ifs = [f"i{n}" for n in range(6)]
        fw = Firewall("Cisco", "FWP", [_i(n, f"172.16.{k}.1", "255.255.255.0") for k, n in enumerate(ifs)],
                      [_conectada(f"10.{k}.0.0/16", n) for k, n in enumerate(ifs)],
                      reglas=[Regla("1", "r", accion="permitir")])
        fw.reglas[0].origen = fw.reglas[0].destino = [ipaddress.IPv4Network("0.0.0.0/0")]
        conductos = []
        for n in range(44000):
            a, b = n % 6, (n // 6 + 1 + n % 5) % 6
            if a == b:
                b = (b + 1) % 6
            conductos.append(_k(f"10.{a}.{n // 250 % 250}.{n % 250 + 1}",
                                f"10.{b}.{(n * 7) // 250 % 250}.{n % 200 + 1}", 1000 + n % 40))
        t0 = time.time()
        d = fi.contrastar(fw, conductos, "p.txt", [], {})
        t1 = time.time()
        pol = po.construir_todo(["FWP"], ["p.txt"], [fw], [d], conductos, {}, lambda x: x, {})
        extra = time.time() - t1
        self.assertGreater(len({(r["ifo"], r["ifd"]) for r in pol["firewalls"][0]["reglas"]}), 20)
        self.assertLess(extra, 60, "contrastar tardo %.1f s" % (t1 - t0))


class SalidasTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        cls.est = gen_exports.escribir(cls.tmp / "ex")["b"]
        (cls.tmp / "fw.txt").write_text(_sesion(RUTAS, PERMITE_TODO), encoding="utf-8")
        (cls.tmp / "zonas.csv").write_text("firewall,interfaz,zona\nFW1,dmz,Z_DMZ\n", encoding="utf-8")
        cls.out = cls.tmp / "out"
        with contextlib.redirect_stdout(io.StringIO()):
            rc = main(["diagrama", "--activos", str(cls.est["activos"]), "--enlaces", str(cls.est["enlaces"]),
                       "-o", str(cls.out), "--firewall", str(cls.tmp / "fw.txt"),
                       "--zonas-fw", str(cls.tmp / "zonas.csv")])
        assert rc == 0

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_cuatro_archivos_sin_prefijo_con_un_firewall(self):
        for nombre, cab in (("politica_propuesta.csv", po.COL_PROPUESTA), ("politica_objetos.csv", po.COL_OBJETOS),
                            ("politica_comparacion.csv", po.COL_COMPARACION),
                            ("politica_bloqueados.csv", po.COL_BLOQUEADOS)):
            with open(self.out / nombre, newline="", encoding="utf-8-sig") as fh:
                self.assertEqual(next(csv.reader(fh)), cab, nombre)

    def test_zonas_fw_sin_firewall_es_error(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            main(["diagrama", "--activos", str(self.est["activos"]), "--enlaces", str(self.est["enlaces"]),
                  "-o", str(self.tmp / "o2"), "--zonas-fw", str(self.tmp / "zonas.csv")])


class IdiomaTest(unittest.TestCase):
    def test_salidas_en_ingles_sin_faltantes(self):
        res = fi.integrar_modelos(_cadena(), ["a.txt", "b.txt", "c.txt"], {}, [
            _k("10.10.0.5", "10.30.1.5", 443), _k("10.10.0.5", "10.30.1.6", 3389),
            _k("45.33.32.156", "10.10.0.7", 22), _k("10.10.0.5", "8.8.8.8", 53, l4="udp")], None)[1]
        i18n.usar("en")
        self.addCleanup(i18n.usar, "es")
        i18n.FALTANTES.clear()
        pol = res["politica"]
        for _a, hoja, cab, filas in po.tablas(pol):
            i18n.t(hoja)
            for c in cab:
                i18n.t(c)
            self.assertIsInstance(filas, list)
        po.tablas_reporte(pol)
        po.resumen_texto(pol)
        i18n.t(po.NOTA)
        i18n.t(po.TITULO)
        for e in po.ESTADOS:
            i18n.t(e)
        self.assertFalse(i18n.FALTANTES, sorted(i18n.FALTANTES))


if __name__ == "__main__":
    unittest.main()


class ReglaDeRetornoTest(unittest.TestCase):
    IDA = "access-list CSM_FW_ACL_ advanced permit tcp ifc inside 10.10.1.0 255.255.255.0 ifc dmz any eq 443 rule-id 1\n"
    VUELTA = ("access-list CSM_FW_ACL_ advanced permit tcp ifc dmz any ifc inside 10.10.1.0 255.255.255.0 "
              "eq {p} rule-id 2\n")

    def _razones(self, puerto):
        p = _pol(self.IDA + self.VUELTA.format(p=puerto), [_k("10.10.9.5", "10.10.1.5", puerto)])
        return p["reglas"][0]["decision"], p["reglas"][0]["razones"]

    def test_conducto_que_solo_entra_por_la_regla_espejo_va_a_revisar(self):
        dec, rz = self._razones(443)
        self.assertEqual(dec, po.D_REVISAR)
        self.assertIn(po.R_RETORNO, rz)

    def test_sin_espejo_no_hay_razon(self):
        p = _pol(self.IDA + self.VUELTA.format(p=8443), [_k("10.10.9.5", "10.10.1.5", 8443)])
        self.assertNotIn(po.R_RETORNO, p["reglas"][0]["razones"])


class SinPuertoTest(unittest.TestCase):
    def test_conducto_sin_puerto_va_a_revisar(self):
        dec, rz = po._razones({"et": set(), "res": "permitido", "dest_global": False, "orig_global": False,
                                "ifo": "a", "ifd": "b", "dias": 5, "puerto": None, "et_grupo": set()}, set(), False)
        self.assertEqual(dec, po.D_REVISAR)
        self.assertIn(po.R_SIN_PUERTO, rz)
