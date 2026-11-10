"""M6: servicios esperados que no se observaron y cobertura temporal (D69). Datos sinteticos."""
from __future__ import annotations

import contextlib
import csv
import io
import json
import shutil
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))
sys.path.insert(0, str(RAIZ / "tests"))

import gen_exports
from test_firewalls_integracion import RUTAS, _sesion
from test_firewalls_politica import PERMITE_TODO, _activo, _k, _pol

from ot_assess import i18n
from ot_assess.cli import main
from ot_assess.firewalls import esperados as es
from ot_assess.firewalls import politica as po

EN = RAIZ / "ot_assess" / "catalogos" / "en.json"


def _filas(p, zona):
    return {f["servicio"]: f for f in p["esperados"]["filas"] if f["zona"] == zona}


def _texto(f, clave):
    return es.texto(f, clave) if isinstance(f[clave], tuple) else f[clave]


def _fila(zona, servicio, n, obs=es.O_NO, cond="activos"):
    """Fila de calcular() armada a mano para probar el agrupado sin armar un firewall."""
    sv = next(x for x in es.catalogo()["servicios"] if x["servicio"] == servicio)
    kw = {"zonas": [zona], "n": n, "servicio": servicio, "puertos": "udp/53"}
    dentro = obs == es.O_DENTRO
    return {"zona": zona, "interfaz": "if_" + zona, "servicio": servicio, "puertos": "udp/53",
            "motivo": (es.MOTIVOS[cond], {"n": n}), "motivo_1": es.MOTIVOS_1[cond], "observado": obs,
            "pregunta": (es.PREGUNTA_DENTRO if dentro else sv["pregunta"], kw),
            "pregunta_1": es.PREGUNTA_DENTRO_1 if dentro else sv["pregunta_1"],
            "regla_sugerida": (es.REGLA_DENTRO if dentro else sv["regla_sugerida"], dict(kw))}


def _pol_filas(*por_firewall, generales=()):
    fws = [{"esperados": {"filas": list(f), "generales": []}} for f in por_firewall]
    if generales and fws:
        fws[0]["esperados"]["generales"] = list(generales)
    return {"firewalls": fws, "multiple": len(fws) > 1}


class _Cap:
    def __init__(self, nombre, ventana):
        self.name, self.ventana, self.info = nombre, ventana, {}


class ServiciosTest(unittest.TestCase):
    def test_equipos_windows_sin_ad_dns_ntp_ni_wsus(self):
        # RDP y SMB hacia 10.10.1.5 desde dos equipos de la DMZ: son 2 equipos Windows en SZ_dmz
        cond = [_k("10.10.9.5", "10.10.1.5", 445), _k("10.10.9.6", "10.10.1.5", 3389)]
        p = _pol(PERMITE_TODO, cond)
        f = _filas(p, "SZ_dmz")
        for sv in ("Kerberos (Active Directory)", "DNS", "NTP", "WSUS (actualizaciones de Windows)"):
            self.assertIn(sv, f)
            self.assertEqual(f[sv]["observado"], "no")
        self.assertEqual(f["Kerberos (Active Directory)"]["motivo"][1]["n"], 2)
        self.assertIn("2 equipos Windows", _texto(f["Kerberos (Active Directory)"], "motivo"))
        self.assertIn("SZ_dmz", _texto(f["DNS"], "pregunta"))
        self.assertIn("88", f["Kerberos (Active Directory)"]["puertos"])
        self.assertIn("udp/53", _texto(f["DNS"], "regla_sugerida"))
        # SMB cruza desde la DMZ: no se pregunta
        self.assertNotIn("SMB a controladores (GPO y SYSVOL)", f)

    def test_si_cruzan_no_se_pregunta_y_si_solo_estan_dentro_cambia_la_pregunta(self):
        cond = [_k("10.10.9.5", "10.10.1.5", 445), _k("10.10.9.6", "10.10.1.5", 3389),
                _k("10.10.9.5", "10.10.1.9", 88), _k("10.10.9.5", "10.10.1.9", 53, l4="udp"),
                _k("10.10.1.5", "10.10.1.9", 53, l4="udp")]     # dentro de 'inside'
        p = _pol(PERMITE_TODO, cond)
        dmz = _filas(p, "SZ_dmz")
        self.assertNotIn("Kerberos (Active Directory)", dmz)
        self.assertNotIn("DNS", dmz)
        self.assertIn("NTP", dmz)
        dentro = _filas(p, "SZ_inside")
        self.assertEqual(dentro["DNS"]["observado"], "solo dentro de la zona")
        self.assertIn("misma zona", _texto(dentro["DNS"], "pregunta"))
        self.assertIn("Sin regla si se resuelve dentro", _texto(dentro["DNS"], "regla_sugerida"))
        self.assertEqual(_filas(p, "SZ_inside")["NTP"]["observado"], "no")

    def test_zona_solo_ot_pregunta_ntp_syslog_snmp_y_nada_de_ad(self):
        assets = {"plc": _activo("10.10.9.5", "Nivel 1", "PLC-1", "PLC"),
                  "hmi": _activo("10.10.9.6", "Nivel 2", "HMI-1", "HMI")}
        p = _pol(PERMITE_TODO, [_k("10.10.9.6", "10.10.9.5", 502)], assets)
        f = _filas(p, "SZ_dmz")
        for sv in ("NTP", "Syslog", "SNMP"):
            self.assertIn(sv, f)
        self.assertIn("2 activos de red u OT", _texto(f["SNMP"], "motivo"))
        for sv in f:
            self.assertNotIn("Active Directory", sv)
            self.assertNotIn("WSUS", sv)
            self.assertNotIn("TACACS", sv)

    def test_sistema_operativo_del_inventario_cuenta_como_windows(self):
        a = _activo("10.10.9.5", "", "SRV")
        a["modelo"] = "Windows Server 2019"
        p = _pol(PERMITE_TODO, [_k("10.10.9.5", "8.8.8.8", 443)], {"srv": a})
        self.assertIn("1 equipo Windows", _texto(_filas(p, "SZ_dmz")["WSUS (actualizaciones de Windows)"], "motivo"))

    def test_sin_activos_en_la_zona_no_hay_filas(self):
        p = _pol(PERMITE_TODO, [])
        self.assertEqual(p["esperados"]["filas"], [])

    def test_orden_determinista_y_tope(self):
        cond = [_k("10.10.9.5", "10.10.1.5", 445), _k("10.10.9.6", "10.10.1.5", 3389)]
        a, b = _pol(PERMITE_TODO, cond), _pol(PERMITE_TODO, list(reversed(cond)))
        self.assertEqual(es.filas(a["esperados"]), es.filas(b["esperados"]))
        antes = es.MAX_FILAS
        es.MAX_FILAS = 3
        try:
            c = _pol(PERMITE_TODO, cond)
        finally:
            es.MAX_FILAS = antes
        self.assertEqual(len(c["esperados"]["filas"]), 3)
        self.assertGreater(c["esperados"]["truncadas"], 0)


class CoberturaTest(unittest.TestCase):
    def test_capturas_de_dos_dias(self):
        cob = es.cobertura([_Cap("a.pcap", [1727740800, 1727827200]), _Cap("b.pcap", [1727780000, 1727790000])])
        self.assertEqual(cob["dias"], 2)
        self.assertTrue(cob["corta"])
        self.assertIn("2 dias", es.texto_cobertura(cob))
        p = _pol(PERMITE_TODO, [_k("10.10.9.5", "10.10.1.5", 445)])
        pol = {"firewalls": [p]}
        es.aplicar(pol, cob)
        self.assertEqual(len(p["esperados"]["generales"]), 4)
        self.assertIn("2 dias", es.texto_resumen(pol))
        self.assertEqual(pol["preguntas"], len(p["esperados"]["filas"]) + 4)
        self.assertTrue(all(len(f) == len(es.COLUMNAS) for f in es.filas(p["esperados"])))

    def test_exportaciones_de_40_dias_no_traen_preguntas_generales(self):
        cond = [dict(_k("10.10.9.5", "10.10.1.5", 445), primera="2024-10-01", ultima="2024-11-09")]
        cob = es.cobertura([], cond)
        self.assertEqual(cob["dias"], 40)
        self.assertFalse(cob["menor_que_mensual"])
        p = _pol(PERMITE_TODO, cond)
        pol = {"firewalls": [p]}
        es.aplicar(pol, cob)
        self.assertEqual(p["esperados"]["generales"], [])

    def test_union_de_dias_entre_fuentes_y_sin_fechas(self):
        cond = [dict(_k("10.10.9.5", "10.10.1.5", 445), primera="2024-10-01", ultima="2024-10-10", fuentes=["A"]),
                dict(_k("10.10.9.6", "10.10.1.5", 445), primera="2024-10-05", ultima="2024-10-12", fuentes=["B"])]
        cob = es.cobertura([], cond)
        self.assertEqual((cob["dias"], len(cob["fuentes"])), (12, 2))
        sin = es.cobertura([], [{"src": "x"}])
        self.assertEqual(sin["dias"], 0)
        self.assertIn("sin fechas", es.texto_cobertura(sin))


class PropuestaIntactaTest(unittest.TestCase):
    def test_las_reglas_no_cambian_con_los_esperados(self):
        cond = [_k("10.10.9.5", "10.10.1.5", 445), _k("10.10.9.6", "10.10.1.5", 3389),
                _k("10.10.1.5", "8.8.8.8", 443)]
        p = _pol(PERMITE_TODO, cond)
        antes = (po.filas_propuesta(p), po.filas_objetos(p), po.filas_bloqueados(p), po.filas_comparacion(p))
        del p["esperados"]
        sin = (po.filas_propuesta(p), po.filas_objetos(p), po.filas_bloqueados(p), po.filas_comparacion(p))
        self.assertEqual(antes, sin)
        self.assertEqual(po.COL_PROPUESTA[:3], ["orden", "nombre", "decision"])


class CatalogoTest(unittest.TestCase):
    def test_puertos_del_brief(self):
        cat = es.catalogo()
        pu = {s["id"]: {(p["puerto"], p["l4"]) for p in s["puertos"]} for s in cat["servicios"]}
        self.assertEqual(pu["dns"], {(53, "udp"), (53, "tcp")})
        self.assertEqual(pu["ntp"], {(123, "udp")})
        self.assertEqual(pu["kerberos"], {(88, "tcp"), (88, "udp")})
        self.assertEqual(pu["catalogo_global"], {(3268, "tcp"), (3269, "tcp")})
        self.assertEqual(pu["wsus"], {(8530, "tcp"), (8531, "tcp")})
        self.assertEqual(pu["kms"], {(1688, "tcp")})
        self.assertEqual(pu["snmp"], {(161, "udp"), (162, "udp")})
        self.assertEqual(pu["radius"], {(1812, "udp"), (1813, "udp")})
        self.assertEqual(pu["tacacs"], {(49, "tcp")})
        for sv in ("respaldo", "antivirus", "licenciamiento", "replicacion_historiador", "soporte_remoto"):
            self.assertEqual(pu[sv], set())

    def test_textos_del_catalogo_estan_en_ingles(self):
        en = json.loads(EN.read_text(encoding="utf-8"))["en"]
        cat = es.catalogo()
        textos = {es.PREGUNTA_DENTRO, es.PREGUNTA_DENTRO_1, es.REGLA_DENTRO, es.MOTIVO_GENERAL, es.O_NO, es.O_DENTRO,
                  es.O_NO_VERIFICABLE, es.HOJA_CLIENTE, *es.MOTIVOS.values(), *es.MOTIVOS_1.values()}
        for s in cat["servicios"] + cat["generales"]:
            textos.update((s["servicio"], s["pregunta"], s["regla_sugerida"]))
            textos.update([s["pregunta_1"]] if "pregunta_1" in s else [])
        self.assertEqual(sorted(x for x in textos if x not in en), [])

    def test_salida_en_ingles_sin_faltantes(self):
        p = _pol(PERMITE_TODO, [_k("10.10.9.5", "10.10.1.5", 445), _k("10.10.1.5", "10.10.1.9", 53, l4="udp")])
        pol = {"firewalls": [p], "multiple": False}
        es.aplicar(pol, es.cobertura([_Cap("a", [1727740800, 1727827200])]))
        i18n.FALTANTES.clear()
        i18n.usar("en")
        try:
            filas = es.filas(p["esperados"])
            es.texto_resumen(pol)
            self.assertEqual(i18n.FALTANTES, set())
            self.assertTrue(filas)
        finally:
            i18n.usar("es")


class RedaccionTest(unittest.TestCase):
    def _win(self, n):
        cond = [_k(f"10.10.9.{5 + i}", "10.10.1.5", 445) for i in range(n)]
        return _filas(_pol(PERMITE_TODO, cond), "SZ_dmz")["WSUS (actualizaciones de Windows)"]

    def test_un_equipo_windows_va_en_singular_con_el_verbo_concordado(self):
        f = self._win(1)
        self.assertIn("1 equipo Windows (", _texto(f, "motivo"))
        self.assertNotIn("equipos", _texto(f, "motivo"))
        q = _texto(f, "pregunta")
        self.assertIn("El equipo Windows de la zona SZ_dmz recibe actualizaciones", q)
        self.assertNotIn("Los 1", q)

    def test_varios_equipos_van_en_plural(self):
        f = self._win(3)
        self.assertIn("3 equipos Windows (", _texto(f, "motivo"))
        self.assertIn("¿Los 3 equipos Windows de la zona SZ_dmz reciben actualizaciones", _texto(f, "pregunta"))

    def test_singular_y_plural_en_ingles(self):
        i18n.usar("en")
        try:
            uno, tres = self._win(1), self._win(3)
            self.assertIn("1 Windows host (", _texto(uno, "motivo"))
            self.assertIn("Does the Windows host in zone SZ_dmz receive updates", _texto(uno, "pregunta"))
            self.assertIn("3 Windows hosts (", _texto(tres, "motivo"))
            self.assertIn("Do the 3 Windows hosts in zone SZ_dmz receive updates", _texto(tres, "pregunta"))
            self.assertNotIn("¿", _texto(tres, "pregunta"))
        finally:
            i18n.usar("es")

    def test_toda_pregunta_en_espanol_abre_con_signo(self):
        cat = es.catalogo()
        for s in cat["servicios"] + cat["generales"]:
            for clave in ("pregunta", "pregunta_1"):
                if clave in s:
                    self.assertTrue(s[clave].startswith("¿"), s["id"] + " " + clave)
        self.assertIn("¿Se resuelve", es.PREGUNTA_DENTRO)
        f = _fila("A", "DNS", 1, es.O_DENTRO)
        self.assertIn("El servicio DNS se vio dentro de la zona A", _texto(f, "pregunta"))
        self.assertIn("el equipo no necesita", _texto(f, "pregunta"))
        self.assertIn("los 4 equipos no necesitan", _texto(_fila("A", "DNS", 4, es.O_DENTRO), "pregunta"))
        p = _pol(PERMITE_TODO, [_k("10.10.9.5", "10.10.1.5", 445), _k("10.10.9.6", "10.10.1.5", 3389)])
        for fila in es.filas(p["esperados"]):
            self.assertIn("¿", fila[6])


class AgrupadoTest(unittest.TestCase):
    def test_mismo_servicio_en_tres_zonas_de_dos_firewalls_es_una_fila(self):
        pol = _pol_filas([_fila("A", "DNS", 10), _fila("B", "DNS", 20)], [_fila("C", "DNS", 7)])
        g = es.agrupar(pol)
        self.assertEqual(len(g), 1)
        fila = es.filas_cliente(pol)[0]
        self.assertEqual(fila[:6], [1, "DNS", "udp/53", "A, B y C", 3, 37])
        self.assertIn("¿Los 37 equipos de las zonas A, B y C resuelven nombres", fila[7])
        self.assertIn("Permitir udp/53 desde las zonas A, B y C hacia el servidor de DNS", fila[8])

    def test_una_sola_zona_dice_la_zona(self):
        fila = es.filas_cliente(_pol_filas([_fila("A", "DNS", 5)]))[0]
        self.assertEqual(fila[3:6], ["A", 1, 5])
        self.assertIn("¿Los 5 equipos de la zona A resuelven", fila[7])
        self.assertIn("desde la zona A hacia", fila[8])
        uno = es.filas_cliente(_pol_filas([_fila("A", "DNS", 1)]))[0]
        self.assertIn("¿El equipo de la zona A resuelve", uno[7])

    def test_ingles_lista_con_and(self):
        pol = _pol_filas([_fila("A", "DNS", 2), _fila("B", "DNS", 3), _fila("C", "DNS", 4)])
        i18n.FALTANTES.clear()
        i18n.usar("en")
        try:
            fila = es.filas_cliente(pol)[0]
            self.assertEqual(fila[3], "A, B and C")
            self.assertIn("Do the 9 hosts in zones A, B and C resolve names", fila[7])
            self.assertIn("Allow udp/53 from zones A, B and C to the DNS server", fila[8])
            self.assertEqual(i18n.FALTANTES, set())
        finally:
            i18n.usar("es")

    def test_orden_y_generales_una_sola_vez_al_final(self):
        gen = {"zona": "", "interfaz": "", "servicio": "Tareas mensuales o trimestrales", "puertos": "",
               "motivo": ("m", {}), "observado": es.O_NO, "pregunta": ("¿Hay tareas?", {}),
               "regla_sugerida": ("r", {})}
        pol = _pol_filas(
            [_fila("A", "NTP", 50), _fila("A", "DNS", 3), _fila("B", "DNS", 3), _fila("A", "Syslog", 9, cond="red_ot")],
            [_fila("A", "DNS", 1)], generales=[gen])
        pol["firewalls"][1]["esperados"]["generales"] = [dict(gen)]      # duplicada: debe salir una vez
        g = es.agrupar(pol)
        self.assertEqual([x["servicio"] for x in g],
                         ["DNS", "NTP", "Syslog", "Tareas mensuales o trimestrales"])
        self.assertEqual((g[0]["zonas"], g[0]["equipos"]), (["A", "B"], 7))
        filas = es.filas_cliente(pol)
        self.assertEqual([f[0] for f in filas], [1, 2, 3, 4])
        self.assertEqual(filas[-1][3:6], ["", "", ""])

    def test_solo_dentro_de_la_zona_se_agrupa_aparte_de_no(self):
        pol = _pol_filas([_fila("A", "DNS", 4), _fila("B", "DNS", 2, es.O_DENTRO), _fila("C", "DNS", 3, es.O_DENTRO)])
        filas = es.filas_cliente(pol)
        self.assertEqual(len(filas), 2)
        por = {f[6]: f for f in filas}
        self.assertEqual(por["solo dentro de la zona"][3:6], ["B y C", 2, 5])
        self.assertIn("dentro de las zonas B y C", por["solo dentro de la zona"][7])
        self.assertEqual(por["no"][3:6], ["A", 1, 4])

    def test_mas_de_diez_zonas_nombra_diez_y_n_mas(self):
        zonas = [f"Z{i:02d}" for i in range(1, 14)]
        pol = _pol_filas([_fila(z, "DNS", 2) for z in zonas])
        fila = es.filas_cliente(pol)[0]
        self.assertEqual(fila[4], 13)
        self.assertEqual(fila[3], "Z01, Z02, Z03, Z04, Z05, Z06, Z07, Z08, Z09, Z10, Z11, Z12 y Z13")
        self.assertIn("las zonas Z01, Z02, Z03, Z04, Z05, Z06, Z07, Z08, Z09, Z10 y 3 mas", fila[7])
        self.assertNotIn("Z11", fila[7])
        self.assertIn("Z13", fila[3])

    def test_resumen_dice_preguntas_por_zona_y_agrupadas(self):
        p = _pol_filas([_fila("A", "DNS", 2), _fila("B", "DNS", 2)])
        es.aplicar(p, es.cobertura([], [dict(_k("10.10.9.5", "10.10.1.5", 445), primera="2024-10-01",
                                             ultima="2024-11-09")]))
        self.assertEqual((p["preguntas"], p["preguntas_cliente"]), (2, 1))
        self.assertIn("2 preguntas por zona", es.texto_resumen(p))
        self.assertIn("1 para el cliente en preguntas_cliente.csv", es.texto_resumen(p))

    def test_tablas_de_politica_traen_el_archivo_y_la_hoja_una_vez(self):
        p = _pol(PERMITE_TODO, [_k("10.10.9.5", "10.10.1.5", 445)])
        pol = {"firewalls": [p, p], "multiple": True}
        t = [x for x in po.tablas(pol) if x[0] == es.ARCHIVO_CLIENTE]
        self.assertEqual(len(t), 1)
        self.assertEqual((t[0][1], t[0][2]), (es.HOJA_CLIENTE, es.COLUMNAS_CLIENTE))
        self.assertTrue(all(len(f) == len(es.COLUMNAS_CLIENTE) for f in t[0][3]))


class CliTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        cls.est = gen_exports.escribir(cls.tmp / "ex")["b"]
        (cls.tmp / "fw.txt").write_text(_sesion(RUTAS, PERMITE_TODO), encoding="utf-8")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _diagrama(self, nombre, *extra):
        out = self.tmp / nombre
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main(["diagrama", "--activos", str(self.est["activos"]), "--enlaces", str(self.est["enlaces"]),
                       "-o", str(out), *extra])
        self.assertEqual(rc, 0)
        return out, buf.getvalue()

    def test_con_firewall_hay_csv_y_cobertura_y_sin_firewall_nada(self):
        out, consola = self._diagrama("con", "--firewall", str(self.tmp / "fw.txt"))
        with open(out / es.ARCHIVO, newline="", encoding="utf-8-sig") as fh:
            self.assertEqual(next(csv.reader(fh)), es.COLUMNAS)
        with open(out / es.ARCHIVO_CLIENTE, newline="", encoding="utf-8-sig") as fh:
            self.assertEqual(next(csv.reader(fh)), es.COLUMNAS_CLIENTE)
        with zipfile.ZipFile(out / "reporte_ot.xlsx") as z:
            self.assertIn(es.HOJA_CLIENTE, z.read("xl/workbook.xml").decode("utf-8"))
        self.assertIn("Cobertura temporal de la evidencia", consola)
        cob = json.loads((out / "resultado.json").read_text(encoding="utf-8"))["firewall"]["politica"]["cobertura"]
        self.assertIn("dias", cob)
        sin, consola2 = self._diagrama("sin")
        self.assertFalse((sin / es.ARCHIVO).exists())
        self.assertNotIn("Cobertura temporal", consola2)
        self.assertEqual(es.registrar({}, (), []), "")


if __name__ == "__main__":
    unittest.main()
