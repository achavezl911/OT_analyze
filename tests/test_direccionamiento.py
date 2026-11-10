"""G1b (D88): direccionamiento IP observado. Datos sinteticos."""
from __future__ import annotations

import contextlib
import csv
import importlib.util
import io
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))
sys.path.insert(0, str(RAIZ / "tests"))

import gen_exports
from test_zonas import _inventario_xdome

from ot_assess import direccionamiento as dr
from ot_assess import i18n
from ot_assess import zonas as zo
from ot_assess.cli_diagrama import main as main_diagrama
from ot_assess.switches.modelo import Svi

TITULO = "Direccionamiento IP observado"


def _activo(ip, **kw):
    a = {"mac": ip, "ips": {ip}, "role": "", "purdue": ""}
    a.update(kw)
    return a


def _assets(*ips, **kw):
    return {ip: _activo(ip, **kw) for ip in ips}


def _perfil(*zonas):
    return {"zonas": [{"nombre": n, "redes": list(r)} for n, r in zonas]}


def _switch(*svis):
    return {"switches": [SimpleNamespace(svis=[Svi(*s) for s in svis])]}


def _correr(assets, perfil=None, switches=None, tablas_fw=None, **kw):
    z = zo.asignar(assets, perfil)
    if tablas_fw:
        z["tablas"] = (z["tablas"][0], tablas_fw)
    return dr.construir(assets, z, switches, **kw)


def _red(r, red):
    return next(f for f in r["filas"] if f["red"] == red)


def _col(r, red, col):
    fila = dr.filas_tabla(r)[[f["red"] for f in r["filas"]].index(red)]
    return fila[dr.COLUMNAS.index(col)]


class PrefijosTest(unittest.TestCase):
    def test_rutas_de_host_del_firewall_sin_activos_no_se_listan(self):
        a = _assets("10.7.1.5", "10.7.2.9")
        tablas = [[(zo.ipaddress.ip_network("10.7.1.5/32"), "dmz"), (zo.ipaddress.ip_network("10.7.9.9/32"), "dmz"),
                   (zo.ipaddress.ip_network("10.7.0.0/16"), "dmz")]]
        r = _correr(a, _perfil(("OT", ["10.8.8.8/32"])), tablas_fw=tablas)
        redes = [f["red"] for f in r["filas"]]
        self.assertIn("10.7.1.5/32", redes)             # con activo: se lista
        self.assertNotIn("10.7.9.9/32", redes)          # ruta de host sin activos: no
        self.assertIn("10.8.8.8/32", redes)             # la del perfil se lista aunque no tenga activos
        self.assertEqual(r["totales"]["rutas_host_omitidas"], 1)
        self.assertIn("1 rutas de host", dr.resumen_texto(r))

    def test_svi_mas_especifica_que_el_perfil(self):
        a = _assets("10.1.5.20", "10.1.9.9")
        r = _correr(a, _perfil(("OT", ["10.1.0.0/16"])), _switch((5, "10.1.5.1", "255.255.255.0")))
        f5 = _red(r, "10.1.5.0/24")
        self.assertEqual((f5["origen"], f5["vlan"], f5["puerta"], f5["activos"]), ("switch", ["5"], ["10.1.5.1"], 1))
        self.assertEqual(f5["primera_ip"], "10.1.5.20")
        f9 = _red(r, "10.1.0.0/16")
        self.assertEqual((f9["origen"], f9["vlan"], f9["puerta"], f9["activos"]), ("perfil", [], [], 1))
        self.assertEqual([f["red"] for f in r["filas"]], ["10.1.0.0/16", "10.1.5.0/24"])        # por IP de red

    def test_a_igual_prefijo_manda_perfil_pero_conserva_vlan_y_puerta_del_switch(self):
        r = _correr(_assets("10.1.5.20"), _perfil(("OT", ["10.1.5.0/24"])),
                    _switch((5, "10.1.5.1", "255.255.255.0")))
        f = _red(r, "10.1.5.0/24")
        self.assertEqual((f["origen"], f["vlan"], f["puerta"]), ("perfil", ["5"], ["10.1.5.1"]))

    def test_firewall_y_prioridad_sobre_switch(self):
        import ipaddress
        fw = [[(ipaddress.ip_network("10.3.0.0/24"), "fw1"), (ipaddress.ip_network("10.4.0.0/24"), "fw1")]]
        r = _correr(_assets("10.3.0.5", "10.4.0.5"), None, _switch((4, "10.4.0.1", "255.255.255.0")), tablas_fw=fw)
        self.assertEqual(_red(r, "10.3.0.0/24")["origen"], "firewall")
        self.assertEqual(_red(r, "10.4.0.0/24")["origen"], "firewall")
        self.assertEqual(_red(r, "10.4.0.0/24")["vlan"], ["4"])

    def test_svi_sin_mascara_se_ignora_y_vlan_del_inventario_si_es_unica(self):
        a = _assets("10.6.0.5", "10.6.0.6", vlans={"20"})
        r = _correr(a, None, _switch((20, "10.6.0.1", "")))
        f = _red(r, "10.6.0.0/24")
        self.assertEqual((f["origen"], f["vlan"], f["puerta"]), ("inferida /24", ["20"], []))
        a["10.6.0.6"]["vlans"] = {"21"}
        self.assertEqual(_red(_correr(a), "10.6.0.0/24")["vlan"], [])


class ObservacionesTest(unittest.TestCase):
    def test_declarada_sin_activos_y_ip_fuera_de_lo_declarado(self):
        r = _correr(_assets("172.16.3.4"), _perfil(("OT", ["10.9.0.0/24"])))
        vacia = _red(r, "10.9.0.0/24")
        self.assertEqual((vacia["activos"], vacia["uso_pct"], vacia["primera_ip"]), (0, 0.0, ""))
        self.assertEqual(vacia["observaciones"], [dr.OBS_SIN_ACTIVOS])
        fuera = _red(r, "172.16.3.0/24")
        self.assertEqual((fuera["origen"], fuera["observaciones"]), ("inferida /24", [dr.OBS_FUERA]))
        self.assertIn("IP fuera de las redes declaradas", _col(r, "172.16.3.0/24", "observaciones"))

    def test_sin_prefijos_declarados_no_hay_fuera_de_las_redes(self):
        r = _correr(_assets("172.16.3.4"))
        self.assertEqual(_red(r, "172.16.3.0/24")["observaciones"], [])

    def test_subred_en_varias_zonas(self):
        a = _assets("10.5.0.5", "10.5.0.6", "10.5.0.7")
        a["10.5.0.5"]["zona"] = "Zona A"
        a["10.5.0.6"]["zona"] = "Zona B"
        a["10.5.0.7"]["zona"] = "Zona B"
        r = _correr(a)
        f = _red(r, "10.5.0.0/24")
        self.assertIn(dr.OBS_ZONAS, f["observaciones"])
        self.assertEqual(_col(r, "10.5.0.0/24", "zonas"), "Zona A; Zona B")
        self.assertNotIn(dr.OBS_ZONAS, _red(_correr(_assets("10.5.0.5", "10.5.0.6")), "10.5.0.0/24")["observaciones"])

    def test_rango_publico_declarado(self):
        r = _correr(_assets("198.51.100.7", "10.0.0.5"),
                    _perfil(("Pub", ["198.51.100.0/24"]), ("Priv", ["10.0.0.0/24"])))
        self.assertIn(dr.OBS_PUBLICO, _red(r, "198.51.100.0/24")["observaciones"])
        self.assertEqual(_red(r, "198.51.100.0/24")["activos"], 1)
        self.assertEqual(_red(r, "10.0.0.0/24")["observaciones"], [])

    def test_uso_y_uso_alto(self):
        a = _assets(*[f"10.2.0.{i}" for i in range(1, 6)], "10.2.1.9")
        r = _correr(a, _perfil(("A", ["10.2.0.0/29"]), ("B", ["10.2.1.0/24"])))
        chico = _red(r, "10.2.0.0/29")
        self.assertEqual((chico["hosts_utiles"], chico["activos"], chico["uso_pct"]), (6, 5, 83.3))
        self.assertIn(dr.OBS_USO_ALTO, chico["observaciones"])
        self.assertEqual(_col(r, "10.2.0.0/29", "uso_pct"), "83.3")
        grande = _red(r, "10.2.1.0/24")
        self.assertEqual((grande["hosts_utiles"], grande["uso_pct"]), (254, 0.4))
        self.assertNotIn(dr.OBS_USO_ALTO, grande["observaciones"])
        # menos de 6 hosts utiles: no se marca aunque este lleno
        r = _correr(_assets("10.2.2.1", "10.2.2.2"), _perfil(("C", ["10.2.2.0/30"])))
        self.assertEqual(_red(r, "10.2.2.0/30")["uso_pct"], 100.0)
        self.assertNotIn(dr.OBS_USO_ALTO, _red(r, "10.2.2.0/30")["observaciones"])


class ExternasYTiposTest(unittest.TestCase):
    def test_zona_internet_y_ipv6_no_entran_a_la_tabla(self):
        a = _assets("10.0.0.5", "203.0.113.9", "8.8.8.8")
        a["x6"] = _activo("2001:db8::1")
        a["203.0.113.9"]["zona"] = "Externo"
        a["203.0.113.9"]["purdue"] = "Externo"
        r = _correr(a)
        self.assertEqual([f["red"] for f in r["filas"]], ["10.0.0.0/24"])
        self.assertEqual(r["totales"]["ip_externas"], 2)
        self.assertEqual(r["totales"]["ip_v6"], 1)
        self.assertEqual(r["totales"]["ip_observadas"], 1)
        self.assertIn("2 IP externas", dr.resumen_texto(r))
        self.assertEqual(dr.construir(_assets("8.8.8.8"), zo.asignar(_assets("8.8.8.8"))), {})

    def test_tipos_con_la_logica_de_t1b(self):
        a = _assets("10.7.0.1", "10.7.0.2", "10.7.0.3", "10.7.0.4")
        a["10.7.0.1"]["ports_served"] = {"502/tcp"}                  # sin rol que sirve Modbus: controlador
        a["10.7.0.2"]["ports_served"] = {"502/tcp"}
        a["10.7.0.3"]["role"] = "servidor"
        r = _correr(a)
        self.assertEqual(_col(r, "10.7.0.0/24", "tipos"), "controlador 2; otro 1; servidor 1")
        a["10.7.0.4"]["role"] = "Indeterminado"
        r = _correr(a, hallazgos=[{"titulo": "X (segun la configuracion del switch)", "activos": ["10.7.0.4"]}])
        self.assertEqual(_col(r, "10.7.0.0/24", "tipos"), "controlador 2; equipo de red 1; servidor 1")

    def test_tipos_maximo_tres(self):
        a = _assets("10.8.0.1", "10.8.0.2", "10.8.0.3", "10.8.0.4")
        for ip, rol in zip(a, ("servidor", "firewall", "estacion", "")):
            a[ip]["role"] = rol
        self.assertLessEqual(len(_red(_correr(a), "10.8.0.0/24")["tipos"]), 3)


class InventarioTest(unittest.TestCase):
    def test_una_mac_enrutada_cuenta_un_activo_por_ip_y_red(self):
        def fila(i, ips, vlan=""):
            campos = {"ips": ";".join(ips), "vlan": vlan, "zona": "Z"}
            return {"id": i, "campos": {c: {"valor": v} for c, v in campos.items() if v}}
        inv = {"filas": [fila("A-1", ["10.0.0.1"]), fila("A-2", ["10.0.1.10"], "7"), fila("A-3", ["10.0.1.11"], "7")]}
        a = {"m": _activo("10.0.0.1", ips={"10.0.0.1", "10.0.1.10", "10.0.1.11"})}
        r = _correr(a, inventario=inv)
        self.assertEqual((_red(r, "10.0.0.0/24")["activos"], _red(r, "10.0.1.0/24")["activos"]), (1, 2))
        self.assertEqual(_red(r, "10.0.1.0/24")["vlan"], ["7"])
        self.assertEqual(_red(r, "10.0.1.0/24")["ultima_ip"], "10.0.1.11")


class SalidasTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_tablas_y_seccion(self):
        r = _correr(_assets("10.1.5.20"), _perfil(("OT", ["10.1.0.0/16"])), _switch((5, "10.1.5.1", "255.255.255.0")))
        (arch, hoja, cab, filas), = dr.tablas(r)
        self.assertEqual((arch, hoja, cab), ("direccionamiento_ip.csv", "Direccionamiento IP", dr.COLUMNAS))
        self.assertTrue(all(f[-4:] == [""] * 4 and len(f) == len(cab) for f in filas))
        s = dr.seccion(r)
        self.assertEqual(s["titulo"], TITULO)
        self.assertEqual(s["mas"], "")
        self.assertIn(["red declarada sin activos observados (verificar cobertura de la captura)", 1],
                      s["observaciones"])
        self.assertIn("minimo", s["nota"])
        self.assertNotIn("cumple", dr.NOTA.replace("determinacion de cumplimiento", ""))
        self.assertEqual(dr.tablas({}), [])

    def test_tabla_de_la_seccion_maximo_30_redes_por_activos(self):
        a = _assets(*[f"10.20.{i}.1" for i in range(40)])
        a["10.20.39.2"] = _activo("10.20.39.2")
        r = _correr(a)
        s = dr.seccion(r)
        self.assertEqual(len(s["redes"]), 30)
        self.assertEqual(s["redes"][0][0], "10.20.39.0/24")           # mas activos primero
        self.assertIn("10 mas", s["mas"])
        self.assertEqual(len(dr.filas_tabla(r)), 40)

    def test_en_ingles_sin_faltantes(self):
        self.addCleanup(i18n.usar, "es")
        i18n.usar("en")
        i18n.FALTANTES.clear()
        a = _assets("10.1.5.20", "10.1.5.21", "172.16.3.4", "10.9.9.9")
        a["10.1.5.21"]["zona"] = "Otra"
        a["10.1.5.20"]["role"] = "servidor"
        r = _correr(a, _perfil(("OT", ["10.1.5.0/24"]), ("Vacia", ["10.8.0.0/24"]), ("Pub", ["198.51.100.0/24"])),
                    _switch((5, "10.1.5.1", "255.255.255.0")))
        for _a, hoja, cab, filas in dr.tablas(r):
            i18n.t(hoja)
            for c in cab:
                i18n.t(c)
        s = dr.seccion(r)
        dr.para_json(r)
        self.assertEqual(i18n.FALTANTES, set())
        self.assertEqual(s["titulo"], "Observed IP addressing")
        self.assertIn("IP outside the declared networks", "".join(c for f in s["redes"] for c in map(str, f)))

    def test_json(self):
        r = _correr(_assets("10.1.5.20"))
        j = dr.para_json(r)
        self.assertEqual(j["totales"]["redes"], 1)
        self.assertEqual(j["filas"][0]["red"], "10.1.5.0/24")
        self.assertEqual(j["filas"][0]["origen_clave"], "inferida /24")
        self.assertEqual(dr.para_json({}), {})

    def correr(self):
        com = gen_exports.xd_escribir_comunicaciones(self.tmp / "com.csv", [
            gen_exports.xd_fila("10.10.1.10", "10.10.2.20", "From A to B", 502, "Modbus", tipo_a="HMI", tipo_b="PLC")])
        inv = _inventario_xdome(self.tmp / "inv.csv", [("HMI-1", "10.10.1.10", "Operacion"),
                                                       ("PLC-1", "10.10.2.20", "Campo")])
        out = self.tmp / "out"
        with contextlib.redirect_stdout(io.StringIO()):
            rc = main_diagrama(["--activos", str(inv), "--enlaces", str(com), "--formato", "xdome", "-o", str(out)])
        self.assertEqual(rc, 0)
        return out

    def test_diagrama_escribe_csv_seccion_y_resultado(self):
        out = self.correr()
        with open(out / dr.ARCHIVO, encoding="utf-8-sig") as fh:
            filas = list(csv.DictReader(fh))
        self.assertEqual(list(filas[0]), dr.COLUMNAS)
        self.assertEqual([f["red"] for f in filas], ["10.10.1.0/24", "10.10.2.0/24"])
        self.assertEqual(filas[0]["origen_prefijo"], "inferida /24")
        self.assertEqual(filas[0]["activos"], "1")
        res = json.loads((out / "resultado.json").read_text(encoding="utf-8"))
        self.assertEqual(res["direccionamiento"]["totales"]["redes"], 2)
        for patron in ("*.md", "*.html"):
            self.assertIn(TITULO, "".join(p.read_text(encoding="utf-8") for p in out.glob(patron)))


def _pcap(ruta: Path) -> None:
    from scapy.all import IP, TCP, Ether, Raw, wrpcap
    pk, t0 = [], 1700000000.0
    for i in range(4):
        q = Ether(src="02:00:00:33:00:03", dst="02:00:00:33:00:04") / IP(src="192.0.2.30", dst="198.51.100.40") \
            / TCP(sport=41000 + i, dport=502, flags="PA") / Raw(b"\x00" * 12)
        q.time = t0 + i
        pk.append(q)
    wrpcap(str(ruta), pk)


class CapturaCliTest(unittest.TestCase):
    def test_capturas_producen_direccionamiento(self):
        if importlib.util.find_spec("scapy") is None:
            self.skipTest("sin scapy")
        from ot_assess.cli import main
        self.addCleanup(i18n.usar, "es")
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        (tmp / "c").mkdir()
        _pcap(tmp / "c" / "a.pcap")
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main([str(tmp / "c"), "-o", str(tmp / "o")]), 0)
        with open(tmp / "o" / dr.ARCHIVO, encoding="utf-8-sig") as fh:
            filas = {f["red"]: f for f in csv.DictReader(fh)}
        self.assertIn("192.0.2.0/24", filas)
        self.assertEqual(filas["192.0.2.0/24"]["origen_prefijo"], "inferida /24")
        self.assertIn(TITULO, "".join(p.read_text(encoding="utf-8") for p in (tmp / "o").glob("*.md")))
        res = json.loads((tmp / "o" / "resultado.json").read_text(encoding="utf-8"))
        self.assertGreaterEqual(res["direccionamiento"]["totales"]["redes"], 1)
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main([str(tmp / "c"), "-o", str(tmp / "o2"), "--idioma", "en"]), 0)
        self.assertIn("Observed IP addressing", "".join(p.read_text(encoding="utf-8") for p in (tmp / "o2").glob("*.md")))


if __name__ == "__main__":
    unittest.main()
