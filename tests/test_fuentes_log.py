"""G1a (D87): inventario de fuentes de log y arquitectura de registro observada. Datos sinteticos."""
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

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))
sys.path.insert(0, str(RAIZ / "tests"))

import gen_exports
from test_zonas import _inventario_xdome

from ot_assess import fuentes_log as fl
from ot_assess import i18n
from ot_assess.cli_diagrama import main as main_diagrama

ROL_PLC = "Controlador / dispositivo de campo (PLC, RTU, IED)"
ROL_RED = "Equipo de red (switch / router)"


def _activo(ip, **kw):
    a = {"mac": ip, "ips": {ip}, "role": "", "purdue": ""}
    a.update(kw)
    return a


def _conducto(src, dst, puerto, l4="udp", servicio="-"):
    return {"src": src, "dst": dst, "l4": l4, "port": puerto, "servicio": servicio}


def _fila(r, ip):
    xs = [f for f in r["filas"] if ip in f["ips"]]
    return xs[0] if xs else None


ASSETS = {"sw": _activo("10.0.0.2", role=ROL_RED), "srv": _activo("10.0.0.9", role="servidor"),
          "fw": _activo("10.0.0.1", role="firewall"), "plc": _activo("10.0.1.5", role=ROL_PLC)}


class EnvioTest(unittest.TestCase):
    def test_switch_que_envia_syslog_a_un_servidor(self):
        r = fl.construir(ASSETS, [_conducto("10.0.0.2", "10.0.0.9", 514, servicio="Syslog")])
        sw, srv = _fila(r, "10.0.0.2"), _fila(r, "10.0.0.9")
        self.assertEqual(sw["estado"], fl.E_ENVIA)
        self.assertEqual(sw["protocolos"], ["syslog"])
        self.assertEqual(sw["colectores"], ["10.0.0.9"])
        fila = fl.filas_fuentes(r)[[f["ips"] for f in r["filas"]].index(["10.0.0.2"])]
        self.assertEqual(fila[fl.COL_FUENTES.index("cifrado")], "no")
        self.assertEqual(srv["estado"], fl.E_COLECTOR)
        self.assertEqual(srv["emisores"], ["10.0.0.2"])
        self.assertEqual(r["colectores"][0]["emisores"], 1)
        self.assertEqual(r["colectores"][0]["ip"], "10.0.0.9")

    def test_sin_conductos_de_registro_firewall_verificar_y_plc_opcional(self):
        r = fl.construir(ASSETS, [_conducto("10.0.1.5", "10.0.0.9", 502, "tcp", "Modbus")])
        self.assertEqual(_fila(r, "10.0.0.1")["estado"], fl.E_VERIFICAR)
        self.assertEqual(_fila(r, "10.0.1.5")["estado"], fl.E_OPCIONAL)
        self.assertEqual(r["colectores"], [])
        self.assertEqual([f["estado"] for f in r["filas"]][:2], [fl.E_VERIFICAR] * 2)       # primero lo que hay que verificar
        self.assertEqual(r["filas"][-1]["estado"], fl.E_OPCIONAL)

    def test_cifrado_por_protocolo_y_514_tcp_no_es_syslog(self):
        r = fl.construir(ASSETS, [_conducto("10.0.0.2", "10.0.0.9", 6514, "tcp")])
        self.assertEqual(_fila(r, "10.0.0.2")["protocolos"], ["syslog_tls"])
        self.assertEqual(fl.filas_fuentes(r)[0][9] if r["filas"][0]["ips"] == ["10.0.0.2"] else
                         next(f for f in fl.filas_fuentes(r) if f[1] == "10.0.0.2")[9], "si")
        r = fl.construir(ASSETS, [_conducto("10.0.0.2", "10.0.0.9", 514, "tcp", "rsh")])
        self.assertEqual(r["totales"]["envios"], 0)
        self.assertEqual(_fila(r, "10.0.0.2")["estado"], fl.E_VERIFICAR)
        r = fl.construir(ASSETS, [_conducto("10.0.0.2", "10.0.0.9", 514, "tcp", "Syslog")])      # la aplicacion cuenta
        self.assertEqual(_fila(r, "10.0.0.2")["protocolos"], ["syslog"])

    def test_aplicacion_identificada_cuenta_con_puerto_fuera_de_la_tabla(self):
        r = fl.construir(ASSETS, [_conducto("10.0.0.2", "10.0.0.9", 5140, servicio="Syslog"),
                                  _conducto("10.0.0.1", "10.0.0.9", 3333, servicio="NetFlow")])
        self.assertEqual(_fila(r, "10.0.0.2")["protocolos"], ["syslog"])
        self.assertEqual(_fila(r, "10.0.0.1")["protocolos"], ["netflow"])
        self.assertEqual(_fila(r, "10.0.0.9")["emisores"], ["10.0.0.1", "10.0.0.2"])

    def test_agente_de_siem_depende_de_la_configuracion(self):
        r = fl.construir(ASSETS, [_conducto("10.0.0.9", "10.0.0.2", 1514, "tcp")])
        fila = next(f for f in fl.filas_fuentes(r) if f[1] == "10.0.0.9")
        self.assertEqual(fila[9], "depende de la configuracion")

    def test_la_respuesta_del_colector_no_crea_un_emisor(self):
        r = fl.construir(ASSETS, [_conducto("10.0.0.2", "10.0.0.9", 514, servicio="Syslog"),
                                  _conducto("10.0.0.9", "10.0.0.2", 40000, servicio="Syslog")])
        self.assertEqual(r["totales"]["envios"], 1)
        self.assertEqual(_fila(r, "10.0.0.2")["estado"], fl.E_ENVIA)
        self.assertEqual(_fila(r, "10.0.0.9")["protocolos"], [])
        self.assertEqual(_fila(r, "10.0.0.2")["emisores"], [])

    def test_colector_que_tambien_envia_dice_ambos(self):
        r = fl.construir(ASSETS, [_conducto("10.0.0.2", "10.0.0.9", 514), _conducto("10.0.0.9", "10.0.0.1", 6514, "tcp")])
        srv = _fila(r, "10.0.0.9")
        self.assertEqual(srv["estado"], fl.E_COLECTOR)
        self.assertEqual(srv["protocolos"], ["syslog_tls"])
        fila = next(f for f in fl.filas_fuentes(r) if f[1] == "10.0.0.9")
        self.assertIn("recibe: Syslog", fila[7])
        self.assertIn("envia: Syslog sobre TLS", fila[7])

    def test_respuesta_de_firewall_no_cuenta_y_sentido_invertido_se_corrige(self):
        con = [_conducto("10.0.0.9", "10.0.0.2", 514), _conducto("10.0.0.2", "10.0.0.1", 514)]
        fw = {"hostname": "fw", "resultados": [{"resultado": "permitido", "sentido": "invertido"},
                                               {"resultado": "respuesta"}]}
        r = fl.construir(ASSETS, con, firewall=fw)
        self.assertEqual(r["totales"]["envios"], 1)
        self.assertEqual(_fila(r, "10.0.0.2")["estado"], fl.E_ENVIA)

    def test_sin_activos_no_hay_fuentes(self):
        self.assertEqual(fl.construir({}, []), {})
        self.assertFalse(fl.hay({}))
        self.assertEqual(fl.tablas({}), [])
        self.assertEqual(fl.para_json({}), {})


def _ffila(ident, ips, rol=""):
    campos = {"ips": ";".join(ips), "rol": rol}
    return {"id": ident, "campos": {c: {"valor": v} for c, v in campos.items() if v}}


class InventarioTest(unittest.TestCase):
    def test_activos_de_una_mac_enrutada_salen_por_ip(self):
        inv = {"filas": [_ffila("A-1", ["10.0.0.1"], rol=ROL_RED), _ffila("A-2", ["10.0.1.10"], rol=ROL_RED),
                         _ffila("A-3", ["10.0.1.11"], rol=ROL_PLC)]}
        assets = {"m": _activo("10.0.0.1", ips={"10.0.0.1", "10.0.1.10", "10.0.1.11"})}
        r = fl.construir(assets, [_conducto("10.0.1.10", "10.0.0.1", 514, servicio="Syslog")], inventario=inv)
        self.assertEqual(r["totales"]["activos"], 3)
        self.assertEqual(_fila(r, "10.0.1.10")["estado"], fl.E_ENVIA)
        self.assertEqual(_fila(r, "10.0.0.1")["estado"], fl.E_COLECTOR)
        self.assertEqual(_fila(r, "10.0.1.11")["estado"], fl.E_OPCIONAL)


class SalidasTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_tablas_y_seccion(self):
        r = fl.construir(ASSETS, [_conducto("10.0.0.2", "10.0.0.9", 514, servicio="Syslog")])
        (arch_f, hoja_f, cab_f, ff), (arch_c, hoja_c, cab_c, fc) = fl.tablas(r)
        self.assertEqual((arch_f, hoja_f, arch_c, hoja_c),
                         ("fuentes_log.csv", "Fuentes de log", "colectores_log.csv", "Colectores de log"))
        self.assertEqual(cab_f, fl.COL_FUENTES)
        self.assertEqual(cab_c, fl.COL_COLECTORES)
        self.assertEqual(len(ff), 4)
        self.assertTrue(all(f[10:] == [""] * 4 for f in ff))
        self.assertEqual(fc[0][:2], ["10.0.0.9", "10.0.0.9"])
        s = fl.seccion(r)
        self.assertEqual(s["titulo"], "Fuentes de log (arquitectura de registro observada)")
        self.assertEqual(s["vacio"], "")
        self.assertIn("no prueba que no envie", s["nota"])
        self.assertNotIn("cumple", fl.NOTA.replace("no concluye cumplimiento", ""))

    def test_sin_envios_la_seccion_lo_dice_y_no_hay_csv_de_colectores(self):
        r = fl.construir(ASSETS, [])
        self.assertEqual([x[0] for x in fl.tablas(r)], ["fuentes_log.csv"])
        s = fl.seccion(r)
        self.assertEqual(s["vacio"], "No se observo envio de registros en la corrida.")
        self.assertEqual(r["totales"]["envian"], 0)

    def test_colectores_maximo_20_en_la_seccion(self):
        assets = {f"a{i}": _activo(f"10.0.2.{i}") for i in range(1, 26)}
        con = [_conducto("10.0.0.2", f"10.0.2.{i}", 514) for i in range(1, 26)]
        r = fl.construir({**ASSETS, **assets}, con)
        s = fl.seccion(r)
        self.assertEqual(len(s["colectores"]), 20)
        self.assertIn("5 mas", s["mas"])
        self.assertEqual(len(fl.filas_colectores(r)), 25)

    def test_en_ingles_sin_faltantes(self):
        self.addCleanup(i18n.usar, "es")
        i18n.usar("en")
        i18n.FALTANTES.clear()
        r = fl.construir(ASSETS, [_conducto("10.0.0.2", "10.0.0.9", 514, servicio="Syslog"),
                                  _conducto("10.0.0.1", "10.0.0.9", 5044, "tcp"),
                                  _conducto("10.0.0.9", "10.0.0.2", 6514, "tcp")])
        for _a, hoja, cab, filas in fl.tablas(r):
            i18n.t(hoja)
            for c in cab:
                i18n.t(c)
        fl.seccion(r)
        fl.seccion(fl.construir(ASSETS, []))
        fl.para_json(r)
        self.assertEqual(i18n.FALTANTES, set())
        self.assertEqual(i18n.t("no"), "no")
        self.assertEqual(i18n.t("si"), "yes")

    def test_datos_coherentes(self):
        d = fl.cargar()
        claves = [p["clave"] for p in d["protocolos"]]
        self.assertEqual(len(claves), len(set(claves)))
        puertos = [pt for p in d["protocolos"] for pt in p["puertos"]]
        self.assertEqual(len(puertos), len(set(puertos)))
        self.assertNotIn("514/tcp", puertos)
        self.assertIs(fl._indices()[0]["syslog_tls"]["cifrado"], True)
        self.assertIsNone(fl._indices()[0]["wazuh"]["cifrado"])
        from ot_assess import hardening
        self.assertEqual(sorted(d["tipos"]), sorted(hardening.cargar()["tipos"]))

    def correr(self, con_syslog=True):
        filas = [gen_exports.xd_fila("10.10.1.10", "10.10.2.20", "From A to B", 502, "Modbus", tipo_a="HMI", tipo_b="PLC")]
        if con_syslog:
            filas.append(gen_exports.xd_fila("10.10.2.20", "10.10.1.10", "From A to B", 514, "Syslog",
                                             tipo_a="PLC", tipo_b="HMI"))
        com = gen_exports.xd_escribir_comunicaciones(self.tmp / "com.csv", filas)
        inv = _inventario_xdome(self.tmp / "inv.csv", [("HMI-1", "10.10.1.10", "Operacion"),
                                                       ("PLC-1", "10.10.2.20", "Campo")])
        out = self.tmp / "out"
        with contextlib.redirect_stdout(io.StringIO()):
            rc = main_diagrama(["--activos", str(inv), "--enlaces", str(com), "--formato", "xdome", "-o", str(out)])
        self.assertEqual(rc, 0)
        return out

    def test_diagrama_escribe_csv_seccion_y_resultado(self):
        out = self.correr()
        with open(out / fl.ARCHIVO_FUENTES, encoding="utf-8-sig") as fh:
            filas = list(csv.DictReader(fh))
        self.assertEqual(list(filas[0]), fl.COL_FUENTES)
        self.assertEqual(len(filas), 2)
        self.assertTrue(all(f[c] == "" for f in filas for c in fl.COL_FUENTES[-4:]))
        self.assertTrue((out / fl.ARCHIVO_COLECTORES).exists())
        res = json.loads((out / "resultado.json").read_text(encoding="utf-8"))
        self.assertEqual(res["fuentes_log"]["totales"]["activos"], res["inventario_normalizado"]["activos"])
        self.assertEqual(res["fuentes_log"]["totales"]["envios"], 1)
        for patron in ("*.md", "*.html"):
            self.assertIn("Fuentes de log (arquitectura de registro observada)",
                          "".join(p.read_text(encoding="utf-8") for p in out.glob(patron)))

    def test_diagrama_sin_registro_deja_la_seccion_y_el_csv_de_fuentes(self):
        out = self.correr(con_syslog=False)
        self.assertTrue((out / fl.ARCHIVO_FUENTES).exists())
        self.assertFalse((out / fl.ARCHIVO_COLECTORES).exists())
        self.assertIn("No se observo envio de registros en la corrida.",
                      "".join(p.read_text(encoding="utf-8") for p in out.glob("*.md")))


def _pcap_syslog(ruta: Path) -> None:
    """Un switch envia syslog (514/udp) a un servidor, que no responde; y un cliente habla Modbus con un PLC."""
    from scapy.all import IP, TCP, UDP, Ether, Raw, wrpcap
    pk, t0 = [], 1700000000.0
    for i in range(4):
        p = Ether(src="02:00:00:33:00:01", dst="02:00:00:33:00:02") / IP(src="192.0.2.10", dst="192.0.2.20") \
            / UDP(sport=40514 + i, dport=514) / Raw(b"<14>sw: evento")
        q = Ether(src="02:00:00:33:00:03", dst="02:00:00:33:00:04") / IP(src="192.0.2.30", dst="192.0.2.40") \
            / TCP(sport=41000 + i, dport=502, flags="PA") / Raw(b"\x00" * 12)
        p.time, q.time = t0 + i, t0 + i + 0.1
        pk += [p, q]
    wrpcap(str(ruta), pk)


class CapturaCliTest(unittest.TestCase):
    def test_capturas_producen_fuentes_log(self):
        if importlib.util.find_spec("scapy") is None:
            self.skipTest("sin scapy")
        from ot_assess.cli import main
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        (tmp / "c").mkdir()
        _pcap_syslog(tmp / "c" / "a.pcap")
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main([str(tmp / "c"), "-o", str(tmp / "o")]), 0)
        with open(tmp / "o" / fl.ARCHIVO_FUENTES, encoding="utf-8-sig") as fh:
            filas = {f["ip"]: f for f in csv.DictReader(fh)}
        self.assertTrue(filas["192.0.2.10"]["estado"].startswith("envia"))
        self.assertEqual(filas["192.0.2.10"]["protocolos"], "Syslog")
        self.assertEqual(filas["192.0.2.10"]["colectores"], "192.0.2.20")
        self.assertEqual(filas["192.0.2.20"]["estado"], "colector")
        self.assertTrue((tmp / "o" / fl.ARCHIVO_COLECTORES).exists())
        self.assertIn("Fuentes de log (arquitectura de registro observada)",
                      (tmp / "o" / "reporte_ot.md").read_text(encoding="utf-8")
                      if (tmp / "o" / "reporte_ot.md").exists()
                      else "".join(p.read_text(encoding="utf-8") for p in (tmp / "o").glob("*.md")))
        res = json.loads((tmp / "o" / "resultado.json").read_text(encoding="utf-8"))
        self.assertEqual(res["fuentes_log"]["totales"]["envios"], 1)

    def test_capturas_en_ingles(self):
        if importlib.util.find_spec("scapy") is None:
            self.skipTest("sin scapy")
        from ot_assess.cli import main
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        self.addCleanup(i18n.usar, "es")
        (tmp / "c").mkdir()
        _pcap_syslog(tmp / "c" / "a.pcap")
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main([str(tmp / "c"), "-o", str(tmp / "o"), "--idioma", "en"]), 0)
        texto = "".join(p.read_text(encoding="utf-8") for p in (tmp / "o").glob("*.md"))
        self.assertIn("Log sources (observed logging architecture)", texto)


if __name__ == "__main__":
    unittest.main()
