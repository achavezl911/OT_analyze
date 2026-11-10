"""T1b (D86): hardening por tipo de equipo, con evidencia de la corrida. Datos sinteticos."""
from __future__ import annotations

import contextlib
import csv
import importlib.util
import io
import json
import re
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

from ot_assess import hardening as hd
from ot_assess import i18n, niveles62443, playbooks
from ot_assess.cli_diagrama import main as main_diagrama
from ot_assess.riesgo import id_hallazgo
from ot_assess.switches import higiene

ROL_PLC = "Controlador / dispositivo de campo (PLC, RTU, IED)"
TIT_CLARO = "Credenciales o administracion en texto claro"


def _activo(ip, **kw):
    a = {"mac": ip, "ips": {ip}, "role": "", "purdue": ""}
    a.update(kw)
    return a


def _hallazgo(titulo, ips, evidencia="x"):
    return {"titulo": titulo, "severidad": "Alta", "activos": list(ips), "evidencia": evidencia}


def _fila(r, ip, pid):
    xs = [f for f in r["filas"] if ip in f["ips"] and f["id_punto"] == pid]
    return xs[0] if xs else None


class CatalogoTest(unittest.TestCase):
    def test_cada_tipo_trae_entre_8_y_12_puntos_con_id_unico_y_referencias_existentes(self):
        d = hd.cargar()
        cat = niveles62443.cargar()
        self.assertEqual(sorted(d["tipos"]), sorted(["controlador", "estacion", "servidor", "red", "seguridad", "otro"]))
        ids = []
        for clave, info in d["tipos"].items():
            ps = d["puntos"][clave]
            self.assertTrue(8 <= len(ps) <= 12, clave)
            for i, p in enumerate(ps, 1):
                self.assertEqual(p["id"], f"HB-{info['prefijo']}-{i:02d}")
                ids.append(p["id"])
                self.assertTrue(p["cr"] and p["sr"], p["id"])
                for r in p["cr"]:
                    self.assertIn(r, cat["componente"], p["id"])
                for r in p["sr"]:
                    self.assertIn(r, cat["sr"], p["id"])
                self.assertTrue(p["texto"].isascii(), p["id"])
            self.assertEqual(len({p["tema"] for p in ps}), len(ps), clave)       # un punto por tema
        self.assertEqual(len(ids), len(set(ids)))

    def test_ingles_con_el_catalogo(self):
        i18n.usar("en")
        self.addCleanup(i18n.usar, "es")
        i18n.FALTANTES.clear()
        d = hd.cargar()
        for info in d["tipos"].values():
            i18n.t(info["nombre"])
        for ps in d["puntos"].values():
            for p in ps:
                i18n.t(p["texto"])
        self.assertEqual(i18n.FALTANTES, set())

    def test_cada_titulo_asignado_existe_en_los_playbooks_y_cada_tema_en_algun_tipo(self):
        d = hd.cargar()
        temas = {p["tema"] for ps in d["puntos"].values() for p in ps}
        for r in d["titulos"]:
            self.assertTrue(playbooks.para_titulo(r["fragmento"]), r["fragmento"])
            self.assertTrue(set(r["temas"]) <= temas, r)
        self.assertIn(d["servicios"]["tema"], temas)
        self.assertTrue(playbooks.para_titulo(higiene.TIT_L2))
        self.assertTrue(any(r["fragmento"] in higiene.TIT_L2 for r in d["titulos"]))


class TipoTest(unittest.TestCase):
    def test_cada_rol_de_roles_py_tiene_tipo(self):
        fuente = (RAIZ / "ot_assess" / "roles.py").read_text(encoding="utf-8")
        roles = re.findall(r'role, purdue = f?"([^"]+)"', fuente)
        self.assertGreaterEqual(len(roles), 7)
        d = hd.cargar()
        for rol in roles:
            rol = rol.split("{")[0]                                   # "Dispositivo OT ({...})"
            self.assertTrue(rol in d["roles"] or any(rol.startswith(p) for p in d["prefijos_rol"]), rol)
        self.assertEqual(hd.tipo_de(_activo("1.1.1.1", role=ROL_PLC)), "controlador")
        self.assertEqual(hd.tipo_de(_activo("1.1.1.1", role="Equipo de red (switch / router)")), "red")
        self.assertEqual(hd.tipo_de(_activo("1.1.1.1", role="Dispositivo OT (Acme)")), "otro")
        self.assertEqual(hd.tipo_de(_activo("1.1.1.1", role="HMI / estacion SCADA")), "estacion")

    def test_tipos_de_plataforma_y_rol_desconocido(self):
        esperado = {"computer": "otro", "switch": "red", "router": "red", "OT_device": "otro",
                    "PLC": "controlador", "HMI": "estacion", "web_server": "servidor",
                    "dhcp_server": "servidor", "printer_scanner": "otro", "Firewall": "seguridad",
                    "Engineering Workstation": "estacion"}
        for texto, tipo in esperado.items():
            self.assertEqual(hd.tipo_de(_activo("1.1.1.1", role=texto)), tipo, texto)
        self.assertEqual(hd.tipo_de(_activo("1.1.1.1", role="Aparato raro")), "otro")
        self.assertEqual(hd.tipo_de(_activo("1.1.1.1")), "otro")


class EvidenciaTest(unittest.TestCase):
    def test_plc_con_telnet_en_sus_ip_revisa_protocolos_en_claro_con_el_id_del_hallazgo(self):
        assets = {"a": _activo("10.0.0.5", role=ROL_PLC, ips={"10.0.0.5", "10.0.0.6"})}
        r = hd.construir(assets, [_hallazgo(TIT_CLARO, ["10.0.0.6"], "Telnet: 3")])
        f = _fila(r, "10.0.0.5", "HB-CTL-05")
        self.assertIsNotNone(f)
        self.assertEqual((f["estado"], f["ids_hallazgo"]), (hd.ESTADO_REVISAR, [id_hallazgo(TIT_CLARO)]))
        self.assertEqual(f["hallazgos"], [TIT_CLARO])
        self.assertEqual(len(r["filas"]), 1)
        fila = hd.filas_activos(r)[0]
        self.assertIn(id_hallazgo(TIT_CLARO), fila[hd.COL_ACTIVOS.index("ids_hallazgo")])
        self.assertIn(TIT_CLARO, fila[hd.COL_ACTIVOS.index("evidencia")])
        self.assertEqual(r["tipos"][0]["pares_verificar"], 11)

    def test_la_ip_en_la_evidencia_basta_si_el_hallazgo_no_trae_activos(self):
        assets = {"a": _activo("10.0.0.5", role=ROL_PLC), "b": _activo("10.0.0.55", role=ROL_PLC)}
        h = {"titulo": TIT_CLARO, "severidad": "Alta", "evidencia": "Telnet desde 10.0.0.55"}
        r = hd.construir(assets, [h])
        self.assertIsNone(_fila(r, "10.0.0.5", "HB-CTL-05"))
        self.assertIsNotNone(_fila(r, "10.0.0.55", "HB-CTL-05"))

    def test_el_mismo_plc_sin_hallazgos_queda_todo_por_verificar_en_sitio(self):
        r = hd.construir({"a": _activo("10.0.0.5", role=ROL_PLC)}, [_hallazgo("Otro hallazgo", ["10.0.0.5"])])
        self.assertEqual(r["filas"], [])
        self.assertEqual(r["tipos"][0]["pares_verificar"], r["tipos"][0]["puntos"])
        self.assertEqual((r["totales"]["contra"], r["totales"]["verificar"]), (0, 12))
        self.assertEqual(r["top"], [])
        self.assertEqual(hd.filas_activos(r), [])

    def test_switch_con_el_hallazgo_de_bpdu_guard_revisa_controles_de_puerto(self):
        assets = {"s": _activo("10.0.0.2", role="Equipo de red (switch / router)"),
                  "p": _activo("10.0.0.5", role=ROL_PLC)}
        h = _hallazgo(higiene.TIT_L2, ["10.0.0.2", "10.0.0.5"], "sin BPDU guard")
        r = hd.construir(assets, [h])
        f = _fila(r, "10.0.0.2", "HB-RED-10")
        self.assertEqual(f["estado"], hd.ESTADO_REVISAR)
        self.assertEqual(f["tema"], "puertos_l2")
        self.assertEqual(len(r["filas"]), 1)       # el PLC no tiene ese punto
        self.assertEqual(r["top"], [{"id_punto": "HB-RED-10", "tipo": "red", "activos": 1}])

    def test_otros_titulos_asignados(self):
        assets = {"s": _activo("10.0.0.2", role="switch"), "e": _activo("10.0.0.3", role="HMI"),
                  "x": _activo("10.0.0.4", role="HMI")}
        hs = [_hallazgo(higiene.TIT_CRED, ["10.0.0.2"]), _hallazgo(higiene.TIT_HORA, ["10.0.0.2"]),
              _hallazgo("Software o sistema operativo fuera de soporte", [],
                        "- 10.0.0.3: SMBv1 - Protocolo obsoleto\n- 10.0.0.4: Windows 7 - Fuera de soporte")]
        r = hd.construir(assets, hs)
        self.assertEqual(_fila(r, "10.0.0.2", "HB-RED-02")["estado"], hd.ESTADO_REVISAR)
        self.assertIsNotNone(_fila(r, "10.0.0.2", "HB-RED-07"))
        self.assertIsNotNone(_fila(r, "10.0.0.3", "HB-EST-09"))       # parches
        self.assertIsNotNone(_fila(r, "10.0.0.3", "HB-EST-04"))       # SMBv1 -> servicios
        self.assertIsNotNone(_fila(r, "10.0.0.4", "HB-EST-09"))
        self.assertIsNone(_fila(r, "10.0.0.4", "HB-EST-04"))
        self.assertEqual({f["estado"] for f in r["filas"]}, {hd.ESTADO_REVISAR})

    def test_activo_que_sirve_ftp_o_telnet_segun_el_inventario(self):
        assets = {"a": _activo("10.0.0.5", role=ROL_PLC, ports_served={(21, "tcp"): 4, (502, "tcp"): 9}),
                  "b": _activo("10.0.0.6", role="PLC", protocolos={"Telnet", "HTTPS", "SFTP", "Modbus"}),
                  "c": _activo("10.0.0.7", role=ROL_PLC, ports_served={(443, "tcp"): 1}, protocolos={"SNMPv3"})}
        r = hd.construir(assets, [])
        fa, fb = _fila(r, "10.0.0.5", "HB-CTL-05"), _fila(r, "10.0.0.6", "HB-CTL-05")
        self.assertEqual((fa["servicios"], fa["ids_hallazgo"]), ([("FTP", "21/tcp")], []))
        self.assertEqual(fb["servicios"], [("Telnet", "")])
        self.assertIsNone(_fila(r, "10.0.0.7", "HB-CTL-05"))
        ev = hd.COL_ACTIVOS.index("evidencia")
        self.assertIn("FTP (21/tcp)", hd.filas_activos(r)[0][ev])
        self.assertIn("Telnet", hd.filas_activos(r)[1][ev])

    def test_snmp_sin_version_no_es_evidencia_y_v2c_si(self):
        assets = {"a": _activo("10.0.0.5", role=ROL_PLC, protocolos={"snmp"}, ports_served={(161, "udp"): 1}),
                  "b": _activo("10.0.0.6", role=ROL_PLC, protocolos={"snmpv2c"})}
        r = hd.construir(assets, [])
        self.assertIsNone(_fila(r, "10.0.0.5", "HB-CTL-05"))
        self.assertEqual(_fila(r, "10.0.0.6", "HB-CTL-05")["servicios"], [("SNMP v2c", "")])

    def test_sin_activos_no_hay_hardening(self):
        self.assertEqual(hd.construir({}, []), {})
        self.assertFalse(hd.hay({}))
        self.assertEqual(hd.tablas({}), [])
        self.assertEqual(hd.para_json({}), {})


def _ffila(ident, ips, rol="", servicios="", protocolos=""):
    campos = {"ips": ";".join(ips), "rol": rol, "servicios": servicios, "protocolos": protocolos}
    return {"id": ident, "campos": {c: {"valor": v} for c, v in campos.items() if v}}


class InventarioTest(unittest.TestCase):
    def test_hallazgo_toca_solo_la_fila_de_su_ip_y_no_la_del_enrutador(self):
        inv = {"filas": [_ffila("A-1", ["10.0.0.1"], rol="Equipo de red (switch / router)"),
                         _ffila("A-2", ["10.0.1.10"], rol="Indeterminado", servicios="3306/tcp"),
                         _ffila("A-3", ["10.0.1.11"]), _ffila("A-4", ["10.0.1.12"])]}
        assets = {"m": _activo("10.0.0.1", ips={"10.0.0.1", "10.0.1.10", "10.0.1.11", "10.0.1.12"})}
        r = hd.construir(assets, [_hallazgo(TIT_CLARO, ["10.0.1.10"], "Telnet: 3")], inv)
        self.assertEqual(r["totales"]["activos"], 4)
        self.assertIsNone(_fila(r, "10.0.0.1", "HB-RED-05"))
        self.assertEqual({tuple(f["ips"]) for f in r["filas"]}, {("10.0.1.10",)})
        self.assertEqual({f["tipo"] for f in r["filas"]}, {"servidor"})

    def test_tipo_por_servicios_y_sin_rol(self):
        inv = {"filas": [_ffila("A-1", ["10.0.1.10"], servicios="502/tcp;80/tcp"),
                         _ffila("A-2", ["10.0.1.11"]), _ffila("A-3", ["10.0.1.12"], servicios="3389/tcp"),
                         _ffila("A-4", ["10.0.1.13"], rol="producer", servicios="502/tcp")]}
        r = hd.construir({}, [_hallazgo(TIT_CLARO, ["10.0.1.10", "10.0.1.11", "10.0.1.12", "10.0.1.13"],
                                        "Telnet: 3")], inv)
        base = {tuple(f["ips"]): (f["tipo"], f["base_tipo"]) for f in r["filas"]}
        self.assertEqual(base[("10.0.1.10",)], ("controlador", "servicios"))
        self.assertEqual(base[("10.0.1.11",)], ("otro", "sin rol"))
        self.assertEqual(base[("10.0.1.12",)], ("estacion", "servicios"))
        self.assertEqual(base[("10.0.1.13",)], ("otro", "rol"))
        self.assertEqual(hd.filas_activos(r)[0][-1], "servicios")
        self.assertEqual(hd.para_json(r)["filas"][0]["base_tipo"], "servicios")

    def test_ip_de_gestion_del_switch_es_red_por_hallazgo(self):
        inv = {"filas": [_ffila("A-1", ["10.0.1.10"], protocolos="NTP"), _ffila("A-2", ["10.0.1.11"], rol="PLC")]}
        r = hd.construir({}, [_hallazgo(higiene.TIT_HORA, ["10.0.1.10", "10.0.1.11"])], inv)
        base = {tuple(f["ips"]): (f["tipo"], f["base_tipo"], f["id_punto"]) for f in r["filas"]}
        self.assertEqual(base[("10.0.1.10",)][:2], ("red", "hallazgo"))
        self.assertTrue(base[("10.0.1.10",)][2].startswith("HB-RED-"))
        self.assertEqual(base[("10.0.1.11",)][:2], ("controlador", "rol"))      # el rol conocido manda
        self.assertTrue(all(r_["fragmento"] in higiene.SUFIJO for r_ in hd.cargar()["tipo_por_hallazgo"]))

    def test_snmp_en_filas(self):
        inv = {"filas": [_ffila("A-1", ["10.0.1.10"], rol="PLC", protocolos="snmp", servicios="161/udp"),
                         _ffila("A-2", ["10.0.1.11"], rol="PLC", protocolos="snmpv2c")]}
        r = hd.construir({}, [], inv)
        self.assertEqual([f["ips"] for f in r["filas"] if f["id_punto"] == "HB-CTL-05"], [["10.0.1.11"]])


class SalidasTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_tablas_y_seccion(self):
        assets = {"a": _activo("10.0.0.5", role=ROL_PLC), "b": _activo("10.0.0.2", role="switch")}
        r = hd.construir(assets, [_hallazgo(TIT_CLARO, ["10.0.0.5"])])
        (arch_b, hoja_b, cab_b, fb), (arch_a, hoja_a, _cab_a, fa) = hd.tablas(r)
        self.assertEqual((arch_b, hoja_b, arch_a, hoja_a),
                         ("hardening_baseline.csv", "Hardening por tipo", "hardening_activos.csv", "Hardening por activo"))
        self.assertEqual(cab_b, hd.COL_BASE)
        self.assertEqual(len(fb), 12 + 12)                              # solo los tipos con activos
        self.assertTrue(all(f[5:] == [""] * 5 for f in fb))
        self.assertEqual(len(fa), 1)
        s = hd.seccion(r)
        self.assertEqual(s["titulo"], "Linea base de hardening por tipo de equipo")
        self.assertEqual([x[1:] for x in s["tipos"]], [[1, 12, 1, 11], [1, 12, 0, 12]])
        self.assertEqual(s["top"][0][0], "HB-CTL-05")
        texto = json.dumps([s, fb, fa]).lower()
        self.assertNotIn("endurecido", texto.replace("ni equipo endurecido", ""))
        j = hd.para_json(r)
        self.assertEqual(j["filas"][0]["estado_clave"], hd.ESTADO_REVISAR)
        self.assertEqual(j["totales"]["contra"], 1)

    def test_top_maximo_15(self):
        assets = {f"a{i}": _activo(f"10.0.{i}.5", role=ROL_PLC) for i in range(3)}
        hs = [_hallazgo(f, [f"10.0.{i}.5" for i in range(3)]) for f in
              ("Credenciales o administracion en texto claro", "Software o sistema operativo fuera de soporte",
               "Puertos de acceso habilitados sin uso")]
        self.assertLessEqual(len(hd.construir(assets, hs)["top"]), hd.MAX_TOP)

    def test_en_ingles_sin_faltantes(self):
        i18n.usar("en")
        self.addCleanup(i18n.usar, "es")
        i18n.FALTANTES.clear()
        assets = {"a": _activo("10.0.0.5", role=ROL_PLC, ports_served={(21, "tcp"): 1}),
                  "b": _activo("10.0.0.2", role="switch", protocolos={"Telnet"})}
        r = hd.construir(assets, [_hallazgo(TIT_CLARO, ["10.0.0.5"]), _hallazgo(higiene.TIT_L2, ["10.0.0.2"])])
        for _a, hoja, cab, filas in hd.tablas(r):
            i18n.t(hoja)
            for c in cab:
                i18n.t(c)
        hd.seccion(r)
        hd.para_json(r)
        self.assertEqual(i18n.FALTANTES, set())

    def correr(self, *extra):
        com = gen_exports.xd_escribir_comunicaciones(self.tmp / "com.csv", [
            gen_exports.xd_fila("10.10.1.10", "10.10.2.20", "From A to B", 502, "Modbus", tipo_a="HMI", tipo_b="PLC"),
            gen_exports.xd_fila("10.10.1.10", "10.10.2.20", "From A to B", 23, "Telnet", tipo_a="HMI", tipo_b="PLC")])
        inv = _inventario_xdome(self.tmp / "inv.csv", [("HMI-1", "10.10.1.10", "Operacion"),
                                                       ("PLC-1", "10.10.2.20", "Campo")])
        out = self.tmp / "out"
        with contextlib.redirect_stdout(io.StringIO()):
            rc = main_diagrama(["--activos", str(inv), "--enlaces", str(com), "--formato", "xdome", "-o", str(out),
                                *extra])
        self.assertEqual(rc, 0)
        return out

    def test_diagrama_escribe_baseline_activos_y_resultado(self):
        out = self.correr()
        with open(out / hd.ARCHIVO_BASE, encoding="utf-8-sig") as fh:
            base = list(csv.DictReader(fh))
        self.assertEqual(list(base[0]), hd.COL_BASE)
        self.assertTrue(base)
        self.assertTrue(all(f[c] == "" for f in base for c in hd.COL_BASE[-5:]))
        with open(out / hd.ARCHIVO_ACTIVOS, encoding="utf-8-sig") as fh:
            act = list(csv.DictReader(fh))
        self.assertTrue(act)
        self.assertEqual(list(act[0]), hd.COL_ACTIVOS)
        self.assertTrue(all(f["ids_hallazgo"].startswith("H-") for f in act))
        self.assertTrue({f["estado"] for f in act} <= {hd.ESTADO_REVISAR})
        res = json.loads((out / "resultado.json").read_text(encoding="utf-8"))
        self.assertIn("tipos", res["hardening"])
        self.assertEqual(res["hardening"]["totales"]["activos"], 2)
        self.assertEqual(res["hardening"]["totales"]["activos"], res["inventario_normalizado"]["activos"])
        for patron in ("*.md", "*.html"):
            self.assertIn("Linea base de hardening por tipo de equipo",
                          "".join(p.read_text(encoding="utf-8") for p in out.glob(patron)))


def _pcap_enrutado(ruta: Path) -> None:
    """Una MAC de enrutador que lleva seis IP de otra red (D74: mas de 4) y un cliente local."""
    from scapy.all import IP, TCP, Ether, Raw, wrpcap
    mr, mc, pk, t0 = "02:00:00:22:00:01", "02:00:00:22:00:02", [], 1700000000.0
    for i, (ip_s, puerto) in enumerate([(f"198.51.100.{10 + j}", (502, 23, 80)[j % 3]) for j in range(6)] * 2):
        p = Ether(src=mc, dst=mr) / IP(src="192.0.2.50", dst=ip_s) / TCP(sport=40000 + i, dport=puerto, flags="PA") \
            / Raw(b"\x00" * 12)
        q = Ether(src=mr, dst=mc) / IP(src=ip_s, dst="192.0.2.50") / TCP(sport=puerto, dport=40000 + i, flags="PA") \
            / Raw(b"\x00" * 12)
        p.time, q.time = t0 + i, t0 + i + 0.01
        pk += [p, q]
    wrpcap(str(ruta), pk)


class CapturaCliTest(unittest.TestCase):
    def test_capturas_usan_el_inventario_normalizado(self):
        if importlib.util.find_spec("scapy") is None:
            self.skipTest("sin scapy")
        from ot_assess.cli import main
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        (tmp / "c").mkdir()
        _pcap_enrutado(tmp / "c" / "a.pcap")
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main([str(tmp / "c"), "-o", str(tmp / "o")]), 0)
        res = json.loads((tmp / "o" / "resultado.json").read_text(encoding="utf-8"))
        self.assertGreater(res["inventario_normalizado"]["activos"], 2)     # la MAC enrutada se reparte por IP
        self.assertEqual(res["hardening"]["totales"]["activos"], res["inventario_normalizado"]["activos"])


if __name__ == "__main__":
    unittest.main()
