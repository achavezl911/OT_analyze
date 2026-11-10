"""I1a (D78): inventario normalizado con procedencia, inventario manual y equipos propios. Datos sinteticos
(IP de documentacion RFC 5737, MAC y nombres inventados)."""
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

from ot_assess import i18n
from ot_assess import inventario_normalizado as inv
from ot_assess import perfil as pf
from ot_assess.cli_diagrama import main as main_diagrama
from ot_assess.consolidate import build_conduits, merge_assets
from ot_assess.importers import importar
from ot_assess.model import Capture

M_PLC, M_HMI, M_SENSOR, M_NUC = "aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02", "aa:bb:cc:00:00:99", "aa:bb:cc:00:00:98"
T_PLC = 1_700_000_500.0       # 2023-11-14 22:21:40 UTC


def _cap(nombre, hosts, flujos=()):
    """Captura sintetica. hosts: [(mac, ips, ultimo_paquete)]; flujos: [(origen, destino, puerto)]."""
    cap = Capture(Path(nombre))
    for mac, ips, ultimo in hosts:
        h = cap.host(mac)
        h["ips"] |= set(ips)
        h["tx_pkts"], h["rx_pkts"], h["first"], h["last"] = 5, 5, ultimo - 10, ultimo
    for src, dst, puerto in flujos:
        cap.flows[(src, dst, puerto, "tcp")] = {"src": src, "dst": dst, "dport": puerto, "l4": "tcp",
                                                "pkts": 4, "bytes": 400, "proto": "Modbus"}
    return cap


def _escribir(path, cab, filas):
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh)
        w.writerow(cab)
        w.writerows(filas)
    return path


def _plataforma(tmp, filas, nombre="plat"):
    """Importacion generica con columnas Name, IP, MAC, Vendor, Model, Firmware, Type, Level, Last Seen."""
    a = _escribir(Path(tmp) / f"{nombre}_activos.csv",
                  ["Name", "IP", "MAC", "Vendor", "Model", "Firmware", "Type", "Level", "Last Seen"], filas)
    e = _escribir(Path(tmp) / f"{nombre}_enlaces.csv", ["Source", "Destination", "Port", "Protocol", "Packets"],
                  [["192.0.2.10", "192.0.2.20", "502", "Modbus", "10"]])
    return importar([str(a)], [str(e)], "generico")


def _registros_plat(imp):
    return inv.registros_activos(imp.assets, (), "nozomi", "2023-11-15 00:00")


def _fila(r, ident_ip):
    return next(f for f in r["filas"] if ident_ip in f["campos"]["ips"]["valor"].split(";"))


class _Base(unittest.TestCase):
    def setUp(self):
        i18n.usar("es")
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def captura(self, firmware="1.2.3"):
        cap = _cap("a.pcap", [(M_PLC, ["192.0.2.10"], T_PLC), (M_HMI, ["192.0.2.20"], T_PLC - 100)],
                   [("192.0.2.20", "192.0.2.10", "502")])
        assets, _ = merge_assets([cap])
        assets[M_PLC]["firmware"] = firmware
        assets[M_PLC]["modelo"] = "Modelo-X"
        return cap, assets


class FuentesTest(_Base):
    def test_mismo_firmware_un_solo_id_y_fuente_plataforma(self):
        cap, assets = self.captura("1.2.3")
        imp = _plataforma(self.tmp, [["PLC-1", "192.0.2.10", M_PLC, "Acme", "Modelo-X", "01.02.003", "PLC", "1",
                                      "2023-11-14 23:00:00"]])
        r = inv.construir(inv.registros_activos(assets, [cap]) + _registros_plat(imp))
        plc = _fila(r, "192.0.2.10")
        self.assertEqual(len([f for f in r["filas"] if M_PLC in f["campos"]["mac"]["valor"]]), 1)
        fw = plc["campos"]["firmware"]
        self.assertEqual((fw["fuente"], fw["estado"]), ("plataforma:nozomi", "importado"))
        self.assertEqual(plc["conflictos"], [])
        origenes = {(x[3], x[2]) for x in r["procedencia"] if x[0] == plc["id"] and x[1] == "firmware"}
        self.assertEqual(origenes, {("captura:a.pcap", "1.2.3"), ("plataforma:nozomi", "01.02.003")})

    def test_firmware_distinto_es_conflicto_y_conserva_ambos(self):
        cap, assets = self.captura("1.2.3")
        imp = _plataforma(self.tmp, [["PLC-1", "192.0.2.10", M_PLC, "Acme", "Modelo-X", "2.0.0", "PLC", "1", ""]])
        r = inv.construir(inv.registros_activos(assets, [cap]) + _registros_plat(imp))
        plc = _fila(r, "192.0.2.10")
        self.assertEqual(plc["campos"]["firmware"]["estado"], "en conflicto")
        self.assertEqual(plc["campos"]["firmware"]["valor"], "2.0.0")      # manda la plataforma sobre la captura
        self.assertEqual(plc["conflictos"], ["firmware: 2.0.0 (plataforma:nozomi) / 1.2.3 (captura:a.pcap)"])
        filas = {x[0]: x for x in inv.filas_tabla(r) for x in [x]}
        texto = filas[plc["id"]][inv.COLUMNAS.index("conflictos")]
        self.assertIn("2.0.0 (plataforma:nozomi)", texto)
        self.assertIn("1.2.3 (captura:a.pcap)", texto)
        estados = {(x[2], x[5]) for x in r["procedencia"] if x[0] == plc["id"] and x[1] == "firmware"}
        self.assertEqual(estados, {("2.0.0", "en conflicto"), ("1.2.3", "en conflicto")})

    def test_ultima_observacion_de_captura_es_el_ultimo_paquete(self):
        cap, assets = self.captura()
        r = inv.construir(inv.registros_activos(assets, [cap]))
        self.assertEqual(_fila(r, "192.0.2.10")["ultima"], "2023-11-14 22:21:40")
        self.assertEqual(_fila(r, "192.0.2.20")["ultima"], "2023-11-14 22:20:00")
        self.assertEqual(_fila(r, "192.0.2.10")["campos"]["firmware"]["ultima"], "2023-11-14 22:21:40")

    def test_ultima_de_exportacion_columna_o_fin_del_periodo(self):
        imp = _plataforma(self.tmp, [["PLC-1", "192.0.2.10", M_PLC, "", "", "", "PLC", "1", "2023-11-14 23:00:00"],
                                     ["HMI-1", "192.0.2.20", M_HMI, "", "", "", "HMI", "2", ""]])
        r = inv.construir(_registros_plat(imp))
        self.assertEqual(_fila(r, "192.0.2.10")["ultima"], "2023-11-14 23:00:00")
        self.assertEqual(_fila(r, "192.0.2.20")["ultima"], "2023-11-15 00:00")

    def test_inferido_nunca_provoca_conflicto(self):
        cap, assets = self.captura()
        assets[M_PLC]["role"], assets[M_PLC]["purdue"] = "Controlador / dispositivo de campo (PLC, RTU, IED)", "Nivel 1"
        imp = _plataforma(self.tmp, [["PLC-1", "192.0.2.10", M_PLC, "", "", "", "PLC", "2", ""]])
        r = inv.construir(inv.registros_activos(assets, [cap]) + _registros_plat(imp))
        n = _fila(r, "192.0.2.10")["campos"]["nivel_purdue"]
        self.assertEqual((n["valor"], n["estado"], n["fuente"]), ("Nivel 2", "importado", "plataforma:nozomi"))

    def test_cpe_inferido_no_pisa_a_la_plataforma_y_queda_en_procedencia(self):   # N2 (D101)
        imp = _plataforma(self.tmp, [["SW-1", "192.0.2.10", M_PLC, "Siemens", "Modelo-P", "", "Switch", "2", ""]])
        clave = next(k for k, a in imp.assets.items() if "192.0.2.10" in a["ips"])
        inferidos = {clave: {"fabricante": "siemens", "modelo": "scalance xc208", "firmware": "04.04.00"}}
        r = inv.construir(inv.registros_activos(imp.assets, (), "nozomi", "2023-11-15 00:00",
                                                inferidos=inferidos, fuente_inferida="cpe v.csv"))
        c = _fila(r, "192.0.2.10")["campos"]
        self.assertEqual((c["modelo"]["valor"], c["modelo"]["estado"]), ("Modelo-P", "importado"))
        self.assertEqual((c["fabricante"]["valor"], c["fabricante"]["estado"]), ("Siemens", "importado"))
        self.assertEqual((c["firmware"]["valor"], c["firmware"]["estado"], c["firmware"]["fuente"]),
                         ("04.04.00", "inferido", "inferido:cpe v.csv"))
        self.assertNotIn("en conflicto", {x["estado"] for x in c.values() if isinstance(x, dict)})
        prov = [p for p in r["procedencia"] if p[1] == "modelo"]
        self.assertIn(("scalance xc208", "inferido:cpe v.csv", "inferido"), [(p[2], p[3], p[5]) for p in prov])
        self.assertIn(("Modelo-P", "plataforma:nozomi"), [(p[2], p[3]) for p in prov])

    def test_id_estable_entre_corridas_y_entre_fuentes(self):
        cap, assets = self.captura()
        a = inv.construir(inv.registros_activos(assets, [cap]))
        cap2, assets2 = self.captura()
        b = inv.construir(inv.registros_activos(assets2, [cap2]))
        self.assertEqual([f["id"] for f in a["filas"]], [f["id"] for f in b["filas"]])
        self.assertRegex(a["filas"][0]["id"], r"^A-[0-9a-f]{8}$")
        imp = _plataforma(self.tmp, [["PLC-1", "192.0.2.10", M_PLC, "", "", "", "PLC", "1", ""]])
        c = inv.construir(_registros_plat(imp))
        self.assertEqual(_fila(c, "192.0.2.10")["id"], _fila(a, "192.0.2.10")["id"])

    def test_columnas_de_qa_vacias(self):
        cap, assets = self.captura()
        r = inv.construir(inv.registros_activos(assets, [cap]))
        for fila in inv.filas_tabla(r):
            for c in inv.QA:
                self.assertEqual(fila[inv.COLUMNAS.index(c)], "")
        self.assertEqual(inv.COLUMNAS[-4:], list(inv.QA))
        self.assertEqual(inv.COL_PROCEDENCIA, ["id", "campo", "valor", "fuente", "ultima_observacion", "estado"])


class ManualTest(_Base):
    def manual(self, filas, cab=("Hostname", "IP Address", "Criticality", "Role")):
        return inv.cargar_manual(_escribir(self.tmp / "manual.csv", cab, filas))

    def test_manual_gana_a_la_plataforma_y_es_declarado(self):
        imp = _plataforma(self.tmp, [["", "192.0.2.10", M_PLC, "", "", "", "", "1", ""]])
        reg, _av = self.manual([["PLC-Bomba-1", "192.0.2.10", "Critica", "PLC"]])
        r = inv.construir(_registros_plat(imp) + reg, con_manual=True)
        plc = _fila(r, "192.0.2.10")
        self.assertEqual([plc["campos"][c]["valor"] for c in ("nombre", "criticidad")], ["PLC-Bomba-1", "Critica"])
        self.assertEqual([plc["campos"][c]["estado"] for c in ("nombre", "criticidad")], ["declarado", "declarado"])
        self.assertEqual(plc["campos"]["nombre"]["fuente"], "manual")

    def test_manual_distinto_de_la_plataforma_gana_pero_queda_en_conflicto(self):
        imp = _plataforma(self.tmp, [["PLC-viejo", "192.0.2.10", M_PLC, "", "", "", "", "1", ""]])
        reg, _av = self.manual([["PLC-Bomba-1", "192.0.2.10", "Alta", "PLC"]])
        r = inv.construir(_registros_plat(imp) + reg, con_manual=True)
        plc = _fila(r, "192.0.2.10")
        self.assertEqual(plc["campos"]["nombre"]["valor"], "PLC-Bomba-1")
        self.assertEqual(plc["campos"]["nombre"]["estado"], "en conflicto")
        self.assertEqual(plc["conflictos"], ["nombre: PLC-Bomba-1 (manual) / PLC-viejo (plataforma:nozomi)"])

    def test_declarado_no_observado_y_observado_no_declarado(self):
        cap, assets = self.captura()
        reg, _av = self.manual([["HMI-1", "192.0.2.20", "Media", "HMI"], ["Historiador", "192.0.2.77", "Alta", ""]])
        r = inv.construir(inv.registros_activos(assets, [cap]) + reg, con_manual=True)
        self.assertEqual(_fila(r, "192.0.2.77")["presencia"], "declarado, no observado")
        self.assertEqual(_fila(r, "192.0.2.10")["presencia"], "observado, no declarado")
        self.assertEqual(_fila(r, "192.0.2.20")["presencia"], "observado y declarado")
        s = r["resumen"]
        self.assertEqual((s["declarados_no_observados"], s["observados_no_declarados"], s["observados_y_declarados"]),
                         (1, 1, 1))
        sin = inv.construir(inv.registros_activos(assets, [cap]))
        self.assertEqual({f["presencia"] for f in sin["filas"]}, {"observado"})      # sin manual no se compara

    def test_alias_de_columnas_y_xlsx(self):
        from ot_assess.report.xlsx import escribir_xlsx
        p = self.tmp / "manual.xlsx"
        escribir_xlsx(p, [("Inventario", ["Equipo", "Direccion IP", "MAC", "Fabricante", "Version firmware"],
                           [["PLC-9", "192.0.2.30", M_NUC, "Acme", "3.1"]])])
        reg, _av = inv.cargar_manual(p)
        self.assertEqual(reg[0]["ips"], ["192.0.2.30"])
        self.assertEqual({(c, v) for c, v, _f, _u in reg[0]["entradas"] if c in ("fabricante", "firmware")},
                         {("fabricante", "Acme"), ("firmware", "3.1")})


class PropiosTest(_Base):
    PERFIL = [{"direccion": "192.0.2.200", "etiqueta": "sensor"}, {"direccion": "198.51.100.0/28", "etiqueta": "NUC"},
              {"direccion": M_NUC.upper(), "etiqueta": "laptop del analista"}]

    def captura_con_propios(self):
        hosts = [(M_SENSOR, ["192.0.2.200"], T_PLC), ("aa:bb:cc:00:00:97", ["198.51.100.5"], T_PLC),
                 (M_NUC, ["203.0.113.9"], T_PLC), (M_PLC, ["192.0.2.10"], T_PLC), (M_HMI, ["192.0.2.20"], T_PLC)]
        flujos = [("192.0.2.200", "192.0.2.10", "502"), ("198.51.100.5", "192.0.2.10", "502"),
                  ("203.0.113.9", "192.0.2.20", "443"), ("192.0.2.20", "192.0.2.10", "502")]
        cap = _cap("a.pcap", hosts, flujos)
        cap.identity.append({"ip": "192.0.2.200", "mac": M_SENSOR, "tipo": "CDP", "valor": "x", "detalle": ""})
        cap.findings.append({"titulo": "solo propio", "activos": ["192.0.2.200"]})
        cap.findings.append({"titulo": "mixto", "activos": ["192.0.2.200", "192.0.2.10"]})
        cap.findings.append({"titulo": "sin activos"})
        return cap

    def propios(self):
        return inv.Propios(pf_normalizados(self.PERFIL))

    def test_ip_cidr_y_mac_salen_de_inventario_y_conductos(self):
        cap, p = self.captura_con_propios(), self.propios()
        inv.excluir_captura(cap, p)
        assets, ip_index = merge_assets([cap])
        self.assertEqual(sorted(a for x in assets.values() for a in x["ips"]), ["192.0.2.10", "192.0.2.20"])
        conduitos = build_conduits([cap], ip_index)
        self.assertEqual([(k["src"], k["dst"]) for k in conduitos], [("192.0.2.20", "192.0.2.10")])
        self.assertEqual(cap.identity, [])
        r = inv.construir(inv.registros_activos(assets, [cap]), propios=p)
        self.assertEqual(sorted(ip for f in r["filas"] for ip in f["campos"]["ips"]["valor"].split(";")),
                         ["192.0.2.10", "192.0.2.20"])
        x = r["resumen"]["excluidos"]
        self.assertEqual((x["equipos"], x["paquetes"], x["conductos"]), (3, 30, 3))

    def test_hallazgo_solo_propio_no_sale_y_el_mixto_pierde_la_ip(self):
        cap, p = self.captura_con_propios(), self.propios()
        inv.filtrar_hallazgos(cap, p)
        self.assertEqual([(f["titulo"], f.get("activos")) for f in cap.findings],
                         [("mixto", ["192.0.2.10"]), ("sin activos", None)])
        self.assertEqual(p.resumen()["hallazgos"], 1)

    def test_sin_propios_no_cambia_nada(self):
        cap = self.captura_con_propios()
        antes = (len(cap.hosts), len(cap.flows), len(cap.findings))
        inv.excluir_captura(cap, inv.Propios())
        inv.filtrar_hallazgos(cap, inv.Propios())
        self.assertEqual((len(cap.hosts), len(cap.flows), len(cap.findings)), antes)

    def test_registro_manual_de_un_equipo_propio_se_ignora(self):
        reg, _ = inv.cargar_manual(_escribir(self.tmp / "m.csv", ["Name", "IP"], [["sensor", "192.0.2.200"],
                                                                                 ["PLC", "192.0.2.10"]]))
        p = self.propios()
        r = inv.construir(reg, propios=p, con_manual=True)
        self.assertEqual(len(r["filas"]), 1)
        self.assertEqual(p.resumen()["registros"], 1)

    def test_perfil_valida_equipos_propios(self):
        base = {"version": 1, "cliente": "C", "marcos": [{"clave": "iec62443"}]}
        ruta = self.tmp / "p.json"
        ruta.write_text(json.dumps({**base, "equipos_propios": self.PERFIL}), encoding="utf-8")
        d = pf.cargar(ruta)
        self.assertEqual([e["direccion"] for e in d["equipos_propios"]],
                         ["192.0.2.200/32", "198.51.100.0/28", M_NUC])
        for malo in ([{"direccion": "no-es-ip", "etiqueta": "x"}], [{"direccion": "192.0.2.1"}],
                     [{"direccion": "192.0.2.1/24", "etiqueta": "x"}], "192.0.2.1"):
            ruta.write_text(json.dumps({**base, "equipos_propios": malo}), encoding="utf-8")
            with self.assertRaises(SystemExit):
                pf.cargar(ruta)


M_RTR = "aa:bb:cc:00:00:fe"
IPS_DETRAS = [f"198.51.100.{n}" for n in (11, 12, 13, 14, 15, 16)]
IP_PUBLICA = "8.8.8.8"
IP_RTR = "198.51.100.1"


def _cap_enrutada(nombre="r.pcap", arp=True):
    """Todas las IP llegan con la MAC del router; cada una con su propio servicio y ultima observacion."""
    cap = _cap(nombre, [(M_RTR, [IP_RTR, *IPS_DETRAS, IP_PUBLICA, "169.254.1.1"], T_PLC)])
    for n, ip in enumerate(IPS_DETRAS):
        cap.flows[(ip, "198.51.100.200", str(1000 + n), "tcp")] = {
            "src": ip, "dst": "198.51.100.200", "dport": str(1000 + n), "l4": "tcp", "pkts": 3, "bytes": 30,
            "proto": f"Proto{n}", "last": T_PLC - 1000 * (n + 1)}
        cap.flows[("198.51.100.200", ip, str(2000 + n), "tcp")] = {
            "src": "198.51.100.200", "dst": ip, "dport": str(2000 + n), "l4": "tcp", "pkts": 2, "bytes": 20,
            "proto": f"Proto{n}", "last": T_PLC - 1000 * (n + 1)}
    if arp:
        cap.arp_events.append({"frame": 1, "t": 1, "opcode": "2", "hw": M_RTR, "sip": IP_RTR, "dip": IPS_DETRAS[0],
                               "dup": ""})
    return cap


class EnrutamientoTest(_Base):
    def inventario(self, **kw):
        cap = _cap_enrutada(**kw)
        assets, _ = merge_assets([cap])
        return inv.construir(inv.registros_activos(assets, [cap]))

    def test_una_mac_de_router_se_parte_en_un_activo_por_ip(self):
        r = self.inventario()
        por_ip = {f["campos"]["ips"]["valor"]: f for f in r["filas"]}
        for n, ip in enumerate(IPS_DETRAS):
            c = por_ip[ip]["campos"]
            self.assertNotIn("mac", c)
            self.assertEqual(c["mac_salto"]["valor"], M_RTR)
            self.assertEqual(c["mac_salto"]["estado"], "observado")
            self.assertEqual(c["servicios"]["valor"], f"{2000 + n}/tcp")      # solo lo que esa IP sirve
            self.assertEqual(c["protocolos"]["valor"], f"Proto{n}")
            self.assertEqual(por_ip[ip]["ultima"], inv._hora(T_PLC - 1000 * (n + 1)))
        self.assertEqual(len({f["id"] for f in r["filas"]}), len(r["filas"]))
        self.assertNotIn("169.254.1.1", por_ip)                             # link-local no es un activo
        self.assertEqual(por_ip[IP_PUBLICA]["campos"]["zona"]["valor"], "Internet")

    def test_el_router_conserva_su_mac_solo_en_la_ip_que_responde_arp(self):
        r = self.inventario()
        con_mac = [f for f in r["filas"] if "mac" in f["campos"]]
        self.assertEqual([f["campos"]["ips"]["valor"] for f in con_mac], [IP_RTR])
        self.assertEqual(con_mac[0]["campos"]["mac"]["valor"], M_RTR)

    def test_sin_arp_ningun_activo_lleva_la_mac(self):
        r = self.inventario(arp=False)
        self.assertEqual([f for f in r["filas"] if "mac" in f["campos"]], [])
        self.assertEqual(len(r["filas"]), 1 + len(IPS_DETRAS) + 1)

    def test_id_estable_por_ip_entre_corridas(self):
        a = {f["campos"]["ips"]["valor"]: f["id"] for f in self.inventario()["filas"]}
        b = {f["campos"]["ips"]["valor"]: f["id"] for f in self.inventario()["filas"]}
        self.assertEqual(a, b)
        self.assertEqual(a[IPS_DETRAS[0]], inv._id_activo([], [IPS_DETRAS[0]], ""))

    def test_mac_con_una_ip_y_link_local_no_cambia(self):
        cap = _cap("a.pcap", [(M_PLC, ["192.0.2.10", "169.254.7.7"], T_PLC)])
        assets, _ = merge_assets([cap])
        r = inv.construir(inv.registros_activos(assets, [cap]))
        self.assertEqual(len(r["filas"]), 1)
        c = r["filas"][0]["campos"]
        self.assertEqual(c["mac"]["valor"], M_PLC)
        self.assertNotIn("mac_salto", c)

    def test_exportacion_respeta_la_union_del_importador_y_no_toma_la_mac_como_identidad(self):
        filas = [[f"N{n}", f"198.51.100.{20 + n}", M_RTR, "", "", "", "", "", ""] for n in range(6)]
        imp = _plataforma(self.tmp, filas)
        r = inv.construir(_registros_plat(imp))
        self.assertEqual(len(r["filas"]), len(imp.assets))       # lo que une el importador (D74) se respeta
        for f in r["filas"]:
            self.assertNotIn("mac", f["campos"])
            self.assertEqual(f["campos"]["mac_salto"]["valor"], M_RTR)


def pf_normalizados(lista):
    """Lo mismo que deja perfil.cargar() para `equipos_propios`."""
    import ipaddress
    out = []
    for e in lista:
        d = e["direccion"].lower()
        out.append({"direccion": d if d.count(":") == 5 else str(ipaddress.ip_network(d, strict=True)),
                    "etiqueta": e["etiqueta"]})
    return out


class DiagramaTest(_Base):
    """De punta a punta con exportaciones: ninguna salida CSV menciona al equipo propio."""

    def correr(self, idioma="es"):
        a = _escribir(self.tmp / "activos.csv", ["Name", "IP", "MAC", "Vendor", "Firmware", "Type", "Level"], [
            ["PLC-1", "10.10.2.20", M_PLC, "Acme", "1.0", "PLC", "1"], ["HMI-1", "10.10.1.10", M_HMI, "Acme", "", "HMI", "2"],
            ["Sensor", "10.99.9.5", M_SENSOR, "Nozomi", "", "Sensor", "3"]])
        e = _escribir(self.tmp / "enlaces.csv", ["Source", "Destination", "Port", "Protocol", "Packets"], [
            ["10.10.1.10", "10.10.2.20", "502", "Modbus", "100"], ["10.99.9.5", "10.10.2.20", "502", "Modbus", "40"],
            ["10.10.1.10", "10.99.9.5", "443", "HTTPS", "7"]])
        m = _escribir(self.tmp / "manual.csv", ["Hostname", "IP", "Firmware", "Criticality"], [
            ["PLC-1", "10.10.2.20", "1.0", "Critica"], ["Historiador", "10.10.3.30", "", "Alta"]])
        p = self.tmp / "perfil.json"
        p.write_text(json.dumps({"version": 1, "cliente": "C", "marcos": [{"clave": "iec62443"}], "idioma": idioma,
                                 "equipos_propios": [{"direccion": "10.99.9.5", "etiqueta": "sensor"}]}),
                     encoding="utf-8")
        out = self.tmp / ("salida_" + idioma)
        with contextlib.redirect_stdout(io.StringIO()) as buf:
            rc = main_diagrama(["--activos", str(a), "--enlaces", str(e), "--formato", "generico", "--perfil", str(p),
                                "--inventario-manual", str(m), "-o", str(out)])
        self.assertEqual(rc, 0)
        return out, buf.getvalue()

    def test_salidas_sin_el_equipo_propio_y_con_el_inventario_normalizado(self):
        out, consola = self.correr()
        for f in out.glob("*.csv"):
            self.assertNotIn("10.99.9.5", f.read_text(encoding="utf-8-sig"), f.name)
            self.assertNotIn("10.99.9.0/24", f.read_text(encoding="utf-8-sig"), f.name)
        self.assertIn("equipos propios excluidos: 1 equipos, 47 paquetes, 2 conductos", consola)
        with open(out / "inventario_normalizado.csv", encoding="utf-8-sig") as fh:
            filas = list(csv.DictReader(fh))
        self.assertEqual(sorted(f["ips"] for f in filas), ["10.10.1.10", "10.10.2.20", "10.10.3.30"])
        por_ip = {f["ips"]: f for f in filas}
        self.assertEqual(por_ip["10.10.3.30"]["observado_declarado"], "declarado, no observado")
        self.assertEqual(por_ip["10.10.1.10"]["observado_declarado"], "observado, no declarado")
        self.assertEqual(por_ip["10.10.2.20"]["nombre"], "PLC-1")
        self.assertEqual(por_ip["10.10.2.20"]["criticidad_estado"], "declarado")
        self.assertEqual(por_ip["10.10.2.20"]["firmware_fuente"], "manual")
        self.assertEqual({f["validado_por"] + f["revisado_por"] + f["fecha_validacion"] + f["comentario"]
                          for f in filas}, {""})
        with open(out / "inventario_procedencia.csv", encoding="utf-8-sig") as fh:
            largo = list(csv.DictReader(fh))
        self.assertEqual(set(largo[0]), set(inv.COL_PROCEDENCIA))
        self.assertTrue((out / "reporte_ot.xlsx").exists())
        md = (out / "reporte_ot.md").read_text(encoding="utf-8")
        self.assertIn("Inventario normalizado", md)
        self.assertIn("equipos propios", md)
        self.assertTrue((out / "inventario_importado.csv").exists())      # los inventarios actuales siguen

    def test_ingles(self):
        i18n.FALTANTES.clear()
        self.addCleanup(i18n.usar, "es")
        out, _ = self.correr("en")
        head = (out / "inventario_normalizado.csv").read_text(encoding="utf-8-sig").splitlines()[0]
        self.assertIn("ips_source", head)
        self.assertIn("observed_declared", head)
        self.assertIn("validated_by", head)
        self.assertEqual(sorted(i18n.FALTANTES), [])


if __name__ == "__main__":
    unittest.main()
