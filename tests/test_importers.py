"""Pruebas de la importacion desde plataformas OT. Solo biblioteca estandar."""
from __future__ import annotations

import csv
import json
import os
import shutil
import stat
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest import mock

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))
sys.path.insert(0, str(RAIZ / "tests"))

import gen_exports

from ot_assess.cli import main
from ot_assess.diagram import Opciones, build_all
from ot_assess.diagram.graph import construir_activos, construir_zonas
from ot_assess.importers import (
    importar,
    lector,
)
from ot_assess.importers import perfiles as pf


class LectorTest(unittest.TestCase):
    def test_csv_con_titulo_previo_y_punto_y_coma(self):
        filas = lector.leer_csv(b"Reporte\nIP;Nombre;Zona\n10.0.0.1;PLC 1;A\n\n10.0.0.2;HMI;\n")
        self.assertEqual(filas, [{"IP": "10.0.0.1", "Nombre": "PLC 1", "Zona": "A"},
                                 {"IP": "10.0.0.2", "Nombre": "HMI", "Zona": ""}])

    def test_codificaciones(self):
        self.assertEqual(lector.leer_csv("a,b\nñ,2\n".encode("utf-8-sig"))[0]["a"], "ñ")
        self.assertEqual(lector.leer_csv("a,b\nñ,2\n".encode("cp1252"))[0]["a"], "ñ")
        self.assertEqual(lector.leer_csv("a\tb\n1\t2\n".encode("utf-16"))[0], {"a": "1", "b": "2"})

    def test_encabezados_repetidos(self):
        self.assertEqual(list(lector.leer_csv(b"ip,ip\n1,2\n")[0]), ["ip", "ip_2"])

    def test_json_de_api_anidado(self):
        crudo = json.dumps({"result": [{"ip": ["1.1.1.1", "2.2.2.2"], "zone": {"name": "A"},
                                        "addresses": [{"address": "3.3.3.3"}, {"address": "4.4.4.4"}],
                                        "level": 0, "ok": True, "nulo": None}]}).encode()
        f = lector.leer_json(crudo)[0]
        self.assertEqual(f["ip"], "1.1.1.1;2.2.2.2")
        self.assertEqual(f["zone_name"], "A")
        self.assertEqual(f["addresses_address"], "3.3.3.3;4.4.4.4")
        self.assertEqual((f["level"], f["ok"], f["nulo"]), ("0", "true", ""))

    def test_json_lines_y_lista_directa(self):
        self.assertEqual(len(lector.leer_json(b'{"a":1}\n{"a":2}\n')), 2)
        self.assertEqual(len(lector.leer_json(b'[{"a":1},{"a":2},{"a":3}]')), 3)

    def test_xlsx(self):
        d = Path(tempfile.mkdtemp())
        try:
            gen_exports.escribir_xlsx(d / "t.xlsx", [["ip", "nombre", "n"], ["10.0.0.1", "A&B <x>", 5], ["10.0.0.2", "C", 7]])
            self.assertEqual(lector.leer_tabla(d / "t.xlsx"),
                             [{"ip": "10.0.0.1", "nombre": "A&B <x>", "n": "5"}, {"ip": "10.0.0.2", "nombre": "C", "n": "7"}])
        finally:
            shutil.rmtree(d)

    def test_archivo_invalido_o_inexistente(self):
        with self.assertRaises(SystemExit):
            lector.leer_tabla("/no/existe.csv")
        d = Path(tempfile.mkdtemp())
        try:
            (d / "x.xlsx").write_bytes(b"PKno es un zip")
            with self.assertRaises(SystemExit):
                lector.leer_tabla(d / "x.xlsx")
        finally:
            shutil.rmtree(d)


def _zip_xlsx(partes: dict) -> bytes:
    import io
    import zipfile
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w", zipfile.ZIP_DEFLATED) as z:
        for n, c in partes.items():
            z.writestr(n, c)
    return b.getvalue()


class BombaZipTest(unittest.TestCase):
    HOJA = ('<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>'
            '<row r="1"><c r="A1" t="inlineStr"><is><t>ip</t></is></c></row></sheetData>{}</worksheet>')

    def test_parte_excede_tope(self):
        raw = _zip_xlsx({"xl/worksheets/sheet1.xml": self.HOJA.format(" " * 5000)})
        with mock.patch.object(lector, "MAX_PARTE", 1000):
            with self.assertRaises(SystemExit) as cm:
                lector.leer_xlsx(raw)
        self.assertIn("bomba zip", str(cm.exception))
        self.assertIn("rechazado: xl/worksheets/sheet1.xml excede", str(cm.exception))

    def test_total_excede_tope(self):
        hoja = self.HOJA.format(" " * 300)
        ss = '<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">' + " " * 300 + "</sst>"
        raw = _zip_xlsx({"xl/sharedStrings.xml": ss, "xl/worksheets/sheet1.xml": hoja})
        with mock.patch.object(lector, "MAX_PARTE", 1000), mock.patch.object(lector, "MAX_TOTAL", 500):
            with self.assertRaises(SystemExit):
                lector.leer_xlsx(raw)
        self.assertEqual(lector.leer_xlsx(raw), [])      # sin parche, valido

    def test_demasiadas_entradas(self):
        raw = _zip_xlsx({f"x{i}": "a" for i in range(6)})
        with mock.patch.object(lector, "MAX_PARTES", 5):
            with self.assertRaises(SystemExit):
                lector.leer_xlsx(raw)


class ValoresTest(unittest.TestCase):
    def test_nivel(self):
        casos = {"Level 1": "Nivel 1", "L2": "Nivel 2", "Purdue Level 3.5": "Nivel 3.5", "DMZ": "Nivel 3.5",
                 "4 - Business": "Nivel 4", "Level 2 - Supervisory": "Nivel 2", "": None, "Level 10": None,
                 "n/a": None}
        for texto, esperado in casos.items():
            self.assertEqual(pf.parse_nivel(texto), esperado, texto)

    def test_nivel_cero_es_un_nivel_no_ausencia(self):
        self.assertEqual(pf.parse_nivel("0"), "Nivel 0")
        self.assertEqual(pf.parse_nivel("Level 0"), "Nivel 0")

    def test_tipo(self):
        casos = {"S7-1500 PLC": "controlador", "Engineering Workstation": "ingenieria", "Domain Controller": "servidor",
                 "HMI": "supervision", "Switch": "red", "Remote I/O": "controlador", "Windows 10": "host",
                 "Firewall": "firewall", "Camera": "otro", "": "otro", "Networking": "red",
                 "Network": "red", "Network Camera": "otro", "Network Attached Storage": "servidor"}
        for texto, esperado in casos.items():
            self.assertEqual(pf.clasificar_tipo(texto)[0], esperado, texto)

    def test_categoria_de_protocolo(self):
        self.assertEqual(pf.categoria_protocolo("Modbus/TCP"), "ot")
        self.assertEqual(pf.categoria_protocolo("IEC 60870-5-104"), "ot")
        self.assertEqual(pf.categoria_protocolo("Telnet"), "claro")
        self.assertIsNone(pf.categoria_protocolo("HTTPS"))       # cifrado: no es "claro"
        self.assertIsNone(pf.categoria_protocolo("SFTP"))
        self.assertIsNone(pf.categoria_protocolo(""))


class MapeoTest(unittest.TestCase):
    def test_alias_exacto_y_por_sufijo(self):
        m = pf.mapear(["Asset Name", "IP Address", "addresses_address", "zone_name", "pera_level"], pf.ACTIVOS)
        self.assertEqual(m["nombre"], "Asset Name")
        self.assertEqual(m["ip"], "IP Address")          # el alias exacto gana al sufijo
        self.assertEqual(m["zona"], "zone_name")          # y 'zone_name' no se confunde con nombre
        self.assertEqual(m["nivel"], "pera_level")
        # JSON anidado: 'asset_type_name' es el tipo; 'name' (exacto) sigue siendo el nombre
        m = pf.mapear(["name", "asset_type_name", "zone_name"], pf.ACTIVOS)
        self.assertEqual((m["nombre"], m["tipo"], m["zona"]), ("name", "asset_type_name", "zone_name"))

    def test_una_columna_no_alimenta_dos_campos(self):
        m = pf.mapear(["name"], pf.ACTIVOS)
        self.assertEqual(list(m.values()), ["name"])

    def test_forzado(self):
        m = pf.mapear(["IP", "Mi columna rara"], pf.ACTIVOS, {"nivel": "mi columna rara"})
        self.assertEqual(m["nivel"], "Mi columna rara")
        with self.assertRaises(SystemExit):
            pf.mapear(["IP"], pf.ACTIVOS, {"nivel": "no existe"})
        with self.assertRaises(SystemExit):
            pf.mapear(["IP"], pf.ACTIVOS, {"campo_inventado": "IP"})

    def test_deteccion_de_perfil(self):
        self.assertEqual(pf.detectar_perfil(["id", "label", "mac_address", "product_name", "level"]), "nozomi")
        self.assertEqual(pf.detectar_perfil(["id", "name", "pera_level", "zone_name", "ip_addresses"]), "dragos")
        self.assertEqual(pf.detectar_perfil(["a", "b", "c"]), "generico")


class ImportarTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        cls.est = gen_exports.escribir(cls.tmp)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _imp(self, estilo: str, **kw):
        e = self.est[estilo]
        return importar([e["activos"]], [e["enlaces"]], **kw)

    def test_los_cuatro_estilos_dan_el_mismo_grafo(self):
        for estilo in "abcd":
            imp = self._imp(estilo)
            self.assertEqual(imp.resumen["activos"], len(gen_exports.ACTIVOS), estilo)
            self.assertEqual(imp.resumen["conductos"], len(gen_exports.ENLACES), estilo)
            self.assertEqual(imp.resumen["extremos_no_resueltos"], 0, estilo)

    def test_estilo_b_resuelve_enlaces_por_nombre_y_mac_con_guiones(self):
        imp = self._imp("b")
        ids = {a["mac"] for a in imp.assets.values()}
        self.assertIn("00:00:bc:10:00:11", ids)                       # MAC normalizada
        self.assertTrue(all(k["src"] in ids and k["dst"] in ids for k in imp.conduits))

    def test_nivel_cero_se_conserva_y_la_ausencia_se_infiere(self):
        imp = self._imp("c")
        por_nombre = {a["nombre"]: a for a in imp.assets.values()}
        self.assertEqual(por_nombre["RIO-ANALOG-1"]["purdue"], "Nivel 0")        # nivel 0 informado
        self.assertEqual(por_nombre["JUMP-SRV"]["purdue"], "Nivel 3.5")          # sin nivel: zona DMZ
        self.assertEqual(por_nombre["FW-DMZ"]["purdue"], "Infraestructura")      # firewall
        self.assertEqual(por_nombre["CAMARA-01"]["purdue"], "")                  # nada que inferir
        self.assertGreater(imp.resumen["activos_nivel_por_tipo"], 0)

    def test_criticidad_por_cruce_de_zonas(self):
        imp = self._imp("a")
        por_id = {a["mac"]: a["nombre"] for a in imp.assets.values()}
        hmi_plc = next(k for k in imp.conduits if por_id[k["src"]] == "HMI-SALA-1" and por_id[k["dst"]] == "PLC-TURBINA")
        self.assertEqual((hmi_plc["categoria"], hmi_plc["cruza_zona"], hmi_plc["criticidad"]), ("ot", True, "Alta"))
        self.assertTrue(all(k["escrituras"] == 0 for k in imp.conduits))         # las exportaciones no distinguen
        self.assertNotIn("Critica", {k["criticidad"] for k in imp.conduits})

    def test_agrupacion_automatica_y_por_zona(self):
        self.assertEqual(self._imp("a").agrupar, "nivel")
        imp = self._imp("a", agrupar="zona")
        self.assertEqual(imp.agrupar, "zona")
        diagramas = build_all(imp.assets, imp.conduits, Opciones(agrupar="zona", origen="plataforma"))
        zonas = next(d for d in diagramas if d.slug == "diagrama_zonas")
        for z in ("Campo", "Control", "Supervision", "DMZ", "Corporativa"):
            self.assertIn(z, zonas.svg)
        self.assertIn("zona de seguridad definida en la plataforma", zonas.descripcion)

    def test_diagramas_validos_y_ordenados(self):
        imp = self._imp("a")
        for d in build_all(imp.assets, imp.conduits, Opciones(origen="plataforma")):
            ET.fromstring(d.svg)
            ET.fromstring(d.svg_completo)
        # De arriba hacia abajo: el orden del modelo Purdue, y "Sin clasificar" al final.
        self.assertEqual([n.id for n in construir_zonas(imp.assets, imp.conduits).nodos],
                         ["Nivel 4", "Nivel 3.5", "Nivel 3", "Nivel 2", "Nivel 1", "Nivel 0",
                          "Infraestructura", "Sin clasificar"])

    def test_sin_inventario(self):
        imp = importar([], [self.est["a"]["enlaces"]])
        self.assertEqual(imp.assets, {})
        self.assertEqual(len(imp.conduits), len(gen_exports.ENLACES))
        self.assertTrue(any("Sin archivo de activos" in a for a in imp.advertencias))

    def test_protocolo_que_solo_trae_transporte(self):
        d = Path(tempfile.mkdtemp())
        try:
            (d / "e.csv").write_text("src,dst,protocol,port\n10.0.0.1,10.0.0.2,TCP,502\n10.0.0.1,10.0.0.3,UDP,161\n")
            imp = importar([], [d / "e.csv"])
            self.assertEqual([k["servicio"] for k in imp.conduits], ["Modbus/TCP", "SNMP"])
            self.assertTrue(any("solo transporte" in a for a in imp.advertencias))
        finally:
            shutil.rmtree(d)

    def test_varios_protocolos_en_una_fila_no_duplican_volumen(self):
        d = Path(tempfile.mkdtemp())
        try:
            (d / "e.csv").write_text("from,to,protocols,bytes\n10.0.0.1,10.0.0.2,Modbus/TCP;DNP3,1000\n")
            imp = importar([], [d / "e.csv"])
            self.assertEqual([k["servicio"] for k in imp.conduits], ["Modbus/TCP", "DNP3"])
            self.assertEqual(sum(k["bytes"] for k in imp.conduits), 1000)
        finally:
            shutil.rmtree(d)

    def test_multicast_no_es_un_nodo(self):
        d = Path(tempfile.mkdtemp())
        try:
            (d / "e.csv").write_text("from,to,protocol\n10.0.0.1,224.0.0.251,mDNS\n10.0.0.1,10.0.0.2,Modbus/TCP\n")
            imp = importar([], [d / "e.csv"])
            self.assertTrue(imp.conduits[0]["multicast"])
            etiquetas = {n.etiqueta for n in construir_activos(imp.assets, imp.conduits).nodos}
            self.assertEqual(etiquetas, {"10.0.0.1", "10.0.0.2"})
        finally:
            shutil.rmtree(d)

    def test_un_nombre_con_espacio_no_genera_alias_parciales(self):
        """El extremo '1' no debe resolverse contra un equipo llamado 'PLC 1'."""
        d = Path(tempfile.mkdtemp())
        try:
            (d / "a.csv").write_text("id,name,ip\nx1,PLC 1,10.0.0.1\n")
            (d / "e.csv").write_text("from,to,protocol\n1,PLC 1,Modbus/TCP\n")
            imp = importar([d / "a.csv"], [d / "e.csv"])
            self.assertEqual(imp.resumen["extremos_no_resueltos"], 1)
        finally:
            shutil.rmtree(d)

    def test_falta_columna_obligatoria_sugiere_mapeo(self):
        d = Path(tempfile.mkdtemp())
        try:
            (d / "e.csv").write_text("columna_x,columna_y\n1,2\n")
            with self.assertRaises(SystemExit) as cm:
                importar([], [d / "e.csv"])
            self.assertIn("--mapeo", str(cm.exception))
            (d / "a.csv").write_text("id\n1\n")
            with self.assertRaises(SystemExit):
                importar([d / "a.csv"], [], formato="auto")      # sin enlaces
            with self.assertRaises(SystemExit):
                importar([], [d / "e.csv"], formato="nada")
        finally:
            shutil.rmtree(d)

    def test_mapeo_manual_rescata_columnas_irreconocibles(self):
        d = Path(tempfile.mkdtemp())
        try:
            (d / "a.csv").write_text("Equipo,Direccion,Capa\nPLC-1,10.0.0.1,Level 1\nHMI-1,10.0.0.2,Level 2\n")
            (d / "e.csv").write_text("Emisor,Receptor,Servicio\nHMI-1,PLC-1,Modbus/TCP\n")
            mapeo = {"activos": {"nombre": "Equipo", "ip": "Direccion", "nivel": "Capa"},
                     "enlaces": {"origen": "Emisor", "destino": "Receptor", "protocolo": "Servicio"}}
            imp = importar([d / "a.csv"], [d / "e.csv"], mapeo=mapeo)
            self.assertEqual({a["purdue"] for a in imp.assets.values()}, {"Nivel 1", "Nivel 2"})
            self.assertEqual(imp.conduits[0]["criticidad"], "Alta")
        finally:
            shutil.rmtree(d)


class XDomeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        cls.xd = gen_exports.xdome(cls.tmp)
        cls.imp = importar([cls.xd["inventario"]], cls.xd["comunicaciones"])

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _activo(self, ip: str) -> dict:
        return next(a for a in self.imp.assets.values() if ip in a["ips"])

    def _conductos(self, puerto: str) -> list:
        return [k for k in self.imp.conduits if k["port"] == puerto]

    def test_deteccion_del_perfil(self):
        self.assertEqual(self.imp.perfil, "xdome")
        self.assertEqual(self.imp.fuente, "Claroty xDome")
        self.assertEqual(pf.detectar_perfil(gen_exports.XD_COMUNICACIONES), "xdome")
        self.assertEqual(pf.detectar_perfil(gen_exports.XD_INVENTARIO), "xdome")
        self.assertEqual(pf.detectar_perfil(["asset_name", "virtual_zone", "purdue_level", "asset_type"]),
                         "claroty")

    def test_la_columna_de_tipo_de_xdome_es_type_y_la_de_otros_perfiles_no_cambia(self):
        self.assertEqual(self.imp.mapeos["activos"]["tipo"], "TYPE")
        self.assertEqual(self._activo("10.10.1.10")["tipo"], "supervision")      # CATEGORY decia "OT"
        self.assertEqual(pf.mapear(["category", "type"], pf.ACTIVOS)["tipo"], "category")

    def test_from_b_to_a_invierte_origen_y_destino(self):
        (k,) = self._conductos("502")
        self.assertEqual((k["src"], k["dst"]), (self._activo("10.10.2.20")["mac"], self._activo("10.10.1.10")["mac"]))
        self.assertFalse(k["bidireccional"])

    def test_bidireccional_en_dos_archivos_es_un_conducto(self):
        (k,) = self._conductos("445")
        self.assertEqual(k["bytes"], 160)
        self.assertEqual((k["primera"], k["ultima"], k["dias"]), ("2026-11-02", "2026-11-04", 3))
        self.assertTrue(k["bidireccional"])
        self.assertEqual(k["src"], self._activo("10.10.1.10")["mac"])      # orientacion de la primera fila

    def test_na_es_sin_dato(self):
        (k,) = self._conductos("445")
        self.assertNotIn("N/A", k["servicio"])
        self.assertNotEqual(k["servicio"], "-")                              # el puerto decide
        self.assertEqual(self._conductos("53")[0]["servicio"], "DNS")
        self.assertTrue(all("N/A" not in str(v) for a in self.imp.assets.values() for v in a.values()))

    def test_ip_current_multiple_no_crea_equipos(self):
        todas = {x for k in self.imp.conduits for x in (k["src"], k["dst"])}
        self.assertNotIn("10.10.9.9", todas)
        self.assertEqual(self.imp.resumen["activos"], len(self.imp.assets))

    def test_tipos_de_los_lados_pasan_al_activo(self):
        self.assertEqual(self._activo("10.10.3.30")["tipo"], "servidor")      # inventario: "Other"; enlace: Historian
        nuevo = self._activo("10.10.5.50")                                    # fuera del inventario
        self.assertEqual((nuevo["tipo"], nuevo["purdue"]), ("servidor", "Nivel 3"))
        self.assertEqual(self._activo("10.10.2.20")["tipo"], "controlador")   # el inventario manda

    def test_nombre_del_lado_b_e_internet(self):
        ext = self._activo("203.0.113.5")
        self.assertEqual(ext["nombre"], "update.example.com")
        self.assertEqual((ext["tipo"], ext["purdue"]), ("externo", "Externo"))
        g = construir_activos(self.imp.assets, self.imp.conduits)
        self.assertIn("Externo", {n.banda for n in g.nodos})

    def test_tipos_de_equipo_de_xdome(self):
        esperado = {"PLC": "controlador", "HMI": "supervision", "Historian": "servidor", "OPC Server": "servidor",
                    "OT Gateway": "controlador", "Firewall": "firewall", "Switch": "red",
                    "Network Equipment": "red", "Domain Server": "servidor", "PC": "host",
                    "Building Management System": "servidor", "Other": "otro", "Smartphone": "otro"}
        for texto, tipo in esperado.items():
            self.assertEqual(pf.clasificar_tipo(texto)[0], tipo, texto)

    def test_aviso_de_exportacion_truncada(self):
        filas = [gen_exports.xd_fila("10.10.1.10", "10.10.2.20", "From A to B", 502, "Modbus")] * 100000
        p = gen_exports.xd_escribir_comunicaciones(self.tmp / "truncada.csv", filas)
        imp = importar([], [p])
        self.assertTrue(any("posible exportacion truncada" in a and "100000" in a for a in imp.advertencias))
        self.assertEqual((len(imp.conduits), imp.conduits[0]["bytes"]), (1, 100 * 100000))
        corto = gen_exports.xd_escribir_comunicaciones(self.tmp / "corta.csv", filas[:10])
        self.assertFalse(any("truncada" in a for a in importar([], [corto]).advertencias))


class CliDiagramaTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        cls.est = gen_exports.escribir(cls.tmp / "ex")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _correr(self, destino: str, *extra) -> Path:
        e = self.est["b"]
        out = self.tmp / destino
        rc = main(["diagrama", "--activos", str(e["activos"]), "--enlaces", str(e["enlaces"]),
                   "-o", str(out), "--cliente", "Central de prueba", *extra])
        self.assertEqual(rc, 0)
        return out

    def test_agrupa_por_interfaz_con_rutas_firewall(self):
        rutas = self.tmp / "rutas.csv"
        rutas.write_text("Interfaz,Zona,CIDR\nCAMPO,Planta,10.20.1.0/24\nSUPERV,,10.20.0.0/16\n",
                         encoding="utf-8")
        con = self._correr("con_rutas", "--rutas-firewall", str(rutas))
        mmd = (con / "diagrama_zonas.mmd").read_text(encoding="utf-8")
        self.assertIn("CAMPO (Planta)", mmd)
        self.assertIn("SUPERV", mmd)
        pagina = (con / "diagramas.html").read_text(encoding="utf-8")
        self.assertIn("<h2>Flujos entre interfaces del firewall</h2>", pagina)
        self.assertIn("interfaz del firewall", pagina)
        self.assertTrue((con / "firewall_matriz.csv").exists())
        # el usuario puede pedir otra agrupacion aunque haya rutas
        nivel = self._correr("con_rutas_nivel", "--rutas-firewall", str(rutas), "--agrupar", "nivel")
        self.assertNotIn("CAMPO", (nivel / "diagrama_zonas.mmd").read_text(encoding="utf-8"))
        # sin la opcion: agrupacion de antes y sin seccion
        sin = self._correr("sin_rutas")
        self.assertNotIn("CAMPO", (sin / "diagrama_zonas.mmd").read_text(encoding="utf-8"))
        self.assertNotIn("Flujos entre interfaces", (sin / "diagramas.html").read_text(encoding="utf-8"))
        with self.assertRaises(SystemExit):
            main(["diagrama", "--enlaces", str(self.est["b"]["enlaces"]), "-o", str(self.tmp / "x"),
                  "--agrupar", "interfaz"])

    def test_md_escape_html(self):
        """SEG-06: HTML crudo no llega al Markdown; & se escapa primero."""
        from ot_assess.report.common import md_escape
        self.assertEqual(md_escape("<script>a|b</script>"), "&lt;script&gt;a\\|b&lt;/script&gt;")
        self.assertEqual(md_escape("A&B &lt;"), "A&amp;B &amp;lt;")

    def test_celda_csv(self):
        from ot_assess.report.common import celda_csv
        for p in "=+-@\t\r":
            self.assertEqual(celda_csv(p + "x"), "'" + p + "x")
        for intacto in ("-5", "+3,5", "-", "PLC 1", "", 7, 1.5, None):
            self.assertEqual(celda_csv(intacto), intacto)

    def _correr_csv(self, nombre: str, activos: str, enlaces: str) -> Path:
        d = self.tmp / nombre
        d.mkdir()
        (d / "a.csv").write_text(activos, encoding="utf-8")
        (d / "e.csv").write_text(enlaces, encoding="utf-8")
        out = d / "o"
        self.assertEqual(main(["diagrama", "--activos", str(d / "a.csv"), "--enlaces", str(d / "e.csv"),
                               "-o", str(out)]), 0)
        return out

    def test_hallazgos_de_inventario_en_la_salida(self):
        out = self._correr_csv(
            "hall", "id,name,ip,type,level,zone\n1,HMI-1,10.0.0.1,Windows XP SP3,2,Z\n2,PLC-1,10.0.0.2,PLC,1,Z\n",
            "from,to,protocol,port\n1,2,telnet,23\n")
        filas = list(csv.DictReader((out / "hallazgos_importados.csv").open(encoding="utf-8-sig")))
        titulos = " | ".join(f["titulo"] for f in filas)
        self.assertIn("Protocolos de gestion sin cifrar", titulos)
        self.assertIn("Software o sistema operativo fuera de soporte", titulos)
        plataforma = json.loads((out / "importacion.json").read_text(encoding="utf-8"))["plataforma"]
        self.assertTrue(all(f["iec62443"] and f["captura"] == f"exportacion {plataforma}" for f in filas), filas)
        html = (out / "diagramas.html").read_text(encoding="utf-8")
        self.assertIn("Hallazgos segun la exportacion", html)
        self.assertIn("no estan validados con exportaciones reales (P1)", html)
        self.assertNotIn("Sin hallazgos de las reglas de inventario.", html)
        self.assertEqual(len(json.loads((out / "importacion.json").read_text(encoding="utf-8"))["hallazgos"]),
                         len(filas))

    def test_alertas_en_el_subcomando(self):
        d = self.tmp / "ale"
        d.mkdir()
        a = d / "a.csv"
        a.write_text("origen,destino,puerto,firma,severidad,conteo\n"
                     "10.20.3.11,10.20.1.21,2404,IEC-104 comando inesperado,high,4\n"
                     "10.20.2.21,10.20.1.12,102,S7 PLC Stop,critical,1\n"
                     "10.20.1.11,10.20.1.12,502,Par sin enlace,low,2\n", encoding="utf-8")
        out = self._correr("ale_con", "--alertas", str(a))
        filas = list(csv.DictReader((out / "hallazgos_importados.csv").open(encoding="utf-8-sig")))
        ha = [f for f in filas if f["captura"] == "alertas a.csv"]
        self.assertEqual(len(ha), 1, filas)
        self.assertEqual(ha[0]["severidad"], "Alta")
        self.assertTrue(ha[0]["iec62443"], ha[0])
        self.assertIn("Alertas sin conducto observado: 2", ha[0]["evidencia"])
        tabla = list(csv.DictReader((out / "alertas.csv").open(encoding="utf-8-sig")))
        self.assertEqual([t["conducto_observado"] for t in tabla], ["si", "si", "no"])
        self.assertEqual(tabla[0]["activo_origen"], "SCADA-SRV-1")
        html = (out / "diagramas.html").read_text(encoding="utf-8")
        self.assertIn("Alertas importadas", html)
        self.assertIn("no valida las firmas", html)
        res = json.loads((out / "importacion.json").read_text(encoding="utf-8"))["alertas"]
        self.assertEqual((res["total"], res["sin_conducto"]), (7, 2))
        sin = self._correr("ale_sin")
        self.assertFalse((sin / "alertas.csv").exists())
        self.assertNotIn("Alertas importadas", (sin / "diagramas.html").read_text(encoding="utf-8"))
        self.assertEqual(json.loads((sin / "importacion.json").read_text(encoding="utf-8"))["alertas"], {})
        self.assertFalse(any(f["captura"].startswith("alertas")
                             for f in csv.DictReader((sin / "hallazgos_importados.csv").open(encoding="utf-8-sig"))))

    def test_vulnerabilidades_en_el_subcomando(self):
        d = self.tmp / "vul"
        d.mkdir()
        v = d / "v.csv"
        v.write_text("ip,cve,severidad,estado\n10.20.1.11,CVE-2021-0001,critica,abierta\n"
                     "10.20.1.12,CVE-2021-0002,baja,mitigada\n9.9.9.9,CVE-2021-0003,media,abierta\n",
                     encoding="utf-8")
        out = self._correr("vul_con", "--vulnerabilidades", str(v))
        filas = list(csv.DictReader((out / "hallazgos_importados.csv").open(encoding="utf-8-sig")))
        hv = [f for f in filas if f["captura"] == "vulnerabilidades v.csv"]
        self.assertEqual(len(hv), 1, filas)
        self.assertTrue(hv[0]["iec62443"], hv[0])
        tabla = list(csv.DictReader((out / "vulnerabilidades.csv").open(encoding="utf-8-sig")))
        self.assertEqual(len(tabla), 3)
        html = (out / "diagramas.html").read_text(encoding="utf-8")
        self.assertIn("Vulnerabilidades importadas", html)
        self.assertIn("no consulta bases de CVE", html)
        res = json.loads((out / "importacion.json").read_text(encoding="utf-8"))["vulnerabilidades"]
        self.assertEqual((res["total"], res["asociadas"], res["sin_activo"]), (3, 2, 1))
        sin = self._correr("vul_sin")
        self.assertFalse((sin / "vulnerabilidades.csv").exists())
        self.assertNotIn("Vulnerabilidades importadas", (sin / "diagramas.html").read_text(encoding="utf-8"))
        self.assertEqual(json.loads((sin / "importacion.json").read_text(encoding="utf-8"))["vulnerabilidades"], {})
        self.assertFalse(any(f["captura"].startswith("vulnerabilidades")
                             for f in csv.DictReader((sin / "hallazgos_importados.csv").open(encoding="utf-8-sig"))))

    def test_sin_hallazgos_de_inventario(self):
        out = self._correr_csv("sinhall", "id,name,ip,type,level,zone\n1,HMI-1,10.0.0.1,HMI,2,Z\n"
                               "2,PLC-1,10.0.0.2,PLC,1,Z\n", "from,to,protocol,port\n1,2,modbus,502\n")
        lineas = (out / "hallazgos_importados.csv").read_text(encoding="utf-8-sig").strip().splitlines()
        self.assertEqual(len(lineas), 1)
        self.assertTrue(lineas[0].startswith("id,captura,severidad"))
        self.assertIn("Sin hallazgos de las reglas de inventario.",
                      (out / "diagramas.html").read_text(encoding="utf-8"))
        self.assertEqual(json.loads((out / "importacion.json").read_text(encoding="utf-8"))["hallazgos"], [])

    def test_formula_en_nombre_se_neutraliza_en_inventario(self):
        hostil = '=HYPERLINK("http://x","click")'
        d = self.tmp / "formula"
        d.mkdir()
        (d / "a.csv").write_text(
            "id,name,ip\n1," + '"' + hostil.replace('"', '""') + '"' + ",10.0.0.1\n2,HMI,10.0.0.2\n",
            encoding="utf-8")
        (d / "e.csv").write_text("from,to,protocol,port\n1,2,modbus,502\n", encoding="utf-8")
        out = d / "o"
        rc = main(["diagrama", "--activos", str(d / "a.csv"), "--enlaces", str(d / "e.csv"), "-o", str(out)])
        self.assertEqual(rc, 0)
        txt = (out / "inventario_importado.csv").read_text(encoding="utf-8-sig")
        self.assertIn("'=HYPERLINK(", txt)
        self.assertNotIn('"=HYPERLINK(', txt)
        self.assertNotIn("\n=HYPERLINK(", txt)

    def test_permisos_de_la_salida_diagrama(self):
        """SEG-04: carpeta nueva 0700, archivos 0600 y umask restaurado."""
        if os.name != "posix":
            return
        antes = os.umask(0o022)
        try:
            out = self._correr("permisos")
            self.assertEqual(os.umask(0o022), 0o022)
        finally:
            os.umask(antes)
        self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o700)
        for n in ("diagramas.html", "inventario_importado.csv"):
            self.assertEqual(stat.S_IMODE((out / n).stat().st_mode), 0o600, n)

    def test_umask_se_restaura_si_main_falla(self):
        if os.name != "posix":
            return
        antes = os.umask(0o022)
        try:
            with self.assertRaises(SystemExit):
                main(["diagrama", "--activos", str(self.tmp / "no_existe.csv"), "--opcion-invalida"])
            self.assertEqual(os.umask(0o022), 0o022)
        finally:
            os.umask(antes)

    def test_genera_pagina_diagramas_e_inventario(self):
        out = self._correr("o1", "--estandar", "nerc-cip")
        for n in ("diagramas.html", "diagrama_zonas.svg", "diagrama_red.svg", "diagrama_zonas.mmd",
                  "diagrama_red.mmd", "diagrama_zonas.drawio", "diagrama_red.drawio",
                  "inventario_importado.csv", "importacion.json"):
            self.assertTrue((out / n).exists(), n)
        for svg in ("diagrama_zonas.svg", "diagrama_red.svg", "diagrama_zonas.drawio", "diagrama_red.drawio"):
            ET.parse(out / svg)
        html = (out / "diagramas.html").read_text(encoding="utf-8")
        self.assertEqual(html.count("<svg"), 3)            # zonas, red y el de zonas y conductos ZCR (Z1b)
        self.assertTrue((out / "diagrama_zcr.svg").exists())
        self.assertIn("Datos de origen y calidad", html)
        self.assertIn("Acceso Electronico (EAP)", html)            # el estandar manda en el texto
        self.assertIn("Central de prueba", html)
        info = json.loads((out / "importacion.json").read_text(encoding="utf-8"))
        self.assertEqual(info["columnas"]["activos"]["nivel"], "Purdue Level")
        self.assertEqual(info["resumen"]["activos"], len(gen_exports.ACTIVOS))

    def test_perfil_de_proyecto(self):
        ej = Path(__file__).resolve().parent.parent / "docs" / "ejemplos" / "perfil.json"
        e = self.est["b"]
        out = self.tmp / "operfil"
        self.assertEqual(main(["diagrama", "--activos", str(e["activos"]), "--enlaces", str(e["enlaces"]),
                               "-o", str(out), "--perfil", str(ej)]), 0)
        html = (out / "diagramas.html").read_text(encoding="utf-8")
        self.assertIn("Perfil del proyecto", html)
        self.assertIn("Cliente Ejemplo", html)
        info = json.loads((out / "importacion.json").read_text(encoding="utf-8"))
        self.assertEqual(info["perfil_proyecto"]["cliente"], "Cliente Ejemplo")
        self.assertIn("perfil", info)
        sin = self._correr("osinperfil")
        self.assertEqual(json.loads((sin / "importacion.json").read_text(encoding="utf-8"))["perfil_proyecto"], {})
        self.assertNotIn("Perfil del proyecto", (sin / "diagramas.html").read_text(encoding="utf-8"))
        with self.assertRaises(SystemExit) as cm:
            main(["diagrama", "--activos", str(e["activos"]), "--enlaces", str(e["enlaces"]),
                  "-o", str(self.tmp / "ox"), "--perfil", str(ej), "--cliente", "X"])
        self.assertEqual(cm.exception.code, 2)

    def test_salida_determinista(self):
        a, b = self._correr("o2"), self._correr("o3")
        for n in ("diagrama_zonas.svg", "diagrama_red.svg", "diagrama_red.mmd", "inventario_importado.csv"):
            self.assertEqual((a / n).read_bytes(), (b / n).read_bytes(), n)

    def test_nombres_hostiles_se_escapan(self):
        """Los nombres vienen de archivos externos y terminan en HTML y SVG."""
        d = self.tmp / "hostil"
        d.mkdir()
        mal = '<script>alert(1)</script>"><img src=x onerror=alert(2)>'
        (d / "a.csv").write_text(f'id,name,ip,type,level,zone\nx1,"{mal.replace(chr(34), chr(34) * 2)}",10.0.0.1,PLC,1,Z\n'
                                 f'x2,HMI,10.0.0.2,HMI,2,Z\n', encoding="utf-8")
        (d / "e.csv").write_text("from,to,protocol,port\n10.0.0.2,10.0.0.1,Modbus/TCP,502\n", encoding="utf-8")
        out = d / "out"
        self.assertEqual(main(["diagrama", "--activos", str(d / "a.csv"), "--enlaces", str(d / "e.csv"),
                               "-o", str(out), "--cliente", mal, "--titulo", mal]), 0)
        for n in ("diagramas.html", "diagrama_red.svg", "diagrama_zonas.svg", "diagrama_red.mmd"):
            t = (out / n).read_text(encoding="utf-8")
            self.assertNotIn("<script>", t, n)
            self.assertNotIn("<img", t, n)
        ET.parse(out / "diagrama_red.svg")             # y el SVG sigue siendo XML valido

    def test_formato_invalido_lo_rechaza_argparse(self):
        e = self.est["a"]
        with self.assertRaises(SystemExit) as cm:
            main(["diagrama", "--enlaces", str(e["enlaces"]), "--formato", "otra"])
        self.assertEqual(cm.exception.code, 2)

    def test_ayuda_del_subcomando(self):
        with self.assertRaises(SystemExit) as cm:
            main(["diagrama", "--help"])
        self.assertEqual(cm.exception.code, 0)


if __name__ == "__main__":
    unittest.main()
