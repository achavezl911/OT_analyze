"""Z1a (D50): zonas declaradas en el perfil y zona de cada activo con su origen. Datos sinteticos."""
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

try:
    import scapy  # noqa: F401
    HAY_SCAPY = True
except ImportError:
    HAY_SCAPY = False

import gen_exports
from test_firewalls_integracion import RUTAS, _c, _sesion
from test_firewalls_topologia import _cadena

from ot_assess import i18n, perfil
from ot_assess import zonas as zo
from ot_assess.cli_diagrama import main as main_diagrama
from ot_assess.firewalls import cisco
from ot_assess.firewalls import integracion as fi

ZONAS = [{"nombre": "Control", "redes": ["10.10.2.0/24"], "sl_t": "SL2"},
         {"nombre": "Supervision", "redes": ["10.10.1.0/24"], "inferida": True, "descripcion": "deducida"},
         {"nombre": "Vacia", "redes": ["10.99.0.0/16"]}]


def _activo(ip, **kw):
    a = {"mac": ip, "ips": {ip}, "vlans": set(), "role": "", "purdue": "", "zona": ""}
    a.update(kw)
    return a


def _perfil(zonas, **extra):
    return dict({"version": 1, "cliente": "C", "marcos": [{"clave": "iec62443"}], "zonas": zonas}, **extra)


class PerfilZonasTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def cargar(self, zonas, **extra):
        p = self.tmp / "perfil.json"
        p.write_text(json.dumps(_perfil(zonas, **extra)), encoding="utf-8")
        return perfil.cargar(p)

    def falla(self, zonas, fragmento, **extra):
        with self.assertRaises(SystemExit) as cm:
            self.cargar(zonas, **extra)
        self.assertIn(fragmento, str(cm.exception))

    def test_ejemplo_del_repositorio(self):
        p = perfil.cargar(RAIZ / "docs" / "ejemplos" / "perfil_zonas.json")
        self.assertEqual([z["nombre"] for z in p["zonas"]],
                         ["Control de proceso", "Supervision", "DMZ industrial", "Equipos especiales"])
        self.assertEqual(len(zo.avisos_perfil(p["zonas"])), 1)

    def test_valido(self):
        p = self.cargar(ZONAS)
        self.assertEqual(p["zonas"][0], {"nombre": "Control", "redes": ["10.10.2.0/24"], "sl_t": "SL2"})
        self.assertTrue(p["zonas"][1]["inferida"])

    def test_errores(self):
        self.falla([{"nombre": "A", "redes": ["10.0.0.0/99"]}], "no es un CIDR valido")
        self.falla([{"nombre": "A", "redes": ["10.0.0.1/24"]}], "no es un CIDR valido")
        self.falla([{"nombre": "A", "redes": ["10.0.0.0/24"]}, {"nombre": "a", "redes": ["10.1.0.0/24"]}],
                   "repetido")
        self.falla([{"nombre": "A", "redes": ["10.0.0.0/24"]}, {"nombre": "B", "redes": ["10.0.0.0/24"]}],
                   "esta en las zonas")
        self.falla([{"nombre": "A", "redes": []}], "lista de CIDR")
        self.falla([{"nombre": "A", "redes": ["10.0.0.0/24"], "sl_t": "SL9"}], "no es SL1 a SL4")
        self.falla([{"nombre": "A", "redes": ["10.0.0.0/24"], "inferida": "si"}], "true o false")
        self.falla([{"nombre": "A", "redes": ["10.0.0.0/24"], "x": 1}], "clave desconocida")

    def test_sl_t_en_conflicto_con_sl_objetivo(self):
        z = [{"nombre": "A", "redes": ["10.0.0.0/24"], "sl_t": "SL3"}]
        self.falla(z, "contradice", sl_objetivo={"A": "SL2"})
        self.assertEqual(self.cargar(z, sl_objetivo={"A": "SL3"})["zonas"][0]["sl_t"], "SL3")

    def test_contenida_avisa_y_gana_la_mas_especifica(self):
        p = self.cargar([{"nombre": "Grande", "redes": ["10.1.0.0/16"]},
                         {"nombre": "Chica", "redes": ["10.1.2.0/24"]}])
        i18n.usar("es")
        avisos = zo.avisos_perfil(p["zonas"])
        self.assertEqual(len(avisos), 1)
        self.assertIn("gana la mas especifica", avisos[0])
        a = _activo("10.1.2.5")
        b = _activo("10.1.3.5")
        zo.asignar({"a": a, "b": b}, p)
        self.assertEqual((a["zona_asignada"], a["origen_zona"]), ("Chica", "perfil"))
        self.assertEqual((b["zona_asignada"], b["origen_zona"]), ("Grande", "perfil"))


class AsignacionTest(unittest.TestCase):
    def setUp(self):
        i18n.usar("es")

    def test_perfil_manda_sobre_firewall_y_plataforma(self):
        fw = cisco.analizar_texto(_sesion(RUTAS, ""))
        assets = {"a": _activo("10.10.1.5", zona="Plataforma")}
        rutas = fi._rutas(fw, "fw.txt", assets, [])
        zo.asignar(assets, _perfil(ZONAS), rutas, {})
        self.assertEqual((assets["a"]["zona_asignada"], assets["a"]["origen_zona"]), ("Supervision", "perfil"))
        # sin la zona declarada, el firewall (inside) manda sobre la plataforma
        sin = {"a": _activo("10.10.1.5", zona="Plataforma")}
        fi._rutas(fw, "fw.txt", sin, [])
        zo.asignar(sin, {}, rutas, {})
        self.assertEqual((sin["a"]["zona_asignada"], sin["a"]["origen_zona"]), ("inside", "firewall"))

    def test_ruta_por_defecto_no_asigna(self):
        fw = cisco.analizar_texto(_sesion(RUTAS, ""))
        assets = {"a": _activo("10.77.0.5"), "b": _activo("8.8.8.8")}   # solo los cubre 0.0.0.0/0
        rutas = fi._rutas(fw, "fw.txt", assets, [_c("10.77.0.5", "8.8.8.8")])
        zo.asignar(assets, {}, rutas, {})
        self.assertEqual((assets["a"]["zona_asignada"], assets["a"]["origen_zona"]),
                         ("Subred 10.77.0.0/24", "subred"))
        self.assertEqual(assets["b"]["origen_zona"], "internet")

    def test_varios_firewalls_primero_con_ruta_y_prefijo(self):
        assets = {"a": _activo("10.30.1.5"), "b": _activo("10.20.1.5")}
        rutas, res = fi.integrar_modelos(_cadena(), ["it.txt", "dmz.txt", "scada.txt"], assets, [])
        zo.asignar(assets, {}, rutas, res)
        # FW-IT llega a 10.30/16 y 10.20/16 por una ruta estatica hacia la interfaz dmz
        self.assertEqual((assets["a"]["zona_asignada"], assets["a"]["origen_zona"]), ("FW-IT/dmz", "firewall"))
        self.assertEqual(assets["b"]["zona_asignada"], "FW-IT/dmz")

    def test_plataforma_subred_vlan_purdue_internet_sin_zona(self):
        assets = {
            "p": _activo("10.1.2.3", zona="Zona de planta"),
            "n": _activo("10.1.2.4", zona="No Zone"),
            "v": _activo("10.1.2.5", vlans={"20", "10"}),
            "u": _activo("10.1.2.6", purdue="Nivel 2"),
            "i": _activo("8.8.8.8", purdue="Nivel 2"),
            "m": _activo("224.0.0.1", purdue="Nivel 2"),
            "s": {"mac": "s", "ips": set(), "vlans": set(), "role": "", "purdue": "", "zona": ""},
        }
        zon = zo.asignar(assets, {})
        z = {k: (a["zona_asignada"], a["origen_zona"]) for k, a in assets.items()}
        self.assertEqual(z["p"], ("Zona de planta", "plataforma"))
        self.assertEqual(z["n"], ("Subred 10.1.2.0/24", "subred"))
        self.assertEqual(z["v"], ("VLAN 10", "subred"))
        self.assertEqual(z["i"], ("Internet", "internet"))
        self.assertEqual(z["m"], ("Nivel 2", "purdue"))
        self.assertEqual(z["s"], ("sin zona", "sin zona"))
        self.assertEqual(zon["avisos"], [])
        fila = next(f for f in zon["filas"] if f["zona"] == "Subred 10.1.2.0/24")
        self.assertEqual(fila["redes"], "10.1.2.0/24")

    def test_declarada_sin_activos_avisa_y_se_lista(self):
        zon = zo.asignar({"a": _activo("10.10.2.5", role="PLC")}, _perfil(ZONAS))
        self.assertEqual([a for a in zon["avisos"] if "Vacia" in a],
                         ["la zona declarada 'Vacia' no tiene ningun activo observado"])
        filas = {f["zona"]: f for f in zon["filas"]}
        self.assertEqual(filas["Vacia"]["activos"], 0)
        self.assertEqual((filas["Control"]["sl_t"], filas["Control"]["inferida"], filas["Control"]["activos"]),
                         ("SL2", "no", 1))
        self.assertEqual(filas["Supervision"]["inferida"], "si")
        self.assertEqual(filas["Control"]["tipos_equipo"], "PLC (1)")

    def test_sl_objetivo_llena_sl_t(self):
        zon = zo.asignar({}, _perfil([{"nombre": "A", "redes": ["10.0.0.0/24"]}], sl_objetivo={"A": "SL3"}))
        self.assertEqual(zon["filas"][0]["sl_t"], "SL3")


def _inventario_xdome(path: Path, zonas: dict) -> Path:
    cab = gen_exports.XD_INVENTARIO + ["RECOMMENDED ZONE NAME"]
    filas = [["Ethernet", n, ip, "aa:bb:cc:00:00:0" + str(i), "Acme", "Net1", "OT", "Controller", "Acme", "PLC",
              "P200", "N/A", "10", "2026-11-02", "Low", 5, "N/A", "No", "N/A", "N/A", "N/A", z]
             for i, (n, ip, z) in enumerate(zonas, 1)]
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh)
        w.writerow(cab)
        w.writerows(filas)
    return path


class DiagramaTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.com = gen_exports.xd_escribir_comunicaciones(self.tmp / "com.csv", [
            gen_exports.xd_fila("10.10.1.10", "10.10.2.20", "From A to B", 502, "Modbus", tipo_a="HMI", tipo_b="PLC"),
            gen_exports.xd_fila("10.10.1.10", "8.8.8.8", "From A to B", 443, "TLS 1.2", ambito="Internet (External)"),
            gen_exports.xd_fila("10.10.1.10", "10.10.3.30", "From A to B", 445, "N/A")])

    def correr(self, *extra):
        inv = _inventario_xdome(self.tmp / "inv.csv", [("HMI-1", "10.10.1.10", "Operacion"),
                                                       ("PLC-1", "10.10.2.20", "No Zone"),
                                                       ("SRV-1", "10.10.3.30", "")])
        out = self.tmp / "out"
        with contextlib.redirect_stdout(io.StringIO()) as buf:
            rc = main_diagrama(["--activos", str(inv), "--enlaces", str(self.com), "--formato", "xdome",
                                "-o", str(out), *extra])
        self.assertEqual(rc, 0)
        filas = {f["nombre"]: f for f in csv.DictReader(open(out / "inventario_importado.csv",
                                                             encoding="utf-8-sig"))}
        return out, filas, buf.getvalue()

    def test_zona_recomendada_de_xdome_es_plataforma(self):
        out, filas, _ = self.correr()
        self.assertEqual((filas["HMI-1"]["zona_asignada"], filas["HMI-1"]["origen_asignacion"]),
                         ("Operacion", "plataforma"))
        self.assertEqual((filas["PLC-1"]["zona_asignada"], filas["PLC-1"]["origen_asignacion"]),
                         ("Subred 10.10.2.0/24", "subred"))
        self.assertEqual(filas["HMI-1"]["zona"], "Operacion")          # la columna que ya existia no cambia
        zonas = list(csv.DictReader(open(out / "zonas.csv", encoding="utf-8-sig")))
        self.assertEqual([z["zona"] for z in zonas if z["origen"] == "plataforma"], ["Operacion"])
        self.assertEqual(list(zonas[0]), zo.COLUMNAS)
        h = (out / "diagramas.html").read_text(encoding="utf-8")
        self.assertIn("<h2>Zonas</h2>", h)
        self.assertIn("IEC 62443-3-2", h)
        self.assertIn("deben confirmarse con el cliente", h)

    def test_ip_global_es_internet(self):
        _out, filas, _ = self.correr()
        self.assertEqual((filas["8.8.8.8"]["zona_asignada"], filas["8.8.8.8"]["origen_asignacion"]),
                         ("Internet", "internet"))

    def test_perfil_manda_y_avisa(self):
        p = self.tmp / "perfil.json"
        p.write_text(json.dumps(_perfil([{"nombre": "Campo", "redes": ["10.10.0.0/16"]},
                                         {"nombre": "Planta 2", "redes": ["10.10.2.0/24"]},
                                         {"nombre": "Aislada", "redes": ["10.99.0.0/24"]}])), encoding="utf-8")
        _out, filas, salida = self.correr("--perfil", str(p))
        self.assertEqual((filas["HMI-1"]["zona_asignada"], filas["HMI-1"]["origen_asignacion"]),
                         ("Campo", "perfil"))
        self.assertEqual(filas["PLC-1"]["zona_asignada"], "Planta 2")
        self.assertIn("la zona declarada 'Aislada' no tiene ningun activo observado", salida)
        self.assertIn("la red 10.10.2.0/24 de la zona 'Planta 2' esta dentro de 10.10.0.0/16", salida)


@unittest.skipUnless(shutil.which("tshark") and HAY_SCAPY, "requiere tshark y scapy")
class CapturasTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import gen_pcaps

        from ot_assess.cli import main
        cls.tmp = Path(tempfile.mkdtemp())
        pcaps = cls.tmp / "pcaps"
        sys.argv = ["gen", str(pcaps)]
        gen_pcaps.main()
        i18n.FALTANTES.clear()
        main([str(pcaps), "-o", str(cls.tmp / "es")])
        cls.faltan_es = set(i18n.FALTANTES)
        main([str(pcaps), "-o", str(cls.tmp / "en"), "--idioma", "en"])
        cls.faltan_en = set(i18n.FALTANTES)
        i18n.usar("es")

    @classmethod
    def tearDownClass(cls):
        i18n.FALTANTES.clear()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_csv_columnas_y_seccion(self):
        o = self.tmp / "es"
        z = list(csv.DictReader(open(o / "zonas.csv", encoding="utf-8-sig")))
        self.assertTrue(z)
        self.assertEqual(list(z[0]), zo.COLUMNAS)
        inv = list(csv.DictReader(open(o / "inventario.csv", encoding="utf-8-sig")))
        self.assertTrue(all(f["zona_asignada"] and f["origen_asignacion"] for f in inv))
        self.assertTrue(all(f["origen_asignacion"] in zo.ORIGENES for f in inv))
        act = list(csv.DictReader(open(o / "activos.csv", encoding="utf-8-sig")))
        self.assertTrue(all(f["zona_asignada"] for f in act))
        self.assertEqual(sum(int(f["activos"]) for f in z), len(inv))    # Z-I3 (D107): las mismas filas que inventario.csv
        for n, marca in (("reporte_ot.html", "<h3>Zonas</h3>"), ("reporte_ot.md", "### Zonas")):
            texto = (o / n).read_text(encoding="utf-8")
            self.assertIn(marca, texto, n)
            self.assertIn("deben confirmarse con el cliente", texto, n)
        with zipfile.ZipFile(o / "informe_ot.docx") as zf:
            doc = zf.read("word/document.xml").decode("utf-8")
        self.assertIn("Zonas", doc)
        self.assertIn("IEC 62443-3-2", doc)
        self.assertTrue((o / "reporte_ot.xlsx").exists())

    def test_ingles_sin_espanol_ni_faltantes(self):
        self.assertEqual(self.faltan_es, set())
        self.assertEqual(self.faltan_en, set())
        h = (self.tmp / "en" / "reporte_ot.html").read_text(encoding="utf-8")
        self.assertIn("<h3>Zones</h3>", h)
        self.assertIn("must be confirmed with the client", h)
        self.assertNotIn("deben confirmarse", h)
        cab = (self.tmp / "en" / "zonas.csv").read_text(encoding="utf-8-sig").splitlines()[0]
        self.assertNotIn("niveles_purdue", cab)

    def test_sin_zonas_las_salidas_existentes_no_cambian(self):
        """Solo se agregan las columnas nuevas al final del inventario y de activos."""
        o = self.tmp / "es"
        for n, nuevas in (("inventario.csv", 2), ("activos.csv", 2)):
            cab = open(o / n, encoding="utf-8-sig").readline().strip().split(",")
            self.assertEqual(cab[-nuevas:], ["zona_asignada", "origen_asignacion"], n)
        cab = open(o / "comunicaciones.csv", encoding="utf-8-sig").readline()
        self.assertNotIn("zona_asignada", cab)


if __name__ == "__main__":
    unittest.main()
