"""EVID2 (D127): registro de evidencias de la corrida. Sin tshark salvo la prueba de capturas."""
from __future__ import annotations

import argparse
import contextlib
import csv
import hashlib
import io
import json
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))
sys.path.insert(0, str(RAIZ / "tests"))

from ot_assess import i18n
from ot_assess import perfil as pf
from ot_assess import registro_evidencias as rv
from ot_assess.cli import crear_parser
from ot_assess.cli_diagrama import crear_parser as crear_parser_diagrama
from ot_assess.cli_diagrama import main as main_diagrama
from ot_assess.model import Assessment, Capture
from ot_assess.report.csvout import write_csvs
from ot_assess.report.jsonout import write_json
from ot_assess.standards import ESTANDARES

C = {c: i for i, c in enumerate(rv.COLUMNAS)}


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _rd(ruta):
    with open(ruta, encoding="utf-8-sig", newline="") as fh:
        return list(csv.DictReader(fh))


def _escribir(ruta: Path, filas, sep=","):
    with open(ruta, "w", newline="", encoding="utf-8-sig") as fh:
        csv.writer(fh, delimiter=sep).writerows(filas)


def _salir2(f):
    with contextlib.redirect_stderr(io.StringIO()) as err:
        try:
            f()
        except SystemExit as e:
            return e.code, err.getvalue()
    return None, ""


def _perfil(tmp: Path, extra: dict):
    p = tmp / "perfil_t.json"
    p.write_text(json.dumps({"version": 1, "cliente": "ACME", "marcos": [{"clave": "iec62443"}], **extra}),
                 encoding="utf-8")
    return pf.cargar(p)


class Base(unittest.TestCase):
    def setUp(self):
        i18n.usar("es")
        self.addCleanup(i18n.usar, "es")
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)


class PerfilTest(Base):
    def malo(self, v, frag="registro_evidencias", **otros):
        with self.assertRaises(SystemExit) as cm:
            _perfil(self.tmp, {"registro_evidencias": v, **otros})
        self.assertIn(frag, str(cm.exception))

    def test_true_y_objeto_completo(self):
        self.assertEqual(_perfil(self.tmp, {"registro_evidencias": True})["registro_evidencias"],
                         {"prefijo": "EV", "valores": {}, "sensibilidades": None, "por_archivo": []})
        completo = {"prefijo": "Ev9", "valores": {"recolector": " Ana ", "planta": "P1", "metodo": "SPAN",
                                                   "sensibilidad": "Interna"},
                    "sensibilidades": ["Interna", "Confidencial"],
                    "por_archivo": [{"patron": "*.pcap", "sensibilidad": "Confidencial", "entregables": ["D-1", "D-1"]}]}
        r = _perfil(self.tmp, {"registro_evidencias": completo})["registro_evidencias"]
        self.assertEqual(r["prefijo"], "Ev9")
        self.assertEqual(r["valores"]["recolector"], "Ana")
        self.assertEqual(r["por_archivo"], [{"patron": "*.pcap", "sensibilidad": "Confidencial",
                                             "entregables": ["D-1"]}])

    def test_invalidos(self):
        for m in (False, "si", 1, [], None, {"extra": 1}, {"prefijo": ""}, {"prefijo": "x" * 11},
                  {"prefijo": "E-V"}, {"valores": []}, {"valores": {"otro": "x"}}, {"valores": {"planta": ""}},
                  {"valores": {"planta": "x" * 81}}, {"valores": {"planta": "a\nb"}},
                  {"sensibilidades": []}, {"sensibilidades": ["a", "a"]}, {"sensibilidades": [str(i) for i in range(11)]},
                  {"sensibilidades": ["a"], "valores": {"sensibilidad": "b"}},
                  {"sensibilidades": ["a"], "por_archivo": [{"patron": "*", "sensibilidad": "b"}]},
                  {"por_archivo": {}}, {"por_archivo": ["x"]}, {"por_archivo": [{}]},
                  {"por_archivo": [{"patron": "*", "otro": 1}]}, {"por_archivo": [{"patron": ""}]},
                  {"por_archivo": [{"patron": "*", "entregables": ["a b"]}]},
                  {"por_archivo": [{"patron": "*", "entregables": ["a"] * 0 + [str(i) for i in range(21)]}]},
                  {"por_archivo": [{"patron": "*"}] * 201}):
            with self.subTest(m=m):
                self.malo(m)

    def test_entregables_contra_catalogo_de_ent1(self):
        ent = {"catalogo": [{"id": "D-1", "nombre": "Uno"}], "mapeo": {"iec62443:SR 1.1": ["D-1"]}}
        ok = {"por_archivo": [{"patron": "*", "entregables": ["D-1"]}]}
        _perfil(self.tmp, {"entregables": ent, "registro_evidencias": ok})
        self.malo({"por_archivo": [{"patron": "*", "entregables": ["D-9"]}]}, "catalogo", entregables=ent)
        # sin catalogo solo se valida el formato
        _perfil(self.tmp, {"registro_evidencias": {"por_archivo": [{"patron": "*", "entregables": ["Z.9"]}]}})
        self.malo({"por_archivo": [{"patron": "*"}] * 201}, "registro_evidencias")


def _entradas(tmp: Path, raiz="in"):
    """Carpeta de entrada sintetica y los argumentos que la apuntan (como los dejaria el CLI)."""
    r = tmp / raiz
    (r / "pcaps").mkdir(parents=True, exist_ok=True)
    (r / "avisos" / "sub").mkdir(parents=True, exist_ok=True)
    datos = {"pcaps/a.pcap": b"AAA", "pcaps/b.pcapng": b"BBBB", "fw.txt": b"firewall", "inv.csv": b"ip,nombre\n",
             "perfil.json": b"{}", "avisos/z.json": b"{\"z\": 1}", "avisos/a.json": b"{\"a\": 1}",
             "avisos/sub/c.json": b"{\"c\": 1}"}
    for n, b in datos.items():
        (r / n).write_bytes(b)
    caps = [SimpleNamespace(name=n, path=r / "pcaps" / n) for n in ("a.pcap", "b.pcapng")]
    entorno = {"capturas": [{"archivo": c.name, "sha256": _sha(datos["pcaps/" + c.name]), "legible": True,
                             "muestreada": False} for c in caps],
               "perfil": {"archivo": "perfil.json", "sha256": _sha(b"{}")}}
    args = argparse.Namespace(firewall=[str(r / "fw.txt")], inventario_manual=str(r / "inv.csv"),
                              avisos_ics=str(r / "avisos"), perfil=str(r / "perfil.json"))
    return caps, entorno, args, datos


def _filas(args):
    return [dict(zip(rv.COLUMNAS, f)) for f in args.registro_evidencias_tabla["filas"]]


class RecopilacionTest(Base):
    def test_filas_por_archivo_y_carpeta(self):
        caps, entorno, args, datos = _entradas(self.tmp)
        rv.preparar(args, {"registro_evidencias": rv.validar(True, print)}, entorno, caps)
        filas = _filas(args)
        self.assertEqual([f["archivo"] for f in filas],
                         ["a.pcap", "b.pcapng", "perfil.json", "fw.txt", "avisos", "inv.csv"])
        self.assertEqual([f["tipo_fuente"] for f in filas],
                         ["captura", "captura", "perfil", "firewall", "avisos_ics", "manual"])
        a = filas[0]
        self.assertEqual((a["id_evidencia"], a["bytes"], a["sha256"], a["opcion"]),
                         ("EV-" + _sha(b"AAA")[:10], 3, _sha(b"AAA"), "capturas"))
        self.assertEqual(filas[3]["opcion"], "firewall")
        carpeta = filas[4]
        lineas = sorted([("a.json", _sha(b"{\"a\": 1}")), ("z.json", _sha(b"{\"z\": 1}")),
                         ("sub/c.json", _sha(b"{\"c\": 1}"))])
        esperado = "".join(s + "  " + r + "\n" for r, s in sorted(lineas))
        self.assertEqual(carpeta["sha256"], _sha(esperado.encode()))
        self.assertEqual(carpeta["bytes"], len(datos["avisos/z.json"]) + len(datos["avisos/a.json"])
                         + len(datos["avisos/sub/c.json"]))
        self.assertEqual(carpeta["nota_equipo"], "carpeta con 3 archivos")
        self.assertEqual(carpeta["id_evidencia"], "EV-" + carpeta["sha256"][:10])

    def test_ids_estables_al_mover_y_entre_corridas(self):
        caps, entorno, args, _ = _entradas(self.tmp, "uno")
        rv.preparar(args, {"registro_evidencias": rv.validar(True, print)}, entorno, caps)
        caps2, entorno2, args2, _ = _entradas(self.tmp, "otra/ruta/distinta")
        rv.preparar(args2, {"registro_evidencias": rv.validar(True, print)}, entorno2, caps2)
        self.assertEqual(_filas(args), _filas(args2))
        caps3, entorno3, args3, _ = _entradas(self.tmp, "tres")
        rv.preparar(args3, {"registro_evidencias": rv.validar(True, print)}, entorno3, caps3)
        self.assertEqual(_filas(args), _filas(args3))

    def test_dos_entradas_iguales_una_fila(self):
        caps, entorno, args, _ = _entradas(self.tmp)
        copia = self.tmp / "in" / "copia_fw.txt"
        copia.write_bytes(b"firewall")
        args.firewall = [str(self.tmp / "in" / "fw.txt"), str(copia)]
        args.switch = [str(copia)]
        rv.preparar(args, {"registro_evidencias": rv.validar(True, print)}, entorno, caps)
        fw = [f for f in _filas(args) if f["sha256"] == _sha(b"firewall")]
        self.assertEqual(len(fw), 1)
        self.assertEqual(fw[0]["archivo"], "copia_fw.txt; fw.txt")
        self.assertEqual(fw[0]["opcion"], "firewall; switch")

    def test_sin_rutas_en_csv_ni_json(self):
        caps, entorno, args, _ = _entradas(self.tmp)
        perfil = {"registro_evidencias": rv.validar(True, print)}
        rv.preparar(args, perfil, entorno, caps)
        cap = Capture(Path("a.pcap"))
        res = Assessment([cap], {}, [], args, estandares=[ESTANDARES["iec62443"]], perfil=perfil)
        write_csvs(res, self.tmp)
        write_json(res, self.tmp)
        for n in ("registro_evidencias.csv", "resultado.json"):
            self.assertNotIn(str(self.tmp), (self.tmp / n).read_text(encoding="utf-8"), n)
        j = json.loads((self.tmp / "resultado.json").read_text(encoding="utf-8"))["registro_evidencias"]
        self.assertEqual(j, {"filas": 6, "por_tipo": {"avisos_ics": 1, "captura": 2, "firewall": 1, "manual": 1,
                                                      "perfil": 1},
                             "sin_recolector": 6, "sin_sensibilidad": 6, "importadas": 0, "ids_no_encontrados": 0})

    def test_paquete_avisos_una_fila_con_el_manifiesto(self):
        caps, entorno, args, _ = _entradas(self.tmp)
        args.paquete_avisos = str(self.tmp / "in" / "avisos")
        args.paquete_avisos_info = {"sha256": "ab" * 32}
        rv.preparar(args, {"registro_evidencias": rv.validar(True, print)}, entorno, caps)   # avisos_ics ya viene del paquete
        paq = [f for f in _filas(args) if f["tipo_fuente"] in ("paquete_avisos", "avisos_ics")]
        self.assertEqual([(f["tipo_fuente"], f["sha256"]) for f in paq], [("paquete_avisos", "ab" * 32)])

    def test_la_tabla_de_opciones_cubre_los_parsers(self):
        """Toda opcion de archivo o carpeta de los dos CLI esta en la tabla o excluida a proposito."""
        no_entrada = {"help", "version", "out", "tshark", "max_packets", "max_rows", "idioma", "titulo", "cliente",
                      "cache", "cache_renovar", "no_detail", "no_diagrams", "diagram_max_nodes",
                      "diagram_max_edges", "estandar", "origen_ataque", "objetivo_ataque", "formato", "agrupar",
                      "fuente", "solo_diagramas", "registro_evidencias"}
        tabla = {d for d, _t in rv.OPCIONES}
        for parser in (crear_parser(), crear_parser_diagrama()):
            dests = {a.dest for a in parser._actions}
            self.assertEqual(sorted(dests - tabla - no_entrada), [])
        self.assertEqual(sorted(tabla - {a.dest for p in (crear_parser(), crear_parser_diagrama())
                                         for a in p._actions}), [])


class MetadatosTest(Base):
    def _correr(self, cfg, perfil_extra=None, caps_args=None):
        caps, entorno, args, _ = _entradas(self.tmp)
        perfil = {**(perfil_extra or {}), "registro_evidencias": rv.validar(cfg, print)}
        rv.preparar(args, perfil, entorno, caps)
        return {f["archivo"]: f for f in _filas(args)}

    def test_valores_planta_desde_sitio_y_no_declarado(self):
        f = self._correr({"valores": {"recolector": "Ana", "metodo": "SPAN"}}, {"sitio": "Planta Norte"})
        self.assertEqual((f["fw.txt"]["recolector"], f["fw.txt"]["planta"], f["fw.txt"]["metodo"],
                          f["fw.txt"]["sensibilidad"]), ("Ana", "Planta Norte", "SPAN", "no declarado"))
        f = self._correr({"valores": {"planta": "P1"}}, {"sitio": "Planta Norte"})
        self.assertEqual(f["fw.txt"]["planta"], "P1")
        f = self._correr(True)
        self.assertEqual((f["fw.txt"]["recolector"], f["fw.txt"]["planta"]), ("no declarado", "no declarado"))

    def test_por_archivo_primera_que_casa_sin_mayusculas(self):
        f = self._correr({"valores": {"recolector": "Ana", "sensibilidad": "Interna"},
                          "por_archivo": [{"patron": "*.PCAP", "recolector": "Luis", "entregables": ["D-1", "D-2"]},
                                          {"patron": "a.*", "recolector": "Otro", "sensibilidad": "Alta"},
                                          {"patron": "*.json", "metodo": "Descarga"}]})
        self.assertEqual((f["a.pcap"]["recolector"], f["a.pcap"]["sensibilidad"], f["a.pcap"]["entregables"]),
                         ("Luis", "Interna", "D-1; D-2"))          # la primera gana; pisa solo sus campos
        self.assertEqual(f["b.pcapng"]["recolector"], "Ana")
        self.assertEqual(f["perfil.json"]["metodo"], "Descarga")
        self.assertEqual(f["fw.txt"]["entregables"], "")

    def test_clase_con_modelo_de_evidencia_y_custodia(self):
        modelo = {"por_fuente": {"captura": "OBS-RED", "manual": "DEC"}}
        f = self._correr(True, {"modelo_evidencia": modelo})
        self.assertEqual((f["a.pcap"]["clase_evidencia"], f["inv.csv"]["clase_evidencia"],
                          f["fw.txt"]["clase_evidencia"]), ("OBS-RED", "DEC", ""))
        f = self._correr(True)
        self.assertEqual(f["a.pcap"]["clase_evidencia"], "")
        caps, entorno, args, _ = _entradas(self.tmp, "c")
        entorno["custodia"] = {"capturas": [{"archivo": "a.pcap", "sha256": _sha(b"AAA"), "estado": "registrada"},
                                            {"archivo": "b.pcapng", "sha256": _sha(b"BBBB"),
                                             "estado": "no registrada"}]}
        rv.preparar(args, {"registro_evidencias": rv.validar(True, print)}, entorno, caps)
        f = {x["archivo"]: x for x in _filas(args)}
        self.assertEqual((f["a.pcap"]["custodia"], f["b.pcapng"]["custodia"], f["fw.txt"]["custodia"]),
                         ("registrada", "no registrada", ""))

    def test_prefijo(self):
        caps, entorno, args, _ = _entradas(self.tmp)
        rv.preparar(args, {"registro_evidencias": rv.validar({"prefijo": "PRJ"}, print)}, entorno, caps)
        self.assertTrue(all(f["id_evidencia"].startswith("PRJ-") for f in _filas(args)))


class ImportacionTest(Base):
    def _ids(self):
        caps, entorno, args, _ = _entradas(self.tmp)
        rv.preparar(args, {"registro_evidencias": rv.validar(True, print)}, entorno, caps)
        return {f["archivo"]: f["id_evidencia"] for f in _filas(args)}

    def _importar(self, filas, sep=",", perfil=None):
        _escribir(self.tmp / "prev.csv", filas, sep)
        caps, entorno, args, _ = _entradas(self.tmp, "n")
        args.registro_evidencias = str(self.tmp / "prev.csv")
        perfil = {"registro_evidencias": rv.validar({"valores": {"recolector": "Perfil"}}, print), **(perfil or {})}
        rv.leer_opcion(argparse.ArgumentParser(), args, perfil)
        with contextlib.redirect_stdout(io.StringIO()) as out:
            rv.preparar(args, perfil, entorno, caps)
        return args, {f["archivo"]: f for f in _filas(args)}, out.getvalue()

    def test_coma_y_punto_y_coma_en_espanol_e_ingles(self):
        ids = self._ids()
        es = [["id_evidencia", "recolector", "planta", "metodo", "sensibilidad", "entregables", "nota_equipo"],
              [ids["fw.txt"], "Ana", "P1", "Respaldo", "Alta", "D-1; D-2", "ok"]]
        en = [["evidence_id", "collector", "plant", "method", "sensitivity", "deliverables", "team_note"],
              [ids["fw.txt"], "Ana", "P1", "Respaldo", "Alta", "D-1, D-2", "ok"]]
        for filas, sep in ((es, ","), (es, ";"), (en, ","), (en, ";")):
            with self.subTest(sep=sep, cab=filas[0][0]):
                args, f, _ = self._importar(filas, sep)
                fw = f["fw.txt"]
                self.assertEqual((fw["recolector"], fw["planta"], fw["metodo"], fw["sensibilidad"],
                                  fw["entregables"], fw["nota_equipo"]),
                                 ("Ana", "P1", "Respaldo", "Alta", "D-1; D-2", "ok"))
                self.assertEqual(f["a.pcap"]["recolector"], "Perfil")       # sin fila importada: perfil
                self.assertEqual(args.registro_evidencias_tabla["json"]["importadas"], 1)

    def test_celda_vacia_no_pisa_y_no_declarado_tampoco(self):
        ids = self._ids()
        _a, f, _o = self._importar([["id_evidencia", "recolector", "metodo", "nota_equipo"],
                                    [ids["fw.txt"], "", "no declarado", ""]])
        self.assertEqual((f["fw.txt"]["recolector"], f["fw.txt"]["metodo"]), ("Perfil", "no declarado"))

    def test_id_inexistente_se_cuenta_y_se_avisa(self):
        ids = self._ids()
        args, _f, salida = self._importar([["id_evidencia", "recolector"], [ids["fw.txt"], "Ana"], ["EV-0000000000", "X"]])
        self.assertEqual(args.registro_evidencias_tabla["json"]["ids_no_encontrados"], 1)
        self.assertIn("1 id_evidencia", salida)

    def test_bom_y_filas_repetidas_iguales(self):
        ids = self._ids()
        _a, f, _o = self._importar([["id_evidencia", "recolector"], [ids["fw.txt"], "Ana"], [ids["fw.txt"], "Ana"]])
        self.assertEqual(f["fw.txt"]["recolector"], "Ana")

    def test_formula_se_neutraliza_al_escribir(self):
        ids = self._ids()
        args, _f, _o = self._importar([["id_evidencia", "metodo", "nota_equipo"], [ids["fw.txt"], "=1+1", "@cmd"]])
        perfil = {"registro_evidencias": rv.validar(True, print)}
        res = Assessment([Capture(Path("a.pcap"))], {}, [], args, estandares=[ESTANDARES["iec62443"]], perfil=perfil)
        write_csvs(res, self.tmp)
        fila = next(f for f in _rd(self.tmp / "registro_evidencias.csv") if f["archivo"] == "fw.txt")
        self.assertEqual((fila["metodo"], fila["nota_equipo"]), ("'=1+1", "'@cmd"))

    def test_errores_codigo_2(self):
        ids = self._ids()
        base = ["id_evidencia", "sensibilidad", "entregables"]
        ent = {"catalogo": [{"id": "D-1", "nombre": "Uno"}], "mapeo": {"iec62443:SR 1.1": ["D-1"]}}
        perfil = _perfil(self.tmp, {"entregables": ent, "registro_evidencias": {"sensibilidades": ["Alta", "Baja"]}})
        casos = {"inexistente": None,
                 "sin_columna": [["recolector"], ["Ana"]],
                 "repetido": [["id_evidencia", "recolector"], [ids["fw.txt"], "A"], [ids["fw.txt"], "B"]],
                 "sensibilidad": [base, [ids["fw.txt"], "Media", ""]],
                 "entregable": [base, [ids["fw.txt"], "Alta", "D-9"]]}
        for nombre, filas in casos.items():
            with self.subTest(nombre):
                ruta = self.tmp / "no_existe.csv"
                if filas is not None:
                    _escribir(self.tmp / "m.csv", filas)
                    ruta = self.tmp / "m.csv"
                args = argparse.Namespace(registro_evidencias=str(ruta))
                codigo, _ = _salir2(lambda a=args: rv.leer_opcion(argparse.ArgumentParser(), a, perfil))
                self.assertEqual(codigo, 2)
        # lo valido pasa con la misma lista y el mismo catalogo
        _escribir(self.tmp / "ok.csv", [base, [ids["fw.txt"], "Baja", "D-1"]])
        args = argparse.Namespace(registro_evidencias=str(self.tmp / "ok.csv"))
        rv.leer_opcion(argparse.ArgumentParser(), args, perfil)
        self.assertEqual(args.registro_evidencias_previo[ids["fw.txt"]],
                         {"sensibilidad": "Baja", "entregables": ["D-1"]})

    def test_sin_clave_la_opcion_activa_el_registro(self):
        ids = self._ids()
        _escribir(self.tmp / "p.csv", [["id_evidencia", "recolector"], [ids["fw.txt"], "Ana"]])
        caps, entorno, args, _ = _entradas(self.tmp, "s")
        args.registro_evidencias = str(self.tmp / "p.csv")
        rv.leer_opcion(argparse.ArgumentParser(), args, {})
        rv.preparar(args, {}, entorno, caps)
        self.assertEqual({f["archivo"]: f for f in _filas(args)}["fw.txt"]["recolector"], "Ana")


ACT = [["id", "name", "ip", "type", "level", "zone"], ["1", "HMI-1", "10.0.0.1", "Windows XP SP3", "2", "Z"],
       ["2", "PLC-1", "10.0.0.2", "PLC", "1", "Z"]]
ENL = [["from", "to", "protocol", "port"], ["1", "2", "telnet", "23"]]
VUL = [["cve", "severidad", "activo"], ["CVE-2020-0001", "Alta", "HMI-1"]]


class DiagramaTest(Base):
    def _correr(self, nombre, *extra, perfil=None):
        _escribir(self.tmp / "a.csv", ACT)
        _escribir(self.tmp / "e.csv", ENL)
        _escribir(self.tmp / "v.csv", VUL)
        args = ["--activos", str(self.tmp / "a.csv"), "--enlaces", str(self.tmp / "e.csv"),
                "--vulnerabilidades", str(self.tmp / "v.csv"), "-o", str(self.tmp / nombre), *extra]
        if perfil is not None:
            p = self.tmp / "perfil.json"
            p.write_text(json.dumps({"version": 1, "cliente": "ACME", "marcos": [{"clave": "iec62443"}],
                                     **perfil}), encoding="utf-8")
            args += ["--perfil", str(p)]
        with contextlib.redirect_stdout(io.StringIO()):
            return main_diagrama(args)

    def test_filas_json_y_hoja(self):
        self.assertEqual(self._correr("o", perfil={"sitio": "Planta Sur", "registro_evidencias": {
            "valores": {"recolector": "Ana"}}}), 0)
        filas = {f["archivo"]: f for f in _rd(self.tmp / "o" / rv.ARCHIVO)}
        self.assertEqual(sorted(filas), ["a.csv", "e.csv", "perfil.json", "v.csv"])
        self.assertEqual([f["tipo_fuente"] for f in _rd(self.tmp / "o" / rv.ARCHIVO)],
                         ["plataforma", "plataforma", "perfil", "vulnerabilidades"])
        self.assertEqual(filas["a.csv"]["sha256"], _sha((self.tmp / "a.csv").read_bytes()))
        self.assertEqual((filas["a.csv"]["recolector"], filas["a.csv"]["planta"]), ("Ana", "Planta Sur"))
        self.assertEqual(filas["v.csv"]["opcion"], "vulnerabilidades")
        self.assertNotIn(str(self.tmp), (self.tmp / "o" / rv.ARCHIVO).read_text(encoding="utf-8"))
        j = json.loads((self.tmp / "o" / "resultado.json").read_text(encoding="utf-8"))["registro_evidencias"]
        self.assertEqual((j["filas"], j["sin_recolector"], j["sin_sensibilidad"]), (4, 0, 4))
        self.assertEqual(j["por_tipo"], {"perfil": 1, "plataforma": 2, "vulnerabilidades": 1})
        import zipfile
        with zipfile.ZipFile(self.tmp / "o" / "reporte_ot.xlsx") as z:
            self.assertIn("Registro de evidencias", z.read("xl/workbook.xml").decode("utf-8"))

    def test_ingles(self):
        self._correr("es_", perfil={"registro_evidencias": True})
        self._correr("en_", "--idioma", "en", perfil={"registro_evidencias": True})
        with open(self.tmp / "en_" / rv.ARCHIVO, encoding="utf-8-sig", newline="") as fh:
            lector = csv.DictReader(fh)
            for c in ("evidence_id", "file", "option", "source_type", "collector", "plant", "method",
                      "sensitivity", "evidence_class", "deliverables", "custody", "team_note"):
                self.assertIn(c, lector.fieldnames)
            en = list(lector)
        self.assertEqual([f["evidence_id"] for f in en], [f["id_evidencia"] for f in _rd(self.tmp / "es_" / rv.ARCHIVO)])
        self.assertEqual(en[0]["collector"], "not declared")
        import zipfile
        with zipfile.ZipFile(self.tmp / "en_" / "reporte_ot.xlsx") as z:
            self.assertIn("Evidence register", z.read("xl/workbook.xml").decode("utf-8"))

    def test_importar_y_reimportar_un_csv_en_ingles(self):
        self._correr("o1", perfil={"registro_evidencias": True})
        ids = {f["archivo"]: f["id_evidencia"] for f in _rd(self.tmp / "o1" / rv.ARCHIVO)}
        _escribir(self.tmp / "prev.csv", [["id_evidencia", "recolector", "sensibilidad"], [ids["a.csv"], "Luis", "Alta"]])
        self._correr("o2", "--registro-evidencias", str(self.tmp / "prev.csv"))          # sin la clave
        f = {x["archivo"]: x for x in _rd(self.tmp / "o2" / rv.ARCHIVO)}
        self.assertEqual((f["a.csv"]["recolector"], f["a.csv"]["sensibilidad"]), ("Luis", "Alta"))
        j = json.loads((self.tmp / "o2" / "resultado.json").read_text(encoding="utf-8"))["registro_evidencias"]
        self.assertEqual((j["filas"], j["importadas"], j["ids_no_encontrados"], j["sin_recolector"]), (3, 1, 0, 2))

    def test_error_de_importacion_no_escribe_nada(self):
        _escribir(self.tmp / "malo.csv", [["recolector"], ["Ana"]])
        codigo, _ = _salir2(lambda: self._correr("o3", "--registro-evidencias", str(self.tmp / "malo.csv")))
        self.assertEqual(codigo, 2)
        self.assertFalse((self.tmp / "o3").exists())
        codigo, _ = _salir2(lambda: self._correr("o4", "--registro-evidencias", str(self.tmp / "nada.csv")))
        self.assertEqual(codigo, 2)
        self.assertFalse((self.tmp / "o4").exists())

    def test_sin_clave_ni_opcion_no_cambia_nada(self):
        self._correr("sin1", perfil={"sitio": "X"})
        self._correr("sin2", perfil={"sitio": "X"})
        self._correr("con", perfil={"sitio": "X", "registro_evidencias": True})
        a = sorted(p.name for p in (self.tmp / "sin1").iterdir())
        self.assertNotIn(rv.ARCHIVO, a)
        self.assertEqual(sorted(p.name for p in (self.tmp / "con").iterdir()), sorted([*a, rv.ARCHIVO]))
        self.assertEqual(a, sorted(p.name for p in (self.tmp / "sin2").iterdir()))
        for n in a:
            if n.endswith((".csv", ".json")):
                self.assertEqual((self.tmp / "sin1" / n).read_bytes(), (self.tmp / "sin2" / n).read_bytes(), n)
        for n in a:
            if n.endswith(".csv") and n != "entregables.csv":
                self.assertEqual((self.tmp / "con" / n).read_bytes(), (self.tmp / "sin1" / n).read_bytes(), n)
        js = json.loads((self.tmp / "sin1" / "resultado.json").read_text(encoding="utf-8"))
        self.assertNotIn("registro_evidencias", js)
        self.assertNotIn("registro_evidencias", js["perfil"])


class CapturasTest(Base):
    def test_corrida_con_capturas(self):
        try:
            import scapy  # noqa: F401
        except ImportError:
            self.skipTest("requiere scapy")
        if not shutil.which("tshark"):
            self.skipTest("requiere tshark")
        import gen_pcaps

        from ot_assess.cli import main
        pcaps = self.tmp / "pcaps"
        sys.argv = ["gen", str(pcaps)]
        with contextlib.redirect_stdout(io.StringIO()):
            gen_pcaps.main()
        perfil = self.tmp / "perfil.json"
        perfil.write_text(json.dumps({"version": 1, "cliente": "ACME", "marcos": [{"clave": "iec62443"}],
                                      "registro_evidencias": {"valores": {"metodo": "SPAN"}}}), encoding="utf-8")
        with contextlib.redirect_stdout(io.StringIO()):
            main([str(pcaps), "-o", str(self.tmp / "o"), "--perfil", str(perfil)])
        filas = _rd(self.tmp / "o" / rv.ARCHIVO)
        caps = sorted(p for p in pcaps.rglob("*") if p.is_file())
        self.assertEqual(sorted(f["archivo"] for f in filas if f["tipo_fuente"] == "captura"),
                         sorted(p.name for p in caps))
        por_nombre = {f["archivo"]: f for f in filas}
        for p in caps:
            self.assertEqual(por_nombre[p.name]["sha256"], _sha(p.read_bytes()))
            self.assertEqual(por_nombre[p.name]["metodo"], "SPAN")
        self.assertEqual(sum(1 for f in filas if f["tipo_fuente"] == "perfil"), 1)
        self.assertIsNone(re.search(re.escape(str(self.tmp)), (self.tmp / "o" / rv.ARCHIVO).read_text(encoding="utf-8")))


if __name__ == "__main__":
    unittest.main()
