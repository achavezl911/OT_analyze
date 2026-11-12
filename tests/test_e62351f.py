"""E62351F (D125): evidencia IEC 62351 por flujo con estado y nota del equipo. Sin tshark."""
from __future__ import annotations

import argparse
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
sys.path.insert(0, str(RAIZ / "tests"))

from test_iec62351 import _cap, _correr, _flujo

from ot_assess import i18n
from ot_assess import iec62351 as ie
from ot_assess import perfil as pf
from ot_assess.cli_diagrama import main as main_diagrama
from ot_assess.consolidate import build_conduits

C = {c: i for i, c in enumerate(ie.COLUMNAS_FLUJOS)}
MMS = "MMS (IEC 61850 cliente-servidor)"


def _captura():
    cap = _cap()
    _flujo(cap, "10.0.0.1", "10.0.0.9", 2404)                 # 104 en claro
    _flujo(cap, "10.0.0.1", "10.0.0.9", 19998)                # 104 seguro, con ServerHello
    _flujo(cap, "10.0.0.2", "10.0.0.9", 19998)                # 104 seguro, sin ServerHello
    _flujo(cap, "10.0.0.1", "10.0.0.5", 20000)                # DNP3 con autenticacion segura
    _flujo(cap, "10.0.0.2", "10.0.0.6", 20000)                # DNP3 sin ella
    _flujo(cap, "10.0.0.3", "10.0.0.7", 102)                  # MMS
    _flujo(cap, "10.0.0.4", "10.0.0.8", 102)                  # S7comm
    _flujo(cap, "10.0.0.2", "10.0.0.8", 102)                  # sin decodificar
    _correr(cap, tls__handshake__type="2", tcp__srcport=19998, ip__src="10.0.0.9", ip__dst="10.0.0.1")
    _correr(cap, dnp3__al__func="32", tcp__dstport=20000, ip__src="10.0.0.1", ip__dst="10.0.0.5")
    _correr(cap, _ws__col__protocol="MMS", ip__src="10.0.0.3", ip__dst="10.0.0.7")
    _correr(cap, _ws__col__protocol="S7COMM", ip__src="10.0.0.4", ip__dst="10.0.0.8")
    _correr(cap, _ws__col__protocol="GOOSE", eth__src="aa:00:00:00:00:01", eth__dst="01:0c:cd:01:00:01")
    cap.l2_flows[("aa:00:00:00:00:02", "01:0c:cd:04:00:01")] += 5000
    return cap


def _preparar(caps, perfil=None, ruta=None, assets=None):
    args = argparse.Namespace(iec62351_estados=ruta)
    ap = argparse.ArgumentParser()
    conduits = build_conduits(caps, {}) if caps and hasattr(caps[0], "flows") else caps
    ie.preparar(ap, args, perfil or {"iec62351_flujos": {"estados": list(ie.ESTADOS_DEFECTO),
                                                         "inicial": ie.ESTADOS_DEFECTO[0]}},
                caps, conduits, assets or {})
    return args


def _por_clave(args):
    return {(f[C["protocolo"]], f[C["origen"]], f[C["destino"]], f[C["puerto"]]): f
            for f in args.iec62351_flujos["filas"]}


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


class Base(unittest.TestCase):
    def setUp(self):
        i18n.usar("es")
        self.addCleanup(i18n.usar, "es")
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)


class CapturaTest(Base):
    def test_filas_canal_tls_auth_y_102(self):
        cap = _captura()
        f = _por_clave(_preparar([cap]))
        self.assertEqual(len(f), 9)
        k104 = f[(ie.cargar()["protocolos"][0]["protocolo"], "10.0.0.1", "10.0.0.9", "2404")]
        self.assertEqual((k104[C["canal"]], k104[C["tls_confirmado"]], k104[C["fuente"]]),
                         ("en claro", "", "captura"))
        self.assertEqual(k104[C["evidencia"]], ie.NO_OBSERVADA)
        self.assertEqual(k104[C["estado_equipo"]], "por revisar")
        n104 = ie.cargar()["protocolos"][0]["protocolo"]
        con = f[(n104, "10.0.0.1", "10.0.0.9", "19998")]
        sin = f[(n104, "10.0.0.2", "10.0.0.9", "19998")]
        self.assertEqual((con[C["canal"]], con[C["tls_confirmado"]], con[C["evidencia"]]),
                         ("puerto seguro", "si", ie.OBSERVADA))
        self.assertEqual((sin[C["tls_confirmado"]], sin[C["evidencia"]]), ("no", ie.NO_OBSERVADA))
        a = f[("DNP3", "10.0.0.1", "10.0.0.5", "20000")]
        b = f[("DNP3", "10.0.0.2", "10.0.0.6", "20000")]
        self.assertEqual((a[C["autenticacion_segura"]], a[C["evidencia"]]), ("si", ie.OBSERVADA))
        self.assertEqual((b[C["autenticacion_segura"]], b[C["evidencia"]]), ("no", ie.NO_OBSERVADA))
        self.assertIn((MMS, "10.0.0.3", "10.0.0.7", "102"), f)
        self.assertFalse([k for k in f if k[1] == "10.0.0.4"])           # S7comm no entra
        sd = f[(ie.PROTO_SIN_DECODIFICAR, "10.0.0.2", "10.0.0.8", "102")]
        self.assertEqual(sd[C["evidencia"]], ie.NO_EVALUABLE)

    def test_capa2(self):
        f = _por_clave(_preparar([_captura()]))
        goose = f[("GOOSE (IEC 61850)", "aa:00:00:00:00:01", "01:0c:cd:01:00:01", "")]
        sv = f[("SV (IEC 61850 Sampled Values)", "aa:00:00:00:00:02", "01:0c:cd:04:00:01", "")]
        for x in (goose, sv):
            self.assertEqual((x[C["canal"]], x[C["transporte"]], x[C["evidencia"]], x[C["tls_confirmado"]]),
                             ("capa 2", "", ie.NO_EVALUABLE, ""))

    def test_id_estable_entre_corridas_e_idiomas(self):
        ids = [f[C["id_flujo"]] for f in _preparar([_captura()]).iec62351_flujos["filas"]]
        self.assertEqual(ids, [f[C["id_flujo"]] for f in _preparar([_captura()]).iec62351_flujos["filas"]])
        self.assertTrue(all(i.startswith("F62-") and len(i) == 14 for i in ids))
        self.assertEqual(len(set(ids)), len(ids))
        i18n.usar("en")
        en = _preparar([_captura()])
        self.assertEqual(ids, [f[C["id_flujo"]] for f in en.iec62351_flujos["filas"]])
        self.assertEqual(en.iec62351_flujos["json"]["por_evidencia"], _en_claves())

    def test_zona_y_nivel(self):
        cap = _cap()
        _flujo(cap, "10.0.0.1", "10.0.0.9", 2404)
        activos = {"m1": {"mac": "m1", "ips": {"10.0.0.1"}, "nombre": "PLC", "zona_asignada": "Z-control",
                          "purdue": "Level 1"}}
        conduits = build_conduits([cap], {"10.0.0.1": {"nombre": "PLC", "purdue": "Level 1"}})
        args = argparse.Namespace(iec62351_estados=None)
        ie.preparar(argparse.ArgumentParser(), args, {"iec62351_flujos": {"estados": ["a", "b"], "inicial": "b"}},
                    [cap], conduits, activos)
        fila = args.iec62351_flujos["filas"][0]
        self.assertEqual((fila[C["origen_zona"]], fila[C["origen_nombre"]], fila[C["estado_equipo"]]),
                         ("Z-control", "PLC", "b"))
        self.assertEqual(fila[C["destino_zona"]], "")


def _en_claves():
    return _preparar([_captura()]).iec62351_flujos["json"]["por_evidencia"]


class PerfilTest(Base):
    def _perfil(self, valor):
        d = {"version": 1, "cliente": "ACME", "marcos": [{"clave": "iec62443"}], "iec62351_flujos": valor}
        p = self.tmp / "perfil.json"
        p.write_text(json.dumps(d), encoding="utf-8")
        return pf.cargar(p)

    def test_true_false_y_objeto(self):
        self.assertEqual(self._perfil(True)["iec62351_flujos"],
                         {"estados": ie.ESTADOS_DEFECTO, "inicial": "por revisar"})
        self.assertNotIn("iec62351_flujos", self._perfil(False))
        p = self._perfil({"estados": ["a", "b", "c"], "inicial": "c"})
        self.assertEqual(p["iec62351_flujos"], {"estados": ["a", "b", "c"], "inicial": "c"})
        self.assertEqual(self._perfil({"estados": ["a", "b"]})["iec62351_flujos"]["inicial"], "a")

    def test_invalidos(self):
        malos = [{"estados": ["a", "a"]}, {"estados": ["a", ""]}, {"estados": [str(i) for i in range(11)]},
                 {"estados": ["a"]}, {"estados": ["a", "b"], "inicial": "z"}, {"estados": ["a", "x" * 41]},
                 {"estados": ["a", "b\nc"]}, {"estados": ["a", 3]}, {"extra": 1}, "si", 1, [], None]
        for m in malos:
            with self.subTest(m=m):
                with self.assertRaises(SystemExit) as cm:
                    self._perfil(m)
                self.assertIn("iec62351_flujos", str(cm.exception))


class EstadosTest(Base):
    def _base(self):
        return _preparar([_captura()]).iec62351_flujos["filas"]

    def _con(self, filas_csv, sep=","):
        ruta = self.tmp / "previo.csv"
        _escribir(ruta, filas_csv, sep)
        return ruta

    def test_traslada_estado_y_nota(self):
        base = self._base()
        ruta = self._con([["id_flujo", "estado_equipo", "nota_equipo", "otra"],
                          [base[0][0], "confirmado", "revisado con operacion", "x"],
                          [base[1][0], "", "solo nota", ""],
                          ["F62-0000000000", "confirmado", "ya no existe", ""]])
        args = _preparar([_captura()], ruta=ruta)
        filas = {f[0]: f for f in args.iec62351_flujos["filas"]}
        self.assertEqual((filas[base[0][0]][C["estado_equipo"]], filas[base[0][0]][C["nota_equipo"]]),
                         ("confirmado", "revisado con operacion"))
        self.assertEqual((filas[base[1][0]][C["estado_equipo"]], filas[base[1][0]][C["nota_equipo"]]),
                         ("por revisar", "solo nota"))
        j = args.iec62351_flujos["json"]
        self.assertEqual((j["estados_importados"], j["ids_no_encontrados"], j["filas"]), (2, 1, 9))
        self.assertEqual(j["por_estado"]["confirmado"], 1)
        self.assertEqual(sum(j["por_estado"].values()), 9)

    def test_aviso_de_ids_inexistentes(self):
        ruta = self._con([["id_flujo", "estado_equipo", "nota_equipo"], ["F62-0000000000", "confirmado", ""]])
        with contextlib.redirect_stdout(io.StringIO()) as out:
            _preparar([_captura()], ruta=ruta)
        self.assertIn("ya no existen", out.getvalue())

    def test_activa_la_tabla_sin_clave_de_perfil(self):
        ruta = self._con([["id_flujo", "estado_equipo", "nota_equipo"]])
        args = argparse.Namespace(iec62351_estados=ruta)
        cap = _captura()
        ie.preparar(argparse.ArgumentParser(), args, {}, [cap], build_conduits([cap], {}), {})
        self.assertEqual(args.iec62351_flujos["json"]["estados"], ie.ESTADOS_DEFECTO)

    def test_separador_punto_y_coma_y_bom(self):
        base = self._base()
        ruta = self._con([["id_flujo", "estado_equipo", "nota_equipo"], [base[0][0], "no aplica", "a, b"]], ";")
        args = _preparar([_captura()], ruta=ruta)
        self.assertEqual(args.iec62351_flujos["filas"][0][C["estado_equipo"]], "no aplica")
        self.assertEqual(args.iec62351_flujos["filas"][0][C["nota_equipo"]], "a, b")

    def test_cabeceras_en_ingles(self):
        base = self._base()
        ruta = self._con([["flow_id", "team_status", "team_note"], [base[0][0], "confirmado", "n"]])
        args = _preparar([_captura()], ruta=ruta)
        self.assertEqual(args.iec62351_flujos["json"]["estados_importados"], 1)

    def test_estado_no_permitido_codigo_2(self):
        base = self._base()
        ruta = self._con([["id_flujo", "estado_equipo", "nota_equipo"], [base[0][0], "inventado", ""],
                          ["F62-0000000000", "inventado", ""]])
        codigo, err = _salir2(lambda: _preparar([_captura()], ruta=ruta))
        self.assertEqual(codigo, 2)
        self.assertIn(base[0][0], err)
        self.assertNotIn("F62-0000000000", err)

    def test_lista_hasta_10_ids(self):
        cap = _cap()
        for i in range(1, 13):
            _flujo(cap, "10.0.0." + str(i), "10.0.1.1", 2404)
        base = _preparar([cap]).iec62351_flujos["filas"]
        ruta = self._con([["id_flujo", "estado_equipo", "nota_equipo"], *[[f[0], "x", ""] for f in base]])
        _codigo, err = _salir2(lambda: _preparar([cap], ruta=ruta))
        self.assertEqual(sum(f[0] in err for f in base), 10)

    def test_id_repetido_distinto_codigo_2(self):
        base = self._base()
        ruta = self._con([["id_flujo", "estado_equipo", "nota_equipo"], [base[0][0], "confirmado", ""],
                          [base[0][0], "no aplica", ""]])
        self.assertEqual(_salir2(lambda: _preparar([_captura()], ruta=ruta))[0], 2)

    def test_id_repetido_igual_se_acepta(self):
        base = self._base()
        ruta = self._con([["id_flujo", "estado_equipo", "nota_equipo"], [base[0][0], "confirmado", "n"],
                          [base[0][0], "confirmado", "n"]])
        self.assertEqual(_preparar([_captura()], ruta=ruta).iec62351_flujos["json"]["estados_importados"], 1)

    def test_sin_columnas_ilegible_y_limites_codigo_2(self):
        sin_col = self._con([["otro", "x"], ["1", "2"]])
        self.assertEqual(_salir2(lambda: _preparar([_captura()], ruta=sin_col))[0], 2)
        self.assertEqual(_salir2(lambda: _preparar([_captura()], ruta=self.tmp / "no_existe.csv"))[0], 2)
        binario = self.tmp / "bin.csv"
        binario.write_bytes(b"\xff\xfe\x00\x01")
        self.assertEqual(_salir2(lambda: _preparar([_captura()], ruta=binario))[0], 2)
        viejo = ie.MAX_FILAS_ESTADOS
        ie.MAX_FILAS_ESTADOS = 1
        self.addCleanup(setattr, ie, "MAX_FILAS_ESTADOS", viejo)
        dos = self._con([["id_flujo", "estado_equipo", "nota_equipo"], ["a", "", ""], ["b", "", ""]])
        self.assertEqual(_salir2(lambda: _preparar([_captura()], ruta=dos))[0], 2)

    def test_nota_con_formula_se_protege_al_escribir(self):
        from ot_assess.report.common import escritor_csv
        base = self._base()
        ruta = self._con([["id_flujo", "estado_equipo", "nota_equipo"], [base[0][0], "", "=HYPERLINK(1)"]])
        fila = _preparar([_captura()], ruta=ruta).iec62351_flujos["filas"][0]
        self.assertEqual(fila[C["nota_equipo"]], "=HYPERLINK(1)")
        buf = io.StringIO()
        escritor_csv(buf).writerow(fila)
        self.assertIn("'=HYPERLINK(1)", buf.getvalue())


ACT = [["id", "label", "ip", "mac_address", "vendor", "product_name", "firmware_version", "type", "level", "zone"],
       ["a1", "PLC-1", "10.1.0.1", "00:00:00:00:01:01", "", "", "", "plc", "1", ""],
       ["a2", "RTU-1", "10.1.0.2", "00:00:00:00:01:02", "", "", "", "rtu", "1", ""],
       ["a3", "HMI-1", "10.1.0.3", "00:00:00:00:01:03", "", "", "", "hmi", "2", ""]]
ENL = [["from", "to", "protocol", "port", "transport", "packets", "bytes"],
       ["a3", "a1", "IEC 104", "2404", "tcp", "10", "1000"],
       ["a3", "a2", "DNP3", "20000", "tcp", "10", "1000"],
       ["a3", "a1", "MMS", "102", "tcp", "10", "1000"],
       ["a3", "a2", "S7comm", "102", "tcp", "10", "1000"],
       ["a1", "a2", "Modbus", "502", "tcp", "10", "1000"]]


class DiagramaTest(Base):
    def _correr(self, nombre, *extra, perfil=None):
        _escribir(self.tmp / "a.csv", ACT)
        _escribir(self.tmp / "e.csv", ENL)
        args = ["--activos", str(self.tmp / "a.csv"), "--enlaces", str(self.tmp / "e.csv"),
                "-o", str(self.tmp / nombre), *extra]
        if perfil is not None:
            p = self.tmp / "perfil.json"
            p.write_text(json.dumps({"version": 1, "cliente": "ACME", "marcos": [{"clave": "iec62443"}],
                                     **perfil}), encoding="utf-8")
            args += ["--perfil", str(p)]
        with contextlib.redirect_stdout(io.StringIO()):
            return main_diagrama(args)

    def test_exportacion_filas_sin_tls(self):
        self.assertEqual(self._correr("o", perfil={"iec62351_flujos": True}), 0)
        with open(self.tmp / "o" / ie.ARCHIVO_FLUJOS, encoding="utf-8-sig", newline="") as fh:
            filas = list(csv.DictReader(fh))
        self.assertEqual({f["protocolo"] for f in filas}, {"DNP3", "IEC 60870-5-104", MMS})
        self.assertEqual(len(filas), 3)                                  # S7comm y Modbus no entran
        self.assertTrue(all(f["fuente"] == "exportacion" and f["tls_confirmado"] == ""
                            and f["autenticacion_segura"] == "" for f in filas))
        self.assertTrue(all("exportacion: sin paquetes para confirmar TLS" in f["nota"] for f in filas))
        j = json.loads((self.tmp / "o" / "resultado.json").read_text(encoding="utf-8"))
        self.assertEqual(j["iec62351_flujos"]["filas"], 3)

    def test_hoja_en_el_excel(self):
        self._correr("x", perfil={"iec62351_flujos": True})
        import zipfile
        with zipfile.ZipFile(self.tmp / "x" / "reporte_ot.xlsx") as z:
            self.assertIn("IEC 62351 flujos", z.read("xl/workbook.xml").decode("utf-8"))

    def test_estado_no_permitido_no_escribe_nada(self):
        _escribir(self.tmp / "previo.csv", [["id_flujo", "estado_equipo", "nota_equipo"]])
        self._correr("o1", "--iec62351-estados", str(self.tmp / "previo.csv"))
        with open(self.tmp / "o1" / ie.ARCHIVO_FLUJOS, encoding="utf-8-sig", newline="") as fh:
            f0 = next(iter(csv.DictReader(fh)))
        _escribir(self.tmp / "malo.csv", [["id_flujo", "estado_equipo", "nota_equipo"], [f0["id_flujo"], "zzz", ""]])
        codigo, _ = _salir2(lambda: self._correr("o2", "--iec62351-estados", str(self.tmp / "malo.csv")))
        self.assertEqual(codigo, 2)
        self.assertFalse((self.tmp / "o2").exists())
        _escribir(self.tmp / "bueno.csv", [["id_flujo", "estado_equipo", "nota_equipo"],
                                           [f0["id_flujo"], "confirmado", "ok"]])
        self._correr("o3", "--iec62351-estados", str(self.tmp / "bueno.csv"))
        with open(self.tmp / "o3" / ie.ARCHIVO_FLUJOS, encoding="utf-8-sig", newline="") as fh:
            self.assertEqual(next(csv.DictReader(fh))["estado_equipo"], "confirmado")

    def test_sin_clave_ni_opcion_no_cambia_nada(self):
        self._correr("sin")
        self._correr("con", perfil={"iec62351_flujos": True})
        self._correr("falso", perfil={"iec62351_flujos": False})
        sin = sorted(p.name for p in (self.tmp / "sin").iterdir())
        con = sorted(p.name for p in (self.tmp / "con").iterdir())
        self.assertNotIn(ie.ARCHIVO_FLUJOS, sin)
        self.assertEqual(con, sorted([*sin, ie.ARCHIVO_FLUJOS]))
        self.assertEqual(sorted(p.name for p in (self.tmp / "falso").iterdir()), sin)
        js = json.loads((self.tmp / "sin" / "resultado.json").read_text(encoding="utf-8"))
        self.assertNotIn("iec62351_flujos", js)
        self.assertNotIn("iec62351_flujos", json.loads(
            (self.tmp / "falso" / "resultado.json").read_text(encoding="utf-8")))

    def test_ingles_mismos_ids(self):
        self._correr("es_", perfil={"iec62351_flujos": True})
        self._correr("en_", "--idioma", "en", perfil={"iec62351_flujos": True})
        with open(self.tmp / "es_" / ie.ARCHIVO_FLUJOS, encoding="utf-8-sig", newline="") as fh:
            es = [f["id_flujo"] for f in csv.DictReader(fh)]
        with open(self.tmp / "en_" / ie.ARCHIVO_FLUJOS, encoding="utf-8-sig", newline="") as fh:
            lector = csv.DictReader(fh)
            self.assertIn("flow_id", lector.fieldnames)
            en = [f["flow_id"] for f in lector]
        self.assertEqual(es, en)


class SinCapturasTest(Base):
    def test_tabla_actual_no_cambia(self):
        self.assertEqual(ie.tablas([]), [])
        self.assertEqual(ie.tablas_flujos(argparse.Namespace()), [])
        self.assertIsNone(ie.para_json(argparse.Namespace()))
        cap = _captura()
        antes = ie.filas([cap])
        _preparar([cap])
        self.assertEqual(ie.filas([cap]), antes)


if __name__ == "__main__":
    unittest.main()
