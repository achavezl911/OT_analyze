"""SEG-08: un JSON muy anidado es un archivo invalido, no una traza. Guarda: todo JSON de entrada pasa por
json_entrada.cargar()."""
from __future__ import annotations

import contextlib
import io
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

from ot_assess import avisos_cisa, evasion, json_entrada
from ot_assess.cli import main as main_cli
from ot_assess.cli_comparar import main as main_comparar
from ot_assess.cli_custodia import main as main_custodia
from ot_assess.cli_diagrama import main as main_diagrama

ANIDADO = "[" * 200000 + "]" * 200000

# Archivos que leen datos internos del paquete (no son entrada del usuario): archivo -> numero de json.load(s).
INTERNOS = {
    "i18n.py": 2,                       # catalogos de idioma del paquete
    "attack_ics.py": 1,                 # catalogo ATT&CK for ICS del paquete (D112)
    "csf_transicion.py": 1,             # catalogo de transicion CSF 1.1 a 2.0 del paquete (D116)
    "tsa_hallazgos.py": 1,              # medidas tecnicas de la TSA SD 1580/82 del paquete (D118)
    "iec62351.py": 1,                  # tabla de protocolos de IEC 62351 del paquete (D117)
    "evasion.py": 1,                # data/ del paquete
    "obsolescencia.py": 1,              # fin_soporte_so.json del paquete
    "hardening.py": 1,                  # catalogo de hardening del paquete
    "madurez.py": 1,                    # dominios de madurez del paquete
    "standards.py": 1,                  # marcos incluidos en el paquete (_incluido)
    "cobertura.py": 1,                  # catalogos de cobertura del paquete
    "vuln_firmware.py": 1,              # fabricantes_alias.json del paquete
    "matriz_controles.py": 3,           # catalogo de controles, referencias CSF 2.0 y marco TSA del paquete
    "sitios.py": 1,                     # dominios de madurez del paquete
    "niveles62443.py": 1,               # niveles del paquete
    "spe62443.py": 1,                   # catalogo de la 2-1 del paquete
    "acceso_remoto.py": 1,              # herramientas de acceso remoto del paquete
    "fuentes_log.py": 1,                # catalogo de fuentes de log del paquete
    "detail/identity.py": 1,            # tabla de identidades del paquete
    "playbooks/__init__.py": 1,         # playbooks del paquete
    "firewalls/validar_politica.py": 1,  # catalogo en.json del paquete
    "firewalls/esperados.py": 1,        # catalogo de flujos esperados del paquete
}
PATRON = re.compile(r"\bjson\.loads?\(")


class FuncionComun(unittest.TestCase):
    def test_json_valido_igual_que_json_loads(self):
        self.assertEqual(json_entrada.cargar('{"a": [1, 2, {"b": null}]}'), {"a": [1, 2, {"b": None}]})
        self.assertEqual(json_entrada.cargar(b"[1]"), [1])

    def test_mal_formado_es_valueerror(self):
        with self.assertRaises(ValueError):
            json_entrada.cargar("{no es json")

    def test_anidado_es_valueerror_con_texto_claro(self):
        with self.assertRaises(ValueError) as cm:
            json_entrada.cargar(ANIDADO)
        self.assertIn("JSON demasiado anidado", str(cm.exception))


class Guarda(unittest.TestCase):
    def test_sin_json_loads_de_usuario_fuera_de_la_funcion_comun(self):
        base = RAIZ / "ot_assess"
        fuera = {}
        for p in sorted(base.rglob("*.py")):
            rel = p.relative_to(base).as_posix()
            if rel == "json_entrada.py":
                continue
            n = len(PATRON.findall(p.read_text(encoding="utf-8")))
            if n != INTERNOS.get(rel, 0):
                fuera[rel] = n
        self.assertEqual(fuera, {}, "json.load(s) fuera de json_entrada.cargar(); si es un dato interno del "
                                    "paquete, agregalo a INTERNOS con su motivo")


class ArchivosAnidados(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.malo = self.tmp / "anidado.json"
        self.malo.write_text(ANIDADO, encoding="utf-8")
        self.com = gen_exports.xd_escribir_comunicaciones(self.tmp / "com.csv", [
            gen_exports.xd_fila("10.10.1.10", "10.10.2.20", "From A to B", 502, "Modbus", tipo_a="HMI", tipo_b="PLC")])
        self.inv = _inventario_xdome(self.tmp / "inv.csv", [("HMI-1", "10.10.1.10", "Operacion"),
                                                            ("PLC-1", "10.10.2.20", "Campo")])

    def _correr(self, main, argv):
        so, se = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(so), contextlib.redirect_stderr(se):
            try:
                rc = main(argv)
            except SystemExit as e:
                rc = e.code if isinstance(e.code, int) else 1
                if isinstance(e.code, str):
                    print(e.code, file=se)
        return rc, so.getvalue() + se.getvalue()

    def _diagrama(self, *extra, activos=None, out="out"):
        return self._correr(main_diagrama, ["--activos", str(activos or self.inv), "--enlaces", str(self.com),
                                            "--formato", "xdome", "-o", str(self.tmp / out), *extra])

    def _controlado(self, rc, salida):
        self.assertNotEqual(rc, 0, salida)
        self.assertIn("[!]", salida)
        self.assertNotIn("Traceback", salida)

    def test_activos(self):
        self._controlado(*self._diagrama(activos=self.malo))

    def test_opciones_json_de_diagrama(self):
        for opcion in ("--perfil", "--mapeo", "--madurez", "--inventario-manual", "--tor-relays"):
            with self.subTest(opcion=opcion):
                rc, salida = self._diagrama(opcion, str(self.malo), out="out_" + opcion.strip("-"))
                self.assertNotIn("Traceback", salida)
                self.assertNotEqual(rc, 0, salida)

    def test_perfil_y_mapeo_con_mensaje(self):
        for opcion in ("--perfil", "--mapeo"):
            with self.subTest(opcion=opcion):
                self._controlado(*self._diagrama(opcion, str(self.malo), out="o" + opcion.strip("-")))

    def test_kev_y_tor_relays(self):
        # --kev solo se lee cuando hay vulnerabilidades importadas: se prueba el lector directamente
        for f in (avisos_cisa.cargar_kev, evasion.cargar_relays):
            with self.subTest(f=f.__name__):
                with self.assertRaises(SystemExit) as cm:
                    f(self.malo)
                self.assertIn("[!]", str(cm.exception))

    def test_custodia_exportar_registro(self):
        reg = self.tmp / "reg.jsonl"
        reg.write_text(ANIDADO + "\n", encoding="utf-8")
        rc, salida = self._correr(main_custodia, ["exportar", "--registro", str(reg), "-o", str(self.tmp / "c")])
        self.assertNotIn("Traceback", salida)
        self.assertNotEqual(rc, 0, salida)

    def test_comparar_resultado_json(self):
        for n in ("antes", "despues"):
            (self.tmp / n).mkdir()
            (self.tmp / n / "resultado.json").write_text(ANIDADO, encoding="utf-8")
        rc, salida = self._correr(main_comparar, ["--antes", str(self.tmp / "antes"),
                                                  "--despues", str(self.tmp / "despues"),
                                                  "-o", str(self.tmp / "cmp")])
        self.assertNotIn("Traceback", salida)

    def test_analisis_perfil_y_estandar(self):
        rc, salida = self._correr(main_cli, [str(self.tmp), "-o", str(self.tmp / "a"), "--perfil", str(self.malo)])
        self.assertNotIn("Traceback", salida)
        self.assertNotEqual(rc, 0, salida)
        rc, salida = self._correr(main_cli, [str(self.tmp), "-o", str(self.tmp / "a"),
                                             "--estandar-archivo", str(self.malo)])
        self.assertNotIn("Traceback", salida)


if __name__ == "__main__":
    unittest.main()
