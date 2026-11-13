"""Pruebas de los marcos de referencia. Solo biblioteca estandar."""
from __future__ import annotations

import glob
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))

from ot_assess import standards as st

# Hallazgos que NO se mapean a ningun marco, a proposito: describen la calidad de la captura
# o son informativos. Una regla nueva que no este mapeada ni en esta lista hace fallar la prueba.
SIN_REFERENCIA = {
    "No se observaron escrituras ni comandos de control",
    "Captura ilegible o sin paquetes",
    "Captura truncada (snaplen por debajo del MTU)",
    "La mayoria de las conversaciones aparece en un solo sentido",
    "El punto de captura casi no ve trafico unicast",
    "La captura no contiene ningun paquete que revele identidad de equipos",
    "Muy pocos paquetes de identidad en la captura",
    "El trafico es casi todo I/O ciclico, que no revela identidad",
    "Paquetes duplicados en la captura",
    "Ventana de captura corta",
}


def titulos_de_las_reglas() -> list:
    out = []
    for f in sorted(glob.glob(str(RAIZ / "ot_assess" / "rules" / "*.py"))):
        out += re.findall(r'finding\(\s*cap,\s*"[^"]+",\s*"([^"]+)"', Path(f).read_text(encoding="utf-8"))
    from ot_assess import conductos_zcr as zc  # conductos entre zonas (Z1b)
    from ot_assess import rutas_acceso as rac  # rutas de acceso a OT (RUTA1, D134)
    from ot_assess import rutas_ataque as ra  # rutas de ataque (A1)
    from ot_assess.alertas import TITULO as TITULO_ALERTAS  # idem (E2b)
    from ot_assess.avisos_cisa import TITULO_KEV  # catalogo KEV de CISA (T6)
    from ot_assess.firewalls import (
        higiene as hg,  # hallazgos de la configuracion del firewall (F1c)
    )
    from ot_assess.fuentes import TIT_SIN_COBERTURA  # fuentes de trafico (M2)
    from ot_assess.obsolescencia import (  # reporte de obsolescencia (I1b)
        TIT_FUERA_REP,
        TIT_PROXIMO,
        TIT_VENTA,  # fin de venta con soporte vigente (OBS2, D135)
    )
    from ot_assess.salud_red import (
        TIT_INTERFAZ,  # interfaces de switch saturadas (L1, D81)
    )
    from ot_assess.switches import (
        higiene as shg,  # hallazgos de la configuracion de los switches (SW1b)
    )
    from ot_assess.vuln_firmware import (
        TITULO_HALLAZGO as TIT_VF,  # fabricante/modelo/firmware (V1a)
    )
    from ot_assess.vulnerabilidades import (
        TITULO,  # hallazgo de una fuente que no es captura (E1b)
    )
    return out + list(shg.TITULOS) + [TIT_INTERFAZ,TIT_FUERA_REP, TIT_PROXIMO, TIT_VENTA, TITULO, TITULO_KEV, TIT_VF, TITULO_ALERTAS, hg.TIT_ANY, hg.TIT_CONFIA, hg.TIT_SOMBRA, hg.TIT_RETORNO,
                  hg.TIT_DENEGADO, hg.TIT_RUTAS, TIT_SIN_COBERTURA, zc.TIT_SIN_FW, zc.TIT_RIESGO, zc.TIT_SALTA, ra.TIT,
                  rac.TIT_SIN_DECLARAR, rac.TIT_VENCIDA]


class MatrizTest(unittest.TestCase):
    def test_todas_las_reglas_tienen_decision_de_mapeo(self):
        titulos = titulos_de_las_reglas()
        self.assertGreater(len(titulos), 20)
        sin = {t for t in titulos if not st.referencias(t)}
        self.assertEqual(sin, SIN_REFERENCIA)

    def test_filas_completas_y_fragmentos_que_si_se_usan(self):
        titulos = " | ".join(titulos_de_las_reglas()).lower()
        fragmentos = list(st.MITRE.refs)
        for e in st.ESTANDARES.values():
            if e.clave == "tsa-sd-1580-82":      # derivado (D118): solo los fragmentos con medida tecnica
                self.assertTrue(set(e.refs) <= set(fragmentos))
                continue
            self.assertEqual(list(e.refs), fragmentos, e.clave)     # misma fila en todos los marcos
        for frag in fragmentos:
            self.assertIn(frag, titulos, f"fragmento sin uso: {frag}")

    def test_nist_csf(self):
        claves = list(st.ESTANDARES)
        self.assertEqual(claves.index("nist-csf"), claves.index("nist-800-82") + 1)
        csf, n82 = st.ESTANDARES["nist-csf"], st.ESTANDARES["nist-800-82"]
        self.assertEqual(list(csf.refs), list(n82.refs))
        permitidos = {"PR.PS-01", "PR.PS-02", "PR.PS-03", "PR.AA-01", "PR.AA-03", "PR.AA-05",
                      "PR.DS-02", "PR.IR-01", "PR.IR-03", "PR.IR-04", "PR.PS-04", "DE.AE-03", "ID.RA-01", "ID.RA-04", "ID.AM-01",
                      "ID.AM-03", "DE.CM-01", "DE.CM-03", "DE.AE-02"}
        patron = re.compile(r"^(GV|ID|PR|DE|RS|RC)\.[A-Z]{2}-\d{2}")
        for frag, texto in csf.refs.items():
            if not texto:
                continue
            for parte in texto.split("; "):
                m = patron.match(parte)
                self.assertTrue(m, f"{frag}: {parte}")
                self.assertIn(m.group(0), permitidos, f"{frag}: {parte}")
        self.assertEqual([e.clave for e in st.elegir("nist-csf,nist-800-82")], ["nist-csf", "nist-800-82"])

    def test_referencias_por_marco(self):
        r = st.referencias("Operaciones de escritura o control observadas en la captura")
        self.assertIn("T1692.001", r["mitre-ics"])
        self.assertIn("SR 2.1", r["iec62443"])
        self.assertIn("CIP-005 R1", r["nerc-cip"])
        self.assertIn("AC-3", r["nist-800-82"])

    def test_texto_vacio_significa_sin_referencia_en_ese_marco(self):
        r = st.referencias("Proporcion alta de trafico de difusion")
        self.assertIn("mitre-ics", r)
        self.assertNotIn("nerc-cip", r)             # CIP no tiene un requisito directo para esto

    def test_elegir(self):
        self.assertEqual([e.clave for e in st.elegir("nerc-cip, iec62443")], ["nerc-cip", "iec62443"])
        self.assertEqual(len(st.elegir("iec62443,iec62443")), 1)
        with self.assertRaises(SystemExit):
            st.elegir("no-existe")
        with self.assertRaises(SystemExit):
            st.elegir(" , ")


class MetadatosTest(unittest.TestCase):
    def test_cada_marco_incluido_declara_fuente_version_y_validacion(self):
        for e in (st.MITRE, *st.ESTANDARES.values()):
            self.assertTrue(e.fuente and e.fuente != st.SIN_DECLARAR, e.clave)
            self.assertTrue(e.version_fuente, e.clave)
            self.assertEqual(e.validacion, {"estado": "sin revisar"}, e.clave)
            if e.clave != "tsa-sd-1580-82":      # derivado (D118): sin JSON propio
                self.assertTrue((st.DIR_MARCOS / f"{e.clave}.json").is_file(), e.clave)
        self.assertEqual(st.ESTANDARES["iec62443"].version_fuente, "IEC 62443-3-3:2013")

    def test_linea_de_fuente_en_el_aviso(self):
        aviso = st.avisos([st.ESTANDARES["iec62443"]])[0]
        self.assertIn("Fuente: IEC 62443-3-3 (SR)", aviso)
        self.assertIn("Version: IEC 62443-3-3:2013. Validacion del mapeo: sin revisar.", aviso)
        self.assertTrue(aviso.isascii())


class ArchivoPropioTest(unittest.TestCase):
    def setUp(self):
        self.antes = dict(st.ESTANDARES)

    def tearDown(self):
        st.ESTANDARES.clear()
        st.ESTANDARES.update(self.antes)

    def _json(self, datos) -> str:
        f = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
        json.dump(datos, f)
        f.close()
        return f.name

    def test_carga_y_aplica(self):
        e = st.cargar_archivo(self._json({
            "clave": "mi-norma", "nombre": "Norma X",
            "referencias": {"texto claro": "Art. 12"}}))
        self.assertIn("mi-norma", st.ESTANDARES)
        self.assertEqual(st.referencias("Credenciales o administracion en texto claro")["mi-norma"], "Art. 12")
        self.assertEqual(e.nombre, "Norma X")

    def test_rechaza_archivos_invalidos(self):
        for malo in ({"nombre": "x", "referencias": {}},                       # sin clave
                     {"clave": "Mala Clave", "nombre": "x", "referencias": {}},
                     {"clave": "iec62443", "nombre": "x", "referencias": {}},   # ya existe
                     {"clave": "ok", "nombre": "x", "referencias": []}):
            with self.assertRaises(SystemExit):
                st.cargar_archivo(self._json(malo))
        with self.assertRaises(SystemExit):
            st.cargar_archivo("/no/existe.json")

    def test_sin_metadatos_usa_valores_por_defecto(self):
        e = st.cargar_archivo(self._json({"clave": "propio", "nombre": "P", "referencias": {}}))
        self.assertEqual((e.fuente, e.version_fuente), ("sin declarar", "sin declarar"))
        self.assertEqual(e.validacion, {"estado": "sin revisar"})

    def test_validacion_revisado_completa(self):
        e = st.cargar_archivo(self._json({
            "clave": "rev", "nombre": "R", "referencias": {}, "fuente": "F", "version_fuente": "V1",
            "validacion": {"estado": "revisado", "por": "Ana", "fecha": "2026-05-01"}}))
        self.assertEqual(st.avisos([st.Estandar("x", "X", alcance="A", fuente=e.fuente,
                                                version_fuente=e.version_fuente,
                                                validacion=e.validacion)])[0],
                         "A Fuente: F. Version: V1. Validacion del mapeo: revisado por Ana, 2026-05-01.")

    def test_rechaza_metadatos_invalidos(self):
        base = {"clave": "m", "nombre": "M", "referencias": {}}
        for extra in ({"validacion": {"estado": "aprobado"}},                          # estado desconocido
                      {"validacion": {"estado": "revisado", "fecha": "2026-05-01"}},   # sin por
                      {"validacion": {"estado": "revisado", "por": "Ana"}},            # sin fecha
                      {"validacion": {"estado": "revisado", "por": "Ana", "fecha": "01/05/2026"}},
                      {"validacion": {"estado": "sin revisar", "otro": 1}},            # clave desconocida
                      {"inventada": 1}):                                               # clave desconocida
            with self.assertRaises(SystemExit, msg=str(extra)):
                st.cargar_archivo(self._json({**base, **extra}))
        self.assertNotIn("m", st.ESTANDARES)


if __name__ == "__main__":
    unittest.main()
