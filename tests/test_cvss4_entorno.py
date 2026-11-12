"""CV4E (D120): puntuacion CVSS v4.0 de entorno (CR/IR/AR) desde la criticidad declarada. Todo sintetico."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))
sys.path.insert(0, str(RAIZ / "tests"))

from ot_assess import cvss4, cvss4_entorno as ce
from ot_assess import vulnerabilidades as vu
from ot_assess import vuln_firmware as vf
from test_vuln_firmware import csaf, ent, inventario

BASE = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
CON_CRL = BASE + "/CR:L"
IP1, IP2 = "192.0.2.1", "192.0.2.2"


def cruce(ip, vector, cve="CVE-2099-00001"):
    v = {"ip": ip, "cve": cve, "severidad": "Alta", "cvss": None, "estado": "abierta", "producto": "", "version": "",
         "fuente": "", "activo": ip, "cvss_v4": cvss4.puntuar(vector) if vector else None, "vector_cvss_v4": vector}
    return {"vuln": v, "activo": None, "por": ""}


class Calculo(unittest.TestCase):
    def test_vector_y_puntuacion(self):
        punt, vec = ce.entorno(BASE, IP1, {IP1: "Media"})
        self.assertEqual(vec, BASE + "/CR:M/IR:M/AR:M")
        self.assertEqual(punt, cvss4.puntuar(vec))
        self.assertEqual(punt, cvss4.puntuar(BASE + "/CR:M/IR:M/AR:M"))

    def test_alta_igual_a_base_y_baja_menor_o_igual(self):
        punt, vec = ce.entorno(BASE, IP1, {IP1: "Alta"})
        self.assertTrue(vec.endswith("/CR:H/IR:H/AR:H"))
        self.assertEqual(punt, cvss4.puntuar(BASE))
        baja, _v = ce.entorno(BASE, IP1, {IP1: "Baja"})
        self.assertLessEqual(baja, punt)
        self.assertLess(baja, punt)

    def test_reemplaza_los_requisitos_del_vector(self):
        _p, vec = ce.entorno(CON_CRL, IP1, {IP1: "Alta"})
        self.assertEqual(vec.count("CR:"), 1)
        self.assertIn("/CR:H", vec)
        self.assertNotIn("CR:L", vec)
        self.assertEqual(cvss4.parsear(vec)["CR"], "H")

    def test_varias_ip_usa_la_mas_critica_y_sin_dato_queda_vacio(self):
        crit = {IP1: "Baja", IP2: "Critica"}
        self.assertEqual(ce.entorno(BASE, f"{IP1};{IP2}", crit), ce.entorno(BASE, IP2, {IP2: "Critica"}))
        self.assertEqual(ce.entorno(BASE, "192.0.2.9", crit), ("", ""))
        self.assertEqual(ce.entorno("", IP1, crit), ("", ""))
        self.assertEqual(ce.entorno("CVSS:4.0/mal", IP1, crit), ("", ""))
        self.assertEqual(ce.entorno(BASE, IP1, None), ("", ""))


class Tablas(unittest.TestCase):
    def test_vulnerabilidades_sin_criticidad_o_sin_filas_iguales_a_main(self):
        cruces = [cruce(IP1, BASE)]
        base_c, base_f = vu.columnas(cruces), vu.filas_tabla(cruces, {})
        for crit in (None, {}, {"192.0.2.9": "Alta"}):
            self.assertEqual(vu.columnas(cruces, crit), base_c)
            self.assertEqual(vu.filas_tabla(cruces, {}, crit), base_f)
        self.assertNotIn("cvss_v4_entorno", base_c)

    def test_vulnerabilidades_columnas_despues_del_vector(self):
        cruces = [cruce(IP1, BASE, "CVE-2099-00001"), cruce(IP2, "", "CVE-2099-00002"),
                  cruce(f"{IP1};{IP2}", BASE, "CVE-2099-00003")]
        crit = {IP1: "Baja", IP2: "Critica"}
        cols = vu.columnas(cruces, crit)
        i = cols.index("vector_cvss_v4")
        self.assertEqual(cols[i + 1:i + 3], ["cvss_v4_entorno", "vector_cvss_v4_entorno"])
        filas = {f[cols.index("cve")]: f for f in vu.filas_tabla(cruces, {}, crit)}
        self.assertEqual(filas["CVE-2099-00001"][i + 1:i + 3], list(ce.entorno(BASE, IP1, crit)))
        self.assertEqual(filas["CVE-2099-00002"][i + 1:i + 3], ["", ""])
        self.assertEqual(filas["CVE-2099-00003"][i + 1:i + 3], list(ce.entorno(BASE, IP2, crit)))
        self.assertEqual(len(filas["CVE-2099-00001"]), len(cols))

    def _firmware(self, crit):
        aviso = csaf("ICSA-99-40", {"CVE-2099-40001": (9.8, [], [])})
        aviso["vulnerabilities"][0]["scores"][0]["cvss_v4"] = {
            "vectorString": BASE, "baseScore": cvss4.puntuar(BASE)}
        regs = [ent(IP1, "Acme Automation", "PLC-5000", "1.0")]
        ind = vf.Indice(vf.fabricantes_de(regs))
        ind.visitar(aviso, "a.json")
        return vf.construir(ind, inventario(*regs), None, {}, None, None, "3", crit)

    def test_firmware_columnas_y_sin_criticidad_iguales_a_main(self):
        sin = self._firmware(None)
        self.assertEqual(self._firmware({"192.0.2.9": "Alta"})["columnas"], sin["columnas"])
        self.assertNotIn("cvss_v4_entorno", sin["columnas"])
        self.assertNotIn(ce.NOTA, vf.seccion(sin)["nota"])
        con = self._firmware({IP1: "Media"})
        cols = con["columnas"]
        i = cols.index("vector_cvss_v4")
        self.assertEqual(cols[i + 1:i + 3], ["cvss_v4_entorno", "vector_cvss_v4_entorno"])
        celdas = con["filas"][0]["celdas"]
        self.assertEqual(celdas[i + 1:i + 3], list(ce.entorno(BASE, IP1, {IP1: "Media"})))
        self.assertEqual(len(celdas), len(cols))
        self.assertIn(ce.NOTA, vf.seccion(con)["nota"])
        self.assertEqual(con["filas"][0]["cvss_ef"], sin["filas"][0]["cvss_ef"])     # informativo


if __name__ == "__main__":
    unittest.main()
