"""E1a: vulnerabilidades por activo y cruce con el inventario."""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ot_assess import vulnerabilidades as vu  # noqa: E402


def _csv(texto, sep=","):
    return vu.vulns_de_filas(vu.leer_csv(texto.replace(",", sep).encode()), "v.csv")


def _error(texto, sep=","):
    with unittest.TestCase().assertRaises(SystemExit) as cm:
        _csv(texto, sep)
    return str(cm.exception)


class TestNormalizacion(unittest.TestCase):
    def test_alias_y_acentos(self):
        v = _csv("Host,IP Address,Vulnerability,Criticidad,Estado,Product,Source\n"
                 "plc1,10.0.0.1,cve-2020-12345,Crítica,Nueva,Siemens,scan\n")[0]
        self.assertEqual((v["activo"], v["ip"], v["cve"], v["severidad"], v["estado"]),
                         ("plc1", "10.0.0.1", "CVE-2020-12345", "Critica", "abierta"))
        self.assertEqual((v["producto"], v["fuente"]), ("Siemens", "scan"))

    def test_severidad_texto(self):
        casos = {"critical": "Critica", "High": "Alta", "alta": "Alta", "moderate": "Media",
                 "media": "Media", "low": "Baja", "info": "Baja", "informativa": "Baja"}
        for txt, esperado in casos.items():
            v = _csv(f"ip,cve,severity\n1.1.1.1,CVE-2021-0001,{txt}\n")[0]
            self.assertEqual(v["severidad"], esperado, txt)

    def test_severidad_por_cvss_bordes(self):
        casos = {"9.0": "Critica", "8.9": "Alta", "7.0": "Alta", "6.9": "Media", "4.0": "Media",
                 "3.9": "Baja", "0.1": "Baja", "10": "Critica"}
        for cvss, esperado in casos.items():
            v = _csv(f"ip,cve,cvss\n1.1.1.1,CVE-2021-0001,{cvss}\n")[0]
            self.assertEqual(v["severidad"], esperado, cvss)

    def test_texto_no_reconocido_usa_cvss(self):
        v = _csv("ip,cve,severidad,cvss\n1.1.1.1,CVE-2021-0001,rara,7.5\n")[0]
        self.assertEqual(v["severidad"], "Alta")

    def test_texto_manda_sobre_cvss(self):
        v = _csv("ip,cve,severidad,cvss\n1.1.1.1,CVE-2021-0001,baja,9.8\n")[0]
        self.assertEqual(v["severidad"], "Baja")

    def test_estados(self):
        casos = {"": "abierta", "open": "abierta", "NEW": "abierta", "fixed": "mitigada",
                 "Resuelta": "mitigada", "mitigated": "mitigada", "accepted": "aceptada",
                 "Riesgo aceptado": "aceptada"}
        for txt, esperado in casos.items():
            v = _csv(f"ip,cve,cvss,estado\n1.1.1.1,CVE-2021-0001,5,{txt}\n")[0]
            self.assertEqual(v["estado"], esperado, txt)

    def test_sin_columna_estado_es_abierta(self):
        self.assertEqual(_csv("ip,cve,cvss\n1.1.1.1,CVE-2021-0001,5\n")[0]["estado"], "abierta")

    def test_cvss_v4_alias_vector_y_columnas_junto_a_cvss(self):
        v4 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"      # 9.3
        vs = _csv(f"ip,cve,cvss,vector_v4\n1.1.1.1,CVE-2021-0001,5,{v4}\n")
        self.assertEqual((vs[0]["cvss_v4"], vs[0]["vector_cvss_v4"], vs[0]["cvss"], vs[0]["severidad"]),
                         (9.3, v4, 5.0, "Media"))                          # severidad sigue con v3
        vs = _csv("ip,cve,cvss,CVSS4\n1.1.1.1,CVE-2021-0001,5,6.5\n")      # solo puntuacion
        self.assertEqual((vs[0]["cvss_v4"], vs[0]["vector_cvss_v4"]), (6.5, ""))
        vs = _csv(f"ip,cve,cvss,cvss_v4_vector,cvss_v4_score\n1.1.1.1,CVE-2021-0001,5,{v4},1.0\n")
        self.assertEqual(vs[0]["cvss_v4"], 9.3)                            # gana el calculado
        vs = _csv("ip,cve,cvss,vector_cvss_v4\n1.1.1.1,CVE-2021-0001,5,CVSS:4.0/mal\n")
        self.assertEqual((vs[0]["cvss_v4"], vs[0]["vector_cvss_v4"]), (None, ""))     # invalido: se ignora

    def test_columnas_v4_solo_si_el_archivo_las_trae(self):
        activos = {"k1": {"nombre": "PLC-UNO", "ips": ["1.1.1.1"], "mac": "k1"}}
        sin = vu.cruzar(_csv("ip,cve,cvss\n1.1.1.1,CVE-2021-0001,5\n"), activos)
        self.assertEqual(vu.columnas(sin), vu.COLUMNAS)
        self.assertEqual(len(vu.filas_tabla(sin, activos)[0]), len(vu.COLUMNAS))
        v4 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
        con = vu.cruzar(_csv(f"ip,cve,cvss,cvss_v4_vector\n1.1.1.1,CVE-2021-0001,5,{v4}\n"), activos)
        cols = vu.columnas(con)
        i = cols.index("cvss")
        self.assertEqual(cols[i:i + 3], ["cvss", "cvss_v4", "vector_cvss_v4"])
        fila = vu.filas_tabla(con, activos)[0]
        self.assertEqual(len(fila), len(cols))
        self.assertEqual(fila[i:i + 3], [5.0, 9.3, v4])

    def test_delimitador_punto_y_coma(self):
        v = _csv("ip,cve,cvss\n1.1.1.1,CVE-2021-0001,5\n", sep=";")
        self.assertEqual((v[0]["ip"], v[0]["cve"]), ("1.1.1.1", "CVE-2021-0001"))


class TestErrores(unittest.TestCase):
    def test_cve_invalido_con_fila(self):
        m = _error("ip,cve,cvss\n1.1.1.1,CVE-2021-0001,5\n1.1.1.2,MS17-010,5\n")
        self.assertIn("fila 2", m)
        self.assertIn("'v.csv'", m)

    def test_cve_corto(self):
        self.assertIn("fila 1", _error("ip,cve,cvss\n1.1.1.1,CVE-2021-123,5\n"))

    def test_cvss_fuera_de_rango(self):
        self.assertIn("fila 1", _error("ip,cve,cvss\n1.1.1.1,CVE-2021-0001,11\n"))
        self.assertIn("fila 1", _error("ip,cve,cvss\n1.1.1.1,CVE-2021-0001,-1\n"))
        self.assertIn("fila 1", _error("ip,cve,cvss\n1.1.1.1,CVE-2021-0001,abc\n"))

    def test_estado_raro(self):
        self.assertIn("fila 1", _error("ip,cve,cvss,estado\n1.1.1.1,CVE-2021-0001,5,quizas\n"))

    def test_severidad_indeterminable(self):
        self.assertIn("fila 1", _error("ip,cve,severidad\n1.1.1.1,CVE-2021-0001,rara\n"))

    def test_columnas_faltantes(self):
        self.assertIn("cve", _error("ip,cvss\n1.1.1.1,5\n"))
        self.assertIn("identificacion", _error("cve,cvss\nCVE-2021-0001,5\n"))
        self.assertIn("severidad o cvss", _error("ip,cve\n1.1.1.1,CVE-2021-0001\n"))

    def test_vacio(self):
        with self.assertRaises(SystemExit):
            vu.vulns_de_filas([], "v.csv")

    def test_tope_de_filas(self):
        with self.assertRaises(SystemExit):
            vu.vulns_de_filas([{"ip": "1.1.1.1"}] * (vu.MAX_FILAS + 1), "v.csv")

    def test_cargar_solo_nombre_de_archivo(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "x.csv")
            with open(p, "w") as f:
                f.write("ip,cve,cvss\n1.1.1.1,nada,5\n")
            with self.assertRaises(SystemExit) as cm:
                vu.cargar(p)
            self.assertIn("'x.csv'", str(cm.exception))
            self.assertNotIn(d, str(cm.exception))


ACTIVOS = {
    "aa:bb:cc:00:00:01": {"mac": "aa:bb:cc:00:00:01", "ips": {"10.0.0.1"}, "alias": set(), "nombre": "PLC-1"},
    "aa:bb:cc:00:00:02": {"mac": "aa:bb:cc:00:00:02", "ips": {"10.0.0.2"}, "alias": {"hmi-norte"}, "nombre": "HMI"},
    "aa:bb:cc:00:00:03": {"mac": "aa:bb:cc:00:00:03", "ips": set(), "nombre": "RTU-3"},   # sin alias
}


def _v(**kw):
    base = {"cve": "CVE-2021-0001", "severidad": "Alta", "cvss": None, "estado": "abierta",
            "activo": "", "ip": "", "mac": "", "producto": "", "version": "", "fuente": ""}
    base.update(kw)
    return base


class TestCruce(unittest.TestCase):
    def test_por_ip(self):
        r = vu.cruzar([_v(ip="10.0.0.2")], ACTIVOS)[0]
        self.assertEqual((r["activo"], r["por"]), ("aa:bb:cc:00:00:02", "ip"))

    def test_por_mac_normalizada(self):
        for mac in ("AA-BB-CC-00-00-01", "AABBCC000001", "Aa:Bb:Cc:00:00:01"):
            r = vu.cruzar([_v(mac=mac)], ACTIVOS)[0]
            self.assertEqual((r["activo"], r["por"]), ("aa:bb:cc:00:00:01", "mac"), mac)

    def test_por_nombre_y_alias(self):
        r = vu.cruzar([_v(activo="plc-1")], ACTIVOS)[0]
        self.assertEqual((r["activo"], r["por"]), ("aa:bb:cc:00:00:01", "nombre"))
        r = vu.cruzar([_v(activo="HMI-NORTE")], ACTIVOS)[0]
        self.assertEqual((r["activo"], r["por"]), ("aa:bb:cc:00:00:02", "nombre"))
        r = vu.cruzar([_v(activo="rtu-3")], ACTIVOS)[0]
        self.assertEqual(r["activo"], "aa:bb:cc:00:00:03")

    def test_sin_coincidencia(self):
        r = vu.cruzar([_v(ip="9.9.9.9", activo="nadie")], ACTIVOS)[0]
        self.assertEqual((r["activo"], r["por"]), (None, ""))

    def test_prioridad_ip_sobre_mac_y_nombre(self):
        r = vu.cruzar([_v(ip="10.0.0.1", mac="aa:bb:cc:00:00:02", activo="HMI")], ACTIVOS)[0]
        self.assertEqual((r["activo"], r["por"]), ("aa:bb:cc:00:00:01", "ip"))
        r = vu.cruzar([_v(ip="9.9.9.9", mac="aa:bb:cc:00:00:02", activo="PLC-1")], ACTIVOS)[0]
        self.assertEqual((r["activo"], r["por"]), ("aa:bb:cc:00:00:02", "mac"))

    def test_lista_de_activos_y_vuln_conservada(self):
        v = _v(ip="10.0.0.1")
        r = vu.cruzar([v], list(ACTIVOS.values()))[0]
        self.assertEqual(r["activo"], "aa:bb:cc:00:00:01")
        self.assertIs(r["vuln"], v)

    def test_extremo_a_extremo(self):
        v = _csv("Asset,IP,CVE,Severity\nx,10.0.0.1,CVE-2022-1111,High\n")
        self.assertEqual(vu.cruzar(v, ACTIVOS)[0]["por"], "ip")


def _cruce(clave, cpes):
    return {"vuln": {"producto": cpes}, "activo": clave, "por": "ip"}


XC208 = "cpe:/h:siemens:scalance_xc208:-, cpe:/o:siemens:scalance_xc208_firmware:04.04.00"
OTROS = ("cpe:/h:siemens:scalance_xc200:-, cpe:/h:siemens:scalance_xc208:-, cpe:/h:siemens:6gk52080ba002ac2:-, "
         "cpe:/o:siemens:scalance_xc208_firmware:04.04.00")


class TestCpeN2(unittest.TestCase):
    def test_lector_formatos(self):
        self.assertEqual(vu.leer_cpes("cpe:/h:siemens:scalance_xc208:-"),
                         [("h", "siemens", "scalance_xc208", "")])
        self.assertEqual(vu.leer_cpes("cpe:/o:siemens:scalance_xc208_firmware:04.04.00"),
                         [("o", "siemens", "scalance_xc208_firmware", "04.04.00")])
        self.assertEqual(vu.leer_cpes("cpe:/o:cisco:ios:15.4%283%29m3"), [("o", "cisco", "ios", "15.4(3)m3")])
        self.assertEqual(vu.leer_cpes("cpe:2.3:h:siemens:scalance_xc208:-:*:*:*:*:*:*:*"),
                         [("h", "siemens", "scalance_xc208", "")])
        self.assertEqual(vu.leer_cpes(r"cpe:2.3:o:acme:r\:x:1.0\(2\):*:*:*:*:*:*:*, "
                                      "cpe:2.3:a:acme:app:*:*:*:*:*:*:*:*"),
                         [("o", "acme", "r:x", "1.0(2)"), ("a", "acme", "app", "")])

    def test_interseccion_da_modelo_y_firmware(self):
        cruces = [_cruce("k", XC208)] * 28 + [_cruce("k", OTROS)] * 2
        inf, amb = vu.inferir_equipos(cruces)
        self.assertEqual(inf, {"k": {"fabricante": "siemens", "modelo": "scalance xc208",
                                     "firmware": "04.04.00"}})
        self.assertEqual(amb, 0)

    def test_mayoria_si_la_interseccion_queda_vacia(self):
        cruces = ([_cruce("k", XC208)] * 14 + [_cruce("k", "cpe:/h:siemens:scalance_xc200:-, "
                                                  "cpe:/o:siemens:scalance_xc200_firmware:04.04.00"),
                                       _cruce("k", "cpe:/h:siemens:6gk52080ba002ac2:-")])
        self.assertEqual(vu.inferir_equipos(cruces), ({"k": {"fabricante": "siemens", "modelo": "scalance xc208",
                                                            "firmware": "04.04.00"}}, 0))
        mitad = [_cruce("k", "cpe:/h:a:uno:-")] * 2 + [_cruce("k", "cpe:/h:a:dos:-")] * 2
        self.assertEqual(vu.inferir_equipos(mitad), ({}, 1))

    def test_solo_so(self):
        inf, amb = vu.inferir_equipos([_cruce("k", "cpe:/o:cisco:ios:15.4(3)m3")] * 2
                                      + [_cruce("k", ""), _cruce("k", "cpe:/a:openbsd:openssh:7.4")])
        self.assertEqual(inf, {"k": {"fabricante": "cisco", "sistema_operativo": "ios 15.4(3)m3"}})
        self.assertEqual(amb, 0)

    def test_ambiguo_y_sin_union(self):
        cruces = [_cruce("k", "cpe:/h:a:uno:-"), _cruce("k", "cpe:/h:a:dos:-"),
                  {"vuln": {"producto": XC208}, "activo": None, "por": ""}]
        self.assertEqual(vu.inferir_equipos(cruces), ({}, 1))
        self.assertIn("1 activos con CPE ambiguo", vu.aviso_cpe_ambiguo(1))


class VersionCvssTest(unittest.TestCase):
    def _v(self, texto, ver):
        return vu.vulns_de_filas(vu.leer_csv(texto.encode()), "v.csv", ver)

    def test_severidad_derivada_de_v4_solo_con_4(self):
        t = "ip,cve,cvss,cvss_v4\n1.1.1.1,CVE-2021-0001,9.8,6.9\n"
        self.assertEqual(self._v(t, "4")[0]["severidad"], "Media")
        self.assertEqual(self._v(t, "3")[0]["severidad"], "Critica")
        self.assertEqual(vu.vulns_de_filas(vu.leer_csv(t.encode()), "v.csv")[0]["severidad"], "Critica")

    def test_severidad_explicita_se_respeta(self):
        t = "ip,cve,severidad,cvss,cvss_v4\n1.1.1.1,CVE-2021-0001,Baja,9.8,9.9\n"
        for ver in ("3", "4"):
            self.assertEqual(self._v(t, ver)[0]["severidad"], "Baja")

    def test_solo_v4_se_acepta_con_4_y_falla_con_3(self):
        t = "ip,cve,cvss_v4\n1.1.1.1,CVE-2021-0001,8.7\n"
        self.assertEqual(self._v(t, "4")[0]["severidad"], "Alta")
        with self.assertRaises(SystemExit):
            self._v(t, "3")
        v = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
        t = f"ip,cve,vector_cvss_v4\n1.1.1.1,CVE-2021-0001,{v}\n"
        self.assertEqual(self._v(t, "4")[0]["severidad"], "Critica")
        with self.assertRaises(SystemExit):
            self._v(t, "3")

    def test_sin_v4_cae_a_v3(self):
        t = "ip,cve,cvss,cvss_v4\n1.1.1.1,CVE-2021-0001,9.8,\n"
        self.assertEqual(self._v(t, "4")[0]["severidad"], "Critica")


if __name__ == "__main__":
    unittest.main()
