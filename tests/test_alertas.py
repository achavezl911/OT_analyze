"""E2a: alertas de IDS/plataformas OT asociadas a conductos y activos."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ot_assess import alertas as al  # noqa: E402


def _csv(texto, sep=","):
    return al.alertas_de_filas(al.leer_csv(texto.replace(",", sep).encode()), "a.csv")


def _error(texto, sep=","):
    with unittest.TestCase().assertRaises(SystemExit) as cm:
        _csv(texto, sep)
    return str(cm.exception)


class TestNormalizacion(unittest.TestCase):
    def test_alias_y_acentos(self):
        a = _csv("Timestamp,Source IP,Destination,Dst Port,Proto,Signature,Severity,Category,Count\n"
                 "2024-01-01 10:00,10.0.0.1,10.0.0.2,502,tcp,Escritura Modbus,High,ICS,4\n")[0]
        self.assertEqual((a["fecha"], a["origen"], a["destino"], a["puerto"], a["protocolo"]),
                         ("2024-01-01 10:00", "10.0.0.1", "10.0.0.2", 502, "tcp"))
        self.assertEqual((a["firma"], a["severidad"], a["categoria"], a["conteo"]),
                         ("Escritura Modbus", "Alta", "ICS", 4))
        b = _csv("Hora,Origen,Regla,Criticidad\n1,1.1.1.1,x,Crítica\n")[0]
        self.assertEqual((b["severidad"], b["conteo"], b["puerto"], b["destino"]), ("Alta", 1, None, ""))

    def test_severidad_texto(self):
        casos = {"critical": "Alta", "critica": "Alta", "High": "Alta", "alta": "Alta", "medium": "Media",
                 "Warning": "Media", "moderate": "Media", "media": "Media", "low": "Baja",
                 "baja": "Baja", "info": "Baja", "informativa": "Baja"}
        for txt, esperado in casos.items():
            a = _csv(f"src,firma,severity\n1.1.1.1,x,{txt}\n")[0]
            self.assertEqual(a["severidad"], esperado, txt)

    def test_severidad_por_prioridad(self):
        for p, esperado in {"1": "Alta", "2": "Media", "3": "Baja", "4": "Baja", "10": "Baja"}.items():
            self.assertEqual(_csv(f"src,firma,priority\n1.1.1.1,x,{p}\n")[0]["severidad"], esperado, p)
        # el texto reconocido manda sobre la prioridad; si no se reconoce, se usa la prioridad
        self.assertEqual(_csv("src,firma,severity,priority\n1.1.1.1,x,low,1\n")[0]["severidad"], "Baja")
        self.assertEqual(_csv("src,firma,severity,priority\n1.1.1.1,x,raro,1\n")[0]["severidad"], "Alta")

    def test_severidad_irreconocible(self):
        e = _error("src,firma,severity\n1.1.1.1,x,alta\n1.1.1.1,y,raro\n")
        self.assertIn("'a.csv': fila 2", e)
        self.assertIn("severidad", e)
        self.assertIn("fila 1", _error("src,firma,priority\n1.1.1.1,x,0\n"))

    def test_conteo(self):
        self.assertEqual(_csv("src,firma,severity,count\n1.1.1.1,x,low,\n")[0]["conteo"], 1)
        for malo in ("0", "-2", "abc", "1.5"):
            self.assertIn("fila 1: conteo invalido", _error(f"src,firma,severity,count\n1.1.1.1,x,low,{malo}\n"))

    def test_puerto(self):
        self.assertEqual(_csv("src,firma,severity,port\n1.1.1.1,x,low,0\n")[0]["puerto"], 0)
        self.assertEqual(_csv("src,firma,severity,port\n1.1.1.1,x,low,65535\n")[0]["puerto"], 65535)
        for malo in ("65536", "-1", "http"):
            self.assertIn("fila 1: puerto invalido", _error(f"src,firma,severity,port\n1.1.1.1,x,low,{malo}\n"))

    def test_columnas_y_celdas_faltantes(self):
        self.assertIn("'firma'", _error("src,severity\n1.1.1.1,low\n"))
        self.assertIn("origen o destino", _error("firma,severity\nx,low\n"))
        self.assertIn("severidad o prioridad", _error("src,firma\n1.1.1.1,x\n"))
        self.assertIn("fila 1: firma vacia", _error("src,firma,severity\n1.1.1.1,,low\n"))
        self.assertIn("fila 1: sin origen ni destino", _error("src,dst,firma,severity\n,,x,low\n"))
        self.assertIn("sin filas", _error("src,firma,severity\n"))

    def test_columna_desconocida_y_solo_destino(self):
        a = _csv("dst,firma,severity,extra\n10.0.0.2,x,low,zzz\n")[0]
        self.assertEqual((a["origen"], a["destino"]), ("", "10.0.0.2"))

    def test_delimitador_punto_y_coma(self):
        a = _csv("fecha,src,dst,port,firma,severidad\n2024,10.0.0.1,10.0.0.2,502,x,media\n", sep=";")[0]
        self.assertEqual((a["origen"], a["puerto"], a["severidad"]), ("10.0.0.1", 502, "Media"))

    def test_tope_de_filas(self):
        filas = [{"src": "1.1.1.1", "firma": "x", "severity": "low"}] * (al.MAX_FILAS + 1)
        with self.assertRaises(SystemExit) as cm:
            al.alertas_de_filas(filas, "a.csv")
        self.assertIn("mas de", str(cm.exception))


CONDUCTOS = [
    {"src": "10.0.0.1", "dst": "10.0.0.2", "l4": "tcp", "port": 502},
    {"src": "10.0.0.1", "dst": "10.0.0.2", "l4": "tcp", "port": "44818"},
    {"src": "10.0.0.3", "dst": "10.0.0.4", "l4": "udp", "port": ""},
]
ASSETS = {
    "aa:aa": {"mac": "aa:aa", "ips": {"10.0.0.1"}, "nombre": "plc1"},
    "bb:bb": {"mac": "bb:bb", "ips": {"10.0.0.2", "10.0.0.22"}, "nombre": "hmi"},
}


def _al(origen, destino, puerto=None, firma="x", sev="Baja", conteo=1):
    return {"fecha": "", "origen": origen, "destino": destino, "puerto": puerto, "protocolo": "",
            "firma": firma, "severidad": sev, "categoria": "", "conteo": conteo}


class TestAsociar(unittest.TestCase):
    def test_par_en_ambos_sentidos_con_puerto(self):
        r = al.asociar([_al("10.0.0.1", "10.0.0.2", 502), _al("10.0.0.2", "10.0.0.1", 502),
                        _al("10.0.0.2", "10.0.0.1", 44818)], CONDUCTOS, ASSETS)
        self.assertEqual([x["conducto"] for x in r], [0, 0, 1])

    def test_puerto_distinto_no_asocia(self):
        r = al.asociar([_al("10.0.0.1", "10.0.0.2", 80)], CONDUCTOS, ASSETS)
        self.assertIsNone(r[0]["conducto"])

    def test_sin_puerto_primer_conducto_del_par(self):
        r = al.asociar([_al("10.0.0.2", "10.0.0.1"), _al("10.0.0.4", "10.0.0.3")], CONDUCTOS, ASSETS)
        self.assertEqual([x["conducto"] for x in r], [0, 2])

    def test_puerto_con_conducto_sin_puerto(self):
        r = al.asociar([_al("10.0.0.3", "10.0.0.4", 123)], CONDUCTOS, ASSETS)
        self.assertIsNone(r[0]["conducto"])

    def test_sin_conducto(self):
        r = al.asociar([_al("10.0.0.1", "9.9.9.9"), _al("10.0.0.1", ""), _al("", "10.0.0.2")],
                       CONDUCTOS, ASSETS)
        self.assertEqual([x["conducto"] for x in r], [None, None, None])

    def test_activos_por_ip(self):
        r = al.asociar([_al("10.0.0.1", "10.0.0.22"), _al("9.9.9.9", "10.0.0.2")], CONDUCTOS, ASSETS)
        self.assertEqual((r[0]["activo_origen"], r[0]["activo_destino"]), ("aa:aa", "bb:bb"))
        self.assertEqual((r[1]["activo_origen"], r[1]["activo_destino"]), (None, "bb:bb"))

    def test_assets_como_lista(self):
        r = al.asociar([_al("10.0.0.1", "10.0.0.2")], CONDUCTOS, list(ASSETS.values()))
        self.assertEqual((r[0]["activo_origen"], r[0]["activo_destino"]), ("aa:aa", "bb:bb"))

    def test_conserva_la_alerta(self):
        a = _al("10.0.0.1", "10.0.0.2")
        self.assertIs(al.asociar([a], CONDUCTOS, ASSETS)[0]["alerta"], a)


class TestResumen(unittest.TestCase):
    def test_resumen_y_orden_de_firmas(self):
        r = al.asociar([_al("10.0.0.1", "10.0.0.2", 502, "b", "Alta", 3),
                        _al("10.0.0.1", "10.0.0.2", 502, "a", "Media", 3),
                        _al("10.0.0.1", "9.9.9.9", None, "c", "Baja", 5),
                        _al("10.0.0.1", "10.0.0.2", 502, "b", "Alta", 1)], CONDUCTOS, ASSETS)
        s = al.resumen(r)
        self.assertEqual(s["total"], 12)
        self.assertEqual(s["por_severidad"], {"Alta": 4, "Media": 3, "Baja": 5})
        self.assertEqual(s["sin_conducto"], 5)
        self.assertEqual(s["firmas"], [("c", 5), ("b", 4), ("a", 3)])

    def test_top_10_y_desempate_alfabetico(self):
        r = al.asociar([_al("1.1.1.1", "2.2.2.2", firma=f"f{i:02d}") for i in range(12)], [], {})
        f = al.resumen(r)["firmas"]
        self.assertEqual(len(f), 10)
        self.assertEqual(f[0], ("f00", 1))

    def test_vacio(self):
        self.assertEqual(al.resumen([]), {"total": 0, "por_severidad": {"Alta": 0, "Media": 0, "Baja": 0},
                                          "sin_conducto": 0, "firmas": []})


if __name__ == "__main__":
    unittest.main()
