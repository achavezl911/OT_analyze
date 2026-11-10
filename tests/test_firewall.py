"""E3a: motor de contraste de reglas de firewall contra conductos."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))

from ot_assess.firewall import cargar, evaluar, reglas_de_filas
from ot_assess.importers.lector import leer_csv

CAB = "origen,destino,puerto,protocolo,accion,id"


def _reglas(*filas, cab=CAB, delim=","):
    texto = "\n".join([cab] + list(filas)).replace(",", delim)
    return reglas_de_filas(leer_csv(texto.encode()), "fw.csv")


def _c(src="10.0.0.1", dst="10.0.0.2", l4="tcp", port=502):
    return {"src": src, "dst": dst, "l4": l4, "port": port}


def _res(reglas, **kw):
    return evaluar(reglas, [_c(**kw)])[0][0]


class TestFirewall(unittest.TestCase):
    def test_aliases_y_acentos(self):
        r = _reglas("10.0.0.1,10.0.0.2,502,tcp,allow,r1",
                    cab="SRC,Destination,DPORT,Proto,Action,Name")
        self.assertEqual(r[0]["id"], "r1")
        r = _reglas("any,any,any,any,permit", cab="Origen,Destino,Puerto,Protocolo,Acción")
        self.assertEqual(r[0]["accion"], "permitir")

    def test_id_por_defecto(self):
        r = _reglas("any,any,any,any,deny", "any,any,any,any,drop")
        self.assertEqual([x["id"] for x in r], ["fila 1", "fila 2"])
        self.assertEqual(r[0]["accion"], "denegar")

    def test_any_en_cada_campo(self):
        for fila in ("any,any,any,any,allow", "*,*,*,*,allow", ",,,,allow", "any,any,any,ip,allow"):
            self.assertEqual(_res(_reglas(fila))["resultado"], "permitido", fila)

    def test_cidr_y_listas(self):
        r = _reglas("10.0.0.0/24 10.1.1.5,10.0.0.0/8 192.168.0.0/16,502 44818,tcp,allow")
        self.assertEqual(_res(r)["resultado"], "permitido")
        self.assertEqual(_res(r, src="10.1.1.5", port=44818)["resultado"], "permitido")
        self.assertEqual(_res(r, src="10.1.1.6")["resultado"], "sin_regla")
        self.assertEqual(_res(r, dst="172.16.0.1")["resultado"], "sin_regla")
        self.assertEqual(_res(r, port=503)["resultado"], "sin_regla")

    def test_rangos_de_puerto(self):
        r = _reglas("any,any,100-200 502,tcp,allow")
        for p, esp in ((100, "permitido"), (200, "permitido"), (150, "permitido"),
                       (502, "permitido"), (99, "sin_regla"), (201, "sin_regla")):
            self.assertEqual(_res(r, port=p)["resultado"], esp, p)

    def test_protocolo(self):
        r = _reglas("any,any,any,udp,allow")
        self.assertEqual(_res(r, l4="udp")["resultado"], "permitido")
        self.assertEqual(_res(r, l4="tcp")["resultado"], "sin_regla")
        self.assertEqual(_res(r, l4="icmp", port=None)["resultado"], "sin_regla")

    def test_puerto_none_solo_con_any(self):
        self.assertEqual(_res(_reglas("any,any,502,any,allow"), l4="icmp", port=None)["resultado"],
                         "sin_regla")
        self.assertEqual(_res(_reglas("any,any,any,any,allow"), l4="icmp", port=None)["resultado"],
                         "permitido")

    def test_primera_coincidencia_gana(self):
        r = _reglas("any,any,502,tcp,allow,a", "any,any,any,any,deny,d")
        self.assertEqual(_res(r), {"resultado": "permitido", "regla": "a"})
        self.assertEqual(_res(r, port=80), {"resultado": "denegado_observado", "regla": "d"})
        r = _reglas("any,any,any,any,deny,d", "any,any,502,tcp,allow,a")
        self.assertEqual(_res(r), {"resultado": "denegado_observado", "regla": "d"})

    def test_sin_regla(self):
        r = _reglas("10.9.9.9,any,any,any,allow,a")
        self.assertEqual(_res(r), {"resultado": "sin_regla", "regla": ""})

    def test_reglas_sin_trafico(self):
        r = _reglas("10.0.0.1,any,502,tcp,allow,usada",
                    "10.5.5.5,any,any,any,allow,huerfana",
                    "any,any,any,any,deny,d",
                    "10.0.0.1,any,502,tcp,allow,sombreada",
                    "10.6.6.6,any,any,any,allow,huerfana2")
        res, sin = evaluar(r, [_c(), _c(src="10.7.7.7")])
        self.assertEqual([x["regla"] for x in res], ["usada", "d"])
        # "sombreada" nunca es primera coincidencia; "d" es denegar y no cuenta
        self.assertEqual(sin, ["huerfana", "sombreada", "huerfana2"])

    def test_ipv6(self):
        r = _reglas("fd00::/8,2001:db8::1,any,tcp,allow")
        self.assertEqual(_res(r, src="fd00::5", dst="2001:db8::1")["resultado"], "permitido")
        self.assertEqual(_res(r, src="fe80::1", dst="2001:db8::1")["resultado"], "sin_regla")
        self.assertEqual(_res(r)["resultado"], "sin_regla")  # IPv4 no casa con redes IPv6

    def test_ip_invalida_del_conducto(self):
        r = _reglas("10.0.0.0/8,any,any,any,allow", "any,any,any,any,deny,d")
        self.assertEqual(_res(r, src="no-es-ip")["regla"], "d")
        self.assertEqual(_res(_reglas("10.0.0.0/8,any,any,any,allow"), src="")["resultado"],
                         "sin_regla")

    def test_delimitador_punto_y_coma(self):
        r = _reglas("10.0.0.0/24 10.1.1.5,any,502 503,tcp,allow", delim=";")
        self.assertEqual(_res(r)["resultado"], "permitido")

    def test_cargar_archivo(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "reglas.csv"
            p.write_bytes((CAB + "\nany,any,any,any,allow\n").encode())
            self.assertEqual(len(cargar(p)), 1)
            p.write_bytes((CAB + "\nany,any,any,any,xx\n").encode())
            with self.assertRaises(SystemExit) as cm:
                cargar(p)
            self.assertIn("'reglas.csv'", str(cm.exception))
            self.assertNotIn(d, str(cm.exception))

    def _error(self, *filas, cab=CAB):
        with self.assertRaises(SystemExit) as cm:
            _reglas(*filas, cab=cab)
        msg = str(cm.exception)
        self.assertTrue(msg.startswith("[!] 'fw.csv'"), msg)
        return msg

    def test_errores(self):
        self.assertIn("falta la columna requerida 'accion'",
                      self._error("any,any,any,any", cab="origen,destino,puerto,protocolo,id"))
        self.assertIn("encabezado desconocido 'color'",
                      self._error("any,any,any,any,allow,rojo", cab="origen,destino,puerto,protocolo,accion,color"))
        self.assertIn("fila 2: accion invalida",
                      self._error("any,any,any,any,allow", "any,any,any,any,quizas"))
        self.assertIn("fila 1: puerto invalido '70000'", self._error("any,any,70000,tcp,allow"))
        self.assertIn("fila 2: puerto invalido", self._error("any,any,1,tcp,allow", "any,any,9-3,tcp,allow"))
        self.assertIn("fila 3: direccion o CIDR invalido '10.0.0.0/33'",
                      self._error("any,any,1,tcp,allow", "any,any,1,tcp,allow",
                                  "10.0.0.0/33,any,1,tcp,allow"))
        self.assertIn("fila 1: protocolo invalido", self._error("any,any,1,icmp,allow"))

    def test_sin_filas(self):
        with self.assertRaises(SystemExit):
            reglas_de_filas([], "fw.csv")


if __name__ == "__main__":
    unittest.main()
