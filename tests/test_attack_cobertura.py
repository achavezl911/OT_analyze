"""AT2 (D115): tacticas por hallazgo y matriz de cobertura de ATT&CK for ICS."""
import re
import unittest

from ot_assess import attack_cobertura as ac
from ot_assess import attack_ics
from ot_assess.report.csvout import cabecera_hallazgos, fila_hallazgo
from ot_assess.standards import ESTANDARES, MITRE

ID = re.compile(r"T[01]\d{3}(?:\.\d{3})?")


def _h(titulo, mitre, sev="Alta"):
    return {"titulo": titulo, "severidad": sev, "categoria": "c", "evidencia": "e", "por_que_importa": "p",
            "recomendacion": "r", "referencias": {"mitre-ics": mitre}}


class CoberturaAttackTest(unittest.TestCase):
    def test_matriz_con_catalogo_real(self):
        cat = attack_ics.cargar()
        filas = ac.filas([])
        self.assertEqual(len(filas), sum(len(v["tacticas"]) for v in cat["tecnicas"].values()))
        orden = []
        for f in filas:
            if f[1] not in orden:
                orden.append(f[1])
        self.assertEqual(orden, [x["id"] for x in cat["tacticas"]])
        self.assertEqual(len(orden), 12)
        for tac in orden:
            ids = [f[2] for f in filas if f[1] == tac]
            self.assertEqual(ids, sorted(ids))
        citados = {i for txt in MITRE.refs.values() for i in ID.findall(txt)}
        self.assertEqual({f[2] for f in filas if f[5] == "si"}, citados)
        self.assertTrue(all(f[5] == "no" for f in filas if f[2] not in citados))
        sub = [f for f in filas if f[2] == "T1692.001"]
        self.assertEqual(len(sub), 2)
        self.assertEqual({f[4] for f in sub}, {"subtecnica"})
        self.assertEqual(ac.COLUMNAS.index("con_regla"), 5)
        self.assertEqual(len(ac.COLUMNAS), len(filas[0]))

    def test_columna_tacticas(self):
        self.assertEqual(ac.tacticas_de("T0814 Denial of Service; T0826 Loss of Availability"),
                         "Inhibit Response Function; Impact")
        self.assertEqual(ac.tacticas_de(""), "")
        self.assertEqual(ac.tacticas_de("T0814 Denial of Service; T0813 Denial of Control"),
                         "Inhibit Response Function; Impact")
        a = ac.tacticas_de("T0846 Remote System Discovery; T0888 Remote System Information Discovery")
        self.assertEqual(a, "Discovery")
        self.assertEqual(ac.tacticas_de("T0826 Loss of Availability; T0814 Denial of Service"),
                         "Inhibit Response Function; Impact")

    def test_cabecera_y_fila(self):
        est = [ESTANDARES["iec62443"]]
        cab = cabecera_hallazgos(est)
        fila = fila_hallazgo("c.pcap", _h("x", "T0814 Denial of Service; T0826 Loss of Availability"), est)
        self.assertEqual(cab.index("mitre_ics_tacticas"), cab.index("mitre_ics") + 1)
        self.assertEqual(fila[cab.index("mitre_ics_tacticas")], "Inhibit Response Function; Impact")
        self.assertEqual(len(fila), len(cab))
        vacia = fila_hallazgo("c.pcap", _h("y", ""), est)
        self.assertEqual(vacia[cab.index("mitre_ics_tacticas")], "")

    def test_corrida_sintetica(self):
        hall = [_h("Uno", "T0846 Remote System Discovery"),
                _h("Uno", "T0846 Remote System Discovery"),          # mismo titulo y severidad: una vez
                _h("Dos", "T0846 Remote System Discovery; T0814 Denial of Service"),
                _h("Tres", "")]
        filas = {(f[1], f[2]): f for f in ac.filas(hall)}
        d = filas[("discovery", "T0846")]
        self.assertEqual(d[ac.COLUMNAS.index("hallazgos_en_esta_corrida")], 2)
        self.assertEqual(d[ac.COLUMNAS.index("titulos")], "Dos; Uno")
        dos = [f for k, f in filas.items() if k[1] == "T0814"]
        self.assertTrue(dos and all(f[7] == 1 and f[8] == "Dos" for f in dos))
        otra = filas[("discovery", "T0888")]
        self.assertEqual((otra[7], otra[8]), (0, ""))

    def test_misma_severidad_distinta_cuenta_dos(self):
        hall = [_h("Uno", "T0846 Remote System Discovery", "Alta"),
                _h("Uno", "T0846 Remote System Discovery", "Baja")]
        d = next(f for f in ac.filas(hall) if f[2] == "T0846")
        self.assertEqual(d[7], 2)
        self.assertEqual(d[8], "Uno")


if __name__ == "__main__":
    unittest.main()
