"""Pruebas de los diagramas. Solo Python estandar: no requieren tshark ni scapy."""
from __future__ import annotations

import random
import sys
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ot_assess.diagram import Opciones, build_all  # noqa: E402
from ot_assess.diagram.graph import construir_activos, construir_zonas  # noqa: E402
from ot_assess.diagram.mermaid import render_mermaid  # noqa: E402

ZONAS = [("Nivel 2", "HMI / estacion SCADA"), ("Nivel 1", "Controlador / dispositivo de campo (PLC, RTU, IED)"),
         ("Nivel 2-3", "Host Windows (estacion de trabajo o servidor)"),
         ("Infraestructura", "Equipo de red (switch / router)")]


def red_sintetica(n: int, seed: int = 7) -> tuple[dict, list]:
    """n equipos repartidos en zonas, con conductos OT, de gestion y una salida a Internet."""
    rnd = random.Random(seed)
    assets = {}
    for i in range(n):
        zona, rol = ZONAS[i % len(ZONAS)]
        ip = f"10.0.{i // 200}.{i % 200 + 1}"
        mac = f"00:00:00:00:{i // 256:02x}:{i % 256:02x}"
        assets[mac] = {"mac": mac, "ips": {ip}, "nombre": f"EQ-{i:03d}", "vendor": "X", "modelo": "",
                       "firmware": "", "role": rol, "purdue": zona, "pkts": rnd.randint(10, 100000)}
    macs = list(assets)
    conduits = []

    def conducto(a, b, svc, cat, crit, escr):
        return {"src": next(iter(a["ips"])), "dst": next(iter(b["ips"])), "servicio": svc, "categoria": cat,
                "criticidad": crit, "escrituras": escr, "pkts": rnd.randint(5, 5000),
                "bytes": rnd.randint(500, 5_000_000), "multicast": False}

    for _ in range(n * 2):
        a, b = assets[rnd.choice(macs)], assets[rnd.choice(macs)]
        if a is b:
            continue
        if rnd.random() < 0.25:
            conduits.append(conducto(a, b, "Modbus/TCP", "ot", "Critica", rnd.randint(1, 9)))
        elif rnd.random() < 0.5:
            conduits.append(conducto(a, b, "SMB", "it", "Media", 0))
        else:
            conduits.append(conducto(a, b, "HTTP", "claro", "Baja", 0))
    conduits.append({"src": "10.0.0.1", "dst": "8.8.8.8", "servicio": "DNS", "categoria": "it",
                     "criticidad": "Media", "escrituras": 0, "pkts": 4, "bytes": 400, "multicast": False})
    conduits.append({"src": "10.0.0.1", "dst": "224.0.0.251", "servicio": "mDNS", "categoria": "multicast",
                     "criticidad": "Baja", "escrituras": 0, "pkts": 4, "bytes": 400, "multicast": True})
    return assets, conduits


class DiagramaTest(unittest.TestCase):
    def test_svg_valido_y_mermaid(self):
        assets, conduits = red_sintetica(20)
        diagramas = build_all(assets, conduits)
        self.assertEqual([d.slug for d in diagramas], ["diagrama_zonas", "diagrama_red"])
        for d in diagramas:
            raiz = ET.fromstring(d.svg)                 # XML bien formado
            self.assertTrue(raiz.tag.endswith("svg"))
            self.assertTrue(d.mermaid.startswith("flowchart TB"))

    def test_ids_de_marcador_unicos_entre_diagramas(self):
        """Los dos SVG se incrustan en la misma pagina: sus ids no pueden chocar."""
        assets, conduits = red_sintetica(20)
        ids = []
        for d in build_all(assets, conduits):
            ids += [e.get("id") for e in ET.fromstring(d.svg).iter() if e.get("id")]
        self.assertEqual(len(ids), len(set(ids)))

    def test_recorte_reporta_omitidos_y_no_deja_aristas_colgando(self):
        assets, conduits = red_sintetica(120)
        g = construir_activos(assets, conduits, max_nodos=30)
        self.assertEqual(len(g.nodos), 30)
        self.assertGreater(g.omitidos, 0)
        ids = {n.id for n in g.nodos}
        self.assertTrue(all(e.a in ids and e.b in ids for e in g.aristas))

    def test_tope_de_trazos_conserva_los_criticos(self):
        assets, conduits = red_sintetica(40)
        g = construir_activos(assets, conduits, max_nodos=40, max_aristas=15)
        self.assertEqual(len(g.aristas), 15)
        self.assertGreater(g.aristas_recortadas, 0)
        completo = construir_activos(assets, conduits, max_nodos=40, max_aristas=10_000)
        n_criticos = sum(1 for e in completo.aristas if e.crit == "Critica")
        self.assertGreaterEqual(n_criticos, 15)         # el escenario da para llenar el tope
        self.assertTrue(all(e.crit == "Critica" for e in g.aristas))

    def test_recorte_prioriza_a_quien_recibe_escrituras(self):
        """Los dos equipos de menor volumen son los unicos con un conducto con escrituras:
        aun asi deben sobrevivir al recorte."""
        assets, _ = red_sintetica(50)
        macs = sorted(assets, key=lambda m: assets[m]["pkts"])
        bajo, otro = assets[macs[0]], assets[macs[1]]
        trafico = [m for m in macs[2:]]
        conduits = []
        for i in range(len(trafico) - 1):
            a, b = assets[trafico[i]], assets[trafico[i + 1]]
            conduits.append({"src": next(iter(a["ips"])), "dst": next(iter(b["ips"])), "servicio": "HTTP",
                             "categoria": "claro", "criticidad": "Baja", "escrituras": 0, "pkts": 9,
                             "bytes": 900, "multicast": False})
        conduits.append({"src": next(iter(bajo["ips"])), "dst": next(iter(otro["ips"])), "servicio": "Modbus/TCP",
                         "categoria": "ot", "criticidad": "Critica", "escrituras": 3, "pkts": 3,
                         "bytes": 300, "multicast": False})
        g = construir_activos(assets, conduits, max_nodos=10)
        ids = {n.id for n in g.nodos}
        self.assertIn(bajo["mac"], ids)
        self.assertIn(otro["mac"], ids)
        self.assertEqual(next(n for n in g.nodos if n.id == otro["mac"]).escrituras_recibidas, 3)

    def test_multicast_y_broadcast_no_son_nodos(self):
        assets, conduits = red_sintetica(10)
        conduits.append({"src": "10.0.0.1", "dst": "10.0.0.255", "servicio": "x", "categoria": "otro",
                         "criticidad": "Baja", "escrituras": 0, "pkts": 1, "bytes": 1, "multicast": False})
        g = construir_activos(assets, conduits)
        etiquetas = {n.etiqueta for n in g.nodos}
        self.assertNotIn("224.0.0.251", etiquetas)
        self.assertNotIn("10.0.0.255", etiquetas)
        self.assertIn("8.8.8.8", etiquetas)             # la salida a Internet si aparece
        self.assertEqual(next(n for n in g.nodos if n.etiqueta == "8.8.8.8").banda, "Externo")

    def test_zonas_agregan_conductos(self):
        assets, conduits = red_sintetica(40)
        g = construir_zonas(assets, conduits)
        total = sum(e.conductos for e in g.aristas) + sum(g.internos.values())
        base = construir_activos(assets, conduits, max_nodos=10_000, max_aristas=10_000)
        self.assertEqual(total, sum(e.conductos for e in base.aristas))

    def test_sin_conductos_no_hay_diagramas(self):
        self.assertEqual(build_all({}, []), [])

    def test_mermaid_escapa_comillas(self):
        assets, conduits = red_sintetica(6)
        next(iter(assets.values()))["nombre"] = 'PLC "Norte" <A>#1'
        texto = render_mermaid(construir_activos(assets, conduits))
        self.assertNotIn('"Norte"', texto)


if __name__ == "__main__":
    unittest.main()
