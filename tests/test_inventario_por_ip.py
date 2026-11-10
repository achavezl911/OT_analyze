"""I3 (D105): el inventario presentado (inventario.csv, hoja Inventario, HTML, Markdown, Word y consola) lleva una fila
por IP cuando una MAC de enrutamiento junta muchas IP. Datos sinteticos (IP de documentacion RFC 5737)."""
from __future__ import annotations

import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))

from ot_assess import i18n
from ot_assess import inventario_normalizado as inv
from ot_assess import inventario_presentado as ip
from ot_assess.consolidate import build_conduits, merge_assets
from ot_assess.model import Assessment, Capture
from ot_assess.report import csvout, html, md, word

M_RTR, M_A, M_B = "aa:bb:cc:00:00:fe", "aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02"
IP_RTR = "198.51.100.1"
DETRAS = [f"198.51.100.{n}" for n in range(11, 23)]          # 12 IP detras del enrutador
PLC = DETRAS[2]
CLIENTE = "198.51.100.200"


def _flujo(cap, src, dst, dport, pkts, nbytes, proto="Modbus"):
    cap.flows[(src, dst, str(dport), "tcp")] = {"src": src, "dst": dst, "dport": str(dport), "l4": "tcp",
                                                "pkts": pkts, "bytes": nbytes, "proto": proto, "first": 100.0, "last": 200.0}


def _host(cap, mac, ips, pkts):
    h = cap.host(mac)
    h["ips"] |= set(ips)
    h["tx_pkts"], h["rx_pkts"] = pkts, pkts
    return h


def _cap_enrutada():
    cap = Capture(Path("r.pcap"))
    _host(cap, M_RTR, [IP_RTR, *DETRAS, "169.254.1.1"], 50)
    for n, ip_ in enumerate(DETRAS):
        _flujo(cap, ip_, CLIENTE, 1000 + n, 3, 30)
    _flujo(cap, CLIENTE, PLC, 502, 7, 70)
    cap.arp_events.append({"frame": 1, "t": 1, "opcode": "2", "hw": M_RTR, "sip": IP_RTR, "dip": DETRAS[0], "dup": ""})
    return cap


def _cap_plana():
    cap = Capture(Path("p.pcap"))
    _host(cap, M_A, ["198.51.100.5"], 9)
    _host(cap, M_B, ["198.51.100.6", "198.51.100.7"], 20)
    _flujo(cap, "198.51.100.5", "198.51.100.6", 502, 4, 40)
    return cap


def _res(cap, tmp=None):
    assets, ip_index = merge_assets([cap])
    args = SimpleNamespace(max_rows=500, titulo="t", cliente="", max_packets=0)
    res = Assessment([cap], assets, build_conduits([cap], ip_index), args)
    res.entorno = {"max_packets": 0, "ot_assess": "x", "commit": "", "tshark": "", "estandares": "iec62443",
                   "campos_ignorados": [], "capturas": []}
    return res


def _viejo(res):
    """Lo que daba inventario.csv antes de I3: un renglon por activo, ordenado por (-paquetes, mac)."""
    return [(a["nombre"], ";".join(sorted(a["ips"])), a["mac"], a["pkts"])
            for a in sorted(res.assets.values(), key=lambda x: (-x["pkts"], x["mac"]))]


def _tabla(res):
    for archivo, _hoja, cab, filas in csvout.tablas(res):
        if archivo == "inventario.csv":
            return cab, filas
    raise AssertionError("sin inventario.csv")


class PorIpTest(unittest.TestCase):
    def setUp(self):
        self.res = _res(_cap_enrutada())
        self.cab, self.filas = _tabla(self.res)
        self.col = {c: i for i, c in enumerate(self.cab)}

    def test_una_fila_por_ip_unicast(self):
        ips = sorted(f[self.col["ips"]] for f in self.filas)
        self.assertEqual(ips, sorted([IP_RTR, *DETRAS]))             # sin link-local, sin filas con varias IP
        self.assertEqual(len(self.res.assets), 1)                    # res.assets no cambia

    def test_mac_solo_en_el_router_y_mac_salto_en_las_demas(self):
        por_ip = {f[self.col["ips"]]: f for f in self.filas}
        self.assertEqual(por_ip[IP_RTR][self.col["mac"]], M_RTR)
        self.assertEqual(por_ip[IP_RTR][self.col["mac_salto"]], "")
        for ip_ in DETRAS:
            self.assertEqual(por_ip[ip_][self.col["mac"]], "")
            self.assertEqual(por_ip[ip_][self.col["mac_salto"]], M_RTR)

    def test_la_ip_que_sirve_502_es_controlador_y_los_paquetes_son_los_suyos(self):
        por_ip = {f[self.col["ips"]]: f for f in self.filas}
        f = por_ip[PLC]
        self.assertIn("502/tcp", f[self.col["puertos_servidos"]])
        self.assertTrue(f[self.col["rol_inferido"]].startswith("Controlador"))
        self.assertEqual(f[self.col["paquetes"]], 3 + 7)             # su flujo saliente y el entrante
        self.assertEqual(f[self.col["bytes"]], 30 + 70)
        otro = por_ip[DETRAS[0]]
        self.assertEqual(otro[self.col["paquetes"]], 3)
        self.assertNotIn("502/tcp", otro[self.col["puertos_servidos"]])
        self.assertEqual(otro[self.col["fabricante"]], "")           # el OUI del router no es el de lo que hay detras

    def test_mismo_conjunto_de_ip_que_el_inventario_normalizado(self):
        caps = [c for c in self.res.caps]
        norm = inv.construir(inv.registros_activos(self.res.assets, caps))
        ips_norm = sorted(f["campos"]["ips"]["valor"] for f in norm["filas"])
        self.assertEqual(sorted(f[self.col["ips"]] for f in self.filas), ips_norm)

    def test_orden_por_paquetes_y_desempate_por_ip(self):
        pk = [f[self.col["paquetes"]] for f in self.filas]
        self.assertEqual(pk, sorted(pk, reverse=True))
        iguales = [f[self.col["ips"]] for f in self.filas if f[self.col["paquetes"]] == 3]
        self.assertEqual(iguales, sorted(iguales))

    def test_todas_las_salidas_cuentan_las_mismas_filas(self):
        n = len(self.filas)
        self.assertEqual(ip.contar(self.res), n)
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        texto_html = html.write_html(self.res, tmp).read_text(encoding="utf-8")
        texto_md = md.write_md(self.res, tmp).read_text(encoding="utf-8")
        self.assertIn(f'<div class="kpi"><div class="n">{n}</div><div class="l">Activos</div></div>', texto_html)
        self.assertIn(f"Equipos distintos (por MAC): **{len(self.res.assets)}**", texto_md)
        filas_md = [ln for ln in texto_md.splitlines() if ln.startswith("| ") and ln.split("|")[1].strip().isdigit()
                    and "`" in ln and "198.51.100." in ln]
        self.assertEqual(len(filas_md), n)
        bloques = word.construir_bloques(self.res)
        self.assertIn(["Activos", n], [fila for b in bloques if b[0] == "tabla" for fila in b[2]])

    def test_en_ingles_el_texto_nuevo_sale_traducido(self):
        i18n.usar("en")
        self.addCleanup(i18n.usar, "es")
        self.assertNotIn("MAC de enrutamiento", ip.nota())
        cab, _ = _tabla(self.res)
        self.assertIn("mac_salto", cab)                              # la cabecera se traduce al escribir (cabecera_t)
        self.assertEqual(csvout.cabecera_t(self.res, ["mac_salto"]), ["hop_mac"])


class SinEnrutadorTest(unittest.TestCase):
    def test_sin_mac_de_enrutamiento_queda_igual_que_antes(self):
        res = _res(_cap_plana())
        cab, filas = _tabla(res)
        self.assertNotIn("mac_salto", cab)
        i = {c: k for k, c in enumerate(cab)}
        self.assertEqual([(f[i["equipo"]], f[i["ips"]], f[i["mac"]], f[i["paquetes"]]) for f in filas], _viejo(res))
        self.assertTrue(all(a is b for a, b in zip(ip.filas(res), sorted(
            res.assets.values(), key=lambda x: (-x["pkts"], x["mac"])))))
        self.assertEqual(ip.contar(res), len(res.assets))



class UnaSolaIpTest(unittest.TestCase):
    def test_una_mac_con_una_sola_ip_publica_no_se_parte(self):
        """Redes con direccionamiento publico: la MAC con una sola IP ya es una fila y conserva MAC y fabricante."""
        cap = Capture(Path("u.pcap"))
        _host(cap, M_A, ["93.184.216.34"], 9)
        _host(cap, M_B, ["198.51.100.6"], 4)
        _flujo(cap, "198.51.100.6", "93.184.216.34", 44818, 4, 40, proto="ENIP")
        res = _res(cap)
        self.assertTrue(inv._enrutamiento(["93.184.216.34"]))
        cab, filas = _tabla(res)
        self.assertNotIn("mac_salto", cab)
        i = {c: k for k, c in enumerate(cab)}
        self.assertEqual([(f[i["equipo"]], f[i["ips"]], f[i["mac"]], f[i["paquetes"]]) for f in filas], _viejo(res))
        self.assertEqual(ip.contar(res), len(res.assets))


if __name__ == "__main__":
    unittest.main()
