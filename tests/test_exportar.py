"""M4: exportacion de la politica propuesta a FortiOS, Check Point y PAN-OS (D58). Archivos de texto; sin red."""
import re
import unittest

from test_fmc import OBJETOS, Base

LARGO = "H_" + "a" * 62            # 64 caracteres: cabe en M3a y FortiOS, no en Check Point ni PAN-OS


def _sin_comentarios(texto):
    return [ln for ln in texto.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]


class Exportar(Base):
    def gen(self, formato, archivo, **kw):
        rc, o, e = self.exportar(extra=["--formato", formato, *kw.pop("extra", [])], **kw)
        self.assertEqual(rc, 0, e)
        return (self.out / archivo).read_text(encoding="utf-8"), o

    def test_fortios_objetos_y_reglas(self):
        t, _ = self.gen("fortios", "fortios_politica.conf")
        for ln in ('edit "H_a"', "set subnet 10.0.0.1 255.255.255.255", 'edit "N_x"', "set subnet 10.0.2.0 255.255.255.0",
                   'set member "H_a" "H_b"', 'edit "S_tcp_443"', "set tcp-portrange 443", "set udp-portrange 53",
                   'set member "S_tcp_443" "S_udp_53"', 'set name "1_in_a_out_S_tcp_443"', 'set srcintf "ZIN"',
                   'set dstintf "ZOUT"', 'set srcaddr "G_1"', 'set dstaddr "N_x"', 'set service "SG_1_x"',
                   "set action accept", 'set schedule "always"', "set logtraffic all", "edit 0"):
            self.assertIn(ln, t)
        self.assertEqual(t.count("edit 0"), 1)
        self.assertNotIn("set status disable", t)
        self.assertEqual(t.count("config firewall address\n"), 1)
        self.assertTrue((self.out / "LEEME_FORTIOS.txt").is_file())

    def test_checkpoint_objetos_y_reglas(self):
        t, _ = self.gen("checkpoint", "checkpoint_mgmt_cli.txt")
        for ln in ("add host name H_a ip-address 10.0.0.1", "add network name N_x subnet 10.0.2.0 mask-length 24",
                   "add group name G_1 members.1 H_a members.2 H_b", "add service-tcp name S_tcp_443 port 443",
                   "add service-udp name S_udp_53 port 53", "add service-group name SG_1_x members.1 S_tcp_443",
                   "add access-rule layer Network position bottom name 1_in_a_out_S_tcp_443 source.1 G_1 "
                   "destination.1 N_x service.1 SG_1_x action Accept track.type Log enabled true"):
            self.assertIn(ln, t)
        self.assertIn("# mgmt_cli -s session.txt publish", t)
        self.assertIn("# mgmt_cli login", t)
        self.assertIn("layer 'Mi capa'", self.gen("checkpoint", "checkpoint_mgmt_cli.txt", extra=["--capa", "Mi capa"])[0])

    def test_panos_objetos_y_reglas(self):
        t, _ = self.gen("panos", "panos_set.txt")
        for ln in ("set address H_a ip-netmask 10.0.0.1/32", "set address N_x ip-netmask 10.0.2.0/24",
                   "set address-group G_1 static [ H_a H_b ]", "set service S_tcp_443 protocol tcp port 443",
                   "set service S_udp_53 protocol udp port 53", "set service-group SG_1_x members [ S_tcp_443 S_udp_53 ]",
                   "set rulebase security rules 1_in_a_out_S_tcp_443 from ZIN to ZOUT source [ G_1 ] "
                   "destination [ N_x ] service [ SG_1_x ] application any action allow log-end yes"):
            self.assertIn(ln, t)
        self.assertIn("# commit", t)
        v, _ = self.gen("panos", "panos_set.txt", extra=["--vsys", "vsys1"])
        self.assertTrue(all(ln.startswith("set vsys vsys1 ") for ln in _sin_comentarios(v)))

    def test_revisar_deshabilitada_bloquear_nunca(self):
        for formato, archivo, marca in (("fortios", "fortios_politica.conf", "set status disable"),
                                        ("checkpoint", "checkpoint_mgmt_cli.txt", "enabled false"),
                                        ("panos", "panos_set.txt", "disabled yes")):
            t, _ = self.gen(formato, archivo)
            self.assertNotIn(marca, t, formato)
            self.assertNotIn("3_in_a_out", t)
            t, _ = self.gen(formato, archivo, extra=["--incluir-revisar"])
            self.assertEqual(t.count(marca), 1, formato)
            self.assertIn("2_in_a_out_S_tcp_443", t)
            self.assertNotIn("3_in_a_out", t)
            self.assertIn("revisar: visto un solo dia; RDP", t)

    def test_servicio_cualquiera_sin_puertos(self):
        objs = OBJETOS + [["S_ip", "servicio", "ip", ""]]
        reglas = [["1", "r1", "permitir", "", "A", "B", "H_a", "H_b", "S_ip", ""]]
        for formato, archivo, esperado in (("fortios", "fortios_politica.conf", 'set service "ALL"'),
                                           ("checkpoint", "checkpoint_mgmt_cli.txt", "service Any"),
                                           ("panos", "panos_set.txt", "service any ")):
            rc, _o, e = self.exportar(reglas=reglas, objetos=objs, extra=["--formato", formato])
            self.assertEqual(rc, 0, e)
            t = (self.out / archivo).read_text()
            self.assertIn(esperado, t)
            self.assertNotIn("S_ip", t)

    def test_nombre_largo_avisa_y_choque_es_error(self):
        objs = OBJETOS + [[LARGO, "host", "10.9.9.9", ""]]
        reglas = [["1", "r1", "permitir", "", "A", "B", LARGO, "N_x", "S_tcp_443", ""]]
        rc, o, _e = self.exportar(reglas=reglas, objetos=objs, extra=["--formato", "fortios"])
        self.assertEqual(rc, 0)
        self.assertNotIn("el nombre pasa de", o)
        for formato, archivo in (("checkpoint", "checkpoint_mgmt_cli.txt"), ("panos", "panos_set.txt")):
            rc, o, _e = self.exportar(reglas=reglas, objetos=objs, extra=["--formato", formato])
            self.assertEqual(rc, 0)
            self.assertIn("[aviso] objeto " + LARGO + ": el nombre pasa de 63", o)
            t = (self.out / archivo).read_text()
            self.assertIn(LARGO[:63], t)
            self.assertNotIn(LARGO + " ", t + " ")
        otro = "H_" + "a" * 61 + "b"
        objs2 = objs + [[otro, "host", "10.9.9.8", ""]]
        reglas2 = [["1", "r1", "permitir", "", "A", "B", LARGO + ";" + otro, "N_x", "S_tcp_443", ""]]
        rc, _o, e = self.exportar(reglas=reglas2, objetos=objs2, extra=["--formato", "panos"])
        self.assertEqual(rc, 2)
        self.assertIn("chocan al recortar", e)

    def test_comillas_y_saltos_escapados(self):
        j = 'dijo "hola" \\ fin; delete all\nset status disable $(id) `x`'
        reglas = [["1", "r1", "permitir", "", "A", "B", "H_a", "H_b", "S_tcp_443", j]]
        t, _ = self.gen("fortios", "fortios_politica.conf", reglas=reglas)
        self.assertIn('set comments "dijo \\"hola\\" \\\\ fin; delete all set status disable $(id) `x`"', t)
        self.assertNotIn("set status disable\n", t)
        t, _ = self.gen("panos", "panos_set.txt", reglas=reglas)
        self.assertIn('description "dijo \\"hola\\" \\\\ fin; delete all set status disable $(id) `x`"', t)
        t, _ = self.gen("checkpoint", "checkpoint_mgmt_cli.txt", reglas=reglas)
        regla = [ln for ln in t.splitlines() if "add access-rule" in ln]
        self.assertEqual(len(regla), 1)
        self.assertIn("'zonas A -> B | dijo \"hola\" \\ fin; delete all set status disable $(id) `x`'", regla[0])

    def test_sin_borrado_ni_confirmacion_sin_comentar(self):
        for formato, archivo in (("fortios", "fortios_politica.conf"), ("checkpoint", "checkpoint_mgmt_cli.txt"),
                                 ("panos", "panos_set.txt")):
            t, _ = self.gen(formato, archivo, extra=["--incluir-revisar"])
            for ln in _sin_comentarios(t):
                self.assertIsNone(re.search(r"(^|\s)(delete|purge|unset|commit|publish|discard)(\s|$)", ln), ln)
            self.assertIn("NOTA:", t)
            self.assertIn("NO probada", t)
            self.assertRegex(t, r"generada el \d{4}-\d{2}-\d{2}")
            leeme = (self.out / ("LEEME_" + formato.upper() + ".txt")).read_text()
            self.assertIn("Objetos creados", leeme)
            self.assertIn("2_in_a_out_S_tcp_443 (deshabilitada)", leeme)

    def test_ipv6_no_se_exporta_a_fortios_ni_checkpoint(self):
        objs = OBJETOS + [["H_v6", "host", "2001:db8::1", ""]]
        reglas = [["1", "r1", "permitir", "", "A", "B", "H_v6", "H_b", "S_tcp_443", ""]]
        for formato in ("fortios", "checkpoint"):
            rc, _o, e = self.exportar(reglas=reglas, objetos=objs, extra=["--formato", formato])
            self.assertEqual(rc, 2)
            self.assertIn("IPv6", e)
        rc, _o, _e = self.exportar(reglas=reglas, objetos=objs, extra=["--formato", "panos"])
        self.assertEqual(rc, 0)
        self.assertIn("ip-netmask 2001:db8::1/128", (self.out / "panos_set.txt").read_text())

    def test_validacion_comun_con_fmc(self):
        reglas = [["1", "r1", "permitir", "", "A", "B", "H_inexistente", "H_b", "S_tcp_443", ""]]
        for formato in ("fortios", "checkpoint", "panos"):
            rc, _o, e = self.exportar(reglas=reglas, extra=["--formato", formato])
            self.assertEqual(rc, 2)
            self.assertIn("H_inexistente", e)
            self.assertFalse(self.out.exists())

    def test_fmc_sigue_siendo_el_formato_por_defecto(self):
        self.assertEqual(self.exportar()[0], 0)
        self.assertTrue((self.out / "fmc_reglas.json").is_file())
        self.assertFalse((self.out / "fortios_politica.conf").exists())


if __name__ == "__main__":
    unittest.main()
