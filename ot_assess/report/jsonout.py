"""Salida JSON completa para alimentar otras herramientas."""
from __future__ import annotations

import collections
import dataclasses
import json
from dataclasses import asdict
from pathlib import Path

from .. import cobertura_captura as _cc
from .. import csf_tiers as _ct
from .. import direccionamiento as _dr
from .. import entregables as _en
from .. import fuentes_log as _fl
from .. import hardening as _hd
from .. import iec62351 as _i62351
from .. import linea_base_aprobada as _lba
from .. import madurez as _ma
from .. import riesgo as _rg
from .. import salud_red as _sr
from .. import sensores as _se
from .. import tobe as _tb
from .. import vuln_firmware as _vf
from ..cobertura import de_corrida
from ..model import Assessment


def _slots(tipo) -> list:
    """Slots declarados en la clase y sus bases (sin __dict__ ni __weakref__), en orden de declaracion."""
    out = []
    for c in reversed(tipo.__mro__):
        s = c.__dict__.get("__slots__", ())
        out.extend(x for x in ((s,) if isinstance(s, str) else s) if not x.startswith("__"))
    return out


def _a_json(o):
    """`default` de json.dumps (J1, D93): objetos y conjuntos por su contenido, nunca por repr con direccion de
    memoria, para que resultado.json traiga los datos y sea igual byte a byte entre corridas."""
    if dataclasses.is_dataclass(o) and not isinstance(o, type):
        return asdict(o)
    slots = _slots(type(o))
    if slots:
        return {s: getattr(o, s) for s in slots if hasattr(o, s)}
    if isinstance(o, (set, frozenset)):
        try:
            return sorted(o)
        except TypeError:
            return sorted(o, key=str)
    return str(o)


def _switches(sw: dict) -> dict:
    """Resumen de los switches (SW1a); los conteos de credenciales no llevan valores ni usuarios."""
    if not sw:
        return {}
    return {"switches": [{"hostname": s.hostname, "modelo": s.modelo, "version": s.version,
                          "vlans": len(s.vlans), "puertos": len(s.puertos), "macs": len(s.mac),
                          "span": [asdict(x) for x in s.span], "credenciales": s.credenciales,
                          "http": s.http, "vty_transport": s.vty_transport}
                         for s in sw["switches"]],
            "ubicados": sw["ubicados"], "con_mac": sw["con_mac"],
            "sin_espejo": [{"switch": h, "vlan": v, "macs": n} for h, v, _nom, n in sw["sin_espejo"]]}


def write_json(res: Assessment, outdir: Path) -> None:
    caps = res.caps
    data = []
    for c in caps:
        data.append({
            "archivo": str(c.path),
            "metadatos": c.info,
            "error": c.error,
            "protocolos": c.protos,
            "paquetes_analizados": c.flow_packets,
            "muestreado": c.sampled,
            "activos": [
                {k: (sorted(v) if isinstance(v, set)
                     else dict(v) if isinstance(v, collections.Counter) else v)
                 for k, v in h.items()
                 if k not in ("ports_served", "ports_used", "proto_seen")}
                | {"puertos_servidos": [f"{p}/{l}" for (p, l) in h["ports_served"]],
                   "protocolos": dict(h["proto_seen"])}
                for h in c.hosts.values()
            ],
            "identidad": c.identity,
            "control": c.control_ops,
            "texto_claro": c.cleartext,
            "hallazgos": c.findings,
        })
    flujos_62351 = _i62351.para_json(res.args)
    ent = _en.para_json(res)       # ENT1 (D126): None sin la clave
    base = _sr.linea_base_json(res.salud_red)
    if base:       # L1 (D81): artefacto para comparar corridas futuras
        (outdir / _sr.A_BASE_JSON).write_text(json.dumps(base, indent=2, ensure_ascii=False, sort_keys=True),
                                              encoding="utf-8")
    (outdir / "resultado.json").write_text(
        json.dumps({"entorno": res.entorno, "perfil": res.perfil,
                    **({"restricciones": {"subcomandos_deshabilitados": res.perfil["subcomandos_deshabilitados"]}}
                       if (res.perfil or {}).get("subcomandos_deshabilitados") else {}),
                    "firewall": res.firewall,
                    "switches": _switches(res.switches),
                    "vulnerabilidades": res.vulnerabilidades,
                    "alertas": res.alertas,
                    "linea_base": res.linea_base,
                    "matriz_controles": res.matriz_controles,
                    "inventario_normalizado": (res.inventario_normalizado or {}).get("resumen", {}),
                    "obsolescencia": (res.obsolescencia or {}).get("resumen", {}),
                    "cobertura_captura": _cc.para_json(res.cobertura_captura),
                    "riesgos": _rg.para_json(_rg.de(res)),
                    **({"iec62351_flujos": flujos_62351} if flujos_62351 else {}),
                    **({"entregables": ent} if ent else {}),
                    "madurez": _ma.para_json(res.madurez),
                    **({"csf_tiers": _ct.para_json(res.csf_tiers)} if _ct.hay(res.csf_tiers) else {}),
                    "tobe": _tb.para_json(res.tobe),
                    "hardening": _hd.para_json(res.hardening),
                    "fuentes_log": _fl.para_json(res.fuentes_log),
                    "vuln_firmware": _vf.para_json(res.vuln_firmware),
                    "direccionamiento": _dr.para_json(res.direccionamiento),
                    "salud_red": _sr.para_json(res.salud_red),
                    **({"sensores": _se.para_json(res.sensores)} if res.sensores else {}),
                    "linea_base_aprobada": _lba.para_json(res.linea_base_aprobada),
                    "cobertura": {e.clave: resum for e, _f, resum in de_corrida(res)},
                    "capturas": data}, indent=2, ensure_ascii=False, default=_a_json), encoding="utf-8"
    )
