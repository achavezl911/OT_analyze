"""Genera ot_assess/marcos/attack_ics.json (catalogo compacto de MITRE ATT&CK for ICS) desde el STIX oficial.

Uso: python3 scripts/actualizar_attack_ics.py STIX.json [--salida RUTA] [--check]

El STIX (mitre-attack/attack-stix-data, ics-attack-<version>.json) no se versiona: se descarga aparte.
Solo se copian ids, nombres, tacticas, revocaciones y la designacion de derechos; ninguna descripcion.
Con --check no escribe: compara y sale 1 si el archivo de salida difiere.
"""
import argparse
import json
import os
import sys

MAX_BYTES = 64 * 1024 * 1024
SALIDA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ot_assess", "marcos", "attack_ics.json")
CADENA_TACTICAS = "mitre-ics-attack"
LICENCIA = ("The MITRE Corporation (MITRE) hereby grants you a non-exclusive, royalty-free license to use "
            "ATT&CK(R) for research, development, and commercial purposes. Any copy you make for such purposes "
            "is authorized provided that you reproduce MITRE's copyright designation and this license in any "
            "such copy.")


def _id_tecnica(obj):
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref["external_id"]
    return ""


def _vigente(obj):
    return not obj.get("revoked") and not obj.get("x_mitre_deprecated")


def construir(bundle, nombre_archivo):
    objs = bundle.get("objects") if isinstance(bundle, dict) else None
    if not isinstance(objs, list):
        raise SystemExit("El archivo no es un bundle STIX de ATT&CK (sin 'objects').")
    colecciones = [o for o in objs if o.get("type") == "x-mitre-collection"]
    matrices = [o for o in objs if o.get("type") == "x-mitre-matrix"]
    tecnicas = [o for o in objs if o.get("type") == "attack-pattern"]
    if not colecciones or not matrices or not tecnicas:
        raise SystemExit("El archivo no es un bundle de ATT&CK for ICS (falta coleccion, matriz o tecnicas).")
    col = colecciones[0]
    version = str(col.get("x_mitre_version", ""))
    if not version:
        raise SystemExit("La coleccion no declara x_mitre_version.")
    por_id = {o.get("id"): o for o in objs}
    tacticas, cortos = [], set()
    for ref in matrices[0].get("tactic_refs", []):
        t = por_id.get(ref)
        if t and t.get("x_mitre_shortname"):
            tacticas.append({"id": t["x_mitre_shortname"], "nombre": t["name"]})
            cortos.add(t["x_mitre_shortname"])
    if not tacticas:
        raise SystemExit("La matriz no trae tacticas.")
    ids = {o["id"]: _id_tecnica(o) for o in tecnicas}

    def nombre(o):
        tid = ids[o["id"]]
        if o.get("x_mitre_is_subtechnique"):
            padre = next((p for p in tecnicas if ids[p["id"]] == tid.split(".")[0]), None)
            if padre is not None:
                return padre["name"] + ": " + o["name"]
        return o["name"]

    vig, rev, obs = {}, {}, {}
    destino = {}
    for o in objs:
        if o.get("type") == "relationship" and o.get("relationship_type") == "revoked-by":
            destino[o.get("source_ref")] = o.get("target_ref")
    for o in tecnicas:
        tid = ids[o["id"]]
        if not tid:
            continue
        if o.get("revoked"):
            por = ids.get(destino.get(o["id"]), "")
            rev[tid] = {"nombre": o["name"], "por": por}
        elif o.get("x_mitre_deprecated"):
            obs[tid] = o["name"]
        else:
            fases = [f["phase_name"] for f in o.get("kill_chain_phases", [])
                     if f.get("kill_chain_name") == CADENA_TACTICAS and f.get("phase_name") in cortos]
            vig[tid] = {"nombre": nombre(o), "tacticas": fases}
    if not vig:
        raise SystemExit("El bundle no trae tecnicas vigentes de ATT&CK for ICS.")
    marcas = [m.get("definition", {}).get("statement", "") for m in objs
              if m.get("type") == "marking-definition" and m.get("definition_type") == "statement"]
    copyright_ = next((m for m in marcas if "MITRE" in m), "")
    return {
        "marco": "MITRE ATT&CK for ICS",
        "version": version,
        "publicada": str(col.get("modified", ""))[:10],
        "fuente": "mitre-attack/attack-stix-data " + nombre_archivo,
        "aviso": (copyright_ + " " + LICENCIA).strip(),
        "tacticas": tacticas,
        "tecnicas": vig,
        "revocadas": rev,
        "obsoletas": obs,
    }


def serializar(cat):
    return json.dumps(cat, ensure_ascii=False, sort_keys=True, indent=1) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("stix")
    ap.add_argument("--salida", default=SALIDA)
    ap.add_argument("--check", action="store_true")
    a = ap.parse_args(argv)
    if os.path.getsize(a.stix) > MAX_BYTES:
        raise SystemExit(f"El archivo supera el limite de {MAX_BYTES // (1024 * 1024)} MB.")
    try:
        with open(a.stix, encoding="utf-8") as f:
            bundle = json.load(f)
    except ValueError as e:
        raise SystemExit(f"El archivo no es JSON valido: {e}")
    texto = serializar(construir(bundle, os.path.basename(a.stix)))
    if a.check:
        try:
            with open(a.salida, encoding="utf-8") as f:
                igual = f.read() == texto
        except OSError:
            igual = False
        if not igual:
            print("attack_ics.json difiere del STIX: regenera con scripts/actualizar_attack_ics.py", file=sys.stderr)
            return 1
        return 0
    with open(a.salida, "w", encoding="utf-8", newline="\n") as f:
        f.write(texto)
    return 0


if __name__ == "__main__":
    sys.exit(main())
