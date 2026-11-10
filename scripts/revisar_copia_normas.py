#!/usr/bin/env python3
"""Revisa que ningun JSON de ot_assess/marcos copie texto de las normas (D75, D20).

Para cada cadena de los JSON busca la secuencia mas larga de palabras consecutivas
que tambien aparezca en algun texto de normas/isa62443/txt. Falla (salida 1) si
alguna tiene 8 palabras o mas, sin contar ids (SR 1.3, ZCR 5.2, RE 1, numeros).
Si normas/ no existe (CI, otros equipos) sale 0 con un aviso.

Uso: python3 scripts/revisar_copia_normas.py [--limite 8]
"""
import argparse
import json
import re
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
TEXTOS = RAIZ / "normas" / "isa62443" / "txt"
MARCOS = RAIZ / "ot_assess" / "marcos"
ID = re.compile(r"^(?:\d+(?:\.\d+)*|sr|cr|re|zcr|ndr|sar|edr|hdr|sl|ml|fr|spr|[a-z]|[a-z]{1,3}\d+)$")


def palabras(texto):
    """Palabras en minuscula, sin ids ni numeros (los ids no cuentan como copia)."""
    texto = texto.replace("‑", "-")
    toks = re.findall(r"[a-z0-9]+(?:\.[0-9]+)*", texto.lower())
    return [w for w in toks if not ID.match(w)]


def sin_espacios(texto):
    """Solo letras y digitos en minuscula: detecta copias aunque el PDF parta palabras con espacios."""
    return re.sub(r"[^a-z0-9]", "", texto.replace("\u2011", "-").lower())


def cadenas(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield str(k)
            yield from cadenas(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from cadenas(v)


def indice(limite):
    """{n-grama de `limite` palabras: [(documento, posicion)]} y las listas de palabras."""
    docs, idx = {}, {}
    for p in sorted(TEXTOS.parent.glob("txt*/*.txt")):
        txt = p.read_text(encoding="utf-8")
        # el PDF parte palabras con espacios; se compara tambien la version sin partir
        w = palabras(txt)
        clave = p.parent.name + "/" + p.name   # txt/ y txt_mupdf/ traen los mismos nombres
        docs[clave] = w
        for i in range(len(w) - limite + 1):
            idx.setdefault(tuple(w[i:i + limite]), []).append((clave, i))
    return docs, idx


def mas_larga(w, docs, idx, limite):
    """Longitud de la secuencia mas larga de `w` que esta en algun texto (0 si < limite)."""
    mejor, donde = 0, None
    for i in range(len(w) - limite + 1):
        for nombre, j in idx.get(tuple(w[i:i + limite]), ()):
            d = docs[nombre]
            n = limite
            while i + n < len(w) and j + n < len(d) and w[i + n] == d[j + n]:
                n += 1
            if n > mejor:
                mejor, donde = n, (nombre, " ".join(w[i:i + n]))
    return mejor, donde


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limite", type=int, default=8)
    a = ap.parse_args()
    if not TEXTOS.is_dir():
        print("AVISO: no existe normas/isa62443/txt; no se puede revisar la copia de texto (salida 0).")
        return 0
    docs, idx = indice(a.limite)
    plano = "\n".join(sin_espacios(p.read_text(encoding="utf-8")) for p in sorted(TEXTOS.parent.glob("txt*/*.txt")))
    ancho = 7 * a.limite   # caracteres seguidos sin espacios (unas `limite` palabras)
    peor = 0
    fallos = []
    n_json = n_cad = 0
    for p in sorted(MARCOS.rglob("*.json")):
        n_json += 1
        for s in cadenas(json.loads(p.read_text(encoding="utf-8"))):
            n_cad += 1
            w = palabras(s)
            largo, donde = mas_larga(w, docs, idx, a.limite)
            peor = max(peor, largo)
            if largo >= a.limite:
                fallos.append((p.relative_to(RAIZ), largo, donde))
            elif p.name.startswith("iec62443"):
                c = sin_espacios(s)
                if any(c[i:i + ancho] in plano for i in range(len(c) - ancho + 1)):
                    fallos.append((p.relative_to(RAIZ), a.limite, ("texto sin espacios", s[:80])))
    print("revisados %d JSON, %d cadenas; secuencia copiada mas larga: %d palabras (limite %d)"
          % (n_json, n_cad, peor, a.limite))
    for ruta, largo, donde in fallos:
        print("COPIA %s: %d palabras en %s: %r" % (ruta, largo, donde[0], donde[1]))
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
