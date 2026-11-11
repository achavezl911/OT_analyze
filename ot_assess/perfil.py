"""Perfil de proyecto (B1a, D24): un JSON por engagement con cliente, sitio, marcos y datos declarados.

La existencia de la clave de cada marco NO se valida aqui: lo hace standards.elegir() en cli.py,
despues de cargar --estandar-archivo (un perfil puede citar un marco propio).
"""
from __future__ import annotations

import ipaddress
import re
from pathlib import Path

from . import json_entrada
from .catalog import CRIT_ORDER
from .i18n import t

TEXTOS = ("sitio", "pais", "sector", "responsable", "clasificacion", "titulo")
NOTA = ("Datos declarados por el analista. La edicion y las partes de cada marco se registran; "
        "el mapeo de hallazgos aun no distingue ediciones ni partes (pendiente B2).")


def cargar(path) -> dict:
    """Lee y normaliza el perfil. Cualquier error termina con SystemExit('[!] ...')."""
    nombre = Path(path).name

    def fallo(msg: str):
        raise SystemExit(f"[!] '{nombre}': {msg}")

    def texto(v, donde: str) -> str:
        if not isinstance(v, str) or not v.strip():
            fallo(f"'{donde}' debe ser un texto no vacio.")
        return v

    def lista_texto(v, donde: str) -> list:
        if not isinstance(v, list):
            fallo(f"'{donde}' debe ser una lista de textos.")
        return [texto(x, donde) for x in v]

    def objeto(v, donde: str, permitidas: tuple) -> dict:
        if not isinstance(v, dict):
            fallo(f"'{donde}' debe ser un objeto.")
        for k in v:
            if k not in permitidas:
                fallo(f"clave desconocida '{k}' en '{donde}'.")
        return v

    try:
        d = json_entrada.cargar(Path(path).read_text(encoding="utf-8-sig"))
    except (OSError, ValueError) as e:
        raise SystemExit(f"[!] No pude leer el perfil '{nombre}': {e}")
    d = objeto(d, "perfil", ("version", "cliente", *TEXTOS, "idioma", "marcos", "regulacion",
                             "captura", "engagement", "sl_objetivo", "ml_objetivo", "linea_base_nist", "cis_ig", "tsa_sd", "criticidad_activos", "dominios_internos", "zonas",
                             "equipos_propios", "vlans_esperadas", "ajustes_riesgo", "madurez_objetivo",
                             "csf_tiers_objetivo", "version_cvss"))
    if d.get("version") != 1 or isinstance(d.get("version"), bool):
        fallo("'version' es requerida y solo se admite 1.")
    out: dict = {"version": 1, "cliente": texto(d["cliente"], "cliente") if "cliente" in d
                 else fallo("falta el campo 'cliente'.")}
    for k in TEXTOS:
        if k in d:
            out[k] = texto(d[k], k)
    idioma = texto(d.get("idioma", "es"), "idioma")
    if idioma not in ("es", "en"):
        fallo("'idioma' debe ser 'es' o 'en'.")
    out["idioma"] = idioma

    marcos = d.get("marcos")
    if not isinstance(marcos, list) or not marcos:
        fallo("'marcos' es requerido y no puede estar vacio.")
    out["marcos"] = []
    for m in marcos:
        m = objeto(m, "marcos", ("clave", "edicion", "partes"))
        if "clave" not in m:
            fallo("cada marco necesita 'clave'.")
        nm = {"clave": texto(m["clave"], "marcos.clave")}
        if "edicion" in m:
            nm["edicion"] = texto(m["edicion"], "marcos.edicion")
        if "partes" in m:
            if nm["clave"] != "iec62443":
                fallo("'partes' solo se admite en el marco 'iec62443'.")
            partes = lista_texto(m["partes"], "marcos.partes")
            for p in partes:
                if not re.fullmatch(r"[1-4]-[0-9]+", p):
                    fallo(f"parte mal formada '{p}' (se espera p. ej. '3-3').")
            nm["partes"] = partes
        out["marcos"].append(nm)

    if "regulacion" in d:
        out["regulacion"] = lista_texto(d["regulacion"], "regulacion")
    if "captura" in d:
        c = objeto(d["captura"], "captura", ("ventana", "punto"))
        out["captura"] = {k: texto(v, f"captura.{k}") for k, v in c.items()}
    if "engagement" in d:
        e = objeto(d["engagement"], "engagement", ("tipo", "exclusiones"))
        ne = {}
        if "tipo" in e:
            ne["tipo"] = texto(e["tipo"], "engagement.tipo")
        if "exclusiones" in e:
            ne["exclusiones"] = lista_texto(e["exclusiones"], "engagement.exclusiones")
        out["engagement"] = ne
    if "sl_objetivo" in d:
        s = d["sl_objetivo"]
        if not isinstance(s, dict):
            fallo("'sl_objetivo' debe ser un objeto zona -> SL.")
        out["sl_objetivo"] = {}
        for zona, sl in s.items():
            if texto(sl, f"sl_objetivo.{zona}") not in ("SL1", "SL2", "SL3", "SL4"):
                fallo(f"sl_objetivo.{zona}: '{sl}' no es SL1 a SL4.")
            out["sl_objetivo"][zona] = sl
    if "ml_objetivo" in d:
        if texto(d["ml_objetivo"], "ml_objetivo") not in ("ML1", "ML2", "ML3", "ML4"):
            fallo(f"'ml_objetivo': '{d['ml_objetivo']}' no es ML1 a ML4.")
        out["ml_objetivo"] = d["ml_objetivo"]
    if "madurez_objetivo" in d:     # M7 (D84): nivel objetivo (0 a 4) por dominio de madurez
        from .madurez import objetivos_validos
        out["madurez_objetivo"] = objetivos_validos(d["madurez_objetivo"], fallo)
    if "csf_tiers_objetivo" in d:   # CSF2T (D110): tier objetivo (1 a 4) por funcion de NIST CSF 2.0
        from .csf_tiers import objetivos_validos as tiers_validos
        out["csf_tiers_objetivo"] = tiers_validos(d["csf_tiers_objetivo"], fallo)
    if "linea_base_nist" in d:
        if texto(d["linea_base_nist"], "linea_base_nist") not in ("baja", "moderada", "alta"):
            fallo(f"'linea_base_nist': '{d['linea_base_nist']}' no es baja, moderada ni alta.")
        out["linea_base_nist"] = d["linea_base_nist"]
    if "cis_ig" in d:
        if texto(d["cis_ig"], "cis_ig") not in ("IG1", "IG2", "IG3"):
            fallo(f"'cis_ig': '{d['cis_ig']}' no es IG1, IG2 ni IG3.")
        out["cis_ig"] = d["cis_ig"]
    if "tsa_sd" in d:       # D109: filas de TSA SD 1580/82 seccion III en la matriz de controles
        from .matriz_controles import EDICIONES_TSA
        if texto(d["tsa_sd"], "tsa_sd") not in EDICIONES_TSA:
            fallo(f"'tsa_sd': '{d['tsa_sd']}' no es una edicion conocida (ediciones: {', '.join(EDICIONES_TSA)}).")
        out["tsa_sd"] = d["tsa_sd"]
    if "version_cvss" in d:     # D114: version de CVSS que decide severidad, orden y umbral
        out["version_cvss"] = version_cvss(d["version_cvss"])
        if out["version_cvss"] is None:
            fallo(f"'version_cvss': {d['version_cvss']!r} no es valido; valores: \"3\" (3.0, 3.1) o \"4\" (4.0).")
    if "zonas" in d:
        out["zonas"] = _zonas(d["zonas"], out.get("sl_objetivo", {}), fallo, texto, objeto)
    if "criticidad_activos" in d:
        c = d["criticidad_activos"]
        if not isinstance(c, dict):
            fallo("'criticidad_activos' debe ser un objeto IPv4 -> nivel.")
        out["criticidad_activos"] = {}
        for ip, nivel in c.items():
            try:
                clave = str(ipaddress.IPv4Address(ip))
            except ValueError:
                fallo(f"criticidad_activos: '{ip}' no es una IPv4 valida.")
            if nivel not in CRIT_ORDER:
                fallo(f"criticidad_activos.{ip}: '{nivel}' no es " + ", ".join(CRIT_ORDER) + ".")
            out["criticidad_activos"][clave] = nivel
    if "equipos_propios" in d:      # I1a (D78): equipos del analista que no son del cliente
        if not isinstance(d["equipos_propios"], list):
            fallo("'equipos_propios' debe ser una lista de objetos {direccion, etiqueta}.")
        out["equipos_propios"] = []
        for e in d["equipos_propios"]:
            e = objeto(e, "equipos_propios", ("direccion", "etiqueta"))
            if "direccion" not in e or "etiqueta" not in e:
                fallo("cada equipo propio necesita 'direccion' (IP, CIDR o MAC) y 'etiqueta'.")
            crudo = texto(e["direccion"], "equipos_propios.direccion").strip().lower().replace("-", ":")
            if re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", crudo):
                direccion = crudo
            else:
                try:
                    direccion = str(ipaddress.ip_network(crudo, strict=True))
                except ValueError:
                    fallo(f"equipos_propios: '{e['direccion']}' no es una IP, un CIDR ni una MAC validos.")
            out["equipos_propios"].append({"direccion": direccion,
                                           "etiqueta": texto(e["etiqueta"], "equipos_propios.etiqueta")})
    if "vlans_esperadas" in d:      # C1 (D80): VLAN que la captura deberia ver
        v = d["vlans_esperadas"]
        if (not isinstance(v, list) or not all(isinstance(x, int) and not isinstance(x, bool)
                                               and 1 <= x <= 4094 for x in v)):
            fallo("'vlans_esperadas' debe ser una lista de numeros de VLAN (1 a 4094).")
        out["vlans_esperadas"] = sorted(set(v))
    if "ajustes_riesgo" in d:       # R1 (D83): el analista corrige probabilidad o impacto de un riesgo
        out["ajustes_riesgo"] = _ajustes_riesgo(d["ajustes_riesgo"], fallo, texto, objeto)
    if "dominios_internos" in d:
        out["dominios_internos"] = []
        for x in lista_texto(d["dominios_internos"], "dominios_internos"):
            dom = x.strip().lower().lstrip(".")
            if not dom:
                fallo("'dominios_internos' tiene un dominio vacio.")
            out["dominios_internos"].append(dom)
    return out


# Dimensiones de impacto del registro de riesgos (R1, D83), en el orden en que desempata la dimension.
DIMENSIONES_IMPACTO = ("seguridad", "ambiente", "produccion", "financiero", "reputacion", "regulatorio")


def _entero_1_5(v, donde: str, fallo) -> int:
    if not isinstance(v, int) or isinstance(v, bool) or not 1 <= v <= 5:
        fallo(f"'{donde}' debe ser un entero de 1 a 5.")
    return v


def _ajustes_riesgo(d, fallo, texto, objeto) -> dict:
    if not isinstance(d, dict):
        fallo("'ajustes_riesgo' debe ser un objeto ID de hallazgo -> ajuste.")
    out = {}
    for hid, aj in d.items():
        if not re.fullmatch(r"H-[0-9a-f]{6}", hid):
            fallo(f"ajustes_riesgo: '{hid}' no es un ID de hallazgo (H- y seis hexadecimales).")
        aj = objeto(aj, f"ajustes_riesgo.{hid}", ("probabilidad", "impacto", "justificacion"))
        if "justificacion" not in aj:
            fallo(f"ajustes_riesgo.{hid}: falta la 'justificacion' (obligatoria).")
        if "probabilidad" not in aj and "impacto" not in aj:
            fallo(f"ajustes_riesgo.{hid}: indique 'probabilidad', 'impacto' o ambos.")
        out[hid] = {"justificacion": texto(aj["justificacion"], f"ajustes_riesgo.{hid}.justificacion")}
        for k in ("probabilidad", "impacto"):
            if k in aj:
                out[hid][k] = _entero_1_5(aj[k], f"ajustes_riesgo.{hid}.{k}", fallo)
    return out


def _zonas(lista, sl_objetivo: dict, fallo, texto, objeto) -> list:
    """Valida la clave `zonas` (Z1a, D50). La misma red en dos zonas es error; una red dentro de otra
    mas grande de otra zona es valida (gana la mas especifica) y la avisa zonas.avisos_perfil()."""
    if not isinstance(lista, list):
        fallo("'zonas' debe ser una lista de objetos.")
    out, vistos, redes = [], set(), {}
    for z in lista:
        z = objeto(z, "zonas", ("nombre", "redes", "descripcion", "sl_t", "inferida", "impacto", "dmz"))
        if "nombre" not in z:
            fallo("cada zona necesita 'nombre'.")
        nombre = texto(z["nombre"], "zonas.nombre").strip()
        if nombre.lower() in vistos:
            fallo(f"zonas: el nombre '{nombre}' esta repetido.")
        vistos.add(nombre.lower())
        crudas = z.get("redes")
        if not isinstance(crudas, list) or not crudas:
            fallo(f"zonas.{nombre}: 'redes' debe ser una lista de CIDR no vacia.")
        nz = {"nombre": nombre, "redes": []}
        for c in crudas:
            try:
                red = ipaddress.ip_network(texto(c, f"zonas.{nombre}.redes"), strict=True)
            except ValueError:
                fallo(f"zonas.{nombre}: '{c}' no es un CIDR valido.")
            otra = redes.get(red)
            if otra is not None and otra != nombre:
                fallo(f"zonas: la red {red} esta en las zonas '{otra}' y '{nombre}'.")
            redes[red] = nombre
            if str(red) not in nz["redes"]:
                nz["redes"].append(str(red))
        if "descripcion" in z:
            nz["descripcion"] = texto(z["descripcion"], f"zonas.{nombre}.descripcion")
        if "sl_t" in z:
            sl = texto(z["sl_t"], f"zonas.{nombre}.sl_t")
            if sl not in ("SL1", "SL2", "SL3", "SL4"):
                fallo(f"zonas.{nombre}: sl_t '{sl}' no es SL1 a SL4.")
            if sl_objetivo.get(nombre, sl) != sl:
                fallo(f"zonas.{nombre}: sl_t {sl} contradice sl_objetivo ({sl_objetivo[nombre]}).")
            nz["sl_t"] = sl
        if "impacto" in z:      # R1 (D83): impacto declarado por dimension
            imp = objeto(z["impacto"], f"zonas.{nombre}.impacto", DIMENSIONES_IMPACTO)
            if not imp:
                fallo(f"zonas.{nombre}: 'impacto' no puede estar vacio.")
            nz["impacto"] = {k: _entero_1_5(v, f"zonas.{nombre}.impacto.{k}", fallo) for k, v in imp.items()}
        if "inferida" in z:
            if not isinstance(z["inferida"], bool):
                fallo(f"zonas.{nombre}: 'inferida' debe ser true o false.")
            nz["inferida"] = z["inferida"]
        if "dmz" in z:      # T1a (D85): la zona es la DMZ industrial del TO-BE
            if not isinstance(z["dmz"], bool):
                fallo(f"zonas.{nombre}: 'dmz' debe ser true o false.")
            nz["dmz"] = z["dmz"]
        out.append(nz)
    return out


def version_cvss(v):
    """'3' o '4' (D114). Acepta 3, 3.0, 3.1, 4, 4.0 y sus textos; bool y lo demas -> None."""
    if not isinstance(v, bool) and isinstance(v, (str, int, float)):
        s = str(v).strip()
        if s in ("3", "3.0", "3.1"):
            return "3"
        if s in ("4", "4.0"):
            return "4"
    return None


def aplicar(ap, args, por_defecto: dict) -> dict:
    """Fija args.titulo/cliente/estandar desde --perfil o desde los valores por defecto.

    Con perfil devuelve el perfil; sin el, devuelve {}. --perfil no se combina con las otras tres.
    """
    from . import i18n
    if not args.perfil:
        i18n.usar(args.idioma or "es")
        for k, v in por_defecto.items():
            if getattr(args, k) is None:       # solo el texto por defecto se traduce, no el del usuario
                setattr(args, k, i18n.t(v) if k in ("titulo", "cliente") else v)
        return {}
    if args.titulo or args.cliente or args.estandar:
        ap.error("--perfil reemplaza a --titulo, --cliente y --estandar: no los combines.")
    p = cargar(args.perfil)
    i18n.usar(args.idioma or p["idioma"])      # --idioma manda sobre el perfil
    args.titulo = p.get("titulo") or i18n.t(por_defecto["titulo"])
    args.cliente = f"{p['cliente']} - {p['sitio']}" if "sitio" in p else p["cliente"]
    args.estandar = ",".join(m["clave"] for m in p["marcos"])
    return p


def etiquetas(p: dict, marcos: dict | None = None) -> list:
    """(etiqueta, valor) en orden fijo para HTML y Markdown. Valores del perfil sin tocar.

    `marcos` ({clave: Estandar}, por defecto standards.ESTANDARES) aporta la version de la
    fuente y la validacion del mapeo a la linea de cada marco conocido."""
    if marcos is None:
        from .standards import ESTANDARES as marcos
    f = [(t("Cliente"), p["cliente"])]
    for k, et in (("sitio", "Sitio"), ("pais", "Pais"), ("sector", "Sector"),
                  ("responsable", "Responsable"), ("clasificacion", "Clasificacion")):
        if k in p:
            f.append((t(et), p[k]))
    for m in p["marcos"]:
        v = t("edicion {e}", e=m.get("edicion") or t("no declarada"))
        if m.get("partes"):
            v += t("; partes {p}", p=", ".join(m["partes"]))
        if m["clave"] in marcos:
            from .standards import etiqueta_mapeo
            v += "; " + etiqueta_mapeo(marcos[m["clave"]])
        f.append((t("Marco {clave}", clave=m["clave"]), v))
    if p.get("regulacion"):
        f.append((t("Regulacion declarada"), "; ".join(p["regulacion"])))
    c = p.get("captura", {})
    if "ventana" in c:
        f.append((t("Ventana de captura"), c["ventana"]))
    if "punto" in c:
        f.append((t("Punto de captura"), c["punto"]))
    e = p.get("engagement", {})
    if "tipo" in e:
        f.append((t("Tipo de engagement"), e["tipo"]))
    if e.get("exclusiones"):
        f.append((t("Exclusiones"), "; ".join(e["exclusiones"])))
    if p.get("sl_objetivo"):
        f.append((t("SL objetivo"), "; ".join(f"{z}: {s}" for z, s in p["sl_objetivo"].items())))
    return f
