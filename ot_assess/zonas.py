"""Z1a (D50): modelo de zonas. Cada activo queda en una zona con el origen de esa asignacion.

Prioridad fija (la primera que aplique): perfil, firewall, plataforma, internet, subred, purdue, sin zona.
El metodo de particion en zonas es el de IEC 62443-3-2 como referencia: la herramienta propone, el
cliente confirma. Las claves del activo son `zona_asignada` y `origen_zona` (`zona` ya es la zona que
trae la plataforma y agrupa los diagramas; no se toca).
"""
from __future__ import annotations

import collections
import ipaddress

from .i18n import t
from .roles import mostrar as mostrar_rol

ORIGENES = ("perfil", "firewall", "plataforma", "subred", "purdue", "internet", "sin zona")
SIN_ZONA = "sin zona"
MAX_REDES = 20
MAX_TIPOS = 5
SIN_PLATAFORMA = ("no zone", "none", "n/a", "unknown")
COLUMNAS = ["zona", "origen", "redes", "sl_t", "inferida", "activos", "niveles_purdue", "tipos_equipo",
            "descripcion"]
TITULO = "Zonas"
NOTA = ("Las zonas declaradas vienen del perfil del proyecto; las demas las infiere la herramienta (firewall, "
        "plataforma, subred o nivel Purdue) y deben confirmarse con el cliente. El metodo de particion en zonas "
        "es el de IEC 62443-3-2, usado como referencia: esto es evidencia tecnica para ese ejercicio, no una "
        "determinacion de cumplimiento.")


def _ip(texto):
    try:
        return ipaddress.ip_address(str(texto).strip())
    except ValueError:
        return None


def _global(a) -> bool:
    return not (a.is_private or a.is_loopback or a.is_link_local or a.is_multicast or a.is_reserved
                or a.is_unspecified)


def avisos_perfil(zonas: list) -> list:
    """Avisos de zonas declaradas cuya red esta dentro de la de otra zona (gana la mas especifica)."""
    redes = [(ipaddress.ip_network(r), z["nombre"]) for z in zonas for r in z["redes"]]
    out = []
    for r, z in redes:
        for r2, z2 in redes:
            if (z != z2 and r.version == r2.version and r != r2 and r.subnet_of(r2)):
                out.append(t("la red {r} de la zona '{z}' esta dentro de {r2} de la zona '{z2}': "
                             "gana la mas especifica ({r})", r=r, z=z, r2=r2, z2=z2))
    return out


def _alias(*nombres) -> list:
    """Nombres con los que --zonas-fw puede citar un firewall (en minusculas, con y sin extension)."""
    out = []
    for n in nombres:
        n = str(n or "").strip().lower()
        for x in (n, n.rsplit(".", 1)[0] if "." in n else n):
            if x and x not in out:
                out.append(x)
    return out


def _tablas_fw(rutas, firewall, zonas_fw=None) -> list:
    """[[(red, zona)]] por firewall, en orden; sin rutas por defecto. Varios firewalls: prefijo.

    `zonas_fw` ({(firewall, interfaz): zona}, de --zonas-fw): la zona dada manda y no lleva prefijo."""
    fuentes = []
    zonas_fw = zonas_fw or {}
    firewalls = (firewall or {}).get("firewalls")
    if firewalls and len(firewalls) > 1:
        for f in firewalls:
            ri = (f.get("datos") or {}).get("rutas_info")
            if ri:
                fuentes.append((f["id"], ri, _alias(f["id"], f.get("hostname"), f.get("archivo"))))
    elif rutas:
        fw = firewall or {}
        fuentes.append(("", rutas, _alias(fw.get("hostname"), fw.get("archivo"), rutas.get("archivo"))))
    out = []
    for pref, ri, alias in fuentes:
        tabla = []
        for i in ri.get("interfaces", ()):
            nombre = i["interfaz"]
            if nombre.endswith(" (ruta por defecto)"):
                continue
            dada = next((zonas_fw[(a, nombre.lower())] for a in alias if (a, nombre.lower()) in zonas_fw), "")
            zona = dada or (i.get("zona") or "").split(";")[0].strip() or nombre
            for r in i["redes"].split(";"):
                try:
                    red = ipaddress.ip_network(r)
                except ValueError:
                    continue
                if red.prefixlen:
                    tabla.append((red, f"{pref}/{zona}" if pref and not dada else zona))
        out.append(tabla)
    return out


def _mas_especifica(ips, tabla):
    mejor = None
    for a in ips:
        for red, z in tabla:
            if a.version == red.version and a in red and (mejor is None or red.prefixlen > mejor[0].prefixlen):
                mejor = (red, z)
    return mejor[1] if mejor else None


def _zona_activo(a: dict, declaradas: list, tablas_fw: list):
    """(zona, origen) del activo. `declaradas`: [(red, nombre)]."""
    ips = [x for x in (_ip(i) for i in sorted(a["ips"])) if x is not None]
    z = _mas_especifica(ips, declaradas)
    if z:
        return z, "perfil"
    for tabla in tablas_fw:
        z = _mas_especifica(ips, tabla)
        if z:
            return z, "firewall"
    plat = str(a.get("zona") or "").strip()
    externo = plat == "Externo" and a.get("purdue") == "Externo"    # lo marca el importador, no la plataforma
    if plat and plat.lower() not in SIN_PLATAFORMA and not externo:
        return plat, "plataforma"
    hosts = [x for x in ips if not (x.is_multicast or x.is_unspecified)]
    if externo or (hosts and all(_global(x) for x in hosts)):
        return "Internet", "internet"
    if a.get("vlans"):
        v = min(a["vlans"], key=lambda x: (not str(x).isdigit(), int(x) if str(x).isdigit() else 0, str(x)))
        return f"VLAN {v}", "subred"
    if hosts:
        red = _red24(str(next((x for x in hosts if x.version == 4), hosts[0])))
        return "Subred " + red, "subred"
    if a.get("purdue"):
        return str(a["purdue"]), "purdue"
    return SIN_ZONA, "sin zona"


def mostrar_zona(zona: str, origen: str) -> str:
    """Nombre de la zona en el idioma del reporte (los nombres de perfil, firewall y plataforma son datos)."""
    if origen == "purdue":
        return mostrar_rol(zona)
    if origen == "sin zona":
        return t(SIN_ZONA)
    if origen == "subred":
        pref, _sep, resto = zona.partition(" ")
        return t("Subred {r}", r=resto) if pref == "Subred" else t("VLAN {n}", n=resto)
    return zona


def asignar(assets: dict, perfil: dict | None = None, rutas: dict | None = None,
            firewall: dict | None = None, zonas_fw: dict | None = None) -> dict:
    """Pone `zona_asignada` y `origen_zona` en cada activo y devuelve {'filas', 'avisos', 'declaradas'}.

    Las filas son dicts con las claves de COLUMNAS (valores sin traducir; filas_tabla() los traduce)."""
    decl = (perfil or {}).get("zonas") or []
    sl_obj = (perfil or {}).get("sl_objetivo") or {}
    declaradas = [(ipaddress.ip_network(r), z["nombre"]) for z in decl for r in z["redes"]]
    tablas_fw = _tablas_fw(rutas, firewall, zonas_fw)
    avisos = avisos_perfil(decl)
    grupos: dict = collections.OrderedDict()
    for a in sorted(assets.values(), key=lambda x: (sorted(x["ips"]), x["mac"])):
        a["zona_asignada"], a["origen_zona"] = _zona_activo(a, declaradas, tablas_fw)
        grupos.setdefault(a["zona_asignada"], []).append(a)
    filas = []
    for z in decl:
        miembros = grupos.pop(z["nombre"], [])
        if not miembros:
            avisos.append(t("la zona declarada '{z}' no tiene ningun activo observado", z=z["nombre"]))
        filas.append(_fila(z["nombre"], "perfil", ";".join(z["redes"]), z.get("sl_t") or sl_obj.get(z["nombre"], ""),
                           "si" if z.get("inferida") else "no", miembros, z.get("descripcion", "")))
    for nombre, miembros in grupos.items():
        origen = min((m["origen_zona"] for m in miembros), key=ORIGENES.index)
        redes = sorted({_red24(i) for m in miembros for i in m["ips"]} - {""})
        if len(redes) > MAX_REDES:
            redes = redes[:MAX_REDES] + [f"+{len(redes) - MAX_REDES}"]
        filas.append(_fila(nombre, origen, ";".join(redes), sl_obj.get(nombre, ""), "si", miembros, ""))
    filas.sort(key=lambda f: (ORIGENES.index(f["origen"]), f["zona"]))
    return {"filas": filas, "avisos": avisos, "declaradas": len(decl), "tablas": (declaradas, tablas_fw)}


def _red24(ip: str) -> str:
    a = _ip(ip)
    if a is None or a.is_multicast or a.is_unspecified:
        return ""
    largo = 24 if a.version == 4 else 64
    return str(ipaddress.ip_network(str(a) + "/" + str(largo), strict=False))


def _fila(zona, origen, redes, sl_t, inferida, miembros, descripcion) -> dict:
    tipos = collections.Counter(m["role"] for m in miembros if m.get("role"))
    top = sorted(tipos.items(), key=lambda x: (-x[1], x[0]))[:MAX_TIPOS]
    niveles = sorted({m["purdue"] for m in miembros if m.get("purdue")})
    return {"zona": zona, "origen": origen, "redes": redes, "sl_t": sl_t, "inferida": inferida,
            "activos": len(miembros), "niveles_purdue": ";".join(mostrar_rol(n) for n in niveles),
            "tipos_equipo": "; ".join(f"{mostrar_rol(r)} ({n})" for r, n in top), "descripcion": descripcion}


def hay(zon: dict) -> bool:
    return bool(zon and zon.get("filas"))


def filas_tabla(zon: dict) -> list:
    return [[mostrar_zona(f["zona"], f["origen"]), t(f["origen"]),
             f["redes"], f["sl_t"], t(f["inferida"]), f["activos"], f["niveles_purdue"], f["tipos_equipo"],
             f["descripcion"]] for f in zon["filas"]]


def resumen_texto(zon: dict) -> str:
    cu = collections.Counter(f["origen"] for f in zon["filas"])
    return t("{n} zonas ({d} declaradas en el perfil); por origen: {o}. Detalle en zonas.csv.",
             n=len(zon["filas"]), d=zon["declaradas"],
             o=", ".join(f"{t(o)} {cu[o]}" for o in ORIGENES if cu[o]))


def tabla_reporte(zon: dict) -> tuple:
    """(cabecera, filas) para HTML, Markdown y Word."""
    return [t(c) for c in COLUMNAS], filas_tabla(zon)


def columnas_activo(a: dict) -> list:
    """[zona_asignada, origen_zona] del activo, traducidos, para el inventario."""
    z, o = a.get("zona_asignada", ""), a.get("origen_zona", "")
    return [mostrar_zona(z, o), t(o) if o else ""]
