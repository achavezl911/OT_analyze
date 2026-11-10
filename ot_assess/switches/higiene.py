"""SW1b: hallazgos de higiene de la configuracion de los switches Cisco IOS/IOS-XE.

Lee solo el modelo de SW1a. La evidencia nombra el switch y los elementos (VLAN, puertos, servicios); de las
credenciales solo da conteos por tipo, nunca valores ni nombres de usuario (D56). Es evidencia pasiva de lo que
muestra la CLI en el momento de la captura, no una evaluacion de cumplimiento.
"""
from __future__ import annotations

from ..i18n import t, unir
from .cisco_ios import clave_if
from .integracion import _enlace

SUFIJO = " (segun la configuracion del switch)"
TIT_SIN_ESPEJO = "VLAN con equipos que el SPAN no espeja" + SUFIJO
TIT_GESTION = "Gestion del switch por protocolos sin cifrar" + SUFIJO
TIT_CRED = "Credenciales del switch con cifrado reversible o sin cifrar" + SUFIJO
TIT_AAA = "Autenticacion local del switch sin AAA centralizado" + SUFIJO
TIT_PUERTOS = "Puertos de acceso habilitados sin uso" + SUFIJO
TIT_VLAN1 = "VLAN 1 en uso o como VLAN nativa" + SUFIJO
TIT_L2 = "Controles de capa 2 ausentes en puertos de acceso" + SUFIJO
TIT_DTP = "Troncales que negocian con DTP" + SUFIJO
TIT_STP = "Inestabilidad de STP o MAC flapping registrada en el switch" + SUFIJO
TIT_BUCLE = "Bucle fisico entre puertos del switch contenido por STP" + SUFIJO
TIT_DESCARTES = "El puerto destino del espejo (SPAN) descarta paquetes" + SUFIJO
TIT_HORA = "Hora del switch sin sincronizar" + SUFIJO
TIT_RAIZ = "Puente raiz de STP sin prioridad fijada" + SUFIJO
TITULOS = (TIT_SIN_ESPEJO, TIT_GESTION, TIT_CRED, TIT_AAA, TIT_PUERTOS, TIT_VLAN1, TIT_L2, TIT_DTP, TIT_STP,
           TIT_BUCLE, TIT_DESCARTES, TIT_HORA, TIT_RAIZ)
MAX_ELEM = 10
PRIORIDAD_FABRICA = 32768      # prioridad de puente por defecto de STP
# Umbrales del estado (SW2, D73). Los contadores son acumulados desde el arranque o el ultimo `clear`.
STP_VENTANA_S = 86400          # un cambio de topologia es reciente si ocurrio en las ultimas 24 h
STP_MIN_RECIENTES = 3          # cambios acumulados de la instancia para que uno reciente cuente
STP_MUCHOS = 20                # cambios acumulados que, aun antiguos, se reportan
BCAST_MIN = 100000             # broadcast recibidos para evaluar la proporcion
BCAST_PCT = 20                 # % de los paquetes de entrada que son broadcast
ERR_MIN = 1000                 # errores de entrada (o CRC) acumulados en un puerto
ERR_UNO_DE = 1000              # y, si se conocen los paquetes, al menos 1 por cada 1000


def _lista(items) -> str:
    items = list(items)
    if len(items) > MAX_ELEM:
        return ", ".join(items[:MAX_ELEM]) + " " + t("y {n} mas", n=len(items) - MAX_ELEM).strip()
    return ", ".join(items)


def _rec(base: str, switches, frase_aoscx: str):
    """Recomendacion; con algun switch AOS-CX en el hallazgo se le agrega la frase con su sintaxis (D99)."""
    if any(sw.origen == "aoscx" for sw in switches):
        return unir(" ", [t(base), t(frase_aoscx)])
    return base


def _gestion_ips(switches) -> list:
    """IP de gestion: la primera SVI con IP de cada switch (si se conoce)."""
    return [sw.svis[0].ip for sw in switches if sw.svis]


def _destinos_span(sw) -> set:
    return {clave_if(s.destino) for s in sw.span if s.destino}


def _gestion_sin_cifrar(sw) -> list:
    out = []
    if "http" in sw.http.split(","):
        out.append(t("servidor HTTP sin cifrar (ip http server)"))
    malos = [x for x in sw.vty_transport if x in ("telnet", "all")]
    if malos:
        out.append(t("vty con transport input {p}", p=" ".join(malos)))
    return out


def _credenciales(sw) -> list:
    c = sw.credenciales
    partes = []
    for clave, rotulo in (("enable_password", "enable password (en lugar de enable secret)"),
                          ("tipo7", "cifrado reversible (tipo 7)"), ("tipo0", "texto sin cifrar (tipo 0)")):
        if c.get(clave):
            partes.append(f"{t(rotulo)}: {c[clave]}")
    return partes


def _puertos_sin_uso(sw) -> list:
    destinos = _destinos_span(sw)
    return [p.nombre for p in sw.puertos
            if p.modo == "access" and not p.apagado and p.estado in ("down", "notconnect")
            and not _enlace(sw, p) and clave_if(p.nombre) not in destinos]


def _vlan1(sw) -> tuple:
    """([puertos de acceso con equipos en VLAN 1], [trunks con nativa 1 explicita o por defecto])."""
    acceso = []
    for vlan, _mac, pto in sw.mac:
        p = sw.puerto(pto)
        if vlan == 1 and p is not None and not _enlace(sw, p) and p.nombre not in acceso:
            acceso.append(p.nombre)
    trunks = [p.nombre for p in sw.puertos
              if p.modo == "trunk" and p.vlan_nativa in (None, 1) and p.canal is None]
    return acceso, trunks


def agregar_hallazgos(cap, res: dict) -> None:
    """Hallazgos de la configuracion de los switches en 'cap' (un Capture de extras)."""
    from ..rules.base import finding

    switches = res["switches"]
    cfg = [sw for sw in switches if sw.config]
    ips = _gestion_ips(switches)
    if res.get("sin_espejo"):
        sin = res["sin_espejo"]
        finding(cap, "Baja", TIT_SIN_ESPEJO,
                t("VLAN: {n}. {lista}", n=len(sin),
                  lista=_lista(t("{h}: VLAN {v} ({nom}), {m} MAC", h=h, v=v, nom=nom or "-", m=m)
                               for h, v, nom, m in sin)),
                "Una VLAN con equipos que ninguna sesion SPAN del switch espeja no llega al sensor por ese "
                "switch: sus comunicaciones no aparecen en el analisis ni en el monitoreo.",
                "Agregar la VLAN a una sesion SPAN (o RSPAN/ERSPAN) hacia el sensor o capturarla con un TAP; "
                "confirmar antes la carga del puerto destino.", "Visibilidad", activos=ips)
    gest = [(sw, _gestion_sin_cifrar(sw)) for sw in cfg]
    gest = [(sw, x) for sw, x in gest if x]
    if gest:
        finding(cap, "Media", TIT_GESTION,
                t("Switches: {n}. {lista}", n=len(gest),
                  lista="; ".join(f"{sw.hostname}: {', '.join(x)}" for sw, x in gest)),
                "La gestion por HTTP o Telnet envia credenciales y comandos en claro: quien observe la red de "
                "gestion puede capturarlos y reutilizarlos.",
                _rec("Dejar solo SSH (transport input ssh) y HTTPS (o desactivar el servidor web) y restringir la "
                     "gestion a la red de gestion con una ACL.", [sw for sw, _x in gest],
                     "En AOS-CX: ssh server vrf y https-server vrf solo en la VRF de gestion."),
                "Higiene", activos=ips)
    cred = [(sw.hostname, _credenciales(sw)) for sw in cfg]
    cred = [(h, x) for h, x in cred if x]
    if cred:
        finding(cap, "Media", TIT_CRED,
                t("Switches: {n}. Solo se cuentan las credenciales; no se reproducen valores ni usuarios. {lista}",
                  n=len(cred), lista="; ".join(f"{h}: {', '.join(x)}" for h, x in cred)),
                "Las contrasenas tipo 7 se revierten con herramientas publicas y las de texto o enable password "
                "se leen de la configuracion: un respaldo o una captura de la configuracion las expone.",
                "Usar enable secret y secretos tipo 8 o 9 para los usuarios locales, rotar las credenciales "
                "expuestas y cuidar donde se guardan los respaldos de configuracion.", "Higiene", activos=ips)
    aaa = [(sw, sw.aaa_modelo, sw.servidores_aaa, sw.credenciales.get("usuario_local", 0))
           for sw in cfg if sw.credenciales.get("usuario_local", 0) and (not sw.aaa_modelo or not sw.servidores_aaa)]
    if aaa:
        finding(cap, "Baja", TIT_AAA,
                t("Switches: {n}. {lista}", n=len(aaa),
                  lista="; ".join(
                      t("{h}: AAA de login {a}, servidores AAA {s}, usuarios locales {u}" if sw.origen == "aoscx"
                        else "{h}: aaa new-model {a}, servidores AAA {s}, usuarios locales {u}", h=sw.hostname,
                        a=t("si") if a else t("no"), s=s, u=u) for sw, a, s, u in aaa)),
                "Con usuarios locales en cada switch no hay una baja central ni registro unificado de quien "
                "administra el equipo: una cuenta de alguien que se va sigue activa hasta que se borra en cada uno.",
                _rec("Centralizar la autenticacion (TACACS+ o RADIUS) y dejar un usuario local solo como acceso de "
                     "emergencia, con secreto fuerte y custodia documentada.", [sw for sw, _a, _s, _u in aaa],
                     "En AOS-CX: aaa authentication login default group tacacs local con tacacs-server host."),
                "Higiene", activos=ips)
    libres = [(sw.hostname, _puertos_sin_uso(sw)) for sw in cfg]
    libres = [(h, x) for h, x in libres if x]
    if libres:
        finding(cap, "Baja", TIT_PUERTOS,
                t("Puertos: {n}. {lista}", n=sum(len(x) for _h, x in libres),
                  lista="; ".join(f"{h}: {_lista(x)}" for h, x in libres)),
                "Un puerto de acceso sin uso y sin shutdown permite conectar un equipo no autorizado a la VLAN "
                "del puerto.",
                "Apagar los puertos que no se usan (shutdown) y moverlos a una VLAN sin uso; confirmar con "
                "operacion que ninguno es un respaldo o un equipo de uso eventual.", "Higiene", activos=ips)
    v1 = [(sw.hostname,) + _vlan1(sw) for sw in cfg]
    v1 = [(h, a, tr) for h, a, tr in v1 if a or tr]
    if v1:
        partes = []
        for h, a, tr in v1:
            p = []
            if a:
                p.append(t("puertos de acceso con equipos en VLAN 1: {l}", l=_lista(a)))
            if tr:
                p.append(t("trunks con VLAN nativa 1: {l}", l=_lista(tr)))
            partes.append(f"{h}: {'; '.join(p)}")
        finding(cap, "Baja", TIT_VLAN1, t("Switches: {n}. {lista}", n=len(v1), lista="; ".join(partes)),
                "La VLAN 1 viaja sin etiqueta por los trunks y lleva trafico de control del switch (CDP, STP, "
                "VTP): usarla para equipos o como nativa facilita el salto entre VLAN y mezcla gestion con datos.",
                "Mover los equipos a una VLAN dedicada, fijar una VLAN nativa sin uso en los trunks y limitar "
                "las VLAN permitidas; hacerlo en ventana, porque un cambio de VLAN corta la comunicacion.",
                "Segmentacion", activos=ips)
    _hallazgos_l2(cap, switches, ips)


# ---------- SW2 (D73): controles de capa 2 y estado de STP ----------
def _acceso(sw) -> list:
    return [p for p in sw.puertos if p.en_config and p.modo == "access" and not p.apagado and p.canal is None]


def _portfast(sw, p) -> bool:
    return p.portfast or (sw.stp_portfast_defecto and not p.portfast_off)


def _bpduguard(sw, p) -> bool:
    return not p.bpduguard_off and (p.bpduguard or (sw.stp_bpduguard_defecto and _portfast(sw, p)))


def _controles_l2(sw) -> list:
    """Partes de evidencia de los controles de capa 2 que faltan en el switch; [] si no falta ninguno."""
    acc = _acceso(sw)
    partes = []
    if sw.origen == "aoscx":      # D99: solo BPDU guard; el resto no esta verificado en AOS-CX
        sin = [p.nombre for p in acc if not _bpduguard(sw, p)]
        if sin:
            partes.append(f"{t('sin BPDU guard')}: {len(sin)}/{len(acc)} ({_lista(sin)})")
            partes.append(t("AOS-CX: storm-control, port-security, DHCP snooping e inspeccion ARP no evaluados"))
        return partes
    if acc:
        faltan = (("sin BPDU guard", [p.nombre for p in acc if not _bpduguard(sw, p)]),
                  ("sin storm-control de broadcast", [p.nombre for p in acc if not p.storm_broadcast]),
                  ("sin port-security", [p.nombre for p in acc if not p.port_security]))
        for rotulo, lista in faltan:
            if lista:
                partes.append(f"{t(rotulo)}: {len(lista)}/{len(acc)} ({_lista(lista)})")
    if not sw.dhcp_snooping:
        partes.append(t("DHCP snooping no habilitado (ip dhcp snooping)"))
    elif not sw.dhcp_snooping_vlans:
        partes.append(t("DHCP snooping sin VLAN (ip dhcp snooping vlan)"))
    if not sw.dai_vlans:
        partes.append(t("inspeccion ARP dinamica sin VLAN (ip arp inspection vlan)"))
    return partes


def _contexto_l2(sw) -> str:
    if sw.origen == "aoscx":      # D99: loopguard y UDLD de AOS-CX no se leen; no se afirma su ausencia
        return t("contexto: modo STP {m}; puertos con root guard (informativo): {r}",
                 m=sw.stp_modo or t("no visto"), r=sum(1 for p in sw.puertos if p.root_guard))
    si, no = t("si"), t("no")
    return t("contexto: modo STP {m}; loopguard por defecto {lg}; UDLD global {u}; puertos con root guard "
             "(informativo): {r}", m=sw.stp_modo or t("no visto"), lg=si if sw.stp_loopguard else no,
             u=si if sw.udld else no, r=sum(1 for p in sw.puertos if p.root_guard))


def _alcance_config(switches) -> str:
    """Que se evaluo de la configuracion y que no (no se supone ausencia de lo que no se vio)."""
    sin = [sw.hostname for sw in switches if not sw.config]
    vacios = [sw.hostname for sw in switches if sw.config and not any(p.en_config for p in sw.puertos)]
    partes = [t("Solo se evaluo lo que muestra la running-config pegada; si la salida esta recortada, la "
                "ausencia de un control puede ser de la salida y no del equipo.")]
    if sin:
        partes.append(t("No evaluado, sin running-config: {l}.", l=", ".join(sin)))
    if vacios:
        partes.append(t("No evaluado, sin interfaces en la running-config: {l}.", l=", ".join(vacios)))
    return " ".join(partes)


def _dtp(sw) -> tuple:
    """([troncales sin nonegotiate], [puertos en modo dinamico], [puertos sin switchport mode])."""
    if sw.origen == "aoscx":      # AOS-CX no negocia troncales: DTP no aplica
        return [], [], []
    vivos = [p for p in sw.puertos if p.en_config and not p.apagado and p.canal is None]
    trunks = [p.nombre for p in vivos if p.modo == "trunk" and not p.nonegotiate]
    dinamicos = [f"{p.nombre} ({p.dtp})" for p in vivos if p.dtp]
    sin_modo = [p.nombre for p in vivos if not p.modo_explicito and not p.dtp and p.modo != "routed"]
    return trunks, dinamicos, sin_modo


def _hace(seg: int) -> str:
    if seg < 3600:
        return f"{seg // 60} min"
    return f"{seg // 3600} h" if seg < 172800 else f"{seg // 86400} d"


def _estabilidad(sw) -> tuple:
    """(urgentes, otros): textos de evidencia. Urgente = cambio de topologia reciente o MAC flapping."""
    urg, otros = [], []
    for c in sw.stp:
        reciente = c.hace_s is not None and c.hace_s <= STP_VENTANA_S and c.cambios >= STP_MIN_RECIENTES
        if not (reciente or c.cambios >= STP_MUCHOS):
            continue
        txt = t("{i}: {n} cambios de topologia", i=c.instancia, n=c.cambios)
        if c.hace_s is not None:
            txt += ", " + t("el ultimo hace {h}", h=_hace(c.hace_s))
        if c.puerto:
            txt += ", " + t("desde {p}", p=c.puerto)
        if c.raiz:
            txt += ", " + t("raiz {r}", r=t("este switch") if c.raiz == "local" else c.raiz)
        (urg if reciente else otros).append(txt)
    if sw.macflap_total:
        urg.append(t("{n} mensajes de MAC flapping en el log", n=sw.macflap_total))
        urg += [t("MAC {m} VLAN {v} entre {p} ({n} mensajes)", m=m or "-", v=v, p=p.replace(" ", " / "), n=n)
                for m, v, p, n in sw.macflap]
    otros += [t("err-disable por {m} en {p} ({n} veces)", m=m, p=p, n=n) for p, m, n in sw.errdisable]
    for c in sw.contadores:
        if c.broadcast and c.paquetes and c.broadcast >= BCAST_MIN and c.broadcast * 100 >= c.paquetes * BCAST_PCT:
            otros.append(t("broadcast alto en {p}: {b} de {n} paquetes de entrada", p=c.puerto, b=c.broadcast,
                           n=c.paquetes))
        err = max(c.errores, c.crc)
        if err >= ERR_MIN and (c.paquetes is None or err * ERR_UNO_DE >= c.paquetes):
            otros.append(t("errores de entrada en {p}: {e} ({c} CRC)", p=c.puerto, e=c.errores, c=c.crc))
    return urg, otros


def _riesgo_acceso(sw, x) -> bool:
    """Puerto de acceso con portfast (en el estado o en la configuracion) y sin BPDU guard."""
    p = sw.puerto(x.nombre)
    if p is not None and p.modo == "trunk":
        return False
    portfast = x.portfast or (p is not None and p.modo == "access" and _portfast(sw, p))
    return portfast and not (p is not None and _bpduguard(sw, p))


def _bucles(sw) -> list:
    """[(texto, alta)] por puerto bloqueado que recibe BPDU del propio switch (puerto backup o designado propio)."""
    out = []
    for c in sw.stp:
        for pt in c.puertos:
            bloqueado = any(x in pt.estado for x in ("blocking", "discarding", "backup"))
            propio = bool(c.puente) and pt.puente_designado == c.puente
            if not ("backup" in pt.estado or (bloqueado and propio)):
                continue
            par = next((x for x in c.puertos if x is not pt and x.numero == pt.puerto_designado), None)
            txt = t("{i}: puerto {p} ({e})", i=c.instancia, p=pt.nombre, e=pt.estado)
            txt += ", " + (t("par {q}", q=par.nombre) if par else t("par no identificado"))
            if pt.bpdu_recibidas is not None:
                txt += ", " + t("BPDU recibidas {n}", n=pt.bpdu_recibidas)
            if c.cambios:
                txt += ", " + t("{n} cambios de topologia en la VLAN", n=c.cambios)
                if c.puerto:
                    txt += " " + t("(el ultimo desde {p})", p=c.puerto)
            out.append((txt, any(_riesgo_acceso(sw, x) for x in (pt, par) if x is not None)))
    return out


def _descartes_espejo(sw) -> list:
    """Textos de evidencia de los puertos destino de un SPAN con descartes de salida."""
    out = []
    for destino in sorted(_destinos_span(sw)):
        c = next((x for x in sw.contadores if clave_if(x.puerto) == destino), None)
        if c is None or c.descartes <= 0:
            continue
        txt = t("{p}: {n} descartes de salida", p=c.puerto, n=c.descartes)
        if c.paquetes_salida:
            txt += " " + t("({pct}% de los {m} paquetes que le tocaba enviar)",
                           pct=f"{c.descartes * 100 / (c.descartes + c.paquetes_salida):.1f}",
                           m=c.descartes + c.paquetes_salida)
        if c.limpieza:
            txt += ", " + t("contadores desde el ultimo clear: {l}", l=c.limpieza)
        out.append(txt)
    return out


def _hora(sw) -> str:
    """Texto de evidencia si la mayoria de las lineas con fecha del log trae hora no autoritativa; si no, ''."""
    n = sw.log_fechadas
    if sw.log_sin_sincronizar * 2 > n:
        txt = t("{a} de {n} lineas del log con fecha empiezan con * (hora no sincronizada)", a=sw.log_sin_sincronizar,
                n=n)
    elif sw.log_sincronia_perdida * 2 > n:
        txt = t("{a} de {n} lineas del log con fecha empiezan con . (hora sincronizada alguna vez pero se perdio)",
                a=sw.log_sincronia_perdida, n=n)
    else:
        return ""
    if not sw.config:
        return txt + "; " + t("sin running-config: no se sabe si hay NTP")
    if sw.ntp_servidores:
        return txt + "; " + t("NTP configurado pero el reloj no esta sincronizado")
    return txt + "; " + t("sin NTP configurado")


def _raices_sin_prioridad(sw) -> list:
    return [c.instancia for c in sw.stp if c.raiz == "local" and c.prioridad == PRIORIDAD_FABRICA]


_SALIDAS = (("stp", "show spanning-tree detail"), ("logging", "show logging"),
            ("interfaces", "show interfaces"))


def _hallazgos_l2(cap, switches, ips) -> None:
    from ..rules.base import finding

    cfg = [sw for sw in switches if sw.config]
    l2 = [(sw, _controles_l2(sw)) for sw in cfg if any(p.en_config for p in sw.puertos)]
    l2 = [(sw, x) for sw, x in l2 if x]
    if l2:
        partes = [f"{sw.hostname}: {'; '.join(x)}; {_contexto_l2(sw)}" for sw, x in l2]
        finding(cap, "Media", TIT_L2,
                t("Switches: {n}. {lista} {alcance}", n=len(l2), lista="; ".join(partes),
                  alcance=_alcance_config(switches)),
                "Sin BPDU guard un equipo o un cable conectado a un puerto de acceso puede enviar BPDU y cambiar "
                "la raiz del arbol o cerrar un bucle; sin storm-control una tormenta de difusion satura el switch "
                "y los equipos de control; sin port-security, DHCP snooping ni inspeccion ARP, un equipo "
                "conectado puede suplantar una MAC, un servidor DHCP o la puerta de enlace.",
                _rec("Habilitar por etapas: BPDU guard (global para los puertos portfast o por puerto), "
                     "storm-control con un umbral basado en el trafico medido, y DHCP snooping e inspeccion ARP en "
                     "las VLAN de equipos. En OT, primero en modo monitor o en un puerto de prueba y luego en "
                     "ventana: BPDU guard apaga el puerto que recibe una BPDU y port-security bloquea el reemplazo "
                     "de un equipo.", [sw for sw, _x in l2],
                     "En AOS-CX: spanning-tree bpdu-guard en los puertos de acceso (spanning-tree port-type "
                     "admin-edge)."),
                "Higiene", activos=ips)
    dt = [(sw, _dtp(sw)) for sw in cfg]
    dt = [(sw, x) for sw, x in dt if x[0] or x[1]]
    if dt:
        partes = []
        for sw, (trunks, dinamicos, sin_modo) in dt:
            p = []
            if trunks:
                p.append(t("troncales sin switchport nonegotiate: {l}", l=_lista(trunks)))
            if dinamicos:
                p.append(t("puertos en modo dinamico: {l}", l=_lista(dinamicos)))
            if sin_modo:
                p.append(t("no se pudo determinar el modo de {n} puertos sin switchport mode (el defecto "
                           "depende de la plataforma): {l}", n=len(sin_modo), l=_lista(sin_modo)))
            partes.append(f"{sw.hostname}: {'; '.join(p)}")
        finding(cap, "Media", TIT_DTP,
                t("Switches: {n}. {lista} {alcance}", n=len(dt), lista="; ".join(partes),
                  alcance=_alcance_config(switches)),
                "Un puerto en trunk sin nonegotiate o en modo dinamico negocia con DTP: un equipo conectado puede "
                "pedir un trunk y recibir las VLAN permitidas (salto de VLAN) o tumbar el enlace.",
                "Fijar switchport mode access en los puertos de equipos y switchport nonegotiate en los troncales, "
                "y limitar las VLAN permitidas; hacerlo en ventana, porque cambiar el modo reinicia la "
                "negociacion del enlace.", "Segmentacion", activos=ips)
    est = []
    for sw in switches:
        urg, otros = _estabilidad(sw)
        if urg or otros:
            est.append((sw, urg, otros))
    if est:
        partes = []
        for sw, urg, otros in est:
            falta = [rot for clave, rot in _SALIDAS if clave not in sw.leyo]
            txt = f"{sw.hostname}: {_lista(urg + otros)}"
            if falta:
                txt += " [" + t("no incluido, no evaluado: {l}", l=", ".join(falta)) + "]"
            partes.append(txt)
        sin = [sw.hostname for sw in switches if not sw.leyo]
        extra = " " + t("Sin salidas de estado, no evaluado: {l}.", l=", ".join(sin)) if sin else ""
        finding(cap, "Alta" if any(u for _s, u, _o in est) else "Media", TIT_STP,
                t("Switches: {n}. {lista}.{extra} Los contadores son acumulados desde el arranque o el ultimo "
                  "clear.", n=len(est), lista="; ".join(partes), extra=extra),
                "Los cambios de topologia repetidos y una MAC que salta entre puertos son sintomas de un bucle, "
                "de un enlace que cae y vuelve o de un equipo con dos conexiones; cada cambio puede vaciar la "
                "tabla MAC y cortar un instante el trafico de control.",
                "Localizar el puerto que origina los cambios (el de la evidencia), revisar el enlace y los equipos "
                "conectados y corregir con operacion en ventana; confirmar BPDU guard y storm-control en los "
                "puertos de acceso.", "Higiene", activos=ips)
    _hallazgos_estado(cap, switches, ips)


def _hallazgos_estado(cap, switches, ips) -> None:
    """T10c (ajusta D73): bucle contenido por STP, perdida en el destino del SPAN, hora y raiz por defecto."""
    from ..rules.base import finding

    bu = [(sw, _bucles(sw)) for sw in switches]
    bu = [(sw, x) for sw, x in bu if x]
    if bu:
        partes = []
        for sw, x in bu:
            txt = f"{sw.hostname}: {_lista(e for e, _a in x)}"
            if not sw.config and any(a for _e, a in x):
                txt += " [" + t("BPDU guard no evaluado, sin running-config") + "]"
            partes.append(txt)
        finding(cap, "Alta" if any(a for _sw, x in bu for _e, a in x) else "Media", TIT_BUCLE,
                t("Switches: {n}. {lista}. Los contadores son acumulados desde el arranque o el ultimo clear.",
                  n=len(bu), lista="; ".join(partes)),
                "Un puerto bloqueado que recibe BPDU del propio switch indica que dos puertos llegan al mismo "
                "segmento (un hub, un switch no administrado o un servidor con las tarjetas en puente): el bucle "
                "fisico existe y solo STP lo contiene; si STP falla o un puerto de acceso con portfast lo reenvia, "
                "la tormenta satura el switch y corta el trafico de control.",
                "Identificar el equipo conectado a los dos puertos (show mac address-table de ambos, CDP/LLDP), "
                "corregir el doble enlace (agregacion LACP o activo/pasivo en el equipo) y activar BPDU guard en "
                "los puertos de acceso; en ventana, porque BPDU guard apagara uno de los dos puertos.",
                "Higiene", activos=ips)
    de = [(sw, _descartes_espejo(sw)) for sw in switches]
    de = [(sw, x) for sw, x in de if x]
    if de:
        finding(cap, "Media", TIT_DESCARTES,
                t("Switches: {n}. {lista}. Los contadores son acumulados desde el arranque o el ultimo clear.",
                  n=len(de), lista="; ".join(f"{sw.hostname}: {', '.join(x)}" for sw, x in de)),
                "Si el puerto destino del SPAN descarta paquetes, la captura que sale de ahi esta incompleta: el "
                "inventario, la matriz de comunicaciones y los hallazgos subestiman el trafico real.",
                "Reducir las fuentes del SPAN (VLAN o puertos que no se analizan), usar un TAP o un puerto de mayor "
                "velocidad hacia el sensor y repetir la captura midiendo los descartes antes y despues.",
                "Visibilidad", activos=ips)
    ho = [(sw, _hora(sw)) for sw in switches if sw.log_fechadas]
    ho = [(sw, x) for sw, x in ho if x]
    if ho:
        finding(cap, "Baja", TIT_HORA,
                t("Switches: {n}. {lista}.", n=len(ho), lista="; ".join(f"{sw.hostname}: {x}" for sw, x in ho)),
                "Con la hora del switch sin sincronizar, sus registros no se pueden correlacionar con los de otros "
                "equipos ni sirven para reconstruir un incidente.",
                "Revisar el alcance al servidor NTP (show ntp status, show ntp associations) y la autenticacion "
                "NTP, y confirmar que el reloj queda sincronizado.", "Higiene", activos=ips)
    ra = [(sw, _raices_sin_prioridad(sw)) for sw in switches]
    ra = [(sw, x) for sw, x in ra if x]
    if ra:
        finding(cap, "Baja", TIT_RAIZ,
                t("Switches: {n}. {lista}.", n=len(ra),
                  lista="; ".join(t("{h}: raiz de {n} VLAN con la prioridad de fabrica ({p}): {l}", h=sw.hostname,
                                    n=len(x), p=PRIORIDAD_FABRICA, l=_lista(x)) for sw, x in ra)),
                "Con la prioridad de fabrica, cualquier switch nuevo con una MAC menor o una prioridad menor toma "
                "la raiz del arbol y cambia los caminos de todo el trafico de la VLAN.",
                _rec("Fijar la prioridad en el switch que debe ser raiz (spanning-tree vlan ... priority o root "
                     "primary) y activar root guard hacia los switches de acceso.", [sw for sw, _x in ra],
                     "En AOS-CX: spanning-tree priority <0-15> (multiplicador de 4096) o spanning-tree vlan N "
                     "priority M."),
                "Higiene", activos=ips)
