# Pruebas

Qué está probado, cómo se mide y qué **no** está probado. Las brechas están en el registro de
[AUDITORIA.md](AUDITORIA.md) (`PRU-xx`). Cifras medidas el **2026-11-02** con Python 3.13 y `tshark` 4.2.2.

## 1. Estrategia

Biblioteca estándar (`unittest`), sin marcos de prueba. Tres niveles:

| Nivel | Archivos | Necesita | Qué demuestra |
|---|---|---|---|
| Unidad | `tests/test_diagram.py`, `tests/test_standards.py`, parte de `tests/test_importers.py` | Nada | Lógica pura: grafo, recorte, marcos, alias de columnas, valores |
| Integración sin `tshark` | `tests/test_importers.py` (`ImportarTest`, `CliDiagramaTest`) | Nada | Exportaciones sintéticas de punta a punta, incluida la página HTML |
| Extremo a extremo | `tests/test_pipeline.py` (`PipelineTest`, `DeteccionesTest`, `CapturaIlegibleTest`) | `tshark` y `scapy` | Capturas sintéticas → `tshark` real → hallazgos, inventario, diagramas; un escenario por grupo de detecciones; capturas corruptas, truncadas y vacías |
| Unidad con `tshark` falso | `tests/test_pipeline.py` (`TsharkConErrorTest`) | Nada | Un script que simula `tshark` con código de salida 2: ni `fields_pass` ni `phs` lo ignoran |
| Documentación | `tests/test_docs.py` | Nada | Catálogo al día, enlaces y rutas válidos, referencias a decisiones y hallazgos definidas |

Sin `tshark` o `scapy`, el nivel extremo a extremo **se omite** y el resultado sigue siendo "OK"
(PRU-03). Por eso se usa `scripts/verificar.sh`, que lo avisa y, con `CI` definido, falla.

```bash
scripts/verificar.sh              # lint, catálogo y pruebas; salida de pocas líneas
python3 -m unittest tests.test_docs -v   # una sola área, con detalle
```

## 2. Datos de prueba: todos sintéticos

- `tests/gen_pcaps.py` genera, con `scapy`, dos puntos de captura (`punto_a`, `punto_b`) de una planta ficticia: Modbus (lecturas y
  escrituras), S7comm (paro de PLC), IEC 60870-5-104, DNP3 (Direct Operate), CIP (Write Tag), CDP, DHCP,
  texto claro (Telnet, FTP, SNMP), un conflicto ARP, una IP pública y un banner HTTP de firmware viejo.
  `punto_c` (ruido IT, RIP, APIPA, barrido ARP, escaneo, STP; sin control OT) y `punto_d` (2100 tramas GOOSE por
  multicast, snaplen de 96) los escribe `DeteccionesTest`, no `main()`: en la misma carpeta alterarían las
  cuentas de `PipelineTest`.
- `tests/gen_exports.py` genera la misma planta en cuatro estilos de exportación (CSV con ids, CSV por nombre
  con punto y coma y título previo, JSON anidado y XLSX). **Son formatos inventados**: sirven para comprobar
  que el lector tolera encabezados distintos, no que lea lo que exportan Nozomi, Claroty o Dragos (PRU-02).
- Los escenarios no deben contener datos reales ni derivados de datos reales (D9).

Límite de fondo: un generador sintético solo prueba lo que su autor pensó. No sustituye a una captura real de
planta, con sus protocolos propietarios, retransmisiones y rarezas.

## 3. Cobertura medida

Comando: `python3 -m coverage run --branch --source=ot_assess -m unittest discover -s tests`, y luego
`python3 -m coverage report --skip-empty`. `scripts/evidencia.sh` lo guarda en `04_cobertura.txt`.

| Área | Líneas | Ramas |
|---|---|---|
| `ot_assess/diagram/` | 97,9 % | 91,5 % |
| `ot_assess/report/` | 97,8 % | 87,8 % |
| `ot_assess/importers/` | 92,9 % | 87,0 % |
| `ot_assess/rules/` | 91,8 % | **78,3 %** |
| `ot_assess/detail/` | 87,0 % | **70,7 %** |
| Raíz de `ot_assess/` (`cli`, `tools`, `util`, `flows`...) | 89,4 % | 76,0 % |
| **Total** | 93 % | 90 % (líneas y ramas combinadas) |

**La cifra de líneas engaña en `rules/`.** Cada regla ejecuta su preámbulo aunque la condición sea falsa, así
que el módulo parece cubierto sin que la detección se haya disparado nunca. La medida útil es la columna
"Detección probada de extremo a extremo" de [CATALOGO.md](CATALOGO.md): **30 de 30** títulos de hallazgo.

## 4. Brechas conocidas

| ID | Brecha |
|---|---|
| PRU-02 | Sin captura real ni exportación real de ninguna plataforma |
| (sin ID) | No se prueba `find_tool` con rutas distintas, ni Windows ni macOS, ni el muestreo con `--max-packets` bajo, ni capturas comprimidas (`.pcapng.gz`) |

## 5. Cómo agregar pruebas

| Cambio | Prueba que debe acompañarlo |
|---|---|
| Regla de hallazgo nueva | Un escenario en `tests/gen_pcaps.py` que la dispare y su título en `esperados` de `test_hallazgos_esperados` (la prueba exige igualdad exacta: una detección nueva sin afirmar la rompe a propósito) |
| Mapeo de la regla a marcos | Una fila en `MATRIZ` de `ot_assess/standards.py` o su título en `SIN_REFERENCIA` de `tests/test_standards.py` |
| Protocolo de control nuevo | Fila en `PROTOCOLOS` (`ot_assess/detail/control.py`), paquete en `gen_pcaps.py` y conteo en `test_operaciones_de_control_por_protocolo` |
| Alias de columna o tipo de equipo | Caso en `ValoresTest` o `MapeoTest` de `tests/test_importers.py` |
| Vista o cambio de diagrama | Prueba en `tests/test_diagram.py` y, si cambia el dibujo, revisar una imagen renderizada |
| Formato de salida | Prueba de extremo a extremo y comprobar que `scripts/generar_catalogo.py` lista las columnas |
| Corrección de un hallazgo de auditoría | La prueba que **falla sin la corrección** (ver el apartado siguiente) |

**Comprobar que una prueba detecta lo que dice detectar.** Antes de confiar en una prueba nueva, rompe a
propósito el código que protege (una mutación a mano: quitar una condición, invertir un orden) y confirma que
la prueba falla; después restaura. Así se verificaron, por ejemplo, la prioridad de equipos con escrituras en el
recorte de diagramas y la regla que impide que un nombre con espacios genere alias parciales.

## 6. Criterios de aceptación de un cambio

1. `scripts/verificar.sh` termina en OK y **sin pruebas omitidas** (`tshark` y `scapy` instalados).
2. Si cambió una regla, un puerto, una opción o una columna: `python3 scripts/generar_catalogo.py` y commit del
   catálogo.
3. Si la corrección cierra un hallazgo de auditoría: la fila del registro actualizada y la prueba incluida.
4. Si cambió una detección, un mapeo o el formato de una salida: subir la versión (AUDITORIA.md, apartado 6).
5. `docs/ESTADO.md` al día.
