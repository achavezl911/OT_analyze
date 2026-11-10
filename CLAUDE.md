# OT_analisis · guía para agentes

**Qué es:** sustituto de bajo costo de Nozomi/Claroty/Dragos para proyectos donde el analista no tiene esas
plataformas. Analiza pcaps con tshark y lo que exportan las plataformas, y produce los entregables para cliente
(inventario, matriz de comunicaciones, hallazgos con marcos de referencia, diagramas, Word/Excel, plan de
remediación, política de firewall propuesta y Solicitud de Cambio; español e inglés). Resumen de capacidades para
presentar el proyecto: `docs/CAPACIDADES.md`. Python >= 3.9, sin dependencias en ejecución. Clientes en México, EE. UU. y Chile
(energía incluido BES y ductos, gas, minería, alimentos, construcción, ferrocarril); **cada cliente puede exigir un
marco distinto**. Alcance, límites y arquitectura objetivo: `docs/ALCANCE.md`.

## Arranque de sesión (el usuario puede escribir solo "continúa")
1. Lee `docs/ESTADO.md`: avance, pendientes, preguntas abiertas, hechos ya investigados. Es la única lectura obligatoria (con un brief de `ot-tarea`, no: ver el apartado siguiente).
2. `scripts/setup.sh` una vez y `scripts/verificar.sh`: debe terminar en OK y sin pruebas omitidas.
3. Sesión interactiva sin tarea explícita: toma la primera fila de "Pendiente" que no esté bloqueada, resúmela en tres líneas y
   ejecútala. Pregunta antes solo si exige una decisión del usuario (ver "Decide el usuario").
4. Sin subagentes y sin PR salvo petición expresa. Rama: la que indique la sesión; si no indica ninguna, crea una desde
   `main` actualizado (`git switch -c <tema>`). Fusionar a `main` (avance rápido) lo decide el usuario en esa sesión y
   exige la verificación en verde en GitHub Actions (D21). Las etiquetas `vX.Y.Z` las crea el propietario si el entorno
   no deja subirlas.

## Arquitecto e implementador (D22)
Si la sesión empieza con un brief de `ot-tarea`, **ese brief es la tarea**: no tomes otra fila de "Pendiente", no busques en la web (los hechos vienen en el brief), no leas `docs/ESTADO.md` ni archivos que el brief no cite salvo que un `grep` lo exija. Crea y edita archivos con Edit y Write, no con heredoc ni scripts en Bash (el arnés los deniega). Para ejecutar Python usa `python3 -c`, `python3 tests/...` o `python3 ot_pcap_assess.py`; un script suelto (`python3 /tmp/x.py`) se deniega. Ejecuta `scripts/verificar.sh` en primer plano (tarda unos 3 minutos): sin segundo plano, monitores ni bucles de espera. El contenedor solo tiene Python 3.13 y la CI tambien prueba 3.9: no uses `match`, `X | Y` fuera de anotaciones, `zip(strict=)` ni barras invertidas, comentarios o la misma comilla dentro de `{}` de una f-string. Trabaja en la rama indicada, haz commit y responde en diez líneas como máximo: qué cambió, cómo se verificó, qué queda. No subas a GitHub ni fusiones: eso lo revisa el arquitecto con `ot-revisar` y lo decide el propietario. Funcionamiento del arnés: `docs/ARNES.md` (lo lee el arquitecto, no el implementador).

## Orden de lectura (cada archivo extra cuesta tokens)
- `docs/DECISIONES.md`: solo si vas a tocar un área que aparece allí. No reabras lo decidido sin un dato nuevo.
- `docs/ALCANCE.md`: al proponer o priorizar funciones, o ante la duda de si algo pertenece al proyecto.
- `docs/PROPUESTAS.md`: al priorizar o cuando el usuario pida ideas.
- `README.md`: solo para uso, estructura o "Cómo extender". No leas código fuente completo: ubica con `grep` y lee el tramo.
- **Auditoría:** solo si el usuario la pide o la menciona, lee `docs/AUDITORIA.md` (índice de `ARQUITECTURA.md`,
  `SEGURIDAD.md`, `PRUEBAS.md` y `CATALOGO.md`). En otras tareas no los abras.

## Comandos
- `scripts/verificar.sh`: lint, catálogo y pruebas con salida corta. Ejecútalo antes de cada commit; no uses `unittest` a pelo (imprime todo el log del CLI).
- `python3 scripts/generar_catalogo.py`: obligatorio tras cambiar una regla, un puerto, una opción de CLI o una columna de salida (`docs/CATALOGO.md` es generado; no lo edites).
- `scripts/evidencia.sh`: paquete de evidencia para una auditoría.
- `scripts/setup.sh`: instala tshark y scapy si faltan (sin ellos se omite la prueba de extremo a extremo).
- `python ot_pcap_assess.py -h` · `python ot_pcap_assess.py diagrama -h`

## Dónde tocar
Capturas: `ot_assess/cli.py` · exportaciones de plataformas: `ot_assess/cli_diagrama.py` + `importers/` ·
marcos de referencia: `standards.py` · diagramas: `diagram/` · formatos de salida: `report/`.
Reglas, colectores y marcos nuevos: tabla "Cómo extender" del README.

## Diseño (modular, auditable, escalable)
- Capas: ingesta, modelo, reglas, marcos, salidas. Una regla no conoce marcos ni formatos; un marco es dato, no lógica;
  un formato de salida solo lee el modelo ya calculado.
- Todo cambio = un módulo + su prueba + catálogo regenerado + su fila en `docs/AUDITORIA.md` si toca una garantía.
- Una prueba nueva debe fallar sin el cambio que protege: rompe el código a propósito y compruébalo.
- Sin dependencias nuevas en ejecución. Salida determinista. Nada de un cliente concreto dentro del código.

## Reglas de trabajo
- **Tokens:** una búsqueda web por tema y se registra el resultado en `docs/ESTADO.md` para no repetirla. Historial con `git log --oneline -10`, no releyendo archivos. Edita con cambios mínimos. Renderiza un diagrama a imagen solo si tocaste `diagram/` (una imagen cuesta mucho más que texto). Nunca imprimas reportes ni logs completos.
- **Honestidad:** no afirmes normativa, requisitos de un estándar ni formatos de exportación de un fabricante sin fuente. Lo no validado se rotula como tal en el código, el reporte y `ESTADO.md`. El reporte nunca dice "cumple" ni "no cumple": un análisis pasivo da evidencia técnica relacionada, no cumplimiento.
- **Datos de cliente:** jamás en el repo (capturas, reportes, exportaciones reales). `.gitignore` ya los excluye; los datos de prueba son sintéticos (`tests/gen_*.py`). Las normas con derechos de autor (IEC, ISA) tampoco: van en `normas/` (ignorada por git); se versionan solo los identificadores de requisito y paráfrasis breves.
- **Sin subagentes:** ejecuta todo de forma secuencial en el contexto principal (preferencia del usuario).
- **Estilo:** respuestas secas, directas, sin adornos ni emojis; si el usuario se equivoca, dilo y explica por qué. Texto generado en reportes: ASCII sin acentos; README y `docs/`: con acentos. Commits en español, el cuerpo explica el porqué.
- **Decide el usuario**, no tú: qué marco exige un cliente, qué se fusiona a `main`, qué pendiente va primero, qué propuesta se construye. Pregunta solo eso; lo demás, resuélvelo y anótalo.

## Entrevistar y proponer
Si el usuario pide ideas, o falta un dato para decidir: pregunta con opciones cerradas (`AskUserQuestion` si existe; si no, opciones
numeradas; tres o cuatro preguntas por ronda), apóyate en `docs/PROPUESTAS.md` y registra las respuestas en la misma sesión (ESTADO
o PROPUESTAS). Una propuesta lleva qué, valor para el entregable, esfuerzo y qué necesita del usuario.

## Al terminar una sesión
1. `scripts/verificar.sh` en OK.
2. `docs/ESTADO.md`: mueve lo hecho, actualiza pendientes y preguntas (solo deltas; si pasa de ~100 líneas, poda lo hecho: el historial está en git). Si cerraste o abriste un hallazgo, actualiza su fila en `docs/AUDITORIA.md`. Si el usuario respondió algo, queda escrito: el siguiente chat no puede tener que preguntarlo otra vez.
3. `docs/DECISIONES.md` si hubo una decisión nueva (2 líneas: qué y por qué). Si cambió una detección, un mapeo o un formato de salida, sube `__version__`.
4. Commit con el código, en la rama que indique la sesión. Sin PR salvo petición expresa.
