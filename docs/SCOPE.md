# Alcance del proyecto — `SCOPE.md`

**Carácter:** documento normativo.
Si algún otro archivo del repositorio entra en contradicción con este documento, prevalece `SCOPE.md`.

---

## 1. Propósito

`sudo-lab` es un laboratorio **educativo y defensivo** que diagnostica, mitiga y —opcionalmente— mide la explotación de vulnerabilidades de escalada de privilegios local en `sudo`, sobre un contenedor reproducible con una versión real y vulnerable del binario. Es el anexo práctico del trabajo de investigación *“Bugs en sudo: escalada de privilegios local, diagnóstico en laboratorio y mitigación”* (Redes de Datos / Software Seguro, Licenciatura en Sistemas de Información, UNNE – FaCENA).

El laboratorio fundamenta el informe con **evidencia reproducible**: demuestra que el sistema cumple las precondiciones de explotación de cada CVE y prueba que las mitigaciones las cierran.

---

## 2. Alcance (lo que el proyecto hace)

1. **Target reproducible.** Contenedor Debian 12 con `sudo 1.9.15` compilado desde el tarball oficial del proyecto sudo (versión parametrizable vía `SUDO_VERSION`).
2. **Diagnóstico de exposición** (`scan.sh`). Por cada CVE, combina la versión del binario contra los rangos vulnerables conocidos con las precondiciones reales del sistema (reglas de `sudoers`, `/tmp` ejecutable, disponibilidad de la opción `chroot`) y emite un estado en formato TSV que consume el dashboard. No explota nada: es el equivalente a una verificación de *blue team*.
3. **Mitigación sin parchear** (`mitigate.sh`). Controles compensatorios para el escenario *legacy* del informe: hardening de `sudoers` y remontaje de `/tmp` como `noexec,nosuid,nodev`. Incluye verificación con re-scan y restauración (`--reset`).
4. **Escenario de la clínica con foothold simulado.** La cadena `red → acceso inicial → usuario raso → sudo → root` se representa con el usuario `webuser`; el vector web se narra, no se implementa (ver §6).
5. **Benchmark opcional con PoC externo (Opción B).** Si el operador provee los scripts `poc_32463.sh` y `poc_32462.sh` en `LAB_POC_DIR`, el laboratorio mide **tasa de éxito** y **tiempo de escalada** antes y después de mitigar. Sin PoC, el benchmark reporta `POC_NO_DISPONIBLE` y el proyecto sigue siendo funcional y completo (modo diagnóstico + mitigación).
6. **Dashboard.** Panel local (solo `localhost`) que orquesta los scripts mediante `docker exec` y muestra hallazgos, registros en vivo y métricas.
7. **Documentación académica.** Modelo de amenaza, contrato de métricas, metodología, resultados, limitaciones y reproducibilidad.

---

## 3. No-alcance (lo que el proyecto no hace)

- **No distribuye exploits.** El repositorio no contiene payloads ni PoCs, ni originales ni adaptados. La explotación se documenta a nivel conceptual y se ejecuta únicamente si el operador provee un PoC externo. Regla del equipo: *“el PoC circula entre nosotros, no entre nosotros y el mundo”* (política completa en `SECURITY.md`; obtención y adaptación en `docs/POC.md`).
- **No implementa el vector web.** No existe un servicio Apache vulnerable, ni `webshell`, ni contenedor web (`Dockerfile.web`): el acceso inicial se *simula* (§6).
- **No ejecuta PoCs contra las CVEs históricas.** El target (`sudo 1.9.15`) no es vulnerable a ninguna de las tres (§5); ejecutarlas no tendría sentido técnico y su diagnóstico queda cubierto por `scan.sh`.
- **No es una herramienta de producción.** Los estados que emite son veredictos de laboratorio para el entorno controlado, no un escáner de seguridad general del sistema anfitrión.
- **No sustituye el parcheo.** La mitigación *completa* de las CVEs de 2025 es actualizar a `sudo 1.9.17p1` o posterior; los controles aplicados son compensatorios, pensados para un sistema *legacy* que no puede actualizarse sin romper el servicio.
- **No exige multi-arquitectura.** Las plataformas objetivo son Linux x86_64 y macOS Apple Silicon (Windows con Docker Desktop como cortesía, sin garantías; equivalencias de comandos en `docs/REPRODUCIBILITY.md` §3.1).

---

## 4. CVEs foco

Objeto central del paper y única superficie donde se contempla la medición con PoC externo.

| CVE | Vector | Rango vulnerable | Precondición que evalúa el lab | Severidad |
|---|---|---|---|---|
| CVE-2025-32463 | `chroot` / carga de NSS (`-R`, `--chroot`) | 1.9.14 – 1.9.17 | versión en rango + `/tmp` ejecutable (la disponibilidad de la opción `chroot` en el binario es informativa; el estado lo decide `/tmp` ejecutable, según `scan.sh`) | Crítica (9.3) |
| CVE-2025-32462 | regla de `sudoers` calificada por host remoto | 1.8.8 – 1.8.32 / 1.9.0 – 1.9.17 | regla calificada por un host distinto del local (en el lab: `clinica-legacy`) | Baja (2.8) |

CVE-2025-32463 es crítica porque escala a root **sin que el usuario figure en `sudoers`**: basta un `sudo` vulnerable y un directorio `chroot` controlado por el atacante. Por eso el `webuser` del escenario —que no tiene ninguna regla de sudo— es un foothold válido para ella.

---

## 5. CVEs históricas

Contexto y comparativa de controles. **No llevan PoC.**

| CVE | Vector | Rango vulnerable | Precondición | Estado esperado del baseline |
|---|---|---|---|---|
| CVE-2023-22809 | `sudoedit` + `EDITOR` | 1.8.0 – 1.9.12p1 | regla de `sudoedit` en `sudoers` (presente: usuario `editor`) | `NO_AFECTADO` (versión fuera de rango) |
| CVE-2021-3156 | Baron Samedit (desbordamiento de heap) | 1.8.2 – 1.8.31p2 / 1.9.0 – 1.9.5p1 | chequeo seguro `sudoedit -s /` (método Qualys) | `NO_AFECTADO` (versión fuera de rango) |
| CVE-2019-14287 | Runas `-u#-1` | < 1.8.28 | regla Runas con `ALL` y negación de root (presente: usuario `operador`) | `NO_AFECTADO` (versión fuera de rango) |

`sudo 1.9.15` es posterior a las correcciones de las tres (1.9.12p2, 1.9.5p2 y 1.8.28, respectivamente): el entorno del laboratorio **no es vulnerable** a ellas, por lo que no tiene sentido técnico ejecutar PoCs contra estas CVEs. Permanecen en el alcance por dos razones: (a) su lógica de detección ya está implementada en `scan.sh` y ejercita el motor de diagnóstico end-to-end, y (b) el paper las utiliza para contextualizar la familia de bugs de `sudo` y comparar tipos de controles.

---

## 6. Decisión: el vector web es simulado

**Decisión del equipo (octubre de 2026).** El acceso inicial por un servicio web mal configurado (CGI inseguro en un Apache heredado) **se narra, no se implementa**:

- El lab representa el eslabón con el usuario `webuser` (foothold de bajos privilegios, sin reglas de sudo, creado por `entrypoint.sh`). Debian trae `www-data`; se usa `webuser` para no confundirlo con el usuario de un Apache real que no existe en el lab.
- No se construyen: Apache vulnerable, `Dockerfile.web`, payload de RCE web ni variables `webRunning`/`webPort`.
- Consecuencia metodológica: el eslabón **[1] acceso inicial** de la cadena queda respaldado documentalmente (`docs/ATTACK-CHAIN.md` y el paper), mientras que la evidencia **experimental** se concentra en el eslabón **[2] escalada por sudo**.
- Requisito de transparencia: `SCOPE.md`, `THREAT-MODEL.md`, `ATTACK-CHAIN.md` y el paper deben declarar explícitamente que el vector web es simulado. Un evaluador nunca debe descubrirlo por sí mismo.

---

## 7. Criterio de estado (glosario unificado)

Estos términos se usan en **todo** el repositorio (README, docs, TSV, dashboard), con esta definición única:

| Término | Definición única |
|---|---|
| `EXPLOTABLE` | Versión en rango vulnerable **y** precondición del sistema presente |
| `MITIGADO` | Versión en rango vulnerable pero precondición cerrada por un control compensatorio |
| `NO_AFECTADO` | Versión fuera de rango **o** binario con backport verificado en vivo |
| `POC_NO_DISPONIBLE` | `LAB_POC_DIR` inexistente o vacío: el benchmark no corre y reporta este estado |
| CVE **foco** | CVE-2025-32463 y CVE-2025-32462 (objeto central del paper) |
| CVE **histórica** | 2023-22809, 2021-3156, 2019-14287 (contexto y comparativa de controles) |
| **Foothold** | Acceso inicial de bajos privilegios; en este lab se **simula** con el usuario `webuser` |

Regla de decisión implementada por `scan.sh` (función `decide`): sin versión vulnerable → `NO_AFECTADO`; versión vulnerable + precondición presente → `EXPLOTABLE`; versión vulnerable sin precondición → `MITIGADO`.

---

## 8. Qué se considera “mitigado”

Definición operativa y reglas que rigen toda mitigación del laboratorio:

1. Un hallazgo pasa a `MITIGADO` cuando, manteniéndose la versión en rango vulnerable, **todas** sus precondiciones quedan cerradas por controles aplicados por `mitigate.sh` y **verificados con re-scan** (no por aserción del script).
2. **Regla de oro del hardening:** `mitigate.sh` **nunca agrega** reglas de `sudoers`; solo elimina o restringe. Todo cambio se valida con `visudo -c` global y con un diff del conjunto de reglas antes/después.
3. Ejemplos canónicos: CVE-2025-32463 → `/tmp` remontado `noexec,nosuid,nodev` (y comentario de las líneas con `CHROOT=`, `--chroot` o `-R` del `sudoers`, si existieran); CVE-2025-32462 → **eliminación** de la regla calificada por host remoto, sin reemplazarla por `ALL` (un reemplazo con un comando interactivo como `less` reconstruiría la escalada).
4. Explícitamente **no** es mitigación: agregar `Defaults !use_chroot` (esa opción no existe en `sudoers` y rompería la validación) ni `chmod u-s /usr/bin/sudo` (rompería el propio laboratorio; queda documentado como opción extrema, no por defecto).
5. `MITIGADO` no es sinónimo de `NO_AFECTADO`: el primero indica un **control compensatorio** sobre una versión vulnerable; el segundo indica una **versión fuera de rango** o un backport verificado en vivo.

---

## 9. Métricas

El contrato completo (fórmulas, unidades y protocolo) reside en `docs/METRICS.md`. Resumen:

- **Diagnóstico (siempre disponibles):** cobertura de precondiciones y distribución de estados (`S` del TSV).
- **Explotación (solo con PoC externo, Opción B):** tasa de éxito (%) y tiempo de escalada (ms; media, mín, máx sobre N iteraciones), antes y después de mitigar.
- **Operativas:** tiempo de diagnóstico y tiempo de mitigación (ms), medidos por el dashboard.
- Sin PoC, las métricas de explotación se reportan **`N/A` documentado**, nunca como cero.

---

## 10. Documentación asociada

El índice completo de la documentación, con una línea de descripción por documento, vive en
[`README.md` §Documentación](../README.md#documentaci%C3%B3n) y no se duplica aquí.
Carácter normativo de este documento: si algún otro archivo del repositorio entra en
contradicción con `SCOPE.md`, prevalece este.
