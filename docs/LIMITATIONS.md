# Limitaciones del laboratorio — `LIMITATIONS.md`

**Fuente única de las limitaciones con ID citable (L-1…L-16).** Propósito: registrar, con la
misma honestidad con la que se registran los resultados, aquello que el laboratorio **no**
dice: los límites del escenario, de los controles, de la medición y del despliegue, junto
con su impacto en la validez del experimento. Este documento alimenta directamente las
secciones *Metodología* y *Discusión* del paper (ver `docs/PAPER-OUTLINE.md`) y cumple la
promesa de `docs/POC.md` §7: si algo no se puede medir, se documenta — nunca se silencia.

> **Nota de uso.** Cada limitación tiene un identificador (L-1, L-2, …) para que el paper y
> los registros de corrida puedan citarla de forma precisa. El "cómo se declara en el paper"
> no es una fórmula: es el dato que el fenómeno observado obliga a admitir.

---

## 1. Clasificación de la validez

Para no mezclar planos, cada limitación se tipa según el aspecto de validez que afecta:

| Tipo | Pregunta que responde | Ejemplo en este lab |
|---|---|---|
| **Validez interna** | ¿El experimento mide lo que dice medir *dentro* del contenedor? | L-2, L-9, L-10 |
| **Validez de constructo** | ¿Las métricas representan el fenómeno que se quiere estudiar? | L-11, L-12, L-13 |
| **Validez externa** | ¿Los resultados se trasladan a otros entornos? | L-3, L-4, L-14, L-15 |
| **Alcance del control** | ¿Qué cubre realmente la mitigación aplicada? | L-5, L-6, L-7, L-8 |

---

## 2. Limitaciones del escenario

### L-1 — El vector web es simulado

- **Qué es:** el acceso inicial ("foothold") lo simula `scripts/foothold.sh` ejecutándose
  como `webuser`. No existe una aplicación web real: no hay HTTP, no hay exploits de
  aplicación, no hay delante un WAF ni un balanceador.
- **Qué implica:** el laboratorio mide la **fase post-compromiso** (escalada de privilegios
  de un usuario raso que ya tiene shell), no la intrusión inicial. Los resultados hablan de
  qué ocurre *después* de que un servicio web fue comprometido, no de cómo se lo evitó.
- **Cómo se declara en el paper:** explicitar que el escenario reproduce el contexto de una
  clínica con servicios legacy (hostname `srv-web`, usuario `webuser`) como **motivación**,
  y que la unidad experimental es la escalada, no la entrada.

### L-2 — El sudoers está diseñado para ejercitar las CVEs

- **Qué es:** las reglas del escenario (`auditor clinica-legacy=(ALL) NOPASSWD:
  /usr/bin/less`, `operador ALL=(ALL, !root) /usr/bin/vi`, etc.) fueron escritas para
  reproducir fielmente las precondiciones de cada CVE.
- **Qué implica:** la **prevalencia** de esas configuraciones en producción no se mide aquí.
  Dos datos externos acotan esa discusión (que el paper debe atribuir, no afirmar): la
  advisory de CVE-2025-32463 aplica con la configuración por defecto de sudo (sin ninguna
  regla), y CVE-2025-32462 estuvo presente sin ser descubierta durante más de 12 años
  (Mirch, 2025). Además, la automatización del PoC de 32462 exige `NOPASSWD` (o gestionar la
  contraseña): los resultados describen ese caso de uso.
- **Cómo se declara:** presentar el sudoers como un "mapa de señales" de las CVEs, no como
  una encuesta de configuraciones reales.

### L-3 — sudo compilado desde fuente

- **Qué es:** el target compila sudo 1.9.15 con `--prefix=/usr --libexecdir=/usr/libexec
  --with-secure-path` (verificado contra el archivo `SHA256` oficial de sudo.ws).
- **Qué implica:** la validez **interna** es alta (los bytes del binario están fijados),
  pero la **externa** es limitada: los paquetes de las distribuciones aplican parches,
  flags y rutas propias. Un sudo 1.9.15 de una distro puede comportarse levemente distinto
  (glibc igual — verificado Debian 12 glibc 2.36 en `docs/POC.md` §5 —, pero no idéntico).
- **Cómo se declara:** declarar la versión exacta y el método de compilación como parte del
  entorno experimental.

### L-4 — Una corrida validada, un operador, una máquina

- **Qué es:** la corrida registrada en `docs/RESULTS.md` (31-10-2026, 20 iteraciones) se
  ejecutó en una única máquina operadora. El conjunto se replicó en Windows 11 + Docker
  Desktop, Linux y macOS a nivel de *arranque y ciclo*, pero el benchmark completo
  validado corresponde a un entorno.
- **Qué implica:** los agregados (media, mín, máx) son **descriptivos**; no hay inferencia
  estadística ni varianza entre máquinas. La lección `SYS_CHROOT` (`SECURITY.md` §2.2)
  demostró además que el entorno del host puede cambiar el resultado sin un error visible.
- **Cómo se declara:** presentar N=5 como diseño de arnés interactivo (justificado en
  `docs/METHODOLOGY.md` §2.4) y como trabajo futuro la replicación multi-máquina.

---

## 3. Limitaciones de las mitigaciones (alcance de los controles)

### L-5 — El control `/tmp noexec` es parcial

- **Qué es:** `mitigate.sh` remonta `/tmp` como `noexec,nosuid,nodev`. Es el control que
  bloquea el `.so` del PoC de CVE-2025-32463.
- **Qué implica:** **solo cubre `/tmp`**. `/dev/shm`, `/var/tmp` y los homes de los
  usuarios siguen siendo ejecutables en el escenario (el propio script lo advierte al
  terminar y el chequeo post-mitigación de `/dev/shm` lo vigila). El staging de la
  biblioteca maliciosa **puede migrar** a cualquiera de esas rutas. Este es, de hecho, el
  contraejemplo más limpio para la Discusión: el control cierra la vía medida, no la clase
  completa de ataque.
- **Cómo se declara:** nunca afirmar que el "control de /tmp" mitiga CVE-2025-32463 en
  abstracto; afirmar que **bloquea el staging en /tmp** observado con el PoC medido.

### L-6 — Controles compensatorios ≠ parche

- **Qué es:** `mitigate.sh` no actualiza sudo: comenta firmas de chroot en sudoers, elimina
  la regla calificada por host y remonta `/tmp`. El propio script termina con el
  recordatorio explícito: la mitigación completa es actualizar a **sudo 1.9.17p1+**.
- **Qué implica:** la vulnerabilidad sigue presente en el binario; los controles cierran
  precondiciones específicas. La opción extrema (`chmod u-s /usr/bin/sudo`) queda
  documentada y **no aplicada** por diseño: rompería el propio instrumento y toda la
  operación legítima de un servidor real.
- **Cómo se declara:** en Resultados y Discusión, "tasa 0 %" significa "el exploit medido
  no logra escalada con los controles aplicados", no "el sistema ya no es vulnerable".

### L-7 — La regla de oro restringe el hardening

- **Qué es:** el hardening **nunca agrega** reglas de sudoers; solo elimina o restringe,
  con verificación mecánica por difusión de conjuntos y rollback ante cualquier ampliación
  (especificación en `SECURITY.md` §2.5).
- **Qué implica:** es una salvaguarda de integridad del experimento, no un framework
  general de hardening. Su verificación compara especificaciones **literalmente** y no
  expande alias: un sudoers con alias complejos requeriría un análisis más fino.

### L-8 — El estado vulnerable es el default (y vuelve)

- **Qué es:** `make reset`, o la simple recreación del contenedor, restauran el escenario
  vulnerable (el entrypoint reinstala la copia prístina `sudoers.lab.orig` en cada
  arranque).
- **Qué implica:** operativamente, un contenedor olvidado encendido es un sistema
  vulnerable. La frontera es el motor Docker (sin puertos publicados, red interna,
  `SECURITY.md` §2.1), pero la disciplina de `down` tras la demo es parte del protocolo.

---

## 4. Limitaciones de la medición

### L-9 — El diagnóstico corre como root: es la vista del auditor, no del atacante

- **Qué es:** `scan.sh` lee `/etc/sudoers` y `/etc/sudoers.d/*` (`0440 root:root`) y ejecuta
  `docker exec` como root. Un usuario raso solo puede confirmar la parte de **binario y
  sistema de archivos** (`sudo --version`, `findmnt /tmp`) — verificado empíricamente desde
  el foothold (`docs/METHODOLOGY.md` §1).
- **Qué implica:** el estado `EXPLOTABLE` del scan es un **diagnóstico heurístico de
  configuración**, no una explotación. La evidencia de explotación real la aporta el
  benchmark con PoC. El paper debe distinguir con claridad M2 (diagnóstico) de M3
  (explotación observada).

### L-10 — El criterio de éxito dual es una heurística válida *en este contenedor*

- **Qué es:** una iteración es éxito si la salida contiene `uid=0(root)` **o** aparece una
  entrada nueva en `/root/`.
- **Qué implica:** la comparación de listados de `/root/` es válida porque "en este
  contenedor nada más escribe en `/root/`". En un entorno con más software residente, un
  falso positivo sería posible. La ventaja compensa: el arnés no depende del formato de
  salida de un PoC de terceros (`docs/METHODOLOGY.md` §2.3).

### L-11 — N=5, tiempos de reloj y aritmética entera

- **Qué es:** N=5 iteraciones por PoC; el tiempo se mide con el reloj del host alrededor de
  `su - usuario -c "timeout -k 5 … bash <poc>"` (incluye arranque de `su` + `timeout` +
  `bash`); la media sale en décimas de ms con aritmética entera de bash.
- **Qué implica:** (a) no es un estudio de varianza; (b) el tiempo es el **tiempo de
  escalada observable desde fuera del PoC**, no un cronómetro interno; (c) la comparación
  entre PoCs (p. ej. 32463 ≈ 66 ms vs. 32462 ≈ 2741 ms) es de **orden de magnitud y
  mecanismo** (disparo único vs. interacción pty scriptada), no un ranking fino; (d) en el
  post-mitigación, el tiempo mide la duración del *intento fallido* y no constituye
  overhead del control (`docs/RESULTS.md` §6).

### L-12 — Dependencia de PoC externos

- **Qué es:** el repo **no distribuye exploits**. El benchmark consume PoC de terceros
  colocados por el operador en `LAB_POC_DIR` (fuentes registradas en `docs/POC.md` §4/§6:
  el `sudo-chwoot.sh` de Rich Mirch/Stratascale para 32463 y el PoC de **0p5cur** para
  32462), adaptados con el checklist de `POC.md` §5.
- **Qué implica:** los resultados miden **esa implementación del exploit**, no la clase
  completa de ataque. Variantes con staging alternativo (L-5) o payloads distintos podrían
  comportarse diferente post-mitigación. Si un PoC no se adapta, la métrica se reporta
  **"N/A documentado"**, nunca cero ni ausencia silenciosa (`docs/METRICS.md` §1).

### L-13 — La identidad de ejecución depende del sidecar `.user`

- **Qué es:** cada PoC declara su usuario con un sidecar `<poc>.user`; sin sidecar corre
  como `webuser` (convención adoptada el 31-10-2026, `POC.md` §3).
- **Qué implica:** un PoC nuevo que necesite otra identidad exige crear el sidecar; si el
  operador lo olvida, el PoC corre con `webuser` y puede fallar por razones *ajenas* al
  control bajo estudio (p. ej. el 32462 requiere la regla de `auditor`). El checklist de
  reproducción (`docs/REPRODUCIBILITY.md`) lo incluye como paso explícito.

---

## 5. Limitaciones de despliegue y operación

### L-14 — Dashboard sin autenticación, monousuario

- **Qué es:** el panel corre en `localhost:3000` sin auth; su frontera de confianza es la
  propia máquina (`SECURITY.md` §2.4).
- **Qué implica:** no es una herramienta multiusuario ni apta para exposición; su rol es el
  de consola de demo del operador. El botón de ataque está guardado por la sonda
  `GET /api/poc` (solo se habilita con PoC presente), pero no hay RBAC ni auditoría de
  pulsaciones.

### L-15 — Las capabilities determinan la validez (lección SYS_CHROOT)

- **Qué es:** el target necesita exactamente las **siete capabilities** de `SECURITY.md`
  §2.2. La lección completa (por qué con seis el pre-test de CVE-2025-32463 cae a 0/5 sin
  ningún error visible) vive en esa sección y no se repite aquí.
- **Qué implica (el aspecto-limitación):** el esquema de capabilities **viaja con el
  experimento**: endurecer más el compose invalida el pre-test silenciosamente y convierte
  un fallo del entorno en una "mitigación" falsa. Es a la vez una decisión de diseño y una
  limitación de portabilidad (el `docker-compose.yml` no puede endurecerse "un poco más"
  sin revalidar todo).

### L-16 — Se mide prevención, no detección ni respuesta

- **Qué es:** las métricas M2–M5 cubren diagnóstico, tasa de éxito, tiempo de escalada y
  comparación pre/post. No hay telemetría de detección (auditd, syslog, EDR), ni medición
  del tiempo-until-detection, ni de la experiencia funcional de un servicio legítimo bajo
  los controles.
- **Qué implica:** el lab responde "¿bloquea?", no "¿cuánto tarda alguien en enterarse?" ni
  "¿qué le cuesta a la operación?". Ambas preguntas quedan como trabajo futuro
  (`docs/PAPER-OUTLINE.md` §5).

---

## 6. Tabla resumen

| ID | Limitación (resumen) | Tipo | Impacto principal en el paper | Dónde se declara / mitiga |
|---|---|---|---|---|
| L-1 | Vector web simulado (no hay app real) | Interna | Alcance: se mide la escalada, no la intrusión | §2 Metodología; escenario como motivación |
| L-2 | Sudoers diseñado para ejercitar las CVEs | Interna | No mide prevalencia de configuraciones | §2; atribuir prevalencia a fuentes externas |
| L-3 | sudo compilado desde fuente | Externa | Generalización a paquetes de distro limitada | §2; declarar versión y flags |
| L-4 | Una corrida validada, una máquina | Externa | Agregados descriptivos, no inferencia | §2 y §4; trabajo futuro multi-máquina |
| L-5 | `/tmp noexec` parcial (/dev/shm, /var/tmp, homes ejecutables) | Alcance | El control cierra la vía medida, no la clase | §4 Discusión (contraejemplo central) |
| L-6 | Controles compensatorios ≠ parche | Alcance | "0 %" ≠ "no vulnerable" | §3 y §4; recordatorio 1.9.17p1+ |
| L-7 | Regla de oro: solo eliminar/restringir; comparación literal sin alias | Alcance | Hardening con alcance acotado | §2; describir la salvaguarda |
| L-8 | Estado vulnerable = default (reset) | Interna | Riesgo operativo del contenedor encendido | §2; disciplina `down` |
| L-9 | Scan como root (vista del auditor) | Interna | M2 es diagnóstico, no explotación | §2; distinguir M2 de M3 |
| L-10 | Criterio dual de éxito (marcador en /root/) | Interna | Heurística válida en este contenedor | §2; condición del listado |
| L-11 | N=5; tiempo de reloj del host; aritmética entera | Constructo | Sin estudio de varianza; tiempos "desde fuera" | §2; lectura condicionada de M4 |
| L-12 | Dependencia de PoC externos (uno por CVE) | Constructo | Mide ESA implementación del exploit | §2 y §4; "N/A documentado" si falla |
| L-13 | Identidad por sidecar `.user` | Constructo | Config del arnés puede sesgar si se omite | `REPRODUCIBILITY.md`; checklist |
| L-14 | Dashboard sin auth, monousuario | Externa | No es herramienta de producción | README; `SECURITY.md` §2.4 |
| L-15 | 7 capabilities obligatorias (SYS_CHROOT) | Externa | Portabilidad: el compose no endurece más sin revalidar | §4; lección del instrumento |
| L-16 | Solo prevención (sin detección/respuesta) | Constructo | Alcance de la afirmación defensiva | §5 trabajo futuro |
