# Resultados empíricos — `RESULTS.md`

**Fuente única de las cifras del proyecto.** Ningún otro documento repite estas tablas: los
demás remiten aquí. Los datos provienen de la primera corrida completa **pre/post
mitigación** con los PoC reales adaptados (ver [`docs/POC.md`](POC.md) §6), conforme al
protocolo de medición de [`docs/METHODOLOGY.md`](METHODOLOGY.md) §2 y al contrato de
[`docs/METRICS.md`](METRICS.md).

---

## 1. Condiciones de la corrida

| Campo | Valor |
|---|---|
| Fecha | 31 de octubre de 2026 (respaldo de sudoers generado por `mitigate.sh`: `/opt/lab/backups/20261031-171738`) |
| Entorno | Contenedor `sudo-lab-target` (Debian 12; `sudo 1.9.15` compilado a mano; hostname `srv-web`) |
| Precondición observada por el foothold (②) | `webuser` sin reglas de sudo; `/tmp` ejecutable (`rw,nosuid,nodev,relatime`); binario `Sudo version 1.9.15` — documentado en `METHODOLOGY.md` §1 |
| PoC utilizados | `poc_32463.sh` (identidad `webuser`) y `poc_32462.sh` (identidad `auditor`, convención `.user` de `POC.md` §3) |
| Parámetros del arnés | `N = 5` iteraciones por PoC · `timeout` 30 s por iteración · criterio de éxito **dual** (`uid=0(root)` en stdout **o** entrada nueva en `/root/`) |
| Volumen experimental | 2 corridas (pre y post mitigación) × 2 PoC × 5 iteraciones = **20 iteraciones** |

---

## 2. Diagnóstico (M2) — antes y después

| Corrida | CVE-2025-32463 (chroot/NSS) | CVE-2025-32462 (host) | Históricas (22809 / 3156 / 14287) | Resumen |
|---|---|---|---|---|
| Pre-mitigación | `EXPLOTABLE` | `EXPLOTABLE` | `NO_AFECTADO` ×3 | 2 explotable(s), 0 mitigado(s), 3 no afectado(s) |
| Post-mitigación | `MITIGADO` | `MITIGADO` | `NO_AFECTADO` ×3 | 0 explotable(s), 2 mitigado(s), 3 no afectado(s) |

---

## 3. Benchmark pre-mitigación (estado vulnerable restaurado)

Tiempos por iteración (ms) tal como los reportan las líneas `B`; los agregados corresponden a
las líneas `BAGG` del TSV (media con una décima).

| PoC | Identidad | CVE | iter 1 | iter 2 | iter 3 | iter 4 | iter 5 | Éxitos/N | Tasa (M3) | Media | Mín | Máx |
|---|---|---|---:|---:|---:|---:|---:|---|---:|---:|---:|---:|
| `poc_32463.sh` | `webuser` | 2025-32463 | 70 | 65 | 65 | 64 | 66 | 5/5 | **100 %** | 66.0 | 64 | 70 |
| `poc_32462.sh` | `auditor` | 2025-32462 | 2740 | 2740 | 2745 | 2740 | 2739 | 5/5 | **100 %** | 2740.8 | 2739 | 2745 |

**Observaciones.**

- La tasa de éxito pre-mitigación es del **100 %** (10/10 iteraciones): ambos vectores escalan
  a root de forma determinista en el estado vulnerable.
- El 32463 es ~41.5× más rápido que el 32462 (66.0 ms vs 2740.8 ms de media): la escalada por
  inyección NSS es un único disparo de `sudo -R`; la del 32462 es una interacción pty
  scriptada donde las pausas de la secuencia (`!sh` → `id` → `exit` → `q`) dominan el tiempo.
  La variabilidad intra-PoC es mínima (rango de 6 ms y 6 ms respectivamente), lo que indica
  mediciones estables.
- La identidad de ejecución quedó evidenciada en cada iteración (`uid=1000(webuser)` y
  `uid=1002(auditor)`), confirmando la convención `.user` de `POC.md` §3.

---

## 4. Mitigación aplicada (controles compensatorios, sin actualizar sudo)

Acciones registradas por `mitigate.sh` (③) en la corrida del 31-10-2026:

1. **Hardening de sudoers**: reescritura de `/etc/sudoers.d/lab` con respaldo previo en
   `/opt/lab/backups/20261031-171738`; reglas activas de 6 → 4 líneas.
   - **Eliminada**: `auditor clinica-legacy=(ALL) NOPASSWD: /usr/bin/less` (el match con el
     host suplantado del 32462 desaparece).
   - **Eliminada**: `editor ALL=(root) sudoedit /etc/motd`.
   - **Restringida**: `operador ALL=(ALL, !root) /usr/bin/vi` → `operador ALL=(operador) /usr/bin/vi`.
2. **Remontaje de `/tmp`** como `noexec,nosuid,nodev` (bloquea el staging del `.so` del 32463:
   la biblioteca compilada en `/tmp` ya no puede mapearse ejecutable); `/dev/shm` ya era
   `noexec`.
3. Verificación de consistencia: `visudo -c` global OK.

Re-diagnóstico (①) posterior: CVE-2025-32463 `MITIGADO (chroot/NSS)` y CVE-2025-32462
`MITIGADO (host)` — tabla de la §2.

---

## 5. Benchmark post-mitigación

Mismos parámetros (N=5, timeout 30 s, criterio dual, mismas identidades).

| PoC | Identidad | CVE | iter 1 | iter 2 | iter 3 | iter 4 | iter 5 | Éxitos/N | Tasa (M3) | Media | Mín | Máx | Estado por iteración |
|---|---|---|---:|---:|---:|---:|---:|---|---:|---:|---:|---:|---|
| `poc_32463.sh` | `webuser` | 2025-32463 | 62 | 64 | 63 | 64 | 62 | 0/5 | **0 %** | 63.0 | 62 | 64 | `MITIGADO` ×5 |
| `poc_32462.sh` | `auditor` | 2025-32462 | 5754 | 5065 | 4970 | 4479 | 3911 | 0/5 | **0 %** | 4835.8 | 3911 | 5754 | `MITIGADO` ×5 |

---

## 6. Comparación antes/después (M5) y lectura de resultados

| PoC | Tasa pre | Tasa post | Δ tasa | Media pre (ms) | Media post (ms) | Δ tiempo |
|---|---:|---:|---:|---:|---:|---:|
| `poc_32463.sh` | 100 % (5/5) | 0 % (0/5) | −100 pp | 66.0 | 63.0 | −3.0 ms (−4.6 %) |
| `poc_32462.sh` | 100 % (5/5) | 0 % (0/5) | −100 pp | 2740.8 | 4835.8 | +2095.0 ms (+76.4 %) |
| **Global** | **100 % (10/10)** | **0 % (0/10)** | **−100 pp** | — | — | — |

**La mitigación fue 100 % efectiva**: ambos PoC pasan de 5/5 escaladas a 0/5, de manera
consistente con el diagnóstico (ambas CVEs de `EXPLOTABLE` a `MITIGADO`) y con el resultado
esperado por el contrato M5 (tasa post-mitigación = 0 % cuando el control aplica).

- **CVE-2025-32463** queda bloqueado por el control de sistema de archivos: con `/tmp`
  `noexec`, el `.so` que el PoC compila en su escenario no puede mapearse ejecutable, la
  inyección NSS no llega a disparar el constructor y `sudo` continúa y termina sin escalada.
  El PoC sigue corriendo completo (≈63 ms), es decir, el control no rompe el arnés: rompe el
  exploit.
- **CVE-2025-32462** queda bloqueado por el control de configuración: la eliminación de la
  regla `auditor clinica-legacy=...` quita todo match posible para el host suplantado.
- **Sobre el aumento de tiempo del 32462 (+76.4 %):** no constituye overhead del control. Con
  la regla eliminada, `sudo` deniega y la automatización pty agota su secuencia completa de
  pausas y reintentos ante la denegación. Cuando la tasa de éxito es 0 %, el tiempo deja de
  ser métrica de interés: M4 se interpreta condicionada a M3 (mide la duración del *intento*,
  no un costo del control).

**Alcance de la evidencia.** Los controles aplicados son compensatorios para entornos legacy
que no pueden parchear; la mitigación completa de ambas CVEs sigue siendo actualizar a
`sudo 1.9.17p1` o superior. La cadena completa del experimento (①→②→④→③→①→④) quedó registrada
en los logs de la corrida y es reproducible con `docs/METHODOLOGY.md` §2 y
`docs/REPRODUCIBILITY.md`.

---

## 7. Trazabilidad

- Fuente de cada cifra: líneas `B`/`BAGG` del TSV de `benchmark.sh` en las dos corridas; los
  agregados de las tablas (§3 y §5) coinciden con los emitidos por el arnés.
- Respaldo de sudoers previo al hardening: `/opt/lab/backups/20261031-171738` (permite
  restaurar el estado vulnerable y repetir la corrida pre).
- Estados de diagnóstico (M2): tabla §2, derivada de las líneas `F`/`S` de `scan.sh`.
- Identidades de ejecución: evidenciadas por iteración en el log (`uid=1000(webuser)`,
  `uid=1002(auditor)`), convención documentada en `POC.md` §3.
