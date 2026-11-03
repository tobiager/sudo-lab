# La cadena de ataque (descripción conceptual)

Describe, a nivel conceptual y con fines educativos, la cadena que reproduce el laboratorio.
**No contiene exploits weaponizados.** Para el paso de explotación en vivo, remite a los PoC
externos del equipo (política en `SECURITY.md` §3: circulan entre nosotros, nunca en este
repositorio versionado). Todo se estudia en el entorno aislado descrito en `SECURITY.md`.

---

## La cadena, de punta a punta

```
Red externa ──▶ [1] acceso inicial (web mal configurada) ──▶ shell webuser (≙ www-data) ──▶ [2] sudo (CVE-2025-32463) ──▶ root
```

Romper **cualquier** eslabón detiene el ataque. La tabla siguiente define, para cada
eslabón, qué representa, cómo lo representa el laboratorio y qué control lo rompe.

| Eslabón | Qué representa | Cómo se representa en el lab | Control que lo rompe | MITRE ATT&CK |
|---|---|---|---|---|
| [1] Acceso inicial | Un atacante externo explota un servicio web expuesto (p. ej., un CGI inseguro en un Apache heredado) y obtiene ejecución de comandos como usuario del servicio. | **Narrado.** Por decisión de alcance (`docs/SCOPE.md` §6) no hay Apache vulnerable ni payload de RCE: el lab lo representa con el usuario `webuser` y el botón "② Simular foothold" del panel. | La corrección del servicio web (parcheo, eliminación del CGI inseguro, permisos). Queda fuera del alcance del lab y se discute en el informe. | Initial Access — T1190 · Execution — T1059.004 |
| [2] Escalada vía sudo | El usuario raso —sin ninguna regla de sudo— escala a root abusando del binario `sudo` setuid-root vulnerable (CVE-2025-32463). | **Real.** El target trae `sudo 1.9.15` compilado con las precondiciones presentes; `scan.sh` (①) las confirma **sin explotar**. | (a) Parche real: actualizar a `sudo 1.9.17p1` o posterior. (b) Controles compensatorios de `mitigate.sh` (③): `/tmp` `noexec,nosuid,nodev` + hardening de sudoers. | Privilege Escalation — T1068 |

> **Nota — CVE-2025-32462 (opción host):** la segunda CVE foco no forma parte de esta
> cadena principal: exige reglas calificadas por un host distinto al actual, condición
> que el lab porta como señal (`auditor clinica-legacy=(ALL) /usr/bin/less`). Se
> estudia en el diagnóstico (①) y su mitigación (③), con el mismo criterio defensivo.

---

## Eslabón [1] — Acceso inicial: el foothold simulado

**Qué representa:** el punto de partida del atacante inmediatamente después del vector
web: una shell sin privilegios con el usuario del servicio.

**Equivalencia `webuser` ≈ `www-data`:** Debian trae `www-data` como usuario de servicio
por defecto; el laboratorio usa `webuser` (creado por `lab/entrypoint.sh` sin contraseña y
**sin reglas de sudo, a propósito**) para no confundirlo con el usuario de un Apache real,
que aquí no existe. En el informe, `webuser` y `www-data` son intercambiables: representan
lo mismo, el usuario raso de un servicio web comprometido.

**Cómo se ejecuta desde el panel:** el botón "② Simular foothold" invoca
`POST /api/foothold`, que corre `foothold.sh` **como usuario raso, no como root**:
`docker exec -u webuser sudo-lab-target bash /opt/lab/scripts/foothold.sh`. Ese es el
punto clave de la simulación: toda la evidencia se produce desde el punto de vista del
atacante sin privilegios. El propio script trae una guardia que aborta (exit 1) si se
lo ejecuta como root, para que la demo nunca se contamine con privilegios.

**Qué deja como evidencia** (registros tipo `foot` en la consola del panel):

1. `id` — la identidad del foothold (usuario raso).
2. `sudo -l` — **ninguna regla** de sudo (respuesta literal de sudo, p. ej.
   `Sorry, user webuser may not run sudo on srv-web.`).
3. `sudo --version` — el binario vulnerable es alcanzable igualmente: sudo es
   setuid-root, su versión no depende de las reglas del usuario.
4. Estado de `/tmp` — si la precondición de CVE-2025-32463 sigue presente.

**Qué puede verificar el foothold y qué no:** la tabla completa (versión de sudo y `/tmp`
ejecutable sí; reglas de sudoers no) está en [`docs/METHODOLOGY.md`](METHODOLOGY.md) §1,
con su justificación. En consecuencia, la parte de CVE-2025-32463 que depende del binario
y del sistema de archivos **sí es comprobable desde el foothold**; las señales de
configuración exigen root, por lo que el diagnóstico completo (①, `scan.sh`) corre como
root.

En MITRE ATT&CK: *Initial Access* (T1190) + *Execution* (T1059.004).

---

## Eslabón [2] — Escalada de privilegios con sudo (CVE-2025-32463)

**En el lab:** el contenedor trae `sudo` en rango vulnerable (1.9.14–1.9.17) con la opción
`--chroot` disponible y `/tmp` ejecutable. `scan.sh` **confirma, sin explotar**, que todas
las precondiciones se cumplen.

**Causa raíz (resumen):** al invocar `sudo --chroot <dir>`, las versiones afectadas hacen
`chroot()` al directorio controlado por el atacante **antes** de terminar de evaluar la
política. Durante esa evaluación, sudo resuelve nombres vía NSS y lee el
`/etc/nsswitch.conf` que quedó *dentro del directorio controlado*. Un `nsswitch.conf`
malicioso hace que sudo cargue una `libnss_*.so` fabricada por el atacante mediante
`dlopen()`, ejecutando su código **como root**. No requiere que el usuario figure en
`sudoers`: por eso es crítica — y por eso el foothold del eslabón [1], sin ninguna
regla, alcanza root.

**Demostración ofensiva:** opcional y externa al repo (política en `SECURITY.md` §3). El
equipo provee los PoC en `PoC - Externos.rar` y se colocan en `LAB_POC_DIR` para la
medición; el repositorio versionado nunca los incluye. PoC público de referencia:
`chwoot` (CVE-2025-32463), citado en el informe. En MITRE ATT&CK: *Privilege Escalation*
(T1068).

---

## Eslabón final — Defensa y verificación

`mitigate.sh` (③) aplica controles compensatorios (hardening de `sudoers` —sin agregar
reglas— + remontaje de `/tmp` `noexec,nosuid,nodev`) y `scan.sh` se vuelve a correr para
**verificar** que los hallazgos pasan de `EXPLOTABLE` a `MITIGADO`. Es la evidencia
reproducible que fundamenta la sección de mitigación del informe. **↺ Restaurar**
(`--reset`) devuelve el target al estado vulnerable para repetir la demo completa.

**Lectura de la cadena a través del panel:**

| Acción del panel | Papel en la cadena |
|---|---|
| ② Simular foothold | *Reproduce* el eslabón [1] (acceso inicial, narrado). |
| ① Diagnosticar | *Verifica* las condiciones del eslabón [2] (exposición, sin explotar). |
| ③ Aplicar mitigaciones + re-escanear | *Rompe* el eslabón [2] y lo demuestra con datos. |
| ↺ Restaurar | *Restaura* la cadena para volver a estudiarla. |
