# La cadena de ataque (descripción conceptual)

Describe, a nivel conceptual y con fines educativos, la cadena que reproduce el
laboratorio. **No contiene exploits weaponizados.** Para el paso de explotación en vivo,
remite a los PoC públicos citados en la bibliografía del informe. Todo se estudia en el
entorno aislado descrito en `SECURITY.md`.

```
Red externa ──▶ [1] acceso inicial (web mal configurada) ──▶ shell www-data ──▶ [2] sudo (CVE-2025-32463) ──▶ root
```

Romper **cualquier** eslabón detiene el ataque. La defensa del laboratorio
(`mitigate.sh`) cierra el eslabón [2]; corregir el servicio web rompería el [1].

---

## Fase 1 — Acceso inicial

**Qué representa:** un atacante que, desde la red, aprovecha una mala configuración de un
servicio web (p. ej. CGI inseguro en un Apache heredado) para lograr ejecución de
comandos, obteniendo una shell con el usuario del servicio (`www-data`), sin privilegios
de administrador.

**En el lab:** esta fase se *representa* con el usuario `webuser` (foothold de bajos
privilegios, sin reglas de sudo). El vector web se documenta en el informe; el lab no
incluye un servicio web explotable ni el payload de RCE. En MITRE ATT&CK: *Initial
Access* + *Execution*.

---

## Fase 2 — Escalada de privilegios con sudo (CVE-2025-32463)

**En el lab:** el contenedor trae `sudo` en rango vulnerable (1.9.14–1.9.17) con la opción
`--chroot` disponible y `/tmp` ejecutable. `scan.sh` **confirma, sin explotar**, que todas
las precondiciones se cumplen.

**Causa raíz (resumen):** al invocar `sudo --chroot <dir>`, las versiones afectadas hacen
`chroot()` al directorio controlado por el atacante **antes** de terminar de evaluar la
política. Durante esa evaluación, sudo resuelve nombres vía NSS y lee el
`/etc/nsswitch.conf` que quedó *dentro del directorio controlado*. Un `nsswitch.conf`
malicioso hace que sudo cargue una `libnss_*.so` fabricada por el atacante mediante
`dlopen()`, ejecutando su código **como root**. No requiere que el usuario figure en
`sudoers`: por eso es crítica.

**Demostración ofensiva:** opcional y externa al repo. PoC público de referencia:
`chwoot` (CVE-2025-32463), citado en el informe. Ejecutarlo es responsabilidad de quien
corre el laboratorio, siempre en aislamiento. En MITRE ATT&CK: *Privilege Escalation*.

---

## Fase 3 — Defensa

`mitigate.sh` aplica controles compensatorios (hardening de `sudoers` + `/tmp` noexec) y
`scan.sh` se vuelve a correr para **verificar** que los hallazgos pasan de `EXPLOTABLE` a
`MITIGADO`. Es la evidencia reproducible que fundamenta la sección de mitigación del
informe.
