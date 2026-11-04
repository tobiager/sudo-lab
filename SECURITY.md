# Seguridad del laboratorio — `SECURITY.md`

**Fuente única** de: las capabilities del contenedor target y su justificación (§2.2),
la lección `SYS_CHROOT` sobre validez experimental (§2.2) y la política de manejo del
PoC (§3). Otros documentos remiten aquí en lugar de repetir estos contenidos. Modela el
ataque `docs/THREAT-MODEL.md`; cómo se obtiene y adapta el PoC externo, `docs/POC.md`.

---

## 1. Propósito y alcance

Este documento describe los riesgos que el propio laboratorio introduce en la máquina del operador, los controles que los acotan y las decisiones de seguridad embebidas en la infraestructura (capabilities, healthcheck, volúmenes y variables de entorno).

El laboratorio existe para **medir** la eficacia de mitigaciones compensatorias sobre un sudo vulnerable. Esa misión impone una tensión de diseño: el instrumento debe ser seguro para el host, pero también **fiel al fenómeno** que instrumenta. Ambos requisitos se tratan aquí juntos, porque son la misma decisión (§2.2).

---

## 2. Riesgos del laboratorio y capabilities del contenedor

### 2.1 Modelo de riesgo en una sección

El laboratorio ejecuta, en una máquina de desarrollo confiable, tres cosas que en un entorno de producción no coexistirían: un contenedor **intencionalmente vulnerable** (sudo 1.9.15 + sudoers con señales de las CVEs), un PoC público de explotación (opcional, externo al repositorio) y un dashboard sin autenticación. El riesgo agregado se acota con cuatro capas:

1. **Aislamiento de red:** el target se publica en una red `bridge` interna (`labnet`) **sin ningún puerto publicado** al host. No es alcanzable desde fuera del motor Docker.
2. **Confianza del dashboard:** el panel corre en `localhost:3000` (`next dev`); **nunca** debe iniciarse con `-H 0.0.0.0` ni exponerse por túnel. No hay auth: su frontera de confianza es la propia máquina.
3. **Superficie de entrada mínima:** el dashboard solo ejecuta los scripts del laboratorio vía `docker exec` (`lib/lab.ts`), contra un contenedor cuyo nombre se valida por regex (`LAB_CONTAINER`); el PoC se monta desde `./poc` (directorio del repo **sin versionar**) en modo **de solo lectura**.
4. **Capabilities default-deny:** el target parte de `cap_drop: [ALL]` y reintroduce únicamente las siete capabilities justificadas de §2.2.

### 2.2 Capabilities del target: lista blanca de siete

| # | Capability | Quién la necesita (uso real en el lab) | Consecuencia si se elimina |
|---|---|---|---|
| 1 | `CHOWN` | `entrypoint.sh`: `useradd` de los usuarios del escenario y ajuste de propiedad de `/opt/lab`. | El arranque falla al crear usuarios y directorios con dueño distinto de root. |
| 2 | `DAC_OVERRIDE` | `entrypoint.sh` y `mitigate.sh`: instalar `/etc/sudoers.d/lab` (modo `0440`), escribir backups `0600` y restaurarlos (`--reset`). | No se pueden escribir ni restaurar archivos con permisos restrictivos: mitigation y reset fallan. |
| 3 | `FOWNER` | `install -m 0400/0440/0600` sobre archivos cuyo dueño puede no coincidir (backups, candidatos de sudoers en `mktemp`). | La instalación del sudoers endurecido y el circuito de backups abortan. |
| 4 | `SETGID` | `sudo` y `su` al cambiar de grupo: el benchmark degrada cada iteración con `su - <usuario>`; los PoCs corren como usuario raso. | El arnés `benchmark.sh` no puede degradar privilegios: toda iteración termina en `ERROR`. |
| 5 | `SETUID` | `sudo` (setuid-root) y `su` (cambio de usuario). Es la capability que define al propio objeto de estudio. | Ni hay escalada ni hay medición: `sudo` queda inoperante y el lab pierde su razón de ser. |
| 6 | `SYS_ADMIN` | Remontaje de `/tmp`: `mitigate.sh` aplica `noexec,nosuid,nodev` (control compensatorio de CVE-2025-32463) y `--reset` lo devuelve a `exec`. | El control de `/tmp` no se aplica: CVE-2025-32463 sigue `EXPLOTABLE` **después** de mitigar, y el post-test del protocolo es inválido. |
| 7 | `SYS_CHROOT` | El camino de `chroot` de sudo (`-R` / `--chroot`), ejercitado por el PoC de CVE-2025-32463 (stage del NSS dentro del chroot y escape). | **El pre-test del protocolo cae de 5/5 a 0/5 sin ningún error visible**: el entorno deja de reproducir el fenómeno y toda la comparación pre/post queda invalidada (lección abajo). |

**Lección `SYS_CHROOT`.** Una versión del endurecimiento con seis capabilities pasó todos los chequeos de infraestructura: `sudo`, `useradd`, `visudo`, `scan.sh` y `mitigate.sh` operaban con normalidad. Sin embargo, el benchmark de CVE-2025-32463 reportó **0 % de éxito en el pre-mitigación** —no porque el control funcionara, sino porque el entorno ya no permitía ejecutar el ataque. Al reintroducir `SYS_CHROOT` en `docker-compose.yml`, el ciclo completo volvió a los valores de referencia: **pre-mitigación 5/5 + 5/5 (100 %), post-mitigación 0/5 + 0/5 (0 %)**. La conclusión se documenta como principio de diseño:

> Las capabilities no solo *protegen*: también *determinan la validez de la medición*. Toda capability que el fenómeno estudiado necesita en producción debe estar presente en el instrumento; quitarla convierte un fallo del entorno en una "mitigación" falsa, que es peor que un fallo ruidoso porque la UI la reporta como resultado válido. Por eso cada capability de la tabla registra su **consecuencia observable al eliminarla**: es un contrato de verificación, no solo una justificación.

### 2.3 El riesgo residual de `SYS_ADMIN` y `SYS_CHROOT`, y por qué se acepta

- **`SYS_ADMIN`** es la capability más poderosa de la lista: habilita operaciones de montaje que, en presencia de otros errores de aislamiento, podrían exponer filesystems del host. Se acepta porque (a) es imprescindible para el único control compensatorio de montaje del lab (remount de `/tmp`), (b) el contenedor no publica puertos y su red es interna, (c) todos los montajes desde el host son `:ro`, y (d) la regla de oro del hardening (§2.5) impide que las mitigaciones amplíen permisos. Cualquier servicio auxiliar futuro (fuera del target) llevará `security_opt: [no-new-privileges:true]`; el target queda **exceptuado por diseño** porque sudo es setuid.
- **`SYS_CHROOT`** es de bajo riesgo relativo: `chroot(2)` está contenido por los permisos DAC del filesystem y es un requisito funcional del propio binario estudiado. El riesgo de retirarla no es de seguridad sino de **validez experimental** (§2.2).

La referencia operativa vive como comentario en `docker-compose.yml`; esta sección es su especificación completa.

### 2.4 Superficie del dashboard y variables de entorno

| Elemento | Riesgo | Control vigente |
|---|---|---|
| Dashboard sin auth (`next dev`, puerto 3000) | Cualquier proceso del host puede pulsar los botones de mitigar/reset. | Solo `localhost`; nunca `-H 0.0.0.0`. En WSL2, revisar la configuración de port-forwarding antes de considerar "local" algo que no lo es. |
| `LAB_CONTAINER` | Un nombre mal configurado apuntaría el `docker exec` a otro contenedor. | Validado por regex en `lib/lab.ts`; los errores tipados devuelven `502` con mensaje accionable. |
| `LAB_POC_DIR` / montaje `./poc` | Distribuir o ejecutar PoCs fuera de control. | `docker-compose.yml` monta `./poc` (directorio del repo **sin versionar**) en `/opt/lab/poc:ro` y fija `LAB_POC_DIR=/opt/lab/poc` dentro del contenedor; el repo versionado no contiene ningún PoC (§3). |
| Contenedor vulnerable | Es, por diseño, un sistema comprometible. | Sin puertos publicados, red interna, capabilities de §2.2; se destruye y reconstruye con `docker compose down && make up` sin estado persistente. |

### 2.5 Contenedor intencionalmente vulnerable: reglas del escenario

El sudoers de laboratorio (`lab/sudoers.lab` → `/etc/sudoers.d/lab`, copia prístina en `/opt/lab/sudoers.lab.orig`) instala a propósito las señales de configuración que los scripts detectan: la regla calificada por host remoto (`auditor clinica-legacy=...`, CVE-2025-32462), la regla con negación de runas y la regla de `vi` (CVE-2019-14287 / escenario de `operador`), entre otras. Dos invariantes lo gobiernan:

1. **Regla de oro:** el hardening **nunca agrega** reglas de sudoers; solo elimina o restringe. `mitigate.sh` lo verifica mecánicamente difundiendo el conjunto de reglas antes/después y revirtiendo ante cualquier ampliación.
2. **El estado vulnerable es el default:** `make reset` (o recrear el contenedor) devuelve el escenario a su estado inicial. No existe estado persistente que "deje seguro" el lab por accidente: esa es la condición experimental, no un descuido.

---

## 3. Política de manejo del PoC

Este laboratorio puede ejecutar PoCs públicos para medir la eficacia de las mitigaciones. Para preservar la ética y la legalidad del proyecto, se aplica la siguiente política:

### Circulación interna (permitida)

- El PoC se comparte entre miembros del equipo por canales privados (chat del equipo, drive compartido, `scp` entre máquinas del equipo, o el comprimido de entrega del proyecto).
- Cada miembro lo descarga de la fuente original o lo recibe del equipo.
- Se ejecuta SOLO dentro del contenedor aislado del laboratorio.
- En el paquete de entrega los PoC viajan como `poc/poc_*.txt` (no ejecutables tal cual) junto al sidecar `poc_32462.sh.user`; el directorio `poc/` permanece excluido del repositorio versionado por `.gitignore`.

### Lo que se publica en el repositorio

- `docs/POC.md`: enlaces a los repositorios originales de cada PoC, cómo adaptarlos, cómo se miden.
- `docs/RESULTS.md`: tablas de resultados (tasa de éxito, tiempos, estados).
- `docs/METHODOLOGY.md`: protocolo de medición.
- `scripts/benchmark.sh`: script que orquesta la ejecución.

### Lo que NO se publica en el repositorio versionado

- El script de exploit (ni original ni adaptado).
- Librerías maliciosas (`.so`, `nsswitch.conf` malicioso).
- Capturas de pantalla donde se vea el exploit en ejecución.
- Logs con payloads o comandos de exploit visibles.
- Cualquier fork, copia o "versión adaptada" del PoC.

### Regla simple

"El PoC circula entre nosotros, no entre nosotros y el mundo."

### Si la cátedra solicita una demo en vivo

Se realiza en la máquina del equipo, en el entorno aislado, durante la defensa oral. No se sube al repositorio.

Obtención, adaptación y uso responsable del PoC: `docs/POC.md`.

---

## 4. Controles de despliegue

| Control | Implementación | Verificación |
|---|---|---|
| `visudo -c` global al arranque | `lab/entrypoint.sh` valida el conjunto completo `/etc/sudoers` + `/etc/sudoers.d/*` antes de dar servicio; un sudoers roto **falla el arranque** en lugar de degradarse en silencio durante la demo. | `docker logs sudo-lab-target` muestra la validación al inicio. |
| `HEALTHCHECK` representativo | `HEALTHCHECK ... CMD visudo -c -q \|\| exit 1` en `lab/Dockerfile`: mide la salud del **sudoers**, no solo del proceso. (`sudo --version` sería siempre verde.) | `docker inspect --format '{{.State.Health.Status}}' sudo-lab-target` → `healthy`. |
| Sin `VOLUME` en el Dockerfile | Los volúmenes (`scripts`, `LAB_POC_DIR`) se declaran solo en `docker-compose.yml`; la imagen suelta no genera volúmenes anónimos residuales. | `docker run --rm <img> ls /opt/lab/scripts` → vacío, sin montajes implícitos. |
| Permisos de `/opt/lab` | Archivos de root, modos `0755`/`0644`; `webuser` no puede escribir allí (el staging del PoC queda confinado a `/tmp` y su home). | `su - webuser -c 'touch /opt/lab/scripts/x'` → denegado. |
| `init: true` | PID 1 delegado a `docker-init` (recolección de zombis de los PoCs con procesos hijos). | `docker exec sudo-lab-target ps -p 1` → `init`. |
