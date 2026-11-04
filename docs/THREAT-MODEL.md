# Modelo de amenaza — `THREAT-MODEL.md`

Modelo ligero basado en activos, adversarios y fronteras de confianza.

---

## 1. Propósito y alcance del modelo

Este documento define **qué protege** el laboratorio, **contra qué** y **hasta dónde**. El objeto del modelo es el laboratorio como sistema —host del operador, dashboard y contenedor target—, no el escenario ficticio de la clínica. El objetivo académico del lab es precisamente *permitir* una escalada de privilegios controlada dentro del contenedor; el modelo de amenaza existe para garantizar que esa actividad quede **contenida** y no degrade la seguridad del host ni la integridad ética del proyecto.

---

## 2. Activos (lo que hay que proteger)

| # | Activo | Por qué importa |
|---|---|---|
| A1 | **Host del operador** | Máquina personal con Docker: archivos, credenciales y recursos. Ningún componente del lab debe debilitarla. |
| A2 | **El laboratorio como evidencia académica** | Scripts, documentación e historial: la reproducibilidad de los resultados es un activo del paper. |
| A3 | **Contención ética y legal** | Que ningún payload ni PoC salga del entorno controlado hacia terceros (política de manejo del PoC, `SECURITY.md`). |
| A4 | **Contenedor target** | Intencionalmente vulnerable. Su compromiso didáctico es el objetivo del lab, no un incidente: se trata como activo **desechable** y reconstruible (`docker compose up -d --build`). |

---

## 3. Adversarios

| # | Adversario | Consideración |
|---|---|---|
| Ad1 | **Atacante simulado (`webuser`)** | Es el **sujeto de estudio**, no una amenaza real: representa el foothold del eslabón [1] de la cadena. Opera dentro del target y sin reglas de sudo. |
| Ad2 | **Código de terceros (PoC externo)** | Los scripts `poc_32463.sh` / `poc_32462.sh` de `LAB_POC_DIR` son contenido no confiable: se montan `:ro`, se ejecutan **solo como usuario raso** (identidad por sidecar `.user`, default `webuser`) dentro del target y jamás en el host ni como root. |
| Ad3 | **Usuario local no autorizado del host** | Fuera del modelo: el dashboard no tiene autenticación y se asume máquina personal del equipo. Mitigación mínima: escucha **solo en `localhost`**, nunca en `0.0.0.0`. |
| Ad4 | **Atacante remoto de red** | Fuera del modelo: el target no publica puertos y el dashboard no se expone. No hay superficie de red externa por diseño. |

---

## 4. Fronteras de confianza

```
┌──────────────────── HOST del operador (confiable) ─────────────────────┐
│  Dashboard Next.js (solo localhost:3000)     CLI de Docker             │
│      │  docker exec: scan.sh · mitigate.sh · foothold.sh ·            │
│      │             benchmark.sh                                        │
├──────┼─────────────────────────────────────────────────────────────────┤
│      ▼                                                                 │
│  Contenedor target «sudo-lab-target»                                  │
│  = NO CONFIABLE POR DISEÑO                                            │
│  (sudo 1.9.15 vulnerable · sudoers con señales · /tmp ejecutable)     │
│      ▲                                                                 │
│  LAB_POC_DIR montado :ro  =  CONTENIDO DE TERCEROS, NO CONFIABLE      │
└────────────────────────────────────────────────────────────────────────┘
```

Propiedades de las fronteras:

- `docker exec` sobre el target equivale a acceso **root** en el contenedor. El dashboard, al poder invocarlo, hereda ese poder: quien controle `localhost:3000` controla las acciones del panel. Esta es la razón de la regla “solo `localhost`”.
- Todo lo que corre **dentro** del target (incluido un PoC) se considera comprometible por diseño; la frontera real que hay que defender es la del **host**, materializada en las capabilities del contenedor y en el aislamiento de red.
- `LAB_POC_DIR` cruza la frontera hacia adentro en solo lectura (`:ro`); nada del target puede escribir en él.

---

## 5. Superficie de ataque y controles

| Superficie | Riesgo | Control |
|---|---|---|
| Dashboard en `:3000` sin autenticación | Uso no autorizado desde la propia máquina | Escucha solo en `localhost`; el target no publica puertos |
| Target vulnerable por diseño | Escalada a root *dentro* del contenedor | Esperado (es el objeto de estudio); red `labnet` aislada, sin puertos publicados; activo desechable (A4) |
| `CAP_SYS_ADMIN` del target | Capability amplia (necesaria para remontar `/tmp` a `noexec`) | `cap_drop: [ALL]` + lista blanca de **7 capabilities** (`CHOWN, DAC_OVERRIDE, FOWNER, SETGID, SETUID, SYS_ADMIN, SYS_CHROOT`); justificación en `SECURITY.md` §2.2 |
| `no-new-privileges` | `sudo` requiere setuid | Target **exceptuado por diseño**; servicios auxiliares futuros lo llevarían |
| `LAB_POC_DIR` (código de terceros) | Ejecución de un PoC en el entorno | Montaje `:ro`; ejecución solo como usuario raso (sidecar `.user`), dentro del target; `POC_NO_DISPONIBLE` si está vacío; política en `SECURITY.md` §3 |
| Variable `LAB_CONTAINER` | Inyección de un nombre de contenedor arbitrario | Validación al arranque con regex `^[A-Za-z0-9][A-Za-z0-9_.-]*$`; valor inválido = error de configuración, no de runtime |
| `sudoers` del laboratorio | Reglas mal formadas rompen la demo (o, peor, agregan permisos) | `visudo -c` global al arranque y tras cada mitigación; el hardening **nunca agrega** reglas, solo elimina o restringe |

---

## 6. Qué NO protege el laboratorio

- **No protege el host frente a un escape de contenedor** o una vulnerabilidad del kernel/Docker. Se asume Docker Engine actualizado y máquina personal; la contención de Docker es la frontera exterior asumida, no re-auditada por este proyecto.
- **No provee autenticación, multiusuario ni auditoría** del dashboard.
- **No es un escáner de producción:** los estados (`EXPLOTABLE`/`MITIGADO`/`NO_AFECTADO`) son veredictos de laboratorio sobre el target, no una evaluación de seguridad integral del sistema anfitrión.
- **No protege datos reales:** el escenario de la clínica es ficticio y no contiene información sensible.

---

## 7. Límite explícito del escenario simulado

El adversario Ad1 es **simulado**: no existe un servicio web vulnerable ni se prueba un RCE de acceso inicial en vivo. Consecuencias para el modelo de amenaza:

1. La única vía de entrada “real” al target es la del operador (`docker exec`); no hay superficie de red de entrada.
2. La evidencia experimental del paper se concentra en el eslabón **[2] escalada por sudo**; el eslabón **[1] acceso inicial** queda respaldado documentalmente (`docs/ATTACK-CHAIN.md` y el paper).
3. Esta limitación se declara aquí, en `SCOPE.md` (§6) y en `docs/LIMITATIONS.md`: un evaluador nunca debe descubrir por sí mismo que el vector web es simulado.

---

## 8. Supuestos

- Docker Engine + Compose y Node 22 LTS están actualizados en la máquina del equipo.
- La máquina del operador es de confianza (entorno académico, un solo equipo de trabajo).
- El contenido de `LAB_POC_DIR` proviene del comprimido provisto por el equipo (`PoC - Externos.rar`, con `poc_32463.sh` y `poc_32462.sh`) y se revisa antes de ejecutarse.
- No hay requisitos de hardening del host más allá de los controles definidos en el compose.

---

## 9. Referencias cruzadas

- `docs/SCOPE.md` — decisión de escenario simulado (§6) y glosario de estados (§7).
- `SECURITY.md` — riesgos del laboratorio y política de manejo del PoC.
- `docs/ATTACK-CHAIN.md` — cadena representada end-to-end y mapeo MITRE ATT&CK: *Initial Access* / *Execution* (representados) y *Privilege Escalation* (núcleo experimental del lab).
