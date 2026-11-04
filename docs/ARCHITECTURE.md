# Arquitectura — `ARCHITECTURE.md`

Describe los componentes del laboratorio y sus flujos de datos. Las capabilities y su
justificación viven en `SECURITY.md` §2.2; los pasos de ejecución, en
`docs/REPRODUCIBILITY.md`; las limitaciones, en `docs/LIMITATIONS.md`.

---

## 1. Visión general

```
                        HOST del operador (confiable)
┌──────────────────────────────────────────────────────────────────────────┐
│  Dashboard (Next.js 15 · React 18 · Tailwind 4 · Node 22)                │
│  http://localhost:3000                                                   │
│  ① Diagnosticar  ② Simular foothold  ③ Mitigar + re-scan                 │
│  ④ Lanzar ataque (requiere PoC externo)  ↺ Restaurar                     │
│        │                                                                 │
│        │ docker exec (execFile, lib/lab.ts)                              │
│        ▼                                                                 │
│  ┌─────────────────────────────┐      ┌───────────────────────────────┐  │
│  │ Contenedor sudo-lab-target  │      │ LAB_POC_DIR (host, opcional)  │  │
│  │ Debian 12 · sudo 1.9.15     │ ◄:ro─│ poc_32463.sh · poc_32462.sh   │  │
│  │ hostname: srv-web           │      │ (de «PoC - Externos.rar»)     │  │
│  │ /opt/lab/scripts            │      └───────────────────────────────┘  │
│  │ scan · mitigate · foothold  │                                         │
│  │ · benchmark                 │                                         │
│  └─────────────────────────────┘                                         │
└──────────────────────────────────────────────────────────────────────────┘
```

El dashboard **nunca "ataca"**: ejecuta los scripts del laboratorio dentro del contenedor mediante `docker exec` y renderiza el resultado. El PoC externo es opcional y de solo lectura.

---

## 2. Componentes

### 2.1 Contenedor target — `sudo-lab-target`

| Aspecto | Detalle |
|---|---|
| Imagen | `debian:12-slim@sha256:99c0b25c46d0214d5a2091092e7908907dcaecd6a962cde0ac700acee222b6f3` (digest pinneado); tarball de sudo verificado contra el archivo `SHA256` oficial de sudo.ws antes de compilar |
| sudo | `1.9.15` compilado desde fuente con `--prefix=/usr` (parametrizable con `SUDO_VERSION`; rango vulnerable a CVE-2025-32463: 1.9.14–1.9.17) |
| Hostname | `srv-web`; en el sudoers de laboratorio existe la regla calificada para `clinica-legacy` (señal de CVE-2025-32462) |
| Usuarios | `webuser` (foothold simulado, **sin reglas de sudo** a propósito), `operador`, `auditor`, `editor` (portan las señales de configuración de las CVEs) |
| sudoers | `lab/sudoers.lab` instalado en `/etc/sudoers.d/lab`; copia prístina en `/opt/lab/sudoers.lab.orig` para el `--reset` |
| `/tmp` | tmpfs `exec,mode=1777`; `mitigate.sh` lo remonta `noexec,nosuid,nodev` como control compensatorio (por eso el target necesita `SYS_ADMIN`) |
| Scripts | Montados como volumen `./scripts:/opt/lab/scripts:ro` (edición sin rebuild); sin `VOLUME` en el Dockerfile |
| Entrypoint | Crea usuarios, instala y valida el sudoers (`visudo -c` global); el contenedor vuelve al estado vulnerable al reiniciarse |
| Salud | `HEALTHCHECK` con `visudo -c -q`: el estado `healthy` certifica sudoers válido, no solo proceso vivo |
| Capabilities | `cap_drop: [ALL]` + lista blanca de **7 capabilities** — contrato de validez experimental especificado en `SECURITY.md` §2.2 (cada una documenta qué se rompe al eliminarla) |

### 2.2 Dashboard (en el host)

| Aspecto | Detalle |
|---|---|
| Stack | Next.js 15.1, React 18.3, Tailwind 4, TypeScript 5.7 sobre **Node 22 LTS** (`.nvmrc` en `dashboard/` y `engines >= 22.0.0`) |
| API | `POST /api/scan`, `POST /api/mitigate`, `POST /api/foothold`, `POST /api/benchmark`, `GET /api/status`, `GET /api/poc` |
| `lib/lab.ts` | `runInLab` (`docker exec` vía `execFile`, timeout, maxBuffer); errores tipados: contenedor ausente → **502 con mensaje claro**; `parseScan` consume el TSV `V`/`F`/`S`; `LAB_CONTAINER` validado por regex |
| Botones | ① Diagnosticar · ② Simular foothold (acceso inicial narrado, sin explotar nada) · ③ Aplicar mitigaciones + re-scan · ④ Lanzar ataque — **habilitado solo si `GET /api/poc` informa `disponible: true`** · ↺ Restaurar |
| Exposición | Solo `localhost`; nunca `0.0.0.0` (`SECURITY.md` §2.4) |

### 2.3 PoC externo opcional (Opción B)

1. El equipo provee el comprimido **`PoC - Externos.rar`**, que contiene únicamente `poc_32463.sh` y `poc_32462.sh` (CVEs foco).
2. El operador extrae los scripts en `./poc` (directorio del repo **sin versionar**); pasos exactos en `docs/REPRODUCIBILITY.md` §4 paso B.
3. `docker-compose.yml` monta `./poc` en `/opt/lab/poc:ro` y fija `LAB_POC_DIR=/opt/lab/poc` dentro del contenedor.
4. `benchmark.sh` itera `N` veces por PoC con la identidad del sidecar `.user`, mide éxito y tiempo (`docs/METRICS.md`) y reporta `POC_NO_DISPONIBLE` si el directorio está vacío o ausente.
5. El repositorio versionado **no incluye** ningún PoC; solo documenta cómo obtenerlos, adaptarlos y medirlos (`docs/POC.md`) y cómo se manejan internamente (`SECURITY.md` §3).

### 2.4 Orquestación — `docker-compose.yml`

| Aspecto | Valor |
|---|---|
| Servicio | `target` único, red `labnet` (bridge), sin puertos publicados |
| Capabilities | `cap_drop: [ALL]` + `cap_add: [CHOWN, DAC_OVERRIDE, FOWNER, SETGID, SETUID, SYS_ADMIN, SYS_CHROOT]` |
| `init` | `init: true` (docker-init como PID 1, recolección de zombis) |
| Healthcheck | `HEALTHCHECK` con `visudo -c -q` en `lab/Dockerfile`; `docker compose up --wait` espera a `healthy` |
| Volúmenes | `./scripts:/opt/lab/scripts:ro` + `./poc:/opt/lab/poc:ro`; sin `VOLUME` en el Dockerfile |
| tmpfs | `/tmp:exec,mode=1777` (precondición de CVE-2025-32463 en el estado vulnerable) |

La lista de capabilities es un **contrato de validez experimental**: la lección `SYS_CHROOT` (por qué quitar una capability invalida la medición sin ningún error visible) está especificada en `SECURITY.md` §2.2.

---

## 3. Flujos de datos

1. **Diagnóstico:** `scan.sh` → TSV (`V`/`F`/`S` + `scope`) → `parseScan` → hallazgos y resumen en la UI.
2. **Foothold simulado:** `POST /api/foothold` → `docker exec -u webuser … foothold.sh` → logs con tipo propio (`foot`) en la consola del panel. No hay servicio web: el vector se narra en `docs/ATTACK-CHAIN.md`.
3. **Mitigación:** `mitigate.sh` → `MITIGATE_OK` → re-scan automático → comparación de estados antes/después (`EXPLOTABLE` → `MITIGADO`).
4. **Benchmark:** `benchmark.sh` → TSV `B`/`BAGG` → vista por iteración + agregados (tasa, media, mín, máx) → comparación pre/post mitigación.

---

## 4. Decisiones de seguridad embebidas en la arquitectura

- Capabilities al mínimo con `cap_drop: [ALL]` y reintroducción justificada: **especificación completa en `SECURITY.md` §2.2**.
- El target queda exceptuado de `no-new-privileges` por diseño (sudo es setuid); cualquier servicio auxiliar futuro lo llevará activado (`SECURITY.md` §2.3).
- `visudo -c` global al arranque del contenedor: un sudoers roto marca `unhealthy` en lugar de fallar silenciosamente durante la demo (`SECURITY.md` §4).
- Dashboard sin auth pero confinado a `localhost`; el target sin puertos publicados (`SECURITY.md` §2.1, `docs/THREAT-MODEL.md`).
- Integridad de la cadena de suministro: imagen base pinneada por digest, tarball de sudo verificado contra el `SHA256` oficial antes de compilar (valores en `docs/REPRODUCIBILITY.md` §2).

---

## 5. Límites de la arquitectura

- **Escenario web simulado:** no existe contenedor web ni `Dockerfile.web`; `webuser` representa el foothold (decisión de alcance, `docs/SCOPE.md` §6).
- **Un solo target:** no hay múltiples versiones de sudo corriendo en paralelo; cambiar de versión implica cambiar `SUDO_VERSION` y reconstruir (la verificación del tarball se adapta automáticamente vía el archivo `SHA256` oficial).
- **PoC no interactivo:** el benchmark asume PoCs no interactivos con timeout de 30 s por iteración.
- **El digest pinneado envejece:** `debian:12-slim` se reconstruye periódicamente upstream; actualizar el digest es una decisión consciente que debe reflejarse en `docs/REPRODUCIBILITY.md` §2.
- Las limitaciones completas (con IDs L-x citables) están en `docs/LIMITATIONS.md`.
