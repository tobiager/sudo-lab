<div align="center">

<img src="assets/banner.png" width="1000" alt="sudo-lab">

<h1 align="center">sudo-lab</h1>

**Laboratorio reproducible de diagnóstico y mitigación de vulnerabilidades de `sudo`.**

[![Licencia MIT](https://img.shields.io/badge/licencia-MIT-green.svg)](LICENSE)
[![Debian 12](https://img.shields.io/badge/target-Debian%2012-A81D33?logo=debian&logoColor=white)](lab/Dockerfile)
[![sudo 1.9.15](https://img.shields.io/badge/sudo-1.9.15%20(vulnerable)-red.svg)](lab/Dockerfile)
[![Docker Compose](https://img.shields.io/badge/Docker-Compose%20v2-2496ED?logo=docker&logoColor=white)](docker-compose.yml)
[![Next.js 15](https://img.shields.io/badge/dashboard-Next.js%2015-black?logo=nextdotjs&logoColor=white)](dashboard/)
[![CVEs](https://img.shields.io/badge/CVEs-2025--32463%20%7C%2032462-orange.svg)](docs/SCOPE.md)

</div>

Anexo práctico del trabajo de investigación *"Bugs en sudo: escalada de
privilegios local, diagnóstico en laboratorio y mitigación"* (Redes de Datos /
Software Seguro, Licenciatura en Sistemas de Información, UNNE – FaCENA).

> [!WARNING]
> Este repositorio contiene un contenedor **intencionalmente vulnerable** (`sudo` real
> sin parchear). Está pensado **solo para uso local, educativo y defensivo**: se ejecuta
> en tu máquina, sin exponer puertos ni atacar sistemas de terceros. No lo despliegues en
> un host accesible desde la red. Reglas completas en [`SECURITY.md`](SECURITY.md).

<details>
<summary><b>English summary</b></summary>

`sudo-lab` is a reproducible, intentionally vulnerable Docker lab (Debian 12, `sudo 1.9.15`
built from source) for an academic paper on local privilege escalation in `sudo`. It
**diagnoses** per-CVE exposure, **simulates** initial access, applies compensating
**mitigations** without patching, and optionally **benchmarks** success rate and escalation
time of operator-supplied PoCs — before and after mitigation. Focus CVEs: CVE-2025-32463
(chroot/NSS) and CVE-2025-32462 (host option), plus three historical CVEs for context. A
local-only Next.js dashboard orchestrates everything over `docker exec`. The repo ships **no
exploits**.

</details>

## Qué es

Un contenedor Docker **intencionalmente vulnerable** (Debian 12, `sudo 1.9.15` compilado
desde fuente) más tres instrumentos defensivos que corren dentro de él:

- **`scan.sh` — Diagnóstico de exposición (①):** determina, CVE por CVE, si el sistema es
  explotable combinando versión + precondiciones reales. No explota nada.
- **`mitigate.sh` — Mitigación (③):** aplica controles compensatorios sin parchear
  (hardening de sudoers + `/tmp noexec`) y verifica con re-scan; `--reset` restaura el
  estado vulnerable.
- **`benchmark.sh` — Medición (④, opcional):** mide tasa de éxito y tiempo de escalada de
  un PoC externo provisto por el operador, antes y después de mitigar.

El acceso inicial se **simula** con el usuario `webuser` (`foothold.sh`, ②): no hay
servicio web ni payload de RCE — la cadena se narra en
[`docs/ATTACK-CHAIN.md`](docs/ATTACK-CHAIN.md). Un dashboard (Next.js 15, solo
`localhost:3000`) orquesta todo vía `docker exec`.

**Alcance:** 2 CVEs foco (CVE-2025-32463 chroot/NSS, CVE-2025-32462 opción host) y 3
CVEs históricas como contexto (2023-22809, 2021-3156, 2019-14287). Definiciones
operativas y glosario de estados: [`docs/SCOPE.md`](docs/SCOPE.md) (normativo).

**PoC externos (Opción B):** el repositorio versionado **no distribuye exploits**
(política en [`SECURITY.md`](SECURITY.md) §3). El operador coloca `poc_32463.sh` y
`poc_32462.sh` en `./poc/` (en el paquete de entrega viajan como `poc/*.txt`); sin PoC,
el benchmark reporta `POC_NO_DISPONIBLE` y el modo diagnóstico + mitigación es igualmente
funcional.

## Resultados en una corrida

Corrida completa pre/post mitigación (2 PoC × 5 iteraciones cada uno; cifras y protocolo en
[`docs/RESULTS.md`](docs/RESULTS.md)):

| | Diagnóstico (M2) | Escaladas a root (M3) |
|---|---|---|
| **Antes de mitigar** | `CVE-2025-32463` y `CVE-2025-32462` → `EXPLOTABLE` | **10/10 (100 %)** |
| **Después de mitigar** | ambas → `MITIGADO` | **0/10 (0 %)** |

Los controles son compensatorios (hardening de sudoers + `/tmp noexec`), sin actualizar el
binario: rompen el exploit, no el arnés de medición. La mitigación completa sigue siendo
actualizar a `sudo 1.9.17p1` o superior.

<table>
<tr>
<td align="center"><b>① Antes — <code>EXPLOTABLE</code></b></td>
<td align="center"><b>③ Después — <code>MITIGADO</code></b></td>
</tr>
<tr>
<td><img src="assets/diagnostico-explotable.png" alt="Dashboard: 2 CVEs EXPLOTABLE"></td>
<td><img src="assets/mitigacion-aplicada.png" alt="Dashboard: 2 CVEs MITIGADO"></td>
</tr>
</table>

## Requisitos

- Docker + Docker Compose v2 (puede verificarse con `make preflight`)
- Node.js 22 LTS (solo para el dashboard; versión fijada en `dashboard/.nvmrc`)

## Puesta en marcha

```bash
docker compose up -d --build --wait    # o: make up   (compila sudo y espera healthy)

cd dashboard && npm install && npm run dev    # http://localhost:3000
```

Flujo sugerido en el panel: **① Diagnosticar** → **② Simular foothold** →
**③ Aplicar mitigaciones + re-escanear** (los hallazgos pasan de `EXPLOTABLE` a
`MITIGADO`) → comparar → **↺ Restaurar** para repetir la demo. El botón **④ Lanzar
ataque** se habilita solo con PoC presente en `./poc/`.

Por consola, los mismos comandos son `make scan | foothold | mitigate | reset | benchmark`
(`make help` lista todo). En Windows (Docker Desktop) no se necesita `make`: tabla de
equivalencias en [`docs/REPRODUCIBILITY.md`](docs/REPRODUCIBILITY.md) §3.1.

Para **reproducir las tablas de resultados** completas (protocolo de medición pre/post,
pasos A–G): [`docs/REPRODUCIBILITY.md`](docs/REPRODUCIBILITY.md). Problemas frecuentes:
§6 de ese mismo documento.

## Documentación

| Documento | Contenido |
|---|---|
| [`docs/SCOPE.md`](docs/SCOPE.md) | Alcance, glosario de estados y criterio de "mitigado" (**normativo**) |
| [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) | Activos, adversarios y fronteras de confianza |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Componentes, flujos de datos y decisiones de diseño |
| [`docs/ATTACK-CHAIN.md`](docs/ATTACK-CHAIN.md) | Cadena de ataque representada y mapeo MITRE ATT&CK |
| [`docs/METRICS.md`](docs/METRICS.md) | Contrato de métricas: definiciones, fórmulas y formato TSV |
| [`docs/METHODOLOGY.md`](docs/METHODOLOGY.md) | Protocolo de medición (cómo se producen los datos) |
| [`docs/RESULTS.md`](docs/RESULTS.md) | **Resultados empíricos** (fuente única de cifras y tablas) |
| [`docs/REPRODUCIBILITY.md`](docs/REPRODUCIBILITY.md) | Pasos exactos para replicar cada tabla + troubleshooting |
| [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md) | Limitaciones con ID citable (L-1…L-16) para el paper |
| [`docs/POC.md`](docs/POC.md) | Fuentes, adaptación y convención `.user` de los PoC externos |
| [`SECURITY.md`](SECURITY.md) | Reglas de uso seguro, capabilities del contenedor (§2.2) y política del PoC (§3) |

## Estructura del repositorio

```
sudo-lab/
├── docker-compose.yml        # orquestación del target (cap_drop ALL + 7 capabilities)
├── Makefile                  # interfaz única de comandos (up/scan/mitigate/…)
├── lab/                      # Dockerfile (sudo vulnerable + HEALTHCHECK), entrypoint, sudoers
├── scripts/                  # scan · mitigate · foothold · benchmark · preflight (montados :ro)
├── dashboard/                # Next.js 15: UI + API routes (docker exec)
│   └── lib/lab.ts            # runner + parser del TSV
├── poc/                      # PoC externos (sin versionar; en la entrega: poc_*.txt)
└── docs/                     # documentación académica (índice arriba)
```

## Uso responsable

Proyecto **educativo y defensivo**: se ejecuta en máquina local, dentro de los contenedores de
este repo, sin exponer puertos ni atacar sistemas de terceros. Reglas completas en
[`SECURITY.md`](SECURITY.md). La mitigación completa de las CVEs de 2025 es actualizar a
`sudo 1.9.17p1` o posterior; los controles del lab son compensatorios para escenarios
legacy.

## Cómo citar

Si usás este laboratorio o sus resultados, citá el trabajo asociado:

```bibtex
@misc{sudolab2026,
  author       = {Orban, Tobias Naim and Esquenon, Ignacio Agustín and
                  Gomez, Sebastian Exequiel and Llopi, Alvaro Benjamin},
  title        = {Bugs en sudo: escalada de privilegios local,
                  diagnóstico en laboratorio y mitigación},
  year         = {2026},
  institution  = {Facultad de Ciencias Exactas y Naturales y Agrimensura (FaCENA),
                  Universidad Nacional del Nordeste (UNNE), Corrientes, Argentina},
  note         = {Redes de Datos / Software Seguro,
                  Licenciatura en Sistemas de Información. Anexo práctico: sudo-lab},
  howpublished = {\url{https://github.com/tobiager/sudo-lab}}
}
```

> Completá autores y la URL del repositorio según corresponda.

## Licencia

Código bajo licencia MIT (ver [`LICENSE`](LICENSE)); los PoC de terceros no forman parte del repositorio y no están cubiertos por esta licencia.
