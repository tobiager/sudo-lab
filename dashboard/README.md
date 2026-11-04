# Dashboard — sudo-lab

Panel web (Next.js 15 + Tailwind v4) para operar el laboratorio y ver los logs del
contenedor en vivo. Escucha solo en `localhost` — nunca exponerlo (`SECURITY.md` §2.4).

## Correr

```bash
npm install
npm run dev
# http://localhost:3000
```

El contenedor objetivo debe estar levantado (`docker compose up -d --build --wait` desde la
raíz del repo). Node 22 LTS (versión fijada en `.nvmrc`).

## Cómo funciona

- `app/page.tsx` — UI: botones ① Diagnosticar / ② Simular foothold / ③ Mitigar +
  re-escanear / ④ Lanzar ataque / ↺ Restaurar, hallazgos agrupados por scope
  (foco/histórica) y consola de logs con coloreado por nivel.
- `app/api/scan/route.ts` y `app/api/mitigate/route.ts` — diagnóstico y mitigación
  (incluye `--reset` según el body).
- `app/api/foothold/route.ts` — ejecuta `foothold.sh` como `webuser` (acceso inicial
  simulado).
- `app/api/benchmark/route.ts` — arnés de medición del PoC externo (botón ④).
- `app/api/poc/route.ts` — sonda de disponibilidad (`benchmark.sh --check`, no ejecuta
  nada): habilita/deshabilita el botón ④.
- `app/api/status/route.ts` — estado del contenedor (polling).
- `lib/lab.ts` — runner `docker exec` (vía `execFile`, sin shell) con errores tipados y
  `parseScan` del TSV. No interpola entrada del usuario: el nombre de contenedor
  (`LAB_CONTAINER`) se valida por regex al arrancar el módulo.

## Variables de entorno (opcional)

- `LAB_CONTAINER` — nombre del contenedor objetivo (default: `sudo-lab-target`).
