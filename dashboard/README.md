# Dashboard — sudo-lab

Panel web (Next.js 15 + Tailwind v4) para operar el laboratorio y ver los logs del
contenedor en vivo.

## Correr

```bash
npm install
npm run dev
# http://localhost:3000
```

El contenedor objetivo debe estar levantado (`docker compose up -d` desde la raíz del
repo). El dashboard ejecuta los scripts del lab vía `docker exec` contra
`sudo-lab-target`.

## Cómo funciona

- `app/page.tsx` — UI: botones Verificar / Mitigar / Reset + consola de logs con
  coloreado por nivel ([VULN], [OK], [WARN]) y estado del contenedor.
- `app/api/{verify,mitigate,reset}/route.ts` — endpoints que disparan cada script.
- `app/api/status/route.ts` — estado del contenedor (polling cada 4 s).
- `lib/runner.ts` — ejecuta `docker exec` con una **lista blanca** de scripts
  (`verify`, `mitigate`, `reset`). No interpola entrada del usuario, para evitar
  inyección de comandos.

## Variables de entorno (opcional)

- `SUDO_LAB_CONTAINER` — nombre del contenedor objetivo (default: `sudo-lab-target`).
