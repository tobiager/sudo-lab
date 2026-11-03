import { NextResponse } from "next/server";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const pexec = promisify(execFile);

/* =============================================================================
 *  /api/foothold — botón "② Simular foothold"
 * -----------------------------------------------------------------------------
 *  Ejecuta scripts/foothold.sh DENTRO del contenedor, como webuser:
 *      docker exec -u webuser <container> bash /opt/lab/scripts/foothold.sh
 *
 *  Por qué NO reutiliza runInLab() de lib/lab.ts: ese runner corre los
 *  scripts como usuario por defecto (root), que es lo correcto para scan.sh
 *  y mitigate.sh. El foothold, en cambio, DEBE correr como usuario raso:
 *  todo su valor pedagógico es mostrar qué ve el atacante tras el acceso
 *  inicial (docs/SCOPE.md §6). Por eso esta ruta tiene su propio
 *  `docker exec -u webuser`, replicando los mismos criterios de seguridad y
 *  de error que el runner de lib/lab.ts (taxonomía abajo).
 *
 *  Respuesta 200: { action: "foothold", user: "webuser", log: string[] }
 *  `log` es la salida completa de foothold.sh; el panel la muestra con el
 *  tipo de registro propio `foot`.
 *  Errores → 502 con mensaje accionable (nunca un "éxito" con salida vacía:
 *  mismo criterio que parseScan en lib/lab.ts).
 * ========================================================================== */

// Misma convención que status/route.ts y lib/lab.ts: override con LAB_CONTAINER.
const CONTAINER = process.env.LAB_CONTAINER ?? "sudo-lab-target";

// Usuario del foothold simulado. Debian trae 'www-data'; el lab usa
// 'webuser' para no confundirlo con el usuario de un Apache real (que no existe).
const FOOTHOLD_USER = "webuser";

// Misma barrera que lab.ts: regex de nombre de contenedor válido.
// execFile no pasa por shell (no hay inyección posible); la regex sirve para
// diagnosticar rápido un .env roto con un mensaje claro, no como defensa.
const CONTAINER_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9_.-]*$/;

/** Limpia códigos ANSI y descarta líneas vacías (mismo criterio que lib.ts). */
function toLogLines(raw: string): string[] {
  return raw
    .replace(/\x1b\[[0-9;]*m/g, "")
    .split("\n")
    .filter((l) => l.trim().length > 0);
}

export async function POST() {
  // Fail-fast de configuración del PANEL (no del laboratorio).
  if (!CONTAINER_NAME_RE.test(CONTAINER)) {
    return NextResponse.json(
      {
        error:
          `LAB_CONTAINER="${CONTAINER}" no es un nombre de contenedor válido. ` +
          "Corregí el .env o el entorno del dashboard."
      },
      { status: 500 }
    );
  }

  try {
    // execFile SIN shell: cada argumento va literal, no hay interpolación.
    const { stdout, stderr } = await pexec(
      "docker",
      ["exec", "-u", FOOTHOLD_USER, CONTAINER, "bash", "/opt/lab/scripts/foothold.sh"],
      { maxBuffer: 10 * 1024 * 1024, timeout: 60_000 }
    );

    // Guard de salida vacía: foothold.sh SIEMPRE imprime evidencia.
    // Un stdout vacío significa script viejo o volumen ./scripts sin montar
    // en /opt/lab/scripts → fallo explícito, no un log vacío "exitoso".
    const log = toLogLines(stdout);
    if (log.length === 0) {
      return NextResponse.json(
        {
          error:
            "foothold.sh no produjo salida. ¿Está montado ./scripts en " +
            `/opt/lab/scripts dentro de "${CONTAINER}"? ¿Es la versión nueva del script?`
        },
        { status: 502 }
      );
    }

    return NextResponse.json({ action: "foothold", user: FOOTHOLD_USER, log });
  } catch (err) {
    // Misma taxonomía de errores que runInLab:
    // distinguir infraestructura (contenedor/daemon/usuario) del script en sí,
    // en lugar de un único mensaje genérico.
    const e = err as {
      code?: number | string; // exit code (number) o señal (string) si fue killed
      stdout?: string;
      stderr?: string;
      message?: string;
      killed?: boolean; // true si el proceso fue terminado (timeout)
    };
    const stderr = e.stderr ?? "";
    const exitCode = typeof e.code === "number" ? e.code : undefined;

    if (exitCode !== undefined) {
      const combined = `${stderr}\n${e.message ?? ""}`;
      if (/No such container|is not running/i.test(combined)) {
        return NextResponse.json(
          {
            error:
              `El contenedor "${CONTAINER}" no existe o está detenido. ` +
              "Ejecutá: docker compose up -d --build"
          },
          { status: 502 }
        );
      }
      if (/Cannot connect to the Docker daemon|docker daemon is not running/i.test(combined)) {
        return NextResponse.json(
          {
            error:
              `No se pudo conectar con el daemon de Docker para operar "${CONTAINER}". ` +
              `¿Está levantado? Detalle: ${stderr.slice(0, 300) || "(sin stderr)"}`
          },
          { status: 502 }
        );
      }
      // Caso específico del foothold: docker exec -u falla si el usuario no existe.
      if (/unable to find user/i.test(combined)) {
        return NextResponse.json(
          {
            error:
              `El usuario "${FOOTHOLD_USER}" no existe en "${CONTAINER}" ` +
              `(¿el entrypoint creó los usuarios?). Detalle: ${stderr.slice(0, 300) || "(sin stderr)"}`
          },
          { status: 502 }
        );
      }
      return NextResponse.json(
        {
          error:
            `foothold.sh terminó con exit ${exitCode} (p. ej., la guardia anti-root ` +
            `abortó la ejecución). Detalle: ${stderr.slice(0, 500) || "(sin stderr)"}`
        },
        { status: 502 }
      );
    }

    // Sin código de salida: docker inexistente, daemon no responde o timeout.
    const detail = e.killed ? "timeout tras 60 s" : (e.message ?? "error desconocido");
    return NextResponse.json(
      {
        error:
          `No se pudo ejecutar docker exec -u ${FOOTHOLD_USER} sobre "${CONTAINER}". ` +
          `¿Docker instalado y daemon corriendo? Detalle: ${detail}`
      },
      { status: 502 }
    );
  }
}
