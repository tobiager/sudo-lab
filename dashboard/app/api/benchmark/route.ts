import { NextResponse } from "next/server";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const pexec = promisify(execFile);

/* =============================================================================
 *  /api/benchmark — botón "④ Lanzar Ataque"
 * -----------------------------------------------------------------------------
 *  Ejecuta el arnés de medición dentro del target y parsea su TSV:
 *      docker exec <container> bash /opt/lab/scripts/benchmark.sh
 *
 *  Por qué corre como root (SIN `docker exec -u`, al contrario que
 *  /api/foothold): benchmark.sh es el ARNÉS, no la vista del atacante. El
 *  script necesita root para degradar al usuario de cada PoC con `su` en cada
 *  iteración y para leer /root/ (criterio de éxito por marcador, METRICS M3).
 *  El PoC en cambio SIEMPRE corre como usuario raso (identidad por sidecar
 *  `.user`) — esa degradación es responsabilidad del script.
 *
 *  Por qué NO reutiliza runInLab() de lib/lab.ts: ese runner tiene el timeout
 *  pensado para scan/mitigate (60 s). Un benchmark realista puede insumir
 *  N × (timeout+gracia) × PoCs — con los defaults 5 × 35 s × 2 ≈ 350 s — así
 *  que esta ruta impone su propio límite mayor (BENCH_TIMEOUT_MS) y mantiene
 *  el contrato de lib/lab.ts intacto.
 *
 *  TSV que consume (contrato METRICS.md §5; el nombre del
 *  PoC viaja como ÚLTIMO campo, misma técnica que `scope` en las líneas F):
 *    POCDIR\t<dir>
 *    POC_NO_DISPONIBLE                                  (si no hay *.sh)
 *    B\t<iter> <exito 0|1> <ms> <estado> <poc>          (una por iteración)
 *    BAGG\t<exito> <total> <media> <min> <max> <poc>    (una por PoC)
 *
 *  Respuesta 200 (con PoC):
 *    { container, disponible: true, pocDir, iterations, aggregate, log }
 *  Respuesta 200 (sin PoC — NO es un error de infraestructura, es el estado
 *  POC_NO_DISPONIBLE del glosario METRICS §1; el script sale 0):
 *    { container, disponible: false, pocDir, message, log }
 *  Errores → 502 con mensaje accionable, misma taxonomía que runInLab.
 * ========================================================================== */

// Misma convención que status/foothold/poc y lib/lab.ts.
const CONTAINER = process.env.LAB_CONTAINER ?? "sudo-lab-target";

// Misma barrera que lib/lab.ts: regex de nombre de contenedor válido.
// execFile no pasa por shell (no hay inyección posible); la regex diagnostica
// rápido un .env roto con un mensaje claro, no es una defensa.
const CONTAINER_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9_.-]*$/;

const BENCHMARK = "/opt/lab/scripts/benchmark.sh";

/**
 * Presupuesto de tiempo del request (ms). Peor caso con los defaults del
 * arnés: 2 PoCs × 5 iteraciones × (30 s de timeout + 5 s de gracia) = 350 s;
 * con los topes del script (2 PoCs ya viene del rar; 50 iter × 305 s) la cota
 * realista queda muy por debajo de 900 s. Si se supera, execFile mata el
 * docker exec y caemos a la rama DOCKER_INACCESIBLE (timeout) → 502.
 */
const BENCH_TIMEOUT_MS = 900_000;

/* ---- Contratos estructurales (los tipos los replica page.tsx por estructura)
 * ------------------------------------------------------------------------- */

export type BenchIterStatus = "EXPLOTABLE" | "MITIGADO" | "TIMEOUT" | "ERROR";

export type BenchIter = {
  poc: string;
  iter: number;
  success: boolean;
  ms: number;
  status: BenchIterStatus;
};

export type BenchAgg = {
  poc: string;
  successes: number;
  total: number;
  /** Tasa de éxito en %, 1 decimal (métrica M3: successes/total × 100). */
  ratePct: number;
  avgMs: number;
  minMs: number;
  maxMs: number;
};

/** Error tipado para un TSV vacío o con registros no reconocibles. */
class ParseBenchmarkError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ParseBenchmarkError";
  }
}

/** Limpia códigos ANSI y descarta líneas vacías (mismo criterio que lib.ts). */
function toLogLines(raw: string): string[] {
  return raw
    .replace(/\x1b\[[0-9;]*m/g, "")
    .split("\n")
    .filter((l) => l.trim().length > 0);
}

/* ---- Parser del TSV B/BAGG ------------------------------------------------- */

const ITER_STATES: ReadonlySet<string> = new Set([
  "EXPLOTABLE",
  "MITIGADO",
  "TIMEOUT",
  "ERROR",
]);

function asInt(v: string | undefined, campo: string, linea: string): number {
  const n = Number(v);
  if (v === undefined || !Number.isInteger(n) || n < 0) {
    throw new ParseBenchmarkError(
      `Campo ${campo} no es un entero válido en "${linea.slice(0, 120)}" (valor: ${JSON.stringify(v)})`
    );
  }
  return n;
}

/** Número con decimales (sólo la media de BAGG viaja con una décima). */
function asNum(v: string | undefined, campo: string, linea: string): number {
  const n = Number(v);
  if (v === undefined || !Number.isFinite(n)) {
    throw new ParseBenchmarkError(
      `Campo ${campo} no es un número válido en "${linea.slice(0, 120)}" (valor: ${JSON.stringify(v)})`
    );
  }
  return n;
}

function round1(n: number): number {
  return Math.round(n * 10) / 10;
}

export type BenchmarkParsed = {
  pocDir: string | null;
  disponible: boolean;
  iterations: BenchIter[];
  aggregate: BenchAgg[];
};

/**
 * Parsea el TSV del arnés. Estricto a propósito (mismo criterio que parseScan):
 * una salida sin registros B/BAGG o con líneas desconocidas NO es un
 * benchmark "con 0 resultados", es un fallo de contrato (script viejo,
 * volumen sin montar, salida contaminada) y se reporta como tal.
 */
function parseBenchmark(stdout: string): BenchmarkParsed {
  const iterations: BenchIter[] = [];
  const aggregate: BenchAgg[] = [];
  let pocDir: string | null = null;
  let sawNoDisponible = false;
  let sawRunRecord = false;

  for (const rawLine of stdout.split("\n")) {
    const line = rawLine.replace(/\r$/, ""); // tolera CRLF
    if (line.length === 0) continue;
    const f = line.split("\t");

    if (f[0] === "POCDIR") {
      pocDir = f[1] ?? null;
    } else if (f[0] === "POC_NO_DISPONIBLE") {
      sawNoDisponible = true;
    } else if (f[0] === "B") {
      // B <iter> <exito 0|1> <ms> <estado> <poc>   (poc = extensión v2, campo 6)
      sawRunRecord = true;
      const exito = asInt(f[2], "exito", line);
      if (exito !== 0 && exito !== 1) {
        throw new ParseBenchmarkError(`Campo exito debe ser 0|1 en "${line.slice(0, 120)}"`);
      }
      const estado = f[4] ?? "";
      if (!ITER_STATES.has(estado)) {
        throw new ParseBenchmarkError(
          `Estado de iteración no reconocido en "${line.slice(0, 120)}" (valor: ${JSON.stringify(estado)})`
        );
      }
      iterations.push({
        poc: f[5] ?? "",
        iter: asInt(f[1], "iter", line),
        success: exito === 1,
        ms: asInt(f[3], "ms", line),
        status: estado as BenchIterStatus,
      });
    } else if (f[0] === "BAGG") {
      // BAGG <exito> <total> <media> <min> <max> <poc>   (poc = campo 7, v2)
      sawRunRecord = true;
      const successes = asInt(f[1], "exitos", line);
      const total = asInt(f[2], "total", line);
      if (total < 1) {
        throw new ParseBenchmarkError(`BAGG con total=0 es un contrato inválido: "${line.slice(0, 120)}"`);
      }
      if (successes > total) {
        throw new ParseBenchmarkError(
          `BAGG con exitos (${successes}) > total (${total}): "${line.slice(0, 120)}"`
        );
      }
      const poc = f[6] ?? "";
      aggregate.push({
        poc,
        successes,
        total,
        // La tasa la calcula la RUTA (no viaja en el TSV): M3 = exitos/total × 100.
        ratePct: round1((successes / total) * 100),
        avgMs: asNum(f[3], "media_ms", line),
        minMs: asInt(f[4], "min_ms", line),
        maxMs: asInt(f[5], "max_ms", line),
      });
    } else {
      throw new ParseBenchmarkError(
        "La salida de benchmark.sh contiene un registro no reconocido " +
          `(se esperaba POCDIR/POC_NO_DISPONIBLE/B/BAGG): ${JSON.stringify(line.slice(0, 120))}`
      );
    }
  }

  if (!sawRunRecord && !sawNoDisponible) {
    throw new ParseBenchmarkError(
      "La salida de benchmark.sh no contiene registros TSV (B/BAGG/" +
        "POC_NO_DISPONIBLE): versión de script desactualizada o ejecución " +
        `fallida. stdout recibido: ${JSON.stringify(stdout.slice(0, 200))}`
    );
  }

  return { pocDir, disponible: sawRunRecord, iterations, aggregate };
}

/* ---- POST ------------------------------------------------------------------- */

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

  let stdout = "";
  let stderr = "";
  try {
    // execFile SIN shell: cada argumento va literal, no hay interpolación.
    // SIN `-u`: el arnés corre como root del contenedor y él mismo degrada a
    // webuser por iteración (ver justificación en el encabezado).
    const res = await pexec("docker", ["exec", CONTAINER, "bash", BENCHMARK], {
      maxBuffer: 10 * 1024 * 1024,
      timeout: BENCH_TIMEOUT_MS,
    });
    stdout = res.stdout;
    stderr = res.stderr;
  } catch (err) {
    // Misma taxonomía que runInLab y /api/foothold:
    // distinguir infraestructura (contenedor/daemon) del script en sí.
    const e = err as {
      code?: number | string;
      stdout?: string;
      stderr?: string;
      message?: string;
      killed?: boolean;
    };
    stderr = e.stderr ?? "";
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
      // Caso específico de esta ruta: benchmark.sh no integrado todavía.
      if (/No such file or directory/i.test(combined)) {
        return NextResponse.json(
          {
            error:
              "No se encontró scripts/benchmark.sh dentro del target (¿copiaste el " +
              "script al repo? ¿está montado ./scripts en /opt/lab/scripts?). " +
              `Detalle: ${stderr.slice(0, 300) || "(sin stderr)"}`
          },
          { status: 502 }
        );
      }
      // El arnés only sale != 0 por guardias de infraestructura (sin root,
      // sin webuser): reportarlo como error del laboratorio con detalle.
      return NextResponse.json(
        {
          error:
            `benchmark.sh terminó con exit ${exitCode} (¿guardia anti-no-root o ` +
            `webuser ausente?). Detalle: ${stderr.slice(0, 500) || "(sin stderr)"}`
        },
        { status: 502 }
      );
    }

    // Sin código de salida: docker inexistente, daemon no responde o timeout.
    const detail = e.killed
      ? `timeout tras ${BENCH_TIMEOUT_MS / 1000} s (¿N o timeout demasiado altos para este request?)`
      : (e.message ?? "error desconocido");
    return NextResponse.json(
      {
        error:
          `No se pudo ejecutar docker exec sobre "${CONTAINER}" para el benchmark. ` +
          `¿Docker instalado y daemon corriendo? Detalle: ${detail}`
      },
      { status: 502 }
    );
  }

  // Guard de salida vacía: el arnés SIEMPRE imprime al menos POCDIR.
  if (stdout.trim().length === 0) {
    return NextResponse.json(
      {
        error:
          "benchmark.sh no produjo salida. ¿Está montado ./scripts en " +
          `/opt/lab/scripts dentro de "${CONTAINER}"? ¿Es la versión nueva del script?`
      },
      { status: 502 }
    );
  }

  const log = toLogLines(stderr);

  let parsed: BenchmarkParsed;
  try {
    parsed = parseBenchmark(stdout);
  } catch (err) {
    // Contrato TSV roto: 502 con la evidencia, no un "0 resultados" silencioso.
    const message = err instanceof Error ? err.message : "Error desconocido";
    return NextResponse.json({ error: message }, { status: 502 });
  }

  if (!parsed.disponible) {
    // Estado de negocio, no error: el operador todavía no colocó PoCs.
    return NextResponse.json({
      container: CONTAINER,
      disponible: false,
      pocDir: parsed.pocDir,
      message:
        "POC_NO_DISPONIBLE: no hay scripts *.sh en el directorio de PoCs. " +
        "Colocalos (ver docs/POC.md) y volvé a lanzar.",
      log,
    });
  }

  return NextResponse.json({
    container: CONTAINER,
    disponible: true,
    pocDir: parsed.pocDir,
    iterations: parsed.iterations,
    aggregate: parsed.aggregate,
    log,
  });
}
