import { execFile } from "node:child_process";
import { promisify } from "node:util";

const pexec = promisify(execFile);

/* =============================================================================
 *  lab.ts — runner del laboratorio + parser del TSV de scan.sh
 * -----------------------------------------------------------------------------
 *  Decisiones de diseño (por qué cada mecanismo es como es):
 *    - Distinguir error de contenedor de error de script: execFile rechaza con
 *      stdout/stderr = "" (string vacío), así que la única forma fiable de
 *      clasificar el fallo es inspeccionar el código de salida y el texto del
 *      error. Un contenedor ausente NUNCA debe parsearse como un TSV vacío
 *      "exitoso".
 *    - Propagar el código de salida: exit != 0 sin patrón de contenedor
 *      => error con el stderr recortado, no un "éxito" silencioso.
 *    - Validar LAB_CONTAINER al boot del módulo (regex de nombre de
 *      contenedor Docker): valor inválido => error de configuración
 *      inmediato, no un fallo críptico en runtime.
 *    - parseScan lee el TSV v2 (campo 8 = scope, default 'historica') y
 *      lanza un error tipado (ParseScanError) si el TSV está vacío:
 *      una salida sin registros es un fallo, no un diagnóstico limpio.
 *      Tests: lab.test.ts.
 * ========================================================================== */

/* ---- Errores tipados ------------------------------------------------------- */

export type LabErrorKind =
  | "CONFIG" // LAB_CONTAINER inválido u otra mala configuración
  | "CONTENEDOR_NO_DISPONIBLE" // contenedor inexistente o detenido
  | "SCRIPT_EXIT" // el script del lab terminó con exit != 0
  | "DOCKER_INACCESIBLE"; // docker no instalado / daemon caído / timeout

export class LabError extends Error {
  readonly kind: LabErrorKind;

  constructor(kind: LabErrorKind, message: string) {
    super(message);
    this.name = "LabError";
    this.kind = kind;
  }
}

/** Error tipado para un TSV vacío o sin registros reconocibles. */
export class ParseScanError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ParseScanError";
  }
}

/* ---- Configuración del runner --------------------------------------------- */

const CONTAINER_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9_.-]*$/;

/**
 * Nombre del contenedor del laboratorio (override con LAB_CONTAINER).
 * Se valida UNA vez, al boot del módulo (al importarse esta librería), no en
 * cada request: un valor inválido —p. ej. con espacios, vacío o con caracteres
 * de shell— falla rápido con un error de configuración claro.
 * Nota: execFile no pasa por shell, así que aquí no hay inyección posible;
 * la regex es una segunda barrera y, sobre todo, diagnostica errores de
 * tipeo en el .env antes de que lleguen a producción.
 */
function labContainerName(): string {
  const raw = process.env.LAB_CONTAINER ?? "sudo-lab-target";
  if (!CONTAINER_NAME_RE.test(raw)) {
    throw new LabError(
      "CONFIG",
      `LAB_CONTAINER="${raw}" no es un nombre de contenedor válido ` +
        `(regex esperada: ${CONTAINER_NAME_RE.source}). Corregí el .env o el entorno.`
    );
  }
  return raw;
}

const CONTAINER = labContainerName();

/* ---- Runner ---------------------------------------------------------------- */

/** Ejecuta un script del laboratorio dentro del contenedor vía `docker exec`. */
export async function runInLab(
  script: "scan.sh" | "mitigate.sh",
  args: string[] = []
): Promise<{ stdout: string; stderr: string }> {
  try {
    const { stdout, stderr } = await pexec(
      "docker",
      ["exec", CONTAINER, "bash", `/opt/lab/scripts/${script}`, ...args],
      { maxBuffer: 10 * 1024 * 1024, timeout: 60_000 }
    );
    return { stdout, stderr };
  } catch (err: unknown) {
    // execFile rechaza con stdout/stderr = "" (nunca undefined): por eso la
    // clasificación del fallo se hace por código de salida y texto del error,
    // no por presencia de esos campos.
    const e = err as {
      code?: number | string; // exit code (number) o señal (string) si fue killed
      stdout?: string;
      stderr?: string;
      message?: string;
      killed?: boolean; // true si el proceso fue terminado (timeout)
    };
    const stderr = e.stderr ?? "";
    const exitCode = typeof e.code === "number" ? e.code : undefined;

    // Hay código de salida => docker corrió. Distinguimos:
    //   (a) contenedor inexistente o detenido => error de infraestructura
    //       (la ruta API responde 502 con instrucción concreta),
    //   (b) daemon de Docker caído o inalcanzable => también infraestructura,
    //   (c) script del lab con exit != 0 => error del laboratorio con detalle.
    if (exitCode !== undefined) {
      const combined = `${stderr}\n${e.message ?? ""}`;
      if (/No such container|is not running/i.test(combined)) {
        throw new LabError(
          "CONTENEDOR_NO_DISPONIBLE",
          `El contenedor "${CONTAINER}" no existe o está detenido. ` +
            `Ejecutá: docker compose up -d --build`
        );
      }
      if (/Cannot connect to the Docker daemon|docker daemon is not running/i.test(combined)) {
        throw new LabError(
          "DOCKER_INACCESIBLE",
          `No se pudo conectar con el daemon de Docker para operar "${CONTAINER}". ` +
            `¿Está levantado? Detalle: ${stderr.slice(0, 300) || "(sin stderr)"}`
        );
      }
      throw new LabError(
        "SCRIPT_EXIT",
        `${script} terminó con exit ${exitCode}. ` +
          `Detalle: ${stderr.slice(0, 500) || "(sin stderr)"}`
      );
    }

    // Sin código de salida: el binario docker no existe, el daemon no responde,
    // o se agotó el timeout (killed). No es un fallo del script del lab.
    const detail = e.killed ? "timeout tras 60 s" : (e.message ?? "error desconocido");
    throw new LabError(
      "DOCKER_INACCESIBLE",
      `No se pudo ejecutar docker exec sobre "${CONTAINER}". ` +
        `¿Docker instalado y daemon corriendo? Detalle: ${detail}`
    );
  }
}

/* ---- Tipos del TSV v2 ----------------------------------------------------- */

export type Precondition = { check: string; met: string };

/**
 * Clasificación del glosario (docs/SCOPE.md §7):
 *   - "foco":      CVE-2025-32463, CVE-2025-32462 (objeto central del paper)
 *   - "historica": 2023-22809, 2021-3156, 2019-14287 (contexto y comparativa)
 */
export type Scope = "foco" | "historica";

export type Finding = {
  cve: string;
  name: string;
  severity: string;
  versionVulnerable: boolean;
  status: "EXPLOTABLE" | "MITIGADO" | "NO_AFECTADO";
  preconditions: Precondition[];
  note: string;
  scope: Scope;
};

export type ScanResult = {
  version: string;
  findings: Finding[];
  summary: { explotable: number; mitigado: number; noAfectado: number };
  log: string[];
};

/* ---- Parser ----------------------------------------------------------------- */

/**
 * Parsea la salida TSV v2 de scan.sh a un objeto tipado.
 *
 * Formato TSV v2 (contrato completo en docs/METRICS.md §5 — la línea F agrega
 * el campo 8 `scope`):
 *   V <version>
 *   F <cve> <nombre> <severidad> <version_vuln 0|1> <estado> <precondiciones> <nota> <scope>
 *   S <explotable> <mitigado> <no_afectado>
 *
 * Errores:
 *   - Si la salida no contiene ningún registro V/F/S => ParseScanError.
 *     Un `docker exec` "exitoso" con salida vacía o basura NO es un diagnóstico
 *     limpio: sin este guard, la UI mostraría 0 hallazgos como éxito.
 */
export function parseScan(stdout: string, stderr: string): ScanResult {
  const findings: Finding[] = [];
  let version = "desconocida";
  let summary = { explotable: 0, mitigado: 0, noAfectado: 0 };
  let sawAnyRecord = false;

  for (const rawLine of stdout.split("\n")) {
    const line = rawLine.replace(/\r$/, ""); // tolera CRLF
    if (line.length === 0) continue;
    const f = line.split("\t");
    if (f[0] === "V") {
      sawAnyRecord = true;
      version = f[1] ?? version;
    } else if (f[0] === "F") {
      sawAnyRecord = true;
      // Campos: f[0]=F | f[1]=cve | f[2]=nombre | f[3]=severidad |
      //         f[4]=version_vuln | f[5]=estado | f[6]=precondiciones |
      //         f[7]=nota | f[8]=scope
      const [, cve, name, severity, vvuln, status, pre, note, scope] = f;
      findings.push({
        cve,
        name,
        severity,
        versionVulnerable: vvuln === "1",
        status: status as Finding["status"],
        preconditions: (pre ?? "")
          .split(";")
          .filter(Boolean)
          .map((kv) => {
            const [check, met] = kv.split("=");
            return { check, met: met ?? "" };
          }),
        note: note ?? "",
        // Default 'historica': mantiene compatibilidad mientras
        // convivan salidas TSV v1 (sin scope) con el script nuevo.
        scope: scope === "foco" ? "foco" : "historica",
      });
    } else if (f[0] === "S") {
      sawAnyRecord = true;
      summary = {
        explotable: Number(f[1] ?? 0),
        mitigado: Number(f[2] ?? 0),
        noAfectado: Number(f[3] ?? 0),
      };
    }
  }

  // TSV vacío / sin registros => error tipado, no éxito con 0 hallazgos.
  if (!sawAnyRecord) {
    throw new ParseScanError(
      "La salida de scan.sh no contiene registros TSV (V/F/S): versión de " +
        "script desactualizada o ejecución fallida. " +
        `stdout recibido: ${JSON.stringify(stdout.slice(0, 200))}`
    );
  }

  // Limpia los códigos de color ANSI del log para mostrarlo en el panel.
  const log = stderr
    .replace(/\x1b\[[0-9;]*m/g, "")
    .split("\n")
    .filter((l) => l.trim().length > 0);

  return { version, findings, summary, log };
}
