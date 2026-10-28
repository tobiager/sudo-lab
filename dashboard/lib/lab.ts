import { execFile } from "node:child_process";
import { promisify } from "node:util";

const pexec = promisify(execFile);

/** Nombre del contenedor del laboratorio (override con LAB_CONTAINER). */
const CONTAINER = process.env.LAB_CONTAINER ?? "sudo-lab-target";

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
    const e = err as { stdout?: string; stderr?: string; message?: string };
    // `docker exec` devuelve !=0 si el contenedor no existe; propagamos el detalle.
    if (e.stdout === undefined && e.stderr === undefined) {
      throw new Error(
        `No se pudo ejecutar docker exec sobre "${CONTAINER}". ` +
          `¿Está el laboratorio levantado? (docker compose up -d). Detalle: ${e.message}`
      );
    }
    return { stdout: e.stdout ?? "", stderr: e.stderr ?? "" };
  }
}

export type Precondition = { check: string; met: string };
export type Finding = {
  cve: string;
  name: string;
  severity: string;
  versionVulnerable: boolean;
  status: "EXPLOTABLE" | "MITIGADO" | "NO_AFECTADO";
  preconditions: Precondition[];
  note: string;
};
export type ScanResult = {
  version: string;
  findings: Finding[];
  summary: { explotable: number; mitigado: number; noAfectado: number };
  log: string[];
};

/** Parsea la salida TSV de scan.sh a un objeto tipado. */
export function parseScan(stdout: string, stderr: string): ScanResult {
  const findings: Finding[] = [];
  let version = "desconocida";
  let summary = { explotable: 0, mitigado: 0, noAfectado: 0 };

  for (const line of stdout.split("\n")) {
    const f = line.split("\t");
    if (f[0] === "V") {
      version = f[1] ?? version;
    } else if (f[0] === "F") {
      const [, cve, name, severity, vvuln, status, pre, note] = f;
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
      });
    } else if (f[0] === "S") {
      summary = {
        explotable: Number(f[1] ?? 0),
        mitigado: Number(f[2] ?? 0),
        noAfectado: Number(f[3] ?? 0),
      };
    }
  }

  // Limpia los códigos de color ANSI del log para mostrarlo en el panel.
  const log = stderr
    .replace(/\x1b\[[0-9;]*m/g, "")
    .split("\n")
    .filter((l) => l.trim().length > 0);

  return { version, findings, summary, log };
}
