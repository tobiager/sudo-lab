import { NextResponse } from "next/server";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const pexec = promisify(execFile);
const CONTAINER = process.env.LAB_CONTAINER ?? "sudo-lab-target";

/* =============================================================================
 *  /api/status — healthcheck del target para el header del panel
 * -----------------------------------------------------------------------------
 *  - Devuelve `sudoVersion`: la versión de sudo del target, obtenida
 *    vía `docker exec <container> sudo --version`, para que el header
 *    muestre "sudo 1.9.15" SIN necesidad de haber corrido un scan completo.
 *    El valor del scan (scan.version) queda como fallback en la UI.
 *  - Deliberadamente NO incluye webRunning/webPort: no hay
 *    servicio web en el lab (decisión de alcance, docs/SCOPE.md §6); el vector
 *    web se narra en docs/ATTACK-CHAIN.md y se representa con `webuser`.
 *
 *  Errores: obtener la versión NO es crítico para un healthcheck. Si
 *  `sudo --version` falla, se devuelve null y el panel sigue mostrando el
 *  estado del contenedor — este endpoint nunca rompe por un detalle
 *  cosmético del header.
 * ========================================================================== */

/** Indica si el contenedor del laboratorio está en ejecución. */
async function isRunning(): Promise<boolean> {
  try {
    const { stdout } = await pexec("docker", [
      "inspect",
      "-f",
      "{{.State.Running}}",
      CONTAINER,
    ]);
    return stdout.trim() === "true";
  } catch {
    // Contenedor inexistente o daemon caído → para la UI es "detenido".
    return false;
  }
}

/**
 * Versión de sudo declarada por el binario del target.
 * Misma extracción que scripts/lib.sh (sudo_version()): primera línea de
 * `sudo --version` ("Sudo version 1.9.15") y regex que acepta el sufijo de
 * patch pN. Sólo se consulta si el contenedor está corriendo.
 */
async function sudoVersion(): Promise<string | null> {
  try {
    const { stdout } = await pexec(
      "docker",
      ["exec", CONTAINER, "sudo", "--version"],
      { timeout: 15_000 }
    );
    const firstLine = (stdout.split("\n")[0] ?? "").trim();
    const m = firstLine.match(/[0-9]+\.[0-9]+\.[0-9]+(p[0-9]+)?/);
    return m ? m[0] : null;
  } catch {
    // Fallo cosmético: el header quedará sin versión, pero el status es válido.
    return null;
  }
}

/** Estado del target: { container, running, sudoVersion }. */
export async function GET() {
  const running = await isRunning();
  const version = running ? await sudoVersion() : null;
  return NextResponse.json({ container: CONTAINER, running, sudoVersion: version });
}
