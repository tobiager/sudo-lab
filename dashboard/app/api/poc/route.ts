import { NextResponse } from "next/server";
import { runInLab } from "@/lib/lab";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/* =============================================================================
 *  GET /api/poc — sonda de disponibilidad de PoC (habilita el botón "④ Lanzar
 *  Ataque" del panel).
 * -----------------------------------------------------------------------------
 *  Corre `benchmark.sh --check` dentro del target (vía runInLab) y parsea su
 *  TSV. El modo --check NO ejecuta ningún PoC: sólo descubre qué archivos *.sh
 *  dejó el operador en LAB_POC_DIR. El repo versionado NO contiene PoCs reales
 *  (SECURITY.md §3): hasta que el operador coloque uno, la sonda responde
 *  disponible:false y el panel mantiene ④ deshabilitado SIN error de JSON.
 *
 *  TSV que consume (contrato docs/METRICS.md §5 y encabezado de benchmark.sh):
 *    POCDIR\t<dir>              (siempre, primera línea)
 *    POC\t<nombre>             (una por PoC descubierto)
 *    POC_NO_DISPONIBLE          (si no hay *.sh)
 *
 *  Respuesta 200 (la consume refreshPoc() en page.tsx):
 *    { disponible: boolean, pocDir: string, pocs: string[] }
 *  Error (contenedor/daemon/script) → 502 { error }, igual que /api/scan y
 *  /api/mitigate.
 * ========================================================================== */

export async function GET() {
  try {
    const { stdout } = await runInLab("benchmark.sh", ["--check"]);

    let pocDir = "";
    const pocs: string[] = [];
    let noDisponible = false;

    for (const rawLine of stdout.split("\n")) {
      const f = rawLine.replace(/\r$/, "").split("\t");
      if (f[0] === "POCDIR") pocDir = f[1] ?? "";
      else if (f[0] === "POC" && f[1]) pocs.push(f[1]);
      else if (f[0] === "POC_NO_DISPONIBLE") noDisponible = true;
    }

    // disponible=false y pocs=[] cuando el script marca POC_NO_DISPONIBLE.
    const disponible = !noDisponible && pocs.length > 0;
    return NextResponse.json({ disponible, pocDir, pocs: disponible ? pocs : [] });
  } catch (err) {
    const error = err instanceof Error ? err.message : "Error desconocido";
    return NextResponse.json({ error }, { status: 502 });
  }
}
