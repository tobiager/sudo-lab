import { NextResponse } from "next/server";
import { runInLab, parseScan } from "@/lib/lab";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * Aplica las mitigaciones y, a continuación, vuelve a diagnosticar para que el
 * panel muestre el "antes/después" en una sola operación.
 * Body opcional: { reset: true } para restaurar el estado vulnerable.
 */
export async function POST(req: Request) {
  try {
    let reset = false;
    try {
      const body = await req.json();
      reset = body?.reset === true;
    } catch {
      /* sin body */
    }

    const mit = await runInLab("mitigate.sh", reset ? ["--reset"] : []);
    const mitLog = mit.stderr
      .replace(/\x1b\[[0-9;]*m/g, "")
      .split("\n")
      .filter((l) => l.trim().length > 0);

    // Re-diagnóstico para verificar el efecto.
    const scan = await runInLab("scan.sh");
    const result = parseScan(scan.stdout, scan.stderr);

    return NextResponse.json({
      action: reset ? "reset" : "mitigate",
      mitigationLog: mitLog,
      scan: result,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : "Error desconocido";
    return NextResponse.json({ error: message }, { status: 502 });
  }
}
