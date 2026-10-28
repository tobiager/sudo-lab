import { NextResponse } from "next/server";
import { runInLab, parseScan } from "@/lib/lab";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST() {
  try {
    const { stdout, stderr } = await runInLab("scan.sh");
    return NextResponse.json(parseScan(stdout, stderr));
  } catch (err) {
    const message = err instanceof Error ? err.message : "Error desconocido";
    return NextResponse.json({ error: message }, { status: 502 });
  }
}
