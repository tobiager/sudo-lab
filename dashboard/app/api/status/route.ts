import { NextResponse } from "next/server";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const pexec = promisify(execFile);
const CONTAINER = process.env.LAB_CONTAINER ?? "sudo-lab-target";

/** Indica si el contenedor del laboratorio está en ejecución. */
export async function GET() {
  try {
    const { stdout } = await pexec("docker", [
      "inspect",
      "-f",
      "{{.State.Running}}",
      CONTAINER,
    ]);
    return NextResponse.json({ container: CONTAINER, running: stdout.trim() === "true" });
  } catch {
    return NextResponse.json({ container: CONTAINER, running: false });
  }
}
