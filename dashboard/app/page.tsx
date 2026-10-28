"use client";

import { useEffect, useRef, useState } from "react";
import type { ScanResult } from "@/lib/lab";

type LogLine = { t: number; text: string; kind: "sys" | "scan" | "mit" };

const STATUS_STYLE: Record<string, { label: string; color: string; bg: string }> = {
  EXPLOTABLE: { label: "EXPLOTABLE", color: "#f87171", bg: "rgba(248,113,113,.12)" },
  MITIGADO: { label: "MITIGADO", color: "#fbbf24", bg: "rgba(251,191,36,.12)" },
  NO_AFECTADO: { label: "NO AFECTADO", color: "#34d399", bg: "rgba(52,211,153,.12)" },
};

export default function Home() {
  const [scan, setScan] = useState<ScanResult | null>(null);
  const [log, setLog] = useState<LogLine[]>([]);
  const [busy, setBusy] = useState<string | null>(null);
  const [running, setRunning] = useState<boolean | null>(null);
  const [error, setError] = useState<string | null>(null);
  const logRef = useRef<HTMLDivElement>(null);

  const push = (lines: string[], kind: LogLine["kind"]) =>
    setLog((prev) => [
      ...prev,
      ...lines.map((text) => ({ t: Date.now(), text, kind })),
    ]);

  useEffect(() => {
    fetch("/api/status")
      .then((r) => r.json())
      .then((d) => {
        setRunning(d.running);
        push(
          [
            d.running
              ? `Contenedor "${d.container}" en ejecución.`
              : `Contenedor "${d.container}" NO está corriendo. Ejecutá: docker compose up -d --build`,
          ],
          "sys"
        );
      })
      .catch(() => setRunning(false));
  }, []);

  useEffect(() => {
    logRef.current?.scrollTo({ top: logRef.current.scrollHeight });
  }, [log]);

  async function diagnose() {
    setBusy("scan");
    setError(null);
    push(["$ scan.sh — diagnóstico de exposición"], "sys");
    try {
      const res = await fetch("/api/scan", { method: "POST" });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error ?? "Fallo el diagnóstico");
      setScan(data);
      push(data.log, "scan");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Error");
    } finally {
      setBusy(null);
    }
  }

  async function mitigate(reset = false) {
    setBusy(reset ? "reset" : "mitigate");
    setError(null);
    push([`$ mitigate.sh${reset ? " --reset" : ""}`], "sys");
    try {
      const res = await fetch("/api/mitigate", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ reset }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error ?? "Fallo la operación");
      push(data.mitigationLog, "mit");
      push(["$ scan.sh — re-diagnóstico"], "sys");
      push(data.scan.log, "scan");
      setScan(data.scan);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Error");
    } finally {
      setBusy(null);
    }
  }

  const s = scan?.summary;

  return (
    <main className="mx-auto max-w-6xl px-4 py-8">
      {/* Header */}
      <header className="mb-6 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">
            sudo-lab <span className="text-[color:var(--muted)]">· panel de laboratorio</span>
          </h1>
          <p className="mt-1 text-sm text-[color:var(--muted)]">
            Diagnóstico de exposición y mitigación de CVEs de sudo · entorno aislado, uso educativo
          </p>
        </div>
        <div className="flex items-center gap-2 rounded-lg border border-[color:var(--border)] bg-[color:var(--panel)] px-3 py-2 text-sm">
          <span
            className="inline-block h-2.5 w-2.5 rounded-full"
            style={{ background: running ? "var(--good)" : "var(--crit)" }}
          />
          <span className="mono">
            {running === null ? "verificando…" : running ? "target activo" : "target detenido"}
          </span>
          {scan && <span className="text-[color:var(--muted)]">· sudo {scan.version}</span>}
        </div>
      </header>

      {/* Banner ético */}
      <div className="mb-6 rounded-lg border border-[color:var(--border)] bg-[rgba(56,189,248,.06)] px-4 py-3 text-sm text-[color:var(--muted)]">
        Entorno de laboratorio aislado para investigación académica. El panel ejecuta{" "}
        <span className="mono text-[color:var(--text)]">diagnóstico</span> y{" "}
        <span className="mono text-[color:var(--text)]">mitigación</span> (defensivo). La explotación
        ofensiva en vivo se documenta en el README y se apoya en PoC públicos.
      </div>

      {/* Acciones */}
      <div className="mb-6 flex flex-wrap gap-3">
        <button
          onClick={diagnose}
          disabled={busy !== null}
          className="rounded-lg px-4 py-2.5 text-sm font-medium transition disabled:opacity-50"
          style={{ background: "var(--accent)", color: "#06131d" }}
        >
          {busy === "scan" ? "Diagnosticando…" : "① Diagnosticar exposición"}
        </button>
        <button
          onClick={() => mitigate(false)}
          disabled={busy !== null}
          className="rounded-lg border px-4 py-2.5 text-sm font-medium transition disabled:opacity-50"
          style={{ borderColor: "var(--good)", color: "var(--good)" }}
        >
          {busy === "mitigate" ? "Aplicando…" : "② Aplicar mitigaciones + re-escanear"}
        </button>
        <button
          onClick={() => mitigate(true)}
          disabled={busy !== null}
          className="rounded-lg border px-4 py-2.5 text-sm font-medium text-[color:var(--muted)] transition disabled:opacity-50"
          style={{ borderColor: "var(--border)" }}
        >
          {busy === "reset" ? "Restaurando…" : "↺ Restaurar estado vulnerable"}
        </button>
      </div>

      {error && (
        <div className="mb-6 rounded-lg border border-[color:var(--crit)] bg-[rgba(248,113,113,.1)] px-4 py-3 text-sm text-[color:var(--crit)]">
          {error}
        </div>
      )}

      {/* Resumen */}
      {s && (
        <div className="mb-6 grid grid-cols-3 gap-3">
          {[
            { k: "Explotables", v: s.explotable, c: "var(--crit)" },
            { k: "Mitigadas", v: s.mitigado, c: "var(--warn)" },
            { k: "No afectadas", v: s.noAfectado, c: "var(--good)" },
          ].map((x) => (
            <div
              key={x.k}
              className="rounded-lg border border-[color:var(--border)] bg-[color:var(--panel)] px-4 py-3"
            >
              <div className="text-3xl font-semibold" style={{ color: x.c }}>
                {x.v}
              </div>
              <div className="text-sm text-[color:var(--muted)]">{x.k}</div>
            </div>
          ))}
        </div>
      )}

      <div className="grid gap-6 lg:grid-cols-2">
        {/* Hallazgos */}
        <section>
          <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-[color:var(--muted)]">
            Hallazgos por CVE
          </h2>
          <div className="space-y-3">
            {!scan && (
              <p className="text-sm text-[color:var(--muted)]">
                Tocá “Diagnosticar exposición” para evaluar el target.
              </p>
            )}
            {scan?.findings.map((f) => {
              const st = STATUS_STYLE[f.status] ?? STATUS_STYLE.NO_AFECTADO;
              return (
                <div
                  key={f.cve}
                  className="rounded-lg border border-[color:var(--border)] bg-[color:var(--panel)] p-4"
                >
                  <div className="flex items-start justify-between gap-2">
                    <div>
                      <div className="mono text-sm font-semibold">{f.cve}</div>
                      <div className="text-xs text-[color:var(--muted)]">
                        {f.name} · {f.severity}
                      </div>
                    </div>
                    <span
                      className="rounded-md px-2 py-1 text-xs font-semibold"
                      style={{ color: st.color, background: st.bg }}
                    >
                      {st.label}
                    </span>
                  </div>
                  <p className="mt-2 text-xs text-[color:var(--muted)]">{f.note}</p>
                  <div className="mt-2 flex flex-wrap gap-1.5">
                    <span
                      className="mono rounded px-1.5 py-0.5 text-[11px]"
                      style={{
                        background: f.versionVulnerable
                          ? "rgba(248,113,113,.12)"
                          : "rgba(52,211,153,.12)",
                        color: f.versionVulnerable ? "var(--crit)" : "var(--good)",
                      }}
                    >
                      versión {f.versionVulnerable ? "vulnerable" : "fuera de rango"}
                    </span>
                    {f.preconditions.map((p) => (
                      <span
                        key={p.check}
                        className="mono rounded bg-[rgba(139,152,169,.12)] px-1.5 py-0.5 text-[11px] text-[color:var(--muted)]"
                      >
                        {p.check}={p.met}
                      </span>
                    ))}
                  </div>
                </div>
              );
            })}
          </div>
        </section>

        {/* Logs en vivo */}
        <section>
          <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-[color:var(--muted)]">
            Registros del servidor (en vivo)
          </h2>
          <div
            ref={logRef}
            className="mono h-[520px] overflow-y-auto rounded-lg border border-[color:var(--border)] bg-black/40 p-3 text-xs leading-relaxed"
          >
            {log.length === 0 && (
              <span className="text-[color:var(--muted)]">— sin actividad —</span>
            )}
            {log.map((l, i) => (
              <div
                key={i}
                style={{
                  color:
                    l.kind === "sys"
                      ? "var(--accent)"
                      : l.kind === "mit"
                      ? "var(--good)"
                      : "var(--text)",
                }}
              >
                {l.text}
              </div>
            ))}
          </div>
        </section>
      </div>

      <footer className="mt-8 text-center text-xs text-[color:var(--muted)]">
        sudo-lab · Trabajo de investigación · Redes de Datos / Software Seguro · UNNE FaCENA
      </footer>
    </main>
  );
}
