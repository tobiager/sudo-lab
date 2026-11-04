"use client";

import { useEffect, useRef, useState } from "react";
import type { Finding, ScanResult } from "@/lib/lab";

/* =============================================================================
 *  page.tsx — panel del laboratorio
 * -----------------------------------------------------------------------------
 *  Acciones del panel: ① Diagnosticar, ② Simular foothold, ③ Aplicar
 *  mitigaciones, ④ Lanzar Ataque, ↺ Restaurar.
 *    - ④ "Lanzar Ataque" → POST /api/benchmark. Queda
 *      DESHABILITADO mientras GET /api/poc informe disponible: false (sonda
 *      `benchmark.sh --check`, que no ejecuta nada); el botón lleva tooltip
 *      "Colocá un PoC en LAB_POC_DIR" y bajo la fila de acciones se explica
 *      dónde colocarlos.
 *    - Sección "Resultados del ataque (benchmark)": tabla de
 *      iteraciones (PoC, n.º, estado, tiempo) y tabla agregada por
 *      PoC con tasa de éxito (%), media y mín/máx (métricas M3/M4).
 *    - Nuevo tipo de registro de consola `atk` (naranja), separado del
 *      violeta del foothold: ④ es la única acción ofensiva del panel y sólo
 *      corre lo que el operador haya colocado en LAB_POC_DIR (el repo
 *      versionado no contiene ningún PoC).
 *    - Los contratos estructurales del benchmark (BenchIter/BenchAgg/PocProbe)
 *      se declaran LOCALMENTE y no en lib/lab.ts: la librería conserva
 *      su contrato de runner/parser; TypeScript casa estos tipos con la
 *      respuesta JSON de /api/benchmark y /api/poc por estructura.
 *    - Pendiente: la comparación antes/después (benchmark pre vs post
 *      mitigación, métrica M5) no está implementada: el panel guarda
 *      sólo el último resultado.
 * ========================================================================== */

type LogLine = { t: number; text: string; kind: "sys" | "scan" | "mit" | "foot" | "atk" };

const STATUS_STYLE: Record<string, { label: string; color: string; bg: string }> = {
  EXPLOTABLE: { label: "EXPLOTABLE", color: "#f87171", bg: "rgba(248,113,113,.12)" },
  MITIGADO: { label: "MITIGADO", color: "#fbbf24", bg: "rgba(251,191,36,.12)" },
  NO_AFECTADO: { label: "NO AFECTADO", color: "#34d399", bg: "rgba(52,211,153,.12)" },
  // Estado propio del benchmark: el arnés no pudo ejecutar el PoC
  // (archivo ilegible, timeout/su ausentes). Gris neutro: no es una mitigación
  // ni un éxito — hay que revisar el montaje/permisos (ver docs/POC.md).
  ERROR: { label: "ERROR", color: "#94a3b8", bg: "rgba(148,163,184,.15)" },
};

// Color del log `foot`: violeta, distinto del azul (sys), del texto
// (scan) y del verde (mit), para que la narrativa del atacante se distinga a
// simple vista de las acciones defensivas del panel.
const FOOT_COLOR = "#c084fc";

// Color del log `atk` (benchmark ofensivo): naranja, visible pero
// distinto del rojo de los badges EXPLOTABLE y del violeta del foothold.
const ATACK_COLOR = "#fb923c";

/* ---- Contratos estructurales del benchmark (réplica por estructura de las
 *      respuestas de /api/poc y /api/benchmark; el contrato TSV lo fija
 *      benchmark.sh, extensión v2 de METRICS.md §5) -------------------------- */

type BenchIterStatus = "EXPLOTABLE" | "MITIGADO" | "TIMEOUT" | "ERROR";

type BenchIter = {
  poc: string;
  iter: number;
  success: boolean;
  ms: number;
  status: BenchIterStatus;
};

type BenchAgg = {
  poc: string;
  successes: number;
  total: number;
  ratePct: number; // %, 1 decimal (métrica M3)
  avgMs: number;
  minMs: number;
  maxMs: number;
};

type PocProbe = {
  container: string;
  disponible: boolean;
  pocs: string[];
  pocDir: string | null;
};

type BenchmarkOk = {
  disponible: true;
  pocDir: string | null;
  iterations: BenchIter[];
  aggregate: BenchAgg[];
};

/** Tarjeta de hallazgo, compartida por las dos secciones de scope. */
function FindingCard({ f }: { f: Finding }) {
  const st = STATUS_STYLE[f.status] ?? STATUS_STYLE.NO_AFECTADO;
  return (
    <div className="rounded-lg border border-[color:var(--border)] bg-[color:var(--panel)] p-4">
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
}

/** Encabezado de cada sección de hallazgos, agrupada por scope. */
function ScopeHeading({
  titulo,
  n,
  detalle,
  color,
}: {
  titulo: string;
  n: number;
  detalle: string;
  color: string;
}) {
  return (
    <h3
      className="mono mb-2 mt-4 text-xs font-semibold uppercase tracking-wide"
      style={{ color }}
    >
      {titulo} ({n}){" "}
      <span className="font-normal normal-case text-[color:var(--muted)]">
        · {detalle}
      </span>
    </h3>
  );
}

/** Badge de estado de iteración (reusa la paleta de hallazgos). */
function EstadoBadge({ estado }: { estado: BenchIterStatus }) {
  const st = STATUS_STYLE[estado] ?? STATUS_STYLE.ERROR;
  return (
    <span
      className="rounded-md px-2 py-0.5 text-xs font-semibold"
      style={{ color: st.color, background: st.bg }}
    >
      {st.label}
    </span>
  );
}

export default function Home() {
  const [scan, setScan] = useState<ScanResult | null>(null);
  const [log, setLog] = useState<LogLine[]>([]);
  const [busy, setBusy] = useState<string | null>(null);
  const [running, setRunning] = useState<boolean | null>(null);
  const [sudoVersion, setSudoVersion] = useState<string | null>(null);
  const [poc, setPoc] = useState<PocProbe | null>(null);
  const [pocNota, setPocNota] = useState<string | null>(null); // error de la sonda
  const [bench, setBench] = useState<BenchmarkOk | null>(null);
  const [error, setError] = useState<string | null>(null);
  const logRef = useRef<HTMLDivElement>(null);

  const push = (lines: string[], kind: LogLine["kind"]) =>
    setLog((prev) => [
      ...prev,
      ...lines.map((text) => ({ t: Date.now(), text, kind })),
    ]);

  // Sonda de disponibilidad de PoC (GET /api/poc → benchmark.sh --check,
  // que NO ejecuta nada). Se consulta al montar el panel y cada vez que un
  // benchmark responde POC_NO_DISPONIBLE (el operador pudo haber colocado o
  // quitado los archivos).
  async function refreshPoc() {
    try {
      const res = await fetch("/api/poc");
      const data = await res.json();
      if (!res.ok) throw new Error(data.error ?? "Fallo la verificación del PoC");
      setPoc(data);
      setPocNota(null);
      push(
        [
          data.disponible
            ? `PoC disponible en ${data.pocDir ?? "LAB_POC_DIR"}: ${data.pocs.join(", ")} — botón ④ habilitado.`
            : `Sin PoC disponible (${data.pocDir ?? "LAB_POC_DIR"}): el botón ④ queda deshabilitado. Ver docs/POC.md.`,
        ],
        "sys"
      );
    } catch (e) {
      // La sonda fallida no rompe el panel: ④ queda deshabilitado por las dudas
      // (nunca se ofrece una acción ofensiva en estado dudoso).
      setPoc(null);
      setPocNota(e instanceof Error ? e.message : "Error desconocido");
    }
  }

  useEffect(() => {
    fetch("/api/status")
      .then((r) => r.json())
      .then((d) => {
        setRunning(d.running);
        setSudoVersion(d.sudoVersion ?? null); // versión sin correr scan
        push(
          [
            d.running
              ? `Contenedor "${d.container}" en ejecución${
                  d.sudoVersion ? ` · sudo ${d.sudoVersion}` : ""
                }.`
              : `Contenedor "${d.container}" NO está corriendo. Ejecutá: docker compose up -d --build`,
          ],
          "sys"
        );
      })
      .catch(() => setRunning(false));
  }, []);

  // Sonda de PoC al montar (paralela al status).
  useEffect(() => {
    void refreshPoc();
    // eslint-disable-next-line react-hooks/exhaustive-deps
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

  // Acción: simular el foothold. No cambia ningún estado de hallazgos
  // ni el resumen: sólo deja evidencia en la consola con tipo `foot` (el guion
  // de lo que ve el atacante tras el acceso inicial simulado).
  async function simFoothold() {
    setBusy("foothold");
    setError(null);
    push(["$ foothold.sh — acceso inicial simulado (como webuser, sin explotar)"], "sys");
    try {
      const res = await fetch("/api/foothold", { method: "POST" });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error ?? "Fallo la simulación del foothold");
      push(data.log, "foot");
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

  // Única acción ofensiva del panel: corre el arnés benchmark.sh sobre
  // el PoC que el OPERADOR colocó en LAB_POC_DIR (el repo no contiene ninguno).
  // El arnés ejecuta cada PoC como webuser, N veces, con timeout por iteración.
  async function launchAttack() {
    setBusy("benchmark");
    setError(null);
    push(
      ["$ benchmark.sh — ejecución controlada del PoC como webuser (N iteraciones, con medición)"],
      "sys"
    );
    try {
      const res = await fetch("/api/benchmark", { method: "POST" });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error ?? "Fallo el benchmark");
      push(data.log ?? [], "atk");
      if (!data.disponible) {
        // Estado de negocio POC_NO_DISPONIBLE (no es un 5xx): avisar y re-sondear
        // para que el botón refleje el estado actual del directorio.
        push([`POC_NO_DISPONIBLE — ${data.message ?? "no hay scripts *.sh en el directorio de PoCs"}`], "atk");
        void refreshPoc();
      } else {
        setBench(data);
        push(
          [
            `Benchmark completo: ${data.iterations.length} iteración(es) sobre ${data.aggregate.length} PoC(s).`,
          ],
          "atk"
        );
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : "Error");
    } finally {
      setBusy(null);
    }
  }

  const s = scan?.summary;

  // Agrupación por scope (campo del TSV v2 que parseScan ya entrega).
  const foco = scan?.findings.filter((f) => f.scope === "foco") ?? [];
  const historicas = scan?.findings.filter((f) => f.scope === "historica") ?? [];

  // El header prioriza la versión de /api/status; si aún no llegó,
  // usa la que trajera el último scan (si lo hubo).
  const sudoEnHeader = sudoVersion ?? scan?.version ?? null;

  // El botón ④ requiere la sonda OK y disponible: en estado dudoso
  // (sonda fallida o todavía cargando) permanece deshabilitado.
  const pocOk = poc?.disponible === true;
  const tooltipAtaque = pocOk
    ? "benchmark.sh: ejecuta el PoC externo como webuser, N iteraciones, con medición (M3/M4)"
    : "Colocá un PoC en LAB_POC_DIR (ver docs/POC.md)";

  return (
    <main className="mx-auto max-w-6xl px-4 py-8">
      {/* Header */}
      <header className="mb-6 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">
            sudo-lab <span className="text-[color:var(--muted)]">· panel de laboratorio</span>
          </h1>
          <p className="mt-1 text-sm text-[color:var(--muted)]">
            Diagnóstico, foothold simulado, mitigación y benchmark opcional de CVEs de sudo ·
            entorno aislado, uso educativo
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
          {/* Versión de sudo visible desde el primer momento. */}
          {sudoEnHeader && <span className="text-[color:var(--muted)]">· sudo {sudoEnHeader}</span>}
        </div>
      </header>

      {/* Banner ético */}
      <div className="mb-6 rounded-lg border border-[color:var(--border)] bg-[rgba(56,189,248,.06)] px-4 py-3 text-sm text-[color:var(--muted)]">
        Entorno de laboratorio aislado para investigación académica. El panel ejecuta{" "}
        <span className="mono text-[color:var(--text)]">diagnóstico</span> y{" "}
        <span className="mono text-[color:var(--text)]">mitigación</span> (defensivo) y{" "}
        <span className="mono text-[color:var(--text)]">simula el acceso inicial</span> como
        usuario de servicio sin explotar nada (foothold narrativo). La acción{" "}
        <span className="mono text-[color:var(--text)]">④ Lanzar Ataque</span> sólo corre un PoC
        que el operador haya colocado explícitamente en <span className="mono">LAB_POC_DIR</span>{" "}
        (el repositorio no contiene ninguno); su uso es responsabilidad exclusiva del operador —
        ver <span className="mono text-[color:var(--text)]">docs/POC.md</span> y{" "}
        <span className="mono text-[color:var(--text)]">SECURITY.md</span>.
      </div>

      {/* Acciones del panel */}
      <div className="mb-6 flex flex-wrap gap-3">
        <button
          onClick={diagnose}
          disabled={busy !== null}
          className="rounded-lg px-4 py-2.5 text-sm font-medium transition disabled:opacity-50"
          style={{ background: "var(--accent)", color: "#06131d" }}
        >
          {busy === "scan" ? "Diagnosticando…" : "① Diagnosticar exposición"}
        </button>
        {/* Foothold simulado (no explota nada). */}
        <button
          onClick={simFoothold}
          disabled={busy !== null}
          className="rounded-lg border px-4 py-2.5 text-sm font-medium transition disabled:opacity-50"
          style={{ borderColor: FOOT_COLOR, color: FOOT_COLOR }}
        >
          {busy === "foothold" ? "Simulando…" : "② Simular foothold"}
        </button>
        <button
          onClick={() => mitigate(false)}
          disabled={busy !== null}
          className="rounded-lg border px-4 py-2.5 text-sm font-medium transition disabled:opacity-50"
          style={{ borderColor: "var(--good)", color: "var(--good)" }}
        >
          {busy === "mitigate" ? "Aplicando…" : "③ Aplicar mitigaciones + re-escanear"}
        </button>
        {/* Lanzar ataque: sólo si la sonda /api/poc informa PoC disponible. */}
        <button
          onClick={launchAttack}
          disabled={busy !== null || !pocOk}
          title={tooltipAtaque}
          className="rounded-lg border px-4 py-2.5 text-sm font-medium transition disabled:opacity-50"
          style={{
            borderColor: pocOk ? ATACK_COLOR : "var(--border)",
            color: pocOk ? ATACK_COLOR : "var(--muted)",
          }}
        >
          {busy === "benchmark" ? "Ejecutando PoC…" : "④ Lanzar Ataque"}
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

      {/* Estado de la sonda de PoC, visible cuando ④ no está disponible. */}
      {!pocOk && (
        <p className="-mt-3 mb-6 text-xs text-[color:var(--muted)]">
          {poc === null
            ? `④ deshabilitado: no se pudo verificar la disponibilidad de PoC${
                pocNota ? ` (${pocNota})` : "."
              }`
            : `④ deshabilitado: no hay scripts *.sh en ${poc.pocDir ?? "LAB_POC_DIR"}. Colocá los PoC (p. ej. poc_32463.sh, poc_32462.sh) en ese directorio — ver docs/POC.md.`}
        </p>
      )}

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
        {/* Hallazgos, agrupados por scope */}
        <section>
          <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-[color:var(--muted)]">
            Hallazgos por CVE
          </h2>
          {!scan && (
            <p className="text-sm text-[color:var(--muted)]">
              Tocá “Diagnosticar exposición” para evaluar el target.
            </p>
          )}
          {scan && (
            <>
              {/* Sección 1: CVEs Foco — el objeto central del paper. */}
              <ScopeHeading
                titulo="CVEs Foco"
                n={foco.length}
                detalle="objeto central del estudio"
                color="var(--crit)"
              />
              <div className="space-y-3">
                {foco.length === 0 ? (
                  <p className="text-sm text-[color:var(--muted)]">
                    — sin hallazgos en esta categoría —
                  </p>
                ) : (
                  foco.map((f) => <FindingCard key={f.cve} f={f} />)
                )}
              </div>

              {/* Sección 2: CVEs Históricas — contexto y comparativa. */}
              <ScopeHeading
                titulo="CVEs Históricas"
                n={historicas.length}
                detalle="contexto y comparativa"
                color="var(--muted)"
              />
              <div className="space-y-3">
                {historicas.length === 0 ? (
                  <p className="text-sm text-[color:var(--muted)]">
                    — sin hallazgos en esta categoría —
                  </p>
                ) : (
                  historicas.map((f) => <FindingCard key={f.cve} f={f} />)
                )}
              </div>
            </>
          )}
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
                        : l.kind === "foot"
                          ? FOOT_COLOR
                          : l.kind === "atk"
                            ? ATACK_COLOR
                            : "var(--text)",
                }}
              >
                {l.text}
              </div>
            ))}
          </div>
        </section>
      </div>

      {/* Resultados del benchmark: sólo tras un ④ exitoso.
          La comparación antes/después (M5) queda pendiente: este
          panel guarda únicamente el último resultado. */}
      {bench && (
        <section className="mt-8">
          <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-[color:var(--muted)]">
            Resultados del ataque (benchmark)
          </h2>
          <p className="mb-3 text-xs text-[color:var(--muted)]">
            {bench.pocDir ? `Directorio de PoCs: ${bench.pocDir} · ` : ""}
            {bench.iterations.length} iteración(es) en total · criterio de éxito:{" "}
            <span className="mono">uid=0(root)</span> en la salida del PoC o marcador nuevo en{" "}
            <span className="mono">/root/</span> (METRICS M3).
          </p>

          {/* Vista agregada : tasa de éxito y tiempos por PoC (M3/M4). */}
          <div className="overflow-x-auto rounded-lg border border-[color:var(--border)]">
            <table className="w-full text-sm">
              <thead className="bg-[color:var(--panel)] text-left text-xs uppercase tracking-wide text-[color:var(--muted)]">
                <tr>
                  <th className="px-3 py-2 font-medium">PoC</th>
                  <th className="px-3 py-2 font-medium">Éxitos</th>
                  <th className="px-3 py-2 font-medium">Total</th>
                  <th className="px-3 py-2 font-medium">Tasa de éxito</th>
                  <th className="px-3 py-2 font-medium">Media (ms)</th>
                  <th className="px-3 py-2 font-medium">Mín (ms)</th>
                  <th className="px-3 py-2 font-medium">Máx (ms)</th>
                </tr>
              </thead>
              <tbody className="mono">
                {bench.aggregate.map((a) => (
                  <tr key={a.poc} className="border-t border-[color:var(--border)]">
                    <td className="px-3 py-2">{a.poc}</td>
                    <td className="px-3 py-2">
                      {a.successes}/{a.total}
                    </td>
                    <td className="px-3 py-2">{a.total}</td>
                    <td
                      className="px-3 py-2 font-semibold"
                      style={{ color: a.ratePct > 0 ? "var(--crit)" : "var(--good)" }}
                    >
                      {a.ratePct.toFixed(1)} %
                    </td>
                    <td className="px-3 py-2">{a.avgMs.toFixed(1)}</td>
                    <td className="px-3 py-2">{a.minMs}</td>
                    <td className="px-3 py-2">{a.maxMs}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Vista por iteración : éxito/estado/tiempo de cada corrida. */}
          <h3 className="mb-2 mt-4 text-xs font-semibold uppercase tracking-wide text-[color:var(--muted)]">
            Por iteración
          </h3>
          <div className="overflow-x-auto rounded-lg border border-[color:var(--border)]">
            <table className="w-full text-sm">
              <thead className="bg-[color:var(--panel)] text-left text-xs uppercase tracking-wide text-[color:var(--muted)]">
                <tr>
                  <th className="px-3 py-2 font-medium">PoC</th>
                  <th className="px-3 py-2 font-medium">N.º</th>
                  <th className="px-3 py-2 font-medium">Estado</th>
                  <th className="px-3 py-2 font-medium">Tiempo (ms)</th>
                </tr>
              </thead>
              <tbody className="mono">
                {bench.iterations.map((it) => (
                  <tr key={`${it.poc}-${it.iter}`} className="border-t border-[color:var(--border)]">
                    <td className="px-3 py-2">{it.poc}</td>
                    <td className="px-3 py-2">{it.iter}</td>
                    <td className="px-3 py-2">
                      <EstadoBadge estado={it.status} />
                    </td>
                    <td className="px-3 py-2">{it.ms}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <p className="mt-3 text-xs text-[color:var(--muted)]">
            <span className="mono">TIMEOUT</span>: el PoC excedió el límite por iteración (
            <span className="mono">LAB_POC_TIMEOUT</span>). <span className="mono">ERROR</span>: el
            arnés no pudo ejecutar el PoC (p. ej. archivo ilegible para webuser — revisar
            permisos del montaje, ver docs/POC.md). Las iteraciones con ERROR cuentan como no
            exitosas: nunca inflan la tasa.
          </p>
        </section>
      )}

      <footer className="mt-8 text-center text-xs text-[color:var(--muted)]">
        sudo-lab · Trabajo de investigación · Redes de Datos / Software Seguro · UNNE FaCENA
      </footer>
    </main>
  );
}
