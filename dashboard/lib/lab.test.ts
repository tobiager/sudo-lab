/**
 * Tests unitarios de parseScan.
 *
 * Ejecución (sin Docker ni contenedor: el parser es una función pura):
 *   cd dashboard
 *   npm i -D tsx
 *   npx tsx --test lib/lab.test.ts
 * (script en package.json:  "test": "tsx --test lib/lab.test.ts")
 */
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { parseScan, ParseScanError } from "./lab";

/** Fixture TSV v2: salida esperada de scan.sh sobre el baseline (sudo 1.9.15). */
const TSV_V2_BASELINE = [
  "V\t1.9.15",
  "F\tCVE-2025-32463\tchroot/NSS\tCritica(9.3)\t1\tEXPLOTABLE\ttmp_exec=si;chroot=si\tEscala a root sin reglas de sudo; requiere /tmp ejecutable para el .so\tfoco",
  "F\tCVE-2025-32462\thost\tBaja(2.8)\t1\tEXPLOTABLE\tregla_host_remoto=si\tRequiere reglas calificadas por Host/Host_Alias\tfoco",
  "F\tCVE-2023-22809\tsudoedit/EDITOR\tAlta(7.8)\t0\tNO_AFECTADO\tregla_sudoedit=no\tRequiere una regla de sudoedit sobre al menos un archivo\thistorica",
  "F\tCVE-2021-3156\tBaronSamedit\tAlta(7.8)\t0\tNO_AFECTADO\tdeteccion_sudoedit_s=fuera_de_rango\tDesbordamiento de heap; explotable en configuracion por defecto\thistorica",
  "F\tCVE-2019-14287\trunas-uid-1\tAlta(8.8)\t0\tNO_AFECTADO\tregla_runas_negacion=no\tRequiere regla Runas con ALL y negacion de root\thistorica",
  "S\t2\t0\t3",
].join("\n");

describe("parseScan — TSV v2", () => {
  it("parsea el fixture del baseline sudo 1.9.15 con campo scope", () => {
    const r = parseScan(TSV_V2_BASELINE, "==>[*] log de prueba");
    assert.equal(r.version, "1.9.15");
    assert.equal(r.findings.length, 5);
    assert.deepEqual(r.summary, { explotable: 2, mitigado: 0, noAfectado: 3 });

    // Agrupación por scope: 2 foco + 3 históricas (glosario docs/SCOPE.md §7).
    const foco = r.findings.filter((f) => f.scope === "foco");
    const historica = r.findings.filter((f) => f.scope === "historica");
    assert.deepEqual(
      foco.map((f) => f.cve),
      ["CVE-2025-32463", "CVE-2025-32462"]
    );
    assert.equal(historica.length, 3);
  });

  it("divide las precondiciones por ';' y cada par en check=met", () => {
    const r = parseScan(
      "V\t1.9.15\nF\tCVE-2025-32463\tchroot/NSS\tCritica(9.3)\t1\tEXPLOTABLE\ttmp_exec=si;chroot=si\tnota\tfoco",
      ""
    );
    assert.deepEqual(r.findings[0].preconditions, [
      { check: "tmp_exec", met: "si" },
      { check: "chroot", met: "si" },
    ]);
  });

  it("TSV v1 (sin campo scope): default 'historica' por compatibilidad", () => {
    const r = parseScan(
      "V\t1.9.15\nF\tCVE-2025-32463\tchroot/NSS\tCritica(9.3)\t1\tMITIGADO\ttmp_exec=no\tnota",
      ""
    );
    assert.equal(r.findings[0].scope, "historica");
  });

  it("estado EXPLOTABLE/MITIGADO/NO_AFECTADO y versionVulnerable se mapean bien", () => {
    const r = parseScan(TSV_V2_BASELINE, "");
    const byCve = Object.fromEntries(r.findings.map((f) => [f.cve, f]));
    assert.equal(byCve["CVE-2025-32463"].status, "EXPLOTABLE");
    assert.equal(byCve["CVE-2025-32463"].versionVulnerable, true);
    assert.equal(byCve["CVE-2023-22809"].status, "NO_AFECTADO");
    assert.equal(byCve["CVE-2023-22809"].versionVulnerable, false);
  });

  it("TSV vacío o sin registros => ParseScanError (error tipado, no éxito con 0 hallazgos)", () => {
    assert.throws(() => parseScan("", ""), ParseScanError);
    assert.throws(() => parseScan("salida sin registros TSV\n", ""), ParseScanError);
  });

  it("limpia códigos ANSI del log y descarta líneas vacías", () => {
    const r = parseScan("V\t1.9.15", "\x1b[32m[+]\x1b[0m ok\n\n\x1b[33m[!]\x1b[0m aviso\n");
    assert.deepEqual(r.log, ["[+] ok", "[!] aviso"]);
  });
});
