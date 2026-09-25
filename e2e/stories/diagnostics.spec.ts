/**
 * Story-mapped browser coverage for the dsregcmd and Intune diagnostics
 * workspaces (areas `dsregcmd` and `intune`).
 *
 * Every test names the user-story ids it verifies (see
 * `docs/qa/user-stories.csv`). The suite runs in a plain browser against the
 * Tauri IPC shim, so it needs no Rust build and no Windows host. Commands the
 * app issues are answered by per-test overrides, and state a real capture or a
 * real device would produce is seeded through the live Vite store singletons so
 * the real components render it.
 *
 * Two authoring rules this file depends on:
 *  - `bootApp({overrides})` values are serialized, so they must be plain data.
 *    Anything request-dependent is installed in-page with `addInitScript` or
 *    `page.evaluate` instead.
 *  - Modules are loaded by path (`await import(path)`) on purpose: the import
 *    runs inside the browser page against the Vite dev server, so the spec must
 *    name the module at runtime rather than statically.
 */
import { test, expect } from "../fixtures";
import type { Locator, Page } from "@playwright/test";
import { MOCK_DSREGCMD, MOCK_INTUNE } from "../fixtures/screenshot-data";
import type { ShimWindow } from "./harness";
import { bootApp, emitBackendEvent, selectWorkspace } from "./harness";

const DSREGCMD_STORE = "/src/workspaces/dsregcmd/dsregcmd-store.ts";
const DSREGCMD_SOURCE = "/src/lib/dsregcmd-source.ts";
const DSREGCMD_WORKSPACE = "/src/workspaces/dsregcmd/index.ts";
const WORKSPACE_REGISTRY = "/src/workspaces/registry.ts";
const UI_STORE = "/src/stores/ui-store.ts";
const LOG_STORE = "/src/stores/log-store.ts";
const DATE_TIME = "/src/lib/date-time-format.ts";
const INTUNE_STORE = "/src/workspaces/intune/intune-store.ts";

const BUNDLE_ROOT = "C:\\Evidence\\dsregcmd-bundle";
const EVIDENCE_FILE = `${BUNDLE_ROOT}\\evidence\\command-output\\dsregcmd-status.txt`;
const STANDALONE_FILE = "C:\\Evidence\\dsregcmd-status.txt";
const IME_FOLDER = "C:\\ProgramData\\Microsoft\\IntuneManagementExtension\\Logs";

const NOT_REPORTED = "Not Reported";

type Tone = "neutral" | "good" | "warn" | "bad";

/** Theme tokens each dsregcmd surface paints a tone with. */
const TIMELINE_TONE_TOKEN: Record<Tone, string> = {
  neutral: "colorNeutralBackground3",
  good: "colorPaletteGreenBackground1",
  warn: "colorPaletteYellowBackground1",
  bad: "colorPaletteRedBackground1",
};
const CARD_TONE_TOKEN: Record<Tone, string> = {
  neutral: "colorNeutralCardBackground",
  good: "colorPaletteGreenBackground1",
  warn: "colorPaletteYellowBackground1",
  bad: "colorPaletteRedBackground1",
};

/** Extra page globals this suite installs on top of the shim. */
interface DiagnosticsShim extends ShimWindow {
  __resolveIntuneAnalysis__?: (value: unknown) => void;
  __dsregcmdLoads__?: Array<{ kind: string; path: string }>;
}

type AnyRecord = Record<string, unknown>;

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

/** Recursive patch for fixture objects; arrays and scalars replace outright. */
function merge<T>(base: T, patch: AnyRecord): T {
  const out: AnyRecord = { ...(base as AnyRecord) };
  for (const [key, value] of Object.entries(patch)) {
    const current = out[key];
    if (
      value !== null &&
      typeof value === "object" &&
      !Array.isArray(value) &&
      current !== null &&
      typeof current === "object" &&
      !Array.isArray(current)
    ) {
      out[key] = merge(current as AnyRecord, value as AnyRecord);
    } else {
      out[key] = value;
    }
  }
  return out as T;
}

const DSREGCMD_REAL = MOCK_DSREGCMD as unknown as {
  rawInput: string;
  result: AnyRecord;
  context: AnyRecord;
};

/** The `dsregcmd /status` text the fixture bundle was derived from. */
const DSREGCMD_STATUS_TEXT = DSREGCMD_REAL.rawInput;

/**
 * Section scoping: the dsregcmd dashboard renders every block as a `<section>`
 * whose first child carries the exact block title.
 */
function section(page: Page, title: string): Locator {
  return page
    .locator("section")
    .filter({ has: page.getByText(title, { exact: true }) })
    .first();
}

/** The value cell that follows a label cell in a fact row or timeline card. */
function valueAfter(label: Locator): Locator {
  return label.locator("xpath=following-sibling::div[1]");
}

/** The block (fact row, flow box, timeline card) a label sits in. */
function blockOf(label: Locator): Locator {
  return label.locator("xpath=..");
}

/**
 * Resolve a Fluent theme token to the rgb() string the browser computes.
 *
 * Fluent exports `tokens` as `var(--color…)` references and paints the theme
 * onto the FluentProvider, so the value is read where the theme actually lives.
 */
async function toneColor(page: Page, token: string): Promise<string> {
  return page.evaluate((name) => {
    const provider = document.querySelector(".fui-FluentProvider") ?? document.body;
    const probe = document.createElement("span");
    probe.style.color = `var(--${name})`;
    provider.appendChild(probe);
    const resolved = getComputedStyle(probe).color;
    probe.remove();
    return resolved;
  }, token);
}

async function expectTone(
  page: Page,
  locator: Locator,
  token: string,
): Promise<void> {
  const expected = await toneColor(page, token);
  await expect
    .poll(async () =>
      locator.evaluate((element) => getComputedStyle(element).backgroundColor),
    )
    .toBe(expected);
}

/** `formatHourDuration` from `dsregcmd-formatters.ts`, for clock-dependent rows. */
function hourDuration(hours: number): string {
  const totalMinutes = Math.max(0, Math.round(hours * 60));
  if (totalMinutes < 60) {
    return `${totalMinutes} min`;
  }
  const whole = Math.floor(totalMinutes / 60);
  const minutes = totalMinutes % 60;
  return minutes === 0 ? `${whole} hr` : `${whole} hr ${minutes} min`;
}

/** Render instants the way the app's own formatter does for the test host. */
async function localRender(page: Page, values: string[]): Promise<(string | null)[]> {
  return page.evaluate(
    async ({ modulePath, inputs }) => {
      const module = (await import(/* @vite-ignore */ modulePath)) as {
        formatDisplayDateTime: (value: string | null) => string | null;
      };
      return inputs.map((input) => module.formatDisplayDateTime(input));
    },
    { modulePath: DATE_TIME, inputs: values },
  );
}

interface DsregcmdSeed {
  result: AnyRecord;
  context?: AnyRecord;
  rawInput?: string;
}

async function seedDsregcmd(page: Page, seed: DsregcmdSeed): Promise<void> {
  await page.evaluate(
    async ({ storePath, rawInput, result, context }) => {
      const module = (await import(/* @vite-ignore */ storePath)) as {
        useDsregcmdStore: {
          getState: () => {
            setResults: (raw: string, result: unknown, context: unknown) => void;
          };
        };
      };
      module.useDsregcmdStore.getState().setResults(rawInput, result, context);
    },
    {
      storePath: DSREGCMD_STORE,
      rawInput: seed.rawInput ?? DSREGCMD_REAL.rawInput,
      result: seed.result,
      context: seed.context ?? DSREGCMD_REAL.context,
    },
  );
}

interface DsregcmdStateView {
  phase: string;
  detail: string | null;
  sourceKind: string | null;
  displayLabel: string;
  resolvedPath: string | null;
  bundlePath: string | null;
  evidenceFilePath: string | null;
  rawInput: string;
  hasResult: boolean;
}

async function readDsregcmdState(page: Page): Promise<DsregcmdStateView> {
  return page.evaluate(async (storePath) => {
    const module = (await import(/* @vite-ignore */ storePath)) as {
      useDsregcmdStore: { getState: () => AnyRecord };
    };
    const state = module.useDsregcmdStore.getState() as {
      analysisState: { phase: string; detail: string | null };
      sourceContext: {
        source: { kind: string } | null;
        displayLabel: string;
        resolvedPath: string | null;
        bundlePath: string | null;
        evidenceFilePath: string | null;
      };
      rawInput: string;
      result: unknown;
    };
    return {
      phase: state.analysisState.phase,
      detail: state.analysisState.detail,
      sourceKind: state.sourceContext.source?.kind ?? null,
      displayLabel: state.sourceContext.displayLabel,
      resolvedPath: state.sourceContext.resolvedPath,
      bundlePath: state.sourceContext.bundlePath,
      evidenceFilePath: state.sourceContext.evidenceFilePath,
      rawInput: state.rawInput,
      hasResult: state.result !== null,
    };
  }, DSREGCMD_STORE);
}

/** Seven call sites need the same "workspace is up" precondition. */
async function openDsregcmd(page: Page): Promise<void> {
  await selectWorkspace(page, "dsregcmd");
  // The lazy workspace chunk has to land before its own controls exist.
  await expect(page.getByText("dsregcmd Workspace", { exact: true })).toBeVisible({
    timeout: 15_000,
  });
}

/** Seven call sites need the same workspace precondition. */
async function openNewIntune(page: Page): Promise<void> {
  await selectWorkspace(page, "New Intune Workspace");
}

/**
 * Install an IPC override whose handler cannot be expressed as serialized data.
 * `bootApp` overrides travel as JSON and the shim's override map is a live page
 * object, so request-dependent handlers are attached here instead.
 *
 * Rejections carry a bare string because that is what a `Result<_, String>`
 * command produces over Tauri IPC; only bare strings (and plain data objects)
 * surface their message through the reader's error normalizer.
 */
async function installHandler(
  page: Page,
  command: string,
  outcome: { kind: "resolve"; value: unknown } | { kind: "reject"; message: string },
): Promise<void> {
  await page.evaluate(
    ({ name, result }) => {
      const shim = window as unknown as DiagnosticsShim;
      const overrides = shim.__e2e_ipc_overrides__;
      if (!overrides) {
        throw new Error("tauri shim did not install __e2e_ipc_overrides__");
      }
      overrides[name] =
        result.kind === "resolve"
          ? () => result.value
          : () => Promise.reject(result.message);
    },
    { name: command, result: outcome },
  );
}

// ---------------------------------------------------------------------------
// dsregcmd — dashboard surfaces
// ---------------------------------------------------------------------------

test.describe("dsregcmd: dashboard", () => {
  test("[DSREG-016] the health summary spotlights the top issue and explains the readout", async ({
    page,
  }) => {
    await bootApp(page);
    await openDsregcmd(page);
    await seedDsregcmd(page, { result: clone(DSREGCMD_REAL.result) });

    const summary = page.getByText(/Source: Sample capture \(Contoso\)/);
    await expect(summary).toBeVisible({ timeout: 15_000 });
    for (const line of [
      /Join type: Microsoft Entra joined/,
      /Current stage: Post-Join/,
      /Stage summary: Device is Entra joined and past registration; token and policy health are being evaluated\./,
      /Capture confidence: High/,
      /Diagnostics: 0 errors, 1 warnings, 1 info/,
      /Top issue: No critical issues detected/,
    ]) {
      await expect(summary).toContainText(line);
    }

    const health = section(page, "Health Summary");
    await expect(health.getByText("Issue spotlight", { exact: true })).toBeVisible();
    await expect(
      health.getByText("Device is Entra joined but not MDM enrolled", { exact: true }),
    ).toBeVisible();
    // High confidence means no interpretation qualifier.
    await expect(health.getByText(/Interpret this in the context of/)).toHaveCount(0);

    const quick = blockOf(health.getByText("Quick interpretation", { exact: true }));
    expect(await quick.locator("li").allInnerTexts()).toEqual([
      "Device is Entra joined and past registration; token and policy health are being evaluated.",
      "Capture confidence is high: Live capture was taken from this session, so freshness is based on the capture action rather than dsregcmd diagnostic timestamps.",
      "Registry-backed WHfB policy evidence is available for this bundle.",
      "No explicit network marker was detected in the capture.",
      "Capture does not look like a SYSTEM remote-session snapshot.",
      "Certificate expiry was not flagged as near-term.",
    ]);

    const explainer = section(page, "Explainer");
    await expect(explainer.getByText("What the health cards mean", { exact: true })).toBeVisible();
    await expect(
      explainer.getByText(
        /Cards summarize join posture, token state, MDM visibility, certificate lifetime, and issue counts\./,
      ),
    ).toBeVisible();
    await expect(explainer.getByText("When the capture may mislead", { exact: true })).toBeVisible();
    await expect(
      explainer.getByText(/SYSTEM and remote-session captures can distort user-scoped token state\./),
    ).toBeVisible();
    await expect(
      explainer.getByText(/Evidence bundle captures can also be older than the current device state/),
    ).toBeVisible();
    await expect(explainer.getByText("Suggested next step", { exact: true })).toBeVisible();
    await expect(
      explainer.getByText(/Start with the highest-severity issue card, validate the evidence line items/),
    ).toBeVisible();

    // A saved bundle is not a live capture: medium confidence qualifies the
    // spotlight, and the first Error diagnostic outranks the earlier Warning.
    const variant = merge(clone(DSREGCMD_REAL.result), {
      derived: {
        captureConfidence: "medium",
        captureConfidenceReason: "Capture came from a saved bundle written three weeks ago.",
      },
      diagnostics: [
        (DSREGCMD_REAL.result.diagnostics as AnyRecord[])[0],
        {
          id: "token-acquisition-failed",
          severity: "Error",
          category: "Authentication",
          title: "Token acquisition failed after join",
          summary: "The PRT request returned HTTP 400 for the user identity in this capture.",
          evidence: ["HttpStatus : 400"],
          nextChecks: ["Re-run dsregcmd /status as the signed-in user"],
          suggestedFixes: ["Re-register the device"],
        },
      ],
    });
    await seedDsregcmd(page, {
      result: variant,
      context: {
        ...DSREGCMD_REAL.context,
        source: { kind: "file", path: EVIDENCE_FILE },
        displayLabel: "dsregcmd-status.txt",
      },
    });

    await expect(
      health.getByText("Token acquisition failed after join", { exact: true }),
    ).toBeVisible();
    await expect(
      health.getByText(
        /The PRT request returned HTTP 400 for the user identity in this capture\. Interpret this in the context of medium capture confidence\./,
      ),
    ).toBeVisible();
    await expect
      .poll(async () => (await quick.locator("li").allInnerTexts())[1])
      .toContain("Capture confidence is medium");
  });

  test("[DSREG-017] the timeline renders each timestamp in local time with its tone", async ({
    page,
  }) => {
    await bootApp(page);
    await openDsregcmd(page);
    await seedDsregcmd(page, { result: clone(DSREGCMD_REAL.result) });

    const timeline = section(page, "Timeline");
    const [certFrom, certTo, prtAttempt, clientTime] = await localRender(page, [
      "2025-01-10 09:14:02.000 UTC",
      "2035-01-08 09:14:02.000 UTC",
      "2026-07-13 06:02:11.000 UTC",
      "2026-07-13 06:02:10.000 UTC",
    ]);

    const rows: Array<[string, string | null, Tone]> = [
      ["Certificate valid from", certFrom, "neutral"],
      ["Certificate valid to", certTo, "neutral"],
      ["Previous PRT attempt", prtAttempt, "neutral"],
      ["Azure AD PRT update", prtAttempt, "good"],
      ["Client reference time", clientTime, "neutral"],
    ];
    for (const [label, value, tone] of rows) {
      const label$ = timeline.getByText(label, { exact: true });
      await expect(label$).toBeVisible();
      await expect(valueAfter(label$)).toHaveText(value as string);
      await expectTone(page, blockOf(label$), TIMELINE_TONE_TOKEN[tone]);
    }

    // A stale PRT and a nearly expired certificate both flip to the warn tone.
    await seedDsregcmd(page, {
      result: merge(clone(DSREGCMD_REAL.result), {
        derived: { stalePrt: true, certificateExpiringSoon: true, certificateDaysRemaining: 12 },
      }),
    });
    await expectTone(
      page,
      blockOf(timeline.getByText("Certificate valid to", { exact: true })),
      TIMELINE_TONE_TOKEN.warn,
    );
    await expectTone(
      page,
      blockOf(timeline.getByText("Azure AD PRT update", { exact: true })),
      TIMELINE_TONE_TOKEN.warn,
    );
  });

  test("[DSREG-017] the timeline drops certificate rows without a value and recomputes a live PRT age", async ({
    page,
  }) => {
    await bootApp(page);
    await openDsregcmd(page);

    await seedDsregcmd(page, {
      result: merge(clone(DSREGCMD_REAL.result), {
        derived: { certificateValidFrom: null, certificateValidTo: null },
        facts: {
          deviceDetails: { deviceCertificateValidity: null },
          diagnostics: { previousPrtAttempt: null, clientTime: null },
          ssoState: { azureAdPrtUpdateTime: null },
        },
      }),
      // A saved bundle is not a live capture, so the parsed PRT age is shown.
      context: {
        ...DSREGCMD_REAL.context,
        source: { kind: "file", path: EVIDENCE_FILE },
        displayLabel: "dsregcmd-status.txt",
      },
    });

    const timeline = section(page, "Timeline");
    await expect(timeline.getByText("Certificate valid from", { exact: true })).toHaveCount(0);
    await expect(timeline.getByText("Certificate valid to", { exact: true })).toHaveCount(0);
    // A row without a value is omitted rather than rendered as a placeholder:
    // the timeline only carries real timestamps.
    await expect(timeline.getByText("Previous PRT attempt", { exact: true })).toHaveCount(0);
    await expect(timeline.getByText("Client reference time", { exact: true })).toHaveCount(0);

    // The PRT age fact reports the parsed age for a saved bundle …
    const ageRow = page.getByText("PRT Age Hours", { exact: true });
    await expect(ageRow).toBeVisible();
    await expect(valueAfter(ageRow)).toHaveText(hourDuration(2.6));

    // … and recomputes it from the clock for a live capture.
    await seedDsregcmd(page, {
      result: clone(DSREGCMD_REAL.result),
      context: { ...DSREGCMD_REAL.context, source: { kind: "capture" } },
    });
    const lastUpdate = Date.parse("2026-07-13T06:02:11.000Z");
    await expect
      .poll(async () => valueAfter(ageRow).innerText(), { timeout: 15_000 })
      .toBe(hourDuration((Date.now() - lastUpdate) / 3_600_000));
  });

  test("[DSREG-017] the timeline omits rows without a timestamp and shows its empty state", async ({
    page,
  }) => {
    await bootApp(page);
    await openDsregcmd(page);
    await seedDsregcmd(page, {
      result: merge(clone(DSREGCMD_REAL.result), {
        derived: { certificateValidFrom: null, certificateValidTo: null },
        facts: {
          deviceDetails: { deviceCertificateValidity: null },
          diagnostics: { previousPrtAttempt: null, clientTime: null },
          ssoState: { azureAdPrtUpdateTime: null },
        },
      }),
    });

    const timeline = section(page, "Timeline");
    await expect(
      timeline.getByText("No timeline-friendly timestamps were found in this capture.", {
        exact: true,
      }),
    ).toBeVisible();
  });

  test("[DSREG-018] a lower-confidence capture qualifies the flow details it routes through the confidence check", async ({
    page,
  }) => {
    await bootApp(page);
    await openDsregcmd(page);
    await seedDsregcmd(page, {
      result: merge(clone(DSREGCMD_REAL.result), {
        derived: {
          captureConfidence: "low",
          captureConfidenceReason: "Capture text was partial, so several sections were absent.",
        },
        facts: { deviceDetails: { deviceAuthStatus: "FAILED", tpmProtected: false } },
      }),
      context: {
        ...DSREGCMD_REAL.context,
        source: { kind: "file", path: EVIDENCE_FILE },
        displayLabel: "dsregcmd-status.txt",
      },
    });

    const flows = section(page, "Flows");
    // The four boxes whose copy is routed through the confidence qualifier.
    await expect(valueAfter(flows.getByText("Device authentication", { exact: true }))).toHaveText(
      /^Based on this capture, .*device auth status is FAILED and TPM protected is No\.$/,
    );
    await expect(valueAfter(flows.getByText("Management", { exact: true }))).toHaveText(
      /^Based on this capture, .*visibility is Unknown and compliance URL present is Yes\. Missing fields are not proof that management is broken\.$/,
    );
    await expect(valueAfter(flows.getByText("PRT and session", { exact: true }))).toHaveText(
      /^Based on this capture, .*PRT present is Yes, stale is No, and remote SYSTEM is No\.$/i,
    );
    await expect(valueAfter(flows.getByText("NGC readiness", { exact: true }))).toHaveText(
      /^Based on this capture, .*NGC is Yes, policy enabled is Yes \(dsregcmd\), PreReq Result is Will Provision, and device eligible is Yes\.$/i,
    );
    // A failed device auth reads bad, and so does the capture trust box.
    await expectTone(
      page,
      blockOf(flows.getByText("Device authentication", { exact: true })),
      CARD_TONE_TOKEN.bad,
    );
    await expectTone(
      page,
      blockOf(flows.getByText("Capture trust", { exact: true })),
      CARD_TONE_TOKEN.bad,
    );
  });

  test("[DSREG-018] every conclusion flow box is confidence-qualified", async ({ page }) => {
      await bootApp(page);
      await openDsregcmd(page);
      await seedDsregcmd(page, {
        result: merge(clone(DSREGCMD_REAL.result), {
          derived: {
            captureConfidence: "low",
            captureConfidenceReason: "Capture text was partial, so several sections were absent.",
          },
        }),
        context: {
          ...DSREGCMD_REAL.context,
          source: { kind: "file", path: EVIDENCE_FILE },
          displayLabel: "dsregcmd-status.txt",
        },
      });

      const flows = section(page, "Flows");
      // Documented: "Each box's text is prefixed 'Based on this capture, ...'
      // when confidence is not High." Observed: only Device authentication,
      // Management, PRT and session and NGC readiness call
      // qualifyByCaptureConfidence; Current phase, Join posture and Capture
      // trust render unqualified copy at low confidence.
      await expect(valueAfter(flows.getByText("Join posture", { exact: true }))).toHaveText(
        /^Based on this capture, /,
      );
    },
  );

  test("[DSREG-027] endpoint connectivity facts render the capture's endpoint probes", async ({
    page,
  }) => {
    await bootApp(page);
    await openDsregcmd(page);

    const probes = [
      {
        endpoint: "https://enterpriseregistration.windows.net",
        reachable: true,
        statusCode: 200,
        latencyMs: 142,
        errorMessage: null,
        timestamp: "2026-07-13T06:01:00Z",
      },
      {
        endpoint: "https://login.microsoftonline.com",
        reachable: true,
        statusCode: 302,
        latencyMs: 2400,
        errorMessage: null,
        timestamp: "2026-07-13T06:01:01Z",
      },
      {
        endpoint: "https://device.login.microsoftonline.com",
        reachable: false,
        statusCode: null,
        latencyMs: null,
        errorMessage: "The remote name could not be resolved",
        timestamp: "2026-07-13T06:01:12Z",
      },
      {
        endpoint: "https://autologon.microsoftazuread-sso.com",
        reachable: true,
        statusCode: 401,
        latencyMs: 96,
        errorMessage: null,
        timestamp: "2026-07-13T06:01:02Z",
      },
    ];

    await expect(section(page, "Endpoint Connectivity")).toHaveCount(0);

    await seedDsregcmd(page, {
      result: merge(clone(DSREGCMD_REAL.result), {
        activeEvidence: { connectivityTests: probes, scpQuery: null },
      }),
    });

    const group = section(page, "Endpoint Connectivity");
    await expect(group).toBeVisible();
    await expect(
      group.getByText("Live reachability tests to required Microsoft Entra endpoints.", {
        exact: true,
      }),
    ).toBeVisible();

    const rows: Array<[string, string, Tone]> = [
      ["enterpriseregistration.windows.net", "Reachable (200) — 142ms", "good"],
      ["login.microsoftonline.com", "Reachable (302) — 2400ms", "warn"],
      [
        "device.login.microsoftonline.com",
        "Unreachable — The remote name could not be resolved",
        "bad",
      ],
      ["autologon.microsoftazuread-sso.com", "Reachable (401) — 96ms", "good"],
    ];
    for (const [host, value, tone] of rows) {
      const label$ = group.getByText(host, { exact: true });
      await expect(label$).toBeVisible();
      await expect(valueAfter(label$)).toHaveText(value);
      await expectTone(page, valueAfter(label$), CARD_TONE_TOKEN[tone]);
    }
  });
});

// ---------------------------------------------------------------------------
// dsregcmd — source loading
// ---------------------------------------------------------------------------

test.describe("dsregcmd: source loading", () => {
  test("[DSREG-008] whitespace-only dsregcmd input is rejected with the documented detail", async ({
    page,
  }) => {
    await bootApp(page, {
      overrides: {
        // The paste path reads the clipboard through the shim.
        "plugin:clipboard-manager|read_text": "   \n \t ",
      },
    });
    await openDsregcmd(page);

    await page.getByRole("button", { name: "Paste", exact: true }).first().click();

    await expect(page.getByText("dsregcmd analysis failed", { exact: true })).toBeVisible();
    // The workspace body and the sidebar both report the failure detail.
    await expect(
      page
        .getByText("The selected dsregcmd source did not contain any text.", { exact: true })
        .first(),
    ).toBeVisible();
    expect(await readDsregcmdState(page)).toMatchObject({
      phase: "error",
      detail: "The selected dsregcmd source did not contain any text.",
      hasResult: false,
    });

    // The text-source branch rejects its own empty input the same way.
    const textOutcome = await page.evaluate(
      async ({ sourcePath, storePath }) => {
        const source = (await import(/* @vite-ignore */ sourcePath)) as {
          analyzeDsregcmdText: (input: string, label?: string) => Promise<unknown>;
        };
        const store = (await import(/* @vite-ignore */ storePath)) as {
          useDsregcmdStore: { getState: () => AnyRecord };
        };
        let thrown: string | null = null;
        try {
          await source.analyzeDsregcmdText("\n  \t");
        } catch (error) {
          thrown = error instanceof Error ? error.message : String(error);
        }
        const state = store.useDsregcmdStore.getState() as {
          analysisState: { phase: string; detail: string | null };
          result: unknown;
        };
        return {
          thrown,
          phase: state.analysisState.phase,
          detail: state.analysisState.detail,
          hasResult: state.result !== null,
        };
      },
      { sourcePath: DSREGCMD_SOURCE, storePath: DSREGCMD_STORE },
    );
    expect(textOutcome).toEqual({
      thrown: "dsregcmd input was empty.",
      phase: "error",
      detail: "dsregcmd input was empty.",
      hasResult: false,
    });
  });

  test("[DSREG-008] a dropped dsregcmd path falls back from the file to the folder source", async ({
    page,
  }) => {
    await bootApp(page);
    await openDsregcmd(page);

    const bundleUnsupported =
      "Selected folder is not a supported dsregcmd evidence bundle location. Choose the bundle root, the bundle's evidence folder, or the bundle's command-output folder.";

    const outcome = await page.evaluate(
      async ({ sourcePath, storePath, evidenceFile, analysis, message }) => {
        const shim = window as unknown as DiagnosticsShim;
        const overrides = shim.__e2e_ipc_overrides__;
        if (!overrides) {
          throw new Error("tauri shim did not install __e2e_ipc_overrides__");
        }
        const calls: Array<{ kind: string; path: string }> = [];
        overrides["load_dsregcmd_source"] = (args) => {
          const request = args as { kind: string; path: string };
          calls.push({ kind: request.kind, path: request.path });
          if (request.kind === "file") {
            // A `Result<_, String>` command rejects with the bare string, which
            // is the only form the reader surfaces verbatim.
            return Promise.reject(message);
          }
          return Promise.resolve({
            input: "AzureAdJoined : YES",
            bundlePath: "C:\\Evidence\\dsregcmd-bundle",
            resolvedPath: evidenceFile,
            evidenceFilePath: evidenceFile,
          });
        };
        overrides["analyze_dsregcmd"] = () => analysis;

        const source = (await import(/* @vite-ignore */ sourcePath)) as {
          analyzeDsregcmdPath: (
            path: string,
            options?: { fallbackToFolder?: boolean },
          ) => Promise<unknown>;
        };
        const store = (await import(/* @vite-ignore */ storePath)) as {
          useDsregcmdStore: { getState: () => AnyRecord };
        };

        await source.analyzeDsregcmdPath("C:\\Evidence\\dsregcmd-bundle");
        const afterFallback = store.useDsregcmdStore.getState() as {
          sourceContext: { source: { kind: string } | null; resolvedPath: string | null };
        };

        let strictError: string | null = null;
        try {
          await source.analyzeDsregcmdPath("C:\\Evidence\\other", {
            fallbackToFolder: false,
          });
        } catch (error) {
          strictError = error instanceof Error ? error.message : String(error);
        }

        return {
          calls,
          sourceKind: afterFallback.sourceContext.source?.kind ?? null,
          resolvedPath: afterFallback.sourceContext.resolvedPath,
          strictError,
        };
      },
      {
        sourcePath: DSREGCMD_SOURCE,
        storePath: DSREGCMD_STORE,
        evidenceFile: EVIDENCE_FILE,
        analysis: MOCK_DSREGCMD.result,
        message: bundleUnsupported,
      },
    );

    // The same dropped path is retried as a folder source, and the successful
    // resolution lands in the store.
    expect(outcome.calls.slice(0, 2)).toEqual([
      { kind: "file", path: BUNDLE_ROOT },
      { kind: "folder", path: BUNDLE_ROOT },
    ]);
    expect(outcome.sourceKind).toBe("folder");
    expect(outcome.resolvedPath).toBe(EVIDENCE_FILE);
    // Without the fallback the first failure propagates instead of retrying.
    expect(outcome.strictError).toBe(bundleUnsupported);
    expect(outcome.calls).toEqual([
      { kind: "file", path: BUNDLE_ROOT },
      { kind: "folder", path: BUNDLE_ROOT },
      { kind: "file", path: "C:\\Evidence\\other" },
    ]);
  });

  test("[DSREG-008] refreshing re-analyzes the recorded source and is refused without one", async ({
    page,
  }) => {
    await bootApp(page);
    await openDsregcmd(page);

    const outcome = await page.evaluate(
      async ({ sourcePath, storePath, evidenceFile, analysis, statusText }) => {
        const shim = window as unknown as DiagnosticsShim;
        const overrides = shim.__e2e_ipc_overrides__;
        if (!overrides) {
          throw new Error("tauri shim did not install __e2e_ipc_overrides__");
        }
        const calls: Array<{ kind: string; path: string }> = [];
        overrides["load_dsregcmd_source"] = (args) => {
          const request = args as { kind: string; path: string };
          calls.push({ kind: request.kind, path: request.path });
          return Promise.resolve({
            input: statusText,
            bundlePath: "C:\\Evidence\\dsregcmd-bundle",
            resolvedPath: evidenceFile,
            evidenceFilePath: evidenceFile,
          });
        };
        overrides["analyze_dsregcmd"] = () => analysis;

        const source = (await import(/* @vite-ignore */ sourcePath)) as {
          analyzeDsregcmdSource: (descriptor: unknown) => Promise<unknown>;
          refreshCurrentDsregcmdSource: () => Promise<boolean>;
          canRefreshDsregcmdSource: (descriptor: unknown) => boolean;
        };
        const store = (await import(/* @vite-ignore */ storePath)) as {
          useDsregcmdStore: { getState: () => AnyRecord };
        };

        // No source recorded yet: nothing to refresh.
        const refreshWithoutSource = await source.refreshCurrentDsregcmdSource();

        await source.analyzeDsregcmdSource({ kind: "file", path: evidenceFile });
        const callsAfterFirst = calls.length;
        const refreshWithSource = await source.refreshCurrentDsregcmdSource();

        const analysisState = (
          store.useDsregcmdStore.getState() as {
            analysisState: { phase: string; requestedKind: string | null };
          }
        ).analysisState;

        return {
          refreshWithoutSource,
          refreshWithSource,
          calls,
          callsAfterFirst,
          phase: analysisState.phase,
          requestedKind: analysisState.requestedKind,
          canRefreshNull: source.canRefreshDsregcmdSource(null),
          canRefreshFile: source.canRefreshDsregcmdSource({ kind: "file", path: "x.log" }),
          canRefreshText: source.canRefreshDsregcmdSource({ kind: "text", label: "pasted" }),
        };
      },
      {
        sourcePath: DSREGCMD_SOURCE,
        storePath: DSREGCMD_STORE,
        evidenceFile: EVIDENCE_FILE,
        analysis: MOCK_DSREGCMD.result,
        statusText: DSREGCMD_STATUS_TEXT,
      },
    );

    expect(outcome.refreshWithoutSource).toBe(false);
    expect(outcome.refreshWithSource).toBe(true);
    expect(outcome.callsAfterFirst).toBe(1);
    // The refresh re-analyzed the very source the first load recorded.
    expect(outcome.calls[1]).toEqual(outcome.calls[0]);
    expect(outcome.phase).toBe("ready");
    expect(outcome.requestedKind).toBe("file");
    expect(outcome.canRefreshNull).toBe(false);
    expect(outcome.canRefreshFile).toBe(true);
    expect(outcome.canRefreshText).toBe(true);
  });

  test("[DSREG-023] a live capture lands as a live source carrying its bundle and evidence paths", async ({
    page,
  }) => {
    await bootApp(page, {
      overrides: {
        capture_dsregcmd: {
          input: DSREGCMD_STATUS_TEXT,
          bundlePath: BUNDLE_ROOT,
          evidenceFilePath: EVIDENCE_FILE,
        },
        analyze_dsregcmd: MOCK_DSREGCMD.result,
      },
    });
    await openDsregcmd(page);

    await page.getByRole("button", { name: "Capture", exact: true }).first().click();

    await expect
      .poll(async () => readDsregcmdState(page))
      .toMatchObject({
        phase: "ready",
        sourceKind: "capture",
        bundlePath: BUNDLE_ROOT,
        evidenceFilePath: EVIDENCE_FILE,
        resolvedPath: EVIDENCE_FILE,
        hasResult: true,
      });
    expect(await readDsregcmdState(page)).toMatchObject({ displayLabel: "Live capture" });
    await expect(page.getByText(/Live capture •/)).toBeVisible();
    await expect(
      page
        .locator("div")
        .filter({ hasText: "Bundle root:" })
        .filter({ hasText: BUNDLE_ROOT })
        .last(),
    ).toBeVisible();
    // The captured text is the analyzer's input and stays available verbatim.
    await page.getByRole("button", { name: "Show raw input", exact: true }).click();
    await expect(page.locator("textarea")).toHaveValue(DSREGCMD_STATUS_TEXT);
  });

  test("[DSREG-023] a refused capture surfaces as an analysis failure with the backend detail", async ({
    page,
  }) => {
    const refusal =
      "Refusing to execute C:\\Windows\\System32\\dsregcmd.exe: expected a valid Authenticode signature but WinVerifyTrust returned 0x800B0100 (TRUST_E_NOSIGNATURE)";
    await bootApp(page);
    await openDsregcmd(page);

    // The signature gate lives in the Rust command; the browser can drive the
    // frontend half of the contract, which must not swallow the refusal.
    await installHandler(page, "capture_dsregcmd", { kind: "reject", message: refusal });

    await page.getByRole("button", { name: "Capture", exact: true }).first().click();

    await expect(page.getByText("dsregcmd analysis failed", { exact: true })).toBeVisible();
    await expect(page.getByText(refusal, { exact: true }).first()).toBeVisible();
    expect(await readDsregcmdState(page)).toMatchObject({
      phase: "error",
      detail: refusal,
      hasResult: false,
    });
  });

  test("[DSREG-024] a folder source resolves to its evidence file and reports both paths", async ({
    page,
  }) => {
    await bootApp(page, {
      overrides: { "plugin:dialog|open": BUNDLE_ROOT, analyze_dsregcmd: MOCK_DSREGCMD.result },
    });
    await openDsregcmd(page);

    await page.evaluate(
      async ({ payload }) => {
        const shim = window as unknown as DiagnosticsShim;
        const overrides = shim.__e2e_ipc_overrides__;
        if (!overrides) {
          throw new Error("tauri shim did not install __e2e_ipc_overrides__");
        }
        shim.__dsregcmdLoads__ = [];
        overrides["load_dsregcmd_source"] = (args) => {
          const request = args as { kind: string; path: string };
          shim.__dsregcmdLoads__?.push({ kind: request.kind, path: request.path });
          return Promise.resolve(payload);
        };
      },
      {
        payload: {
          input: DSREGCMD_STATUS_TEXT,
          bundlePath: BUNDLE_ROOT,
          resolvedPath: EVIDENCE_FILE,
          evidenceFilePath: EVIDENCE_FILE,
        },
      },
    );

    await page.getByRole("button", { name: /open evidence folder/i }).first().click();

    await expect
      .poll(async () => readDsregcmdState(page))
      .toMatchObject({
        phase: "ready",
        sourceKind: "folder",
        displayLabel: "dsregcmd-status.txt",
        bundlePath: BUNDLE_ROOT,
        evidenceFilePath: EVIDENCE_FILE,
        resolvedPath: EVIDENCE_FILE,
      });
    expect(
      await page.evaluate(() => {
        const shim = window as unknown as DiagnosticsShim;
        return shim.__dsregcmdLoads__;
      }),
    ).toEqual([{ kind: "folder", path: BUNDLE_ROOT }]);

    // The sidebar reports which evidence file the bundle resolved to.
    await expect(
      page.locator("div").filter({ hasText: "Evidence file:" }).last(),
    ).toContainText(EVIDENCE_FILE);
    await expect(
      page.locator("div").filter({ hasText: "Bundle root:" }).last(),
    ).toContainText(BUNDLE_ROOT);

    // A file source reports the evidence file separately from the file opened,
    // and still carries the bundle the ancestor manifest.json identified.
    await page.evaluate(
      async ({ payload }) => {
        const shim = window as unknown as DiagnosticsShim;
        const overrides = shim.__e2e_ipc_overrides__;
        if (!overrides) {
          throw new Error("tauri shim did not install __e2e_ipc_overrides__");
        }
        shim.__dsregcmdLoads__ = [];
        overrides["load_dsregcmd_source"] = (args) => {
          const request = args as { kind: string; path: string };
          shim.__dsregcmdLoads__?.push({ kind: request.kind, path: request.path });
          return Promise.resolve(payload);
        };
      },
      {
        payload: {
          input: DSREGCMD_STATUS_TEXT,
          bundlePath: BUNDLE_ROOT,
          resolvedPath: STANDALONE_FILE,
          evidenceFilePath: EVIDENCE_FILE,
        },
      },
    );
    await page.evaluate((filePath) => {
      const shim = window as unknown as DiagnosticsShim;
      const overrides = shim.__e2e_ipc_overrides__;
      if (!overrides) {
        throw new Error("tauri shim did not install __e2e_ipc_overrides__");
      }
      overrides["plugin:dialog|open"] = () => filePath;
    }, STANDALONE_FILE);

    await page.getByRole("button", { name: /open text file/i }).first().click();

    await expect
      .poll(async () => readDsregcmdState(page))
      .toMatchObject({
        sourceKind: "file",
        resolvedPath: STANDALONE_FILE,
        evidenceFilePath: EVIDENCE_FILE,
        bundlePath: BUNDLE_ROOT,
      });
    expect(
      await page.evaluate(() => {
        const shim = window as unknown as DiagnosticsShim;
        return shim.__dsregcmdLoads__;
      }),
    ).toEqual([{ kind: "file", path: STANDALONE_FILE }]);
    await expect(page.getByText(`evidence ${EVIDENCE_FILE}`, { exact: false }).first()).toBeVisible();
  });

  test("[DSREG-022] the dsregcmd workspace is Windows-only and never offers known-source presets", async ({
    page,
  }) => {
    await bootApp(page, {
      overrides: {
        get_known_log_sources: [
          {
            id: "windows-intune-ime-logs",
            label: "Intune IME logs",
            description: "Live Intune Management Extension log folder.",
            platform: "windows",
            sourceKind: "known",
            source: {
              kind: "known",
              sourceId: "windows-intune-ime-logs",
              defaultPath: IME_FOLDER,
              pathKind: "folder",
            },
            filePatterns: ["*.log"],
            grouping: {
              familyId: "intune",
              familyLabel: "Intune",
              groupId: "intune:ime",
              groupLabel: "Management Extension",
              groupOrder: 1,
              sourceOrder: 1,
            },
          },
        ],
      },
    });

    // The catalog reaches the toolbar in the log workspace …
    await expect(page.getByRole("button", { name: "Open known log source..." })).toBeEnabled({
      timeout: 15_000,
    });

    // … and is refused in the dsregcmd workspace, whose capabilities disable it.
    await openDsregcmd(page);
    const knownButton = page.getByRole("button", {
      name: "Known sources unavailable",
      exact: true,
    });
    await expect(knownButton).toBeDisabled();
    await expect(page.getByRole("button", { name: "Open known log source..." })).toHaveCount(0);

    // The workspace refuses a preset source itself, not just the catalog gate.
    const refused = await page.evaluate(async (modulePath) => {
      const module = (await import(/* @vite-ignore */ modulePath)) as {
        dsregcmdWorkspace: {
          onOpenSource: (source: unknown, trigger: string) => Promise<void>;
        };
      };
      let thrown: string | null = null;
      try {
        await module.dsregcmdWorkspace.onOpenSource(
          {
            kind: "known",
            sourceId: "windows-intune-ime-logs",
            defaultPath: "C:\\ProgramData\\Microsoft\\IntuneManagementExtension\\Logs",
            pathKind: "folder",
          },
          "spec.known-source",
        );
      } catch (error) {
        thrown = error instanceof Error ? error.message : String(error);
      }
      return thrown;
    }, DSREGCMD_WORKSPACE);
    expect(refused).toBe("Known log presets are not supported in the dsregcmd workspace.");

    // The declared capabilities back both gates.
    const declaration = await page.evaluate(async (modulePath) => {
      const module = (await import(/* @vite-ignore */ modulePath)) as {
        getWorkspace: (id: string) => {
          platforms: unknown;
          capabilities: Record<string, unknown>;
          fileFilters: Array<{ name: string; extensions: string[] }>;
        };
      };
      const workspace = module.getWorkspace("dsregcmd");
      return {
        platforms: workspace.platforms,
        knownSources: workspace.capabilities.knownSources,
        fileFilters: workspace.fileFilters,
      };
    }, WORKSPACE_REGISTRY);
    expect(declaration.platforms).toEqual(["windows"]);
    expect(declaration.knownSources).toBe(false);
    expect(declaration.fileFilters).toEqual([
      { name: "Text Files", extensions: ["txt"] },
      { name: "Log Files", extensions: ["log"] },
      { name: "All Files", extensions: ["*"] },
    ]);
  });

  test("[DSREG-022] a non-Windows host drops the dsregcmd workspace from the switcher", async ({
    page,
  }) => {
    await bootApp(page, { platform: "macos" });

    // The OS probe is the toolbar's own concern; the gate under test is the
    // workspace's declared platform, so the probed result is applied the same
    // way the toolbar applies it.
    await page.evaluate(async (storePath) => {
      const module = (await import(/* @vite-ignore */ storePath)) as {
        useUiStore: {
          getState: () => { setCurrentPlatform: (platform: string) => void };
        };
      };
      module.useUiStore.getState().setCurrentPlatform("macos");
    }, UI_STORE);
    await expect
      .poll(async () =>
        page.evaluate(async (storePath) => {
          const module = (await import(/* @vite-ignore */ storePath)) as {
            useUiStore: { getState: () => { currentPlatform: string } };
          };
          return module.useUiStore.getState().currentPlatform;
        }, UI_STORE),
      )
      .toBe("macos");

    const combo = page.getByRole("combobox", { name: "Workspace" });
    await combo.click();
    await expect(page.getByRole("option", { name: "Log Explorer", exact: true })).toBeVisible();
    await expect(page.getByRole("option", { name: "dsregcmd", exact: true })).toHaveCount(0);
    await page.keyboard.press("Escape");

    // The gate is the platform alone: the log view stays active.
    await expect(page.getByText(/Log view/)).toBeVisible();
  });
});

// ---------------------------------------------------------------------------
// Intune — fixtures and helpers
// ---------------------------------------------------------------------------

const EVENT_LOG_CHANNEL_A = "DeviceManagement-Operational";
const EVENT_LOG_CHANNEL_B = "User Device Registration";

function bundleMeta(label: string | null, id: string | null): AnyRecord {
  return {
    manifestPath: `${BUNDLE_ROOT}\\manifest.json`,
    notesPath: null,
    evidenceRoot: BUNDLE_ROOT,
    primaryEntryPoints: [],
    availablePrimaryEntryPoints: [],
    bundleId: id,
    bundleLabel: label,
    createdUtc: null,
    caseReference: null,
    summary: null,
    collectorProfile: null,
    collectorVersion: null,
    collectedUtc: null,
    deviceName: null,
    primaryUser: null,
    platform: null,
    osVersion: null,
    tenant: null,
    artifactCounts: null,
  };
}

/** What `parse_intune_evtx_bundle` produces for a bundle holding EVTX files. */
const BUNDLE_EVENT_LOGS = {
  sourceKind: "Bundle",
  entries: [
    {
      id: 1,
      channel: "DeviceManagementOperational",
      channelDisplay: EVENT_LOG_CHANNEL_A,
      provider: "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider",
      eventId: 1204,
      severity: "Critical",
      timestamp: "2026-07-13 09:22:20.000",
      computer: "WORKSTATION",
      message: "MDM policy evaluation failed with 0x87D1041C for the enforcement transaction.",
      correlationActivityId: null,
      sourceFile: "DeviceManagement-Operational.evtx",
    },
    {
      id: 2,
      channel: "DeviceManagementOperational",
      channelDisplay: EVENT_LOG_CHANNEL_A,
      provider: "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider",
      eventId: 1101,
      severity: "Error",
      timestamp: "2026-07-13 09:22:59.000",
      computer: "WORKSTATION",
      message: "Detection of the Win32 application failed after install.",
      correlationActivityId: null,
      sourceFile: "DeviceManagement-Operational.evtx",
    },
    {
      id: 3,
      channel: "DeviceManagementOperational",
      channelDisplay: EVENT_LOG_CHANNEL_A,
      provider: "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider",
      eventId: 1101,
      severity: "Error",
      timestamp: "2026-07-13 09:47:10.000",
      computer: "WORKSTATION",
      message: "Detection of the Win32 application failed after install.",
      correlationActivityId: null,
      sourceFile: "DeviceManagement-Operational.evtx",
    },
    {
      id: 4,
      channel: "DeviceManagementOperational",
      channelDisplay: EVENT_LOG_CHANNEL_A,
      provider: "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider",
      eventId: 1050,
      severity: "Warning",
      timestamp: "2026-07-13 09:31:06.000",
      computer: "WORKSTATION",
      message: "Remediation script exited with a non-zero status.",
      correlationActivityId: null,
      sourceFile: "DeviceManagement-Operational.evtx",
    },
    {
      id: 5,
      channel: "UserDeviceRegistrationAdmin",
      channelDisplay: EVENT_LOG_CHANNEL_B,
      provider: "Microsoft-Windows-User Device Registration",
      eventId: 3000,
      severity: "Information",
      timestamp: "2026-07-13 09:15:00.000",
      computer: "WORKSTATION",
      message: "Device registration succeeded for the tenant.",
      correlationActivityId: null,
      sourceFile: "UserDeviceRegistration.evtx",
    },
    {
      id: 6,
      channel: "UserDeviceRegistrationAdmin",
      channelDisplay: EVENT_LOG_CHANNEL_B,
      provider: "Microsoft-Windows-User Device Registration",
      eventId: 1000,
      severity: "Verbose",
      timestamp: "2026-07-13 09:14:58.000",
      computer: "WORKSTATION",
      message: "Registration task started.",
      correlationActivityId: null,
      sourceFile: "UserDeviceRegistration.evtx",
    },
  ],
  channelSummaries: [
    {
      channel: "DeviceManagementOperational",
      channelDisplay: EVENT_LOG_CHANNEL_A,
      entryCount: 4,
      errorCount: 2,
      warningCount: 1,
      timestampBounds: null,
      sourceFile: "DeviceManagement-Operational.evtx",
    },
    {
      channel: "UserDeviceRegistrationAdmin",
      channelDisplay: EVENT_LOG_CHANNEL_B,
      entryCount: 2,
      errorCount: 0,
      warningCount: 0,
      timestampBounds: null,
      sourceFile: "UserDeviceRegistration.evtx",
    },
  ],
  correlationLinks: [
    {
      eventLogEntryId: 6,
      linkedIntuneEventId: 1,
      linkedDiagnosticId: null,
      correlationKind: "TimeWindowChannelMatch",
      timeDeltaSecs: 5,
    },
    {
      eventLogEntryId: 5,
      linkedIntuneEventId: 1,
      linkedDiagnosticId: null,
      correlationKind: "TimeWindowChannelMatch",
      timeDeltaSecs: 10,
    },
    {
      eventLogEntryId: 4,
      linkedIntuneEventId: 3,
      linkedDiagnosticId: "diag-script-access-denied",
      correlationKind: "ErrorCodeMatch",
      timeDeltaSecs: 7200,
    },
    {
      eventLogEntryId: 2,
      linkedIntuneEventId: 2,
      linkedDiagnosticId: "diag-win32-detect-fail",
      correlationKind: "ErrorCodeMatch",
      timeDeltaSecs: 300,
    },
    {
      eventLogEntryId: 1,
      linkedIntuneEventId: 2,
      linkedDiagnosticId: "diag-win32-detect-fail",
      correlationKind: "TimeWindowChannelMatch",
      timeDeltaSecs: 900,
    },
    {
      eventLogEntryId: 3,
      linkedIntuneEventId: 2,
      linkedDiagnosticId: "diag-win32-detect-fail",
      correlationKind: "TimeWindowChannelMatch",
      timeDeltaSecs: 45,
    },
  ],
  parsedFileCount: 2,
  totalEntryCount: 6,
  errorEntryCount: 2,
  warningEntryCount: 1,
  timestampBounds: null,
  liveQuery: null,
};

/**
 * The reader validates every `analyze_intune_logs` response field, so the
 * payload an overridden backend resolves with must carry the same fields the
 * Rust command returns.
 */
const INTUNE_ANALYSIS_RESULT = {
  ...MOCK_INTUNE,
  diagnosticsCoverage: {
    files: [],
    timestampBounds: null,
    hasRotatedLogs: false,
    dominantSource: null,
  },
  diagnosticsConfidence: { level: "Medium", score: 0.5, reasons: ["Fixture analysis"] },
  repeatedFailures: [],
  guidRegistry: {},
};

interface IntuneSeed {
  events?: unknown;
  downloads?: unknown;
  summary?: unknown;
  diagnostics?: unknown;
  sourceFile?: unknown;
  sourceFiles?: unknown;
  metadata?: AnyRecord;
}

async function seedIntuneResults(page: Page, seed: IntuneSeed = {}): Promise<void> {
  await page.evaluate(
    async ({ storePath, payload }) => {
      const module = (await import(/* @vite-ignore */ storePath)) as {
        useIntuneStore: {
          getState: () => { setResults: (...args: unknown[]) => void };
        };
      };
      module.useIntuneStore
        .getState()
        .setResults(
          payload.events,
          payload.downloads,
          payload.summary,
          payload.diagnostics,
          payload.sourceFile,
          payload.sourceFiles,
          payload.metadata,
        );
    },
    {
      storePath: INTUNE_STORE,
      payload: {
        events: MOCK_INTUNE.events,
        downloads: MOCK_INTUNE.downloads,
        summary: MOCK_INTUNE.summary,
        diagnostics: MOCK_INTUNE.diagnostics,
        sourceFile: MOCK_INTUNE.sourceFile,
        sourceFiles: MOCK_INTUNE.sourceFiles,
        ...seed,
      },
    },
  );
}

interface IntuneStateView {
  phase: string;
  message: string;
  detail: string | null;
  lastError: string | null;
  requestId: string | null;
  requestedPath: string | null;
  requestedKind: string | null;
  progress: AnyRecord | null;
  selectedEventLogEntryId: number | null;
  isAnalyzing: boolean;
}

async function readIntuneState(page: Page): Promise<IntuneStateView> {
  return page.evaluate(async (storePath) => {
    const module = (await import(/* @vite-ignore */ storePath)) as {
      useIntuneStore: { getState: () => AnyRecord };
    };
    const state = module.useIntuneStore.getState() as {
      analysisState: {
        phase: string;
        message: string;
        detail: string | null;
        lastError: string | null;
        requestId: string | null;
        requestedPath: string | null;
        requestedKind: string | null;
        progress: AnyRecord | null;
      };
      selectedEventLogEntryId: number | null;
      isAnalyzing: boolean;
    };
    return {
      phase: state.analysisState.phase,
      message: state.analysisState.message,
      detail: state.analysisState.detail,
      lastError: state.analysisState.lastError,
      requestId: state.analysisState.requestId,
      requestedPath: state.analysisState.requestedPath,
      requestedKind: state.analysisState.requestedKind,
      progress: state.analysisState.progress,
      selectedEventLogEntryId: state.selectedEventLogEntryId,
      isAnalyzing: state.isAnalyzing,
    };
  }, INTUNE_STORE);
}

/**
 * The hero renders Source / State / Bundle as caption + value pills, and the
 * sidebar repeats the same values, so the value is read through its caption.
 * Three captions share this shape.
 */
function pillValue(page: Page, caption: string): Locator {
  return page
    .getByText(caption, { exact: true })
    .locator("xpath=following-sibling::*[1]");
}

// ---------------------------------------------------------------------------
// Intune — analysis, bundle EVTX evidence and triage
// ---------------------------------------------------------------------------

test.describe("intune: new intune analysis", () => {
  test("[INTUNE-016] analysis progress streams into the hero and stale requests are dropped", async ({
    page,
  }) => {
    await page.addInitScript(() => {
      const shim = window as unknown as DiagnosticsShim;
      const overrides = shim.__e2e_ipc_overrides__;
      if (!overrides) {
        throw new Error("tauri shim did not install __e2e_ipc_overrides__");
      }
      overrides["analyze_intune_logs"] = () => {
        const { promise, resolve } = Promise.withResolvers<unknown>();
        shim.__resolveIntuneAnalysis__ = resolve;
        return promise;
      };
    });
    await bootApp(page, { overrides: { "plugin:dialog|open": IME_FOLDER } });
    await openNewIntune(page);

    await page.getByRole("button", { name: "Open IME or evidence folder...", exact: true }).click();

    await expect
      .poll(async () => (await readIntuneState(page)).message)
      .toBe("Analyzing Intune folder...");
    const started = await readIntuneState(page);
    expect(started.phase).toBe("analyzing");
    expect(started.requestedPath).toBe(IME_FOLDER);
    expect(started.isAnalyzing).toBe(true);

    // The app generates the request id; the backend echoes it back per stage.
    const liveRequestId = started.requestId as string;
    expect(typeof liveRequestId).toBe("string");
    const stages: Array<[string, string, string | null]> = [
      ["resolving", "Resolving Intune log sources", null],
      ["enumerating", "Enumerating Intune log files", "0 of 7 complete | "],
      ["reading-file", "Reading AppWorkload.log", "3 of 7 complete | AppWorkload.log"],
      [
        "parsing-event-logs",
        "Parsing Windows event log evidence",
        "7 of 7 complete | System.evtx",
      ],
      ["finalizing", "Finalizing Intune diagnostics", null],
    ];
    for (const [stage, message, detail] of stages) {
      await emitBackendEvent(page, "intune-analysis-progress", {
        requestId: liveRequestId,
        stage,
        message,
        detail,
        currentFile: "AppWorkload.log",
        completedFiles: 3,
        totalFiles: 7,
      });
      await expect.poll(async () => (await readIntuneState(page)).message).toBe(message);
      const view = await readIntuneState(page);
      expect(view.detail).toBe(detail);
      expect(view.progress).toMatchObject({
        stage,
        currentFile: "AppWorkload.log",
        completedFiles: 3,
        totalFiles: 7,
      });
      await expect(pillValue(page, "State")).toHaveText(message);
    }

    // A payload from another request is dropped.
    await emitBackendEvent(page, "intune-analysis-progress", {
      requestId: "some-other-request",
      stage: "reading-file",
      message: "Reading AgentExecutor.log",
      detail: "5 of 9 complete | AgentExecutor.log",
      currentFile: "AgentExecutor.log",
      completedFiles: 5,
      totalFiles: 9,
    });
    expect(await readIntuneState(page)).toMatchObject({
      message: "Finalizing Intune diagnostics",
      progress: { stage: "finalizing", completedFiles: 3, totalFiles: 7 },
    });

    // Completing the analysis closes the gate: later progress is ignored.
    await page.evaluate((payload) => {
      const shim = window as unknown as DiagnosticsShim;
      shim.__resolveIntuneAnalysis__?.(payload);
    }, { ...INTUNE_ANALYSIS_RESULT });
    await expect.poll(async () => (await readIntuneState(page)).phase).toBe("ready");
    expect((await readIntuneState(page)).message).toBe("Analysis complete (3 files)");

    await emitBackendEvent(page, "intune-analysis-progress", {
      requestId: liveRequestId,
      stage: "reading-file",
      message: "Reading after the fact",
      detail: "1 of 1 complete | late.log",
      currentFile: "late.log",
      completedFiles: 1,
      totalFiles: 1,
    });
    expect(await readIntuneState(page)).toMatchObject({
      phase: "ready",
      message: "Analysis complete (3 files)",
      progress: null,
    });
  });

  test("[INTUNE-025] a bundle's EVTX evidence renders as the Intune event-log section", async ({
    page,
  }) => {
    await bootApp(page);
    await openNewIntune(page);

    // With no EVTX evidence in the bundle there is simply no event-log section.
    await seedIntuneResults(page, { metadata: { eventLogAnalysis: null } });
    await expect(page.getByRole("group", { name: /^Event log signals/ })).toHaveCount(0);
    const eventLogTab = page.getByRole("tab", { name: /Event log evidence/ });
    await expect(eventLogTab).toBeDisabled();

    await seedIntuneResults(page, {
      metadata: { eventLogAnalysis: clone(BUNDLE_EVENT_LOGS) },
    });

    // Two errors plus one warning, drawn from two parsed channels …
    await expect(page.getByRole("group", { name: "Event log signals: 3" })).toBeVisible();
    await expect(page.getByText("6 entries across 2 channel(s)", { exact: true })).toBeVisible();
    await expect(eventLogTab).toBeEnabled();
    await expect(eventLogTab).toContainText("2");

    await eventLogTab.click();
    await expect(page.locator("select").first()).toContainText("All channels (6)");
    await expect(page.getByRole("button", { name: /DeviceManagement-Operational/ })).toContainText(
      "4 entries",
    );
    await expect(page.getByRole("button", { name: /User Device Registration/ })).toContainText(
      "2 entries",
    );
    await expect(page.getByText("ID 1204", { exact: true })).toBeVisible();
    await expect(page.getByText("ID 3000", { exact: true })).toBeVisible();
    await expect(page.getByText("linked", { exact: true }).first()).toBeVisible();

    // The channel summary narrows the list to that channel's entries.
    await page.getByRole("button", { name: /User Device Registration/ }).click();
    await expect(page.getByText(/2 of 6 entries/)).toBeVisible();
    await expect(page.getByText("ID 1204", { exact: true })).toHaveCount(0);
  });
});

test.describe("intune: overview triage", () => {
  test("[INTUNE-027] correlated event-log entries back the priority issue cards", async ({
    page,
  }) => {
    const corroboration =
      "Windows Event Log: DeviceManagement-Operational Event ID 1204 (Critical) at 2026-07-13 09:22:20.000 — MDM policy evaluation failed with 0x87D1041C for the enforcement transaction.";
    await bootApp(page);
    await openNewIntune(page);

    await seedIntuneResults(page, {
      diagnostics: [
        {
          ...(MOCK_INTUNE.diagnostics[0] as AnyRecord),
          evidence: [corroboration, "AppWorkload.log:1044 - detection failed (0x87D1041C)"],
        },
        MOCK_INTUNE.diagnostics[1],
      ],
      metadata: { eventLogAnalysis: clone(BUNDLE_EVENT_LOGS) },
    });

    // The diagnostic evidence list carries the corroboration line verbatim.
    await expect(page.getByText(corroboration, { exact: true })).toBeVisible();
    // Three links point at the Win32 detection diagnostic, one at the script.
    await expect(page.getByRole("button", { name: "3 event log signals", exact: true })).toBeVisible();
    await expect(page.getByRole("button", { name: "1 event log signal", exact: true })).toBeVisible();

    await page.getByRole("button", { name: "1 event log signal", exact: true }).click();
    await expect(page.locator("select").first()).toContainText("All channels (6)");
    await expect(page.getByText("ID 1050", { exact: true })).toBeVisible();

    // A diagnostic with no correlation links grows no signal button at all.
    await page.getByRole("tab", { name: "Overview" }).click();
    await seedIntuneResults(page, {
      diagnostics: [
        { ...(MOCK_INTUNE.diagnostics[0] as AnyRecord), id: "diag-unlinked" },
        { ...(MOCK_INTUNE.diagnostics[1] as AnyRecord), id: "diag-unlinked-2" },
      ],
      metadata: { eventLogAnalysis: clone(BUNDLE_EVENT_LOGS) },
    });
    await expect(
      page.getByText("Win32 app installed but failed detection", { exact: true }),
    ).toBeVisible();
    await expect(
      page.getByText("Remediation script blocked by permissions", { exact: true }),
    ).toBeVisible();
    await expect(page.getByRole("button", { name: /event log signal/ })).toHaveCount(0);
  });

  test("[INTUNE-033] the correlated evidence card ranks the top five entries and jumps into the event log", async ({
    page,
  }) => {
    await bootApp(page);
    await openNewIntune(page);
    await seedIntuneResults(page, {
      metadata: { eventLogAnalysis: clone(BUNDLE_EVENT_LOGS) },
    });

    const card = page
      .locator(".fui-Card")
      .filter({ hasText: "Correlated event log evidence" })
      .first();
    await expect(card).toBeVisible();
    await expect(card.getByText("6 links", { exact: true })).toBeVisible();
    await expect(
      card.getByText(
        "Windows Event Log entries linked to IME diagnostics by time, channel, or error code.",
        { exact: true },
      ),
    ).toBeVisible();

    // Five rows: the sixth entry (Verbose) is beyond the cap.
    await expect(card.getByText("Registration task started.", { exact: true })).toHaveCount(0);
    await expect(card.getByText("ID 1204", { exact: true })).toBeVisible();
    await expect(card.getByText("ID 1050", { exact: true })).toBeVisible();
    await expect(card.getByText("15m delta", { exact: true })).toBeVisible();
    await expect(card.getByText("45s delta", { exact: true })).toBeVisible();
    await expect(card.getByText("5m delta", { exact: true })).toBeVisible();
    await expect(card.getByText("2h delta", { exact: true })).toBeVisible();
    await expect(card.getByText("10s delta", { exact: true })).toBeVisible();
    await expect(card.getByText("Error", { exact: true })).toHaveCount(2);
    await expect(card.getByText("Critical", { exact: true })).toHaveCount(1);
    await expect(card.getByText(EVENT_LOG_CHANNEL_B, { exact: true })).toBeVisible();

    // Rows are laid out top-to-bottom in that ranked order: Critical, the two
    // Errors by ascending delta, then Warning, then Information.
    const rankedRows = [
      ["MDM policy evaluation failed with 0x87D1041C", "15m delta"],
      ["Detection of the Win32 application failed after install.", "45s delta"],
      ["Detection of the Win32 application failed after install.", "5m delta"],
      ["Remediation script exited with a non-zero status.", "2h delta"],
      ["Device registration succeeded for the tenant.", "10s delta"],
    ];
    const positions: number[] = [];
    for (const [message, delta] of rankedRows) {
      const row = card
        .locator("div")
        .filter({ hasText: message })
        .filter({ hasText: delta })
        .last();
      await expect(row).toBeVisible();
      const box = await row.boundingBox();
      positions.push(box ? box.y : Number.NaN);
    }
    expect(positions).toHaveLength(5);
    expect(positions).toEqual([...positions].sort((left, right) => left - right));

    // "View all event log evidence" moves to the event log surface without
    // selecting anything.
    await card.getByRole("button", { name: "View all event log evidence", exact: true }).click();
    await expect(page.locator("select").first()).toContainText("All channels (6)");
    expect((await readIntuneState(page)).selectedEventLogEntryId).toBeNull();

    // Clicking a row selects that entry and moves to the same surface.
    await page.getByRole("tab", { name: "Overview" }).click();
    await card.getByText("MDM policy evaluation failed with 0x87D1041C").first().click();
    await expect
      .poll(async () => (await readIntuneState(page)).selectedEventLogEntryId)
      .toBe(1);
    await expect(page.getByRole("tab", { name: /Event log evidence/ })).toHaveAttribute(
      "aria-selected",
      "true",
    );
    await expect(page.getByText("Provider:", { exact: false }).first()).toBeVisible();
    await expect(page.getByText("Related IME Evidence", { exact: true })).toBeVisible();

    // No correlation links means no card at all.
    await page.getByRole("tab", { name: "Overview" }).click();
    await seedIntuneResults(page, {
      metadata: {
        eventLogAnalysis: { ...clone(BUNDLE_EVENT_LOGS), correlationLinks: [] },
      },
    });
    await expect(page.getByText("Correlated event log evidence", { exact: true })).toHaveCount(0);
    await expect(page.getByText("Event log signals", { exact: true })).toBeVisible();
  });

  test("[INTUNE-030] the empty New Intune hero starts a live investigation", async ({ page }) => {
    await page.addInitScript(() => {
      const shim = window as unknown as DiagnosticsShim;
      const overrides = shim.__e2e_ipc_overrides__;
      if (!overrides) {
        throw new Error("tauri shim did not install __e2e_ipc_overrides__");
      }
      overrides["analyze_intune_logs"] = () => {
        const { promise, resolve } = Promise.withResolvers<unknown>();
        shim.__resolveIntuneAnalysis__ = resolve;
        return promise;
      };
    });
    await bootApp(page, {
      overrides: {
        get_known_log_sources: [
          {
            id: "windows-intune-ime-logs",
            label: "Intune IME logs",
            description: "Live Intune Management Extension log folder.",
            platform: "windows",
            sourceKind: "known",
            source: {
              kind: "known",
              sourceId: "windows-intune-ime-logs",
              defaultPath: IME_FOLDER,
              pathKind: "folder",
            },
            filePatterns: ["*.log"],
            grouping: {
              familyId: "intune",
              familyLabel: "Intune",
              groupId: "intune:ime",
              groupLabel: "Management Extension",
              groupOrder: 1,
              sourceOrder: 1,
            },
          },
        ],
      },
    });
    await openNewIntune(page);

    const liveButton = page.getByRole("button", {
      name: "Analyze live logs + event logs",
      exact: true,
    });
    await expect(liveButton).toBeVisible({ timeout: 15_000 });
    const startCard = liveButton.locator("xpath=ancestor::div[contains(@class,'fui-Card')][1]");
    await expect(startCard.getByText("New Intune Workspace", { exact: true })).toBeVisible();
    await expect(
      startCard.getByText("Start from the signals, not the scrollback", { exact: true }),
    ).toBeVisible();
    await expect(
      startCard.getByText(
        /Analyze the live IME logs and live Windows event channels directly from the machine/,
      ),
    ).toBeVisible();
    await expect(liveButton).toBeEnabled();
    await expect(page.getByRole("button", { name: "Open IME log file...", exact: true })).toBeEnabled();
    await expect(
      page.getByRole("button", { name: "Open IME or evidence folder...", exact: true }),
    ).toBeEnabled();

    await liveButton.click();
    await expect
      .poll(async () => readIntuneState(page))
      .toMatchObject({
        requestedPath: IME_FOLDER,
        requestedKind: "known",
        phase: "analyzing",
      });
    await expect(pillValue(page, "State")).toHaveText("Analyzing Intune log source...");
    await expect(
      page.getByText("Start from the signals, not the scrollback", { exact: true }),
    ).toHaveCount(0);
  });

  test("[INTUNE-030] the empty state refuses the live action without a known source catalog", async ({
    page,
  }) => {
    await bootApp(page);
    await openNewIntune(page);

    const liveButton = page.getByRole("button", {
      name: "Analyze live logs + event logs",
      exact: true,
    });
    await expect(liveButton).toBeVisible({ timeout: 15_000 });
    await expect(liveButton).toBeDisabled();
    await expect(page.getByRole("button", { name: "Open IME log file...", exact: true })).toBeEnabled();
    await expect(
      page.getByRole("button", { name: "Open IME or evidence folder...", exact: true }),
    ).toBeEnabled();

    // Until the catalog exists the action cannot resolve its source, so it
    // stays refused rather than failing later inside the analysis.
    await expect(liveButton).toBeDisabled();
  });

  test("[INTUNE-030] the populated hero shows source pills, actions and a permanently disabled refresh", async ({
    page,
  }) => {
    await bootApp(page);
    await openNewIntune(page);
    await seedIntuneResults(page);

    await expect(
      page.getByText("Operational Triage for Intune Evidence", { exact: true }),
    ).toBeVisible();
    await expect(
      page.getByText(
        "Move from failure signal to supporting log activity without dropping into a long text-first summary.",
        { exact: true },
      ),
    ).toBeVisible();

    // Source / State / Bundle pills. The sidebar repeats the same values, so
    // each is read through its caption.
    await expect(pillValue(page, "Source")).toHaveText(MOCK_INTUNE.sourceFile);
    await expect(pillValue(page, "State")).toHaveText("Analysis complete (3 files)");
    await expect(pillValue(page, "Bundle")).toHaveText("Standalone logs");

    // The documented action set, and the refresh that can never enable here.
    await expect(page.getByRole("button", { name: "Analyze Live Logs + Event Logs" })).toBeVisible();
    await expect(page.getByRole("button", { name: "Open IME Log File" })).toBeEnabled();
    await expect(page.getByRole("button", { name: "Open IME Or Evidence Folder" })).toBeEnabled();
    const refresh = page.getByRole("button", { name: "Refresh analysis", exact: true });
    await expect(refresh).toBeDisabled();

    // Bundle label falls back to the bundle id, then to the standalone marker.
    await seedIntuneResults(page, {
      metadata: { evidenceBundle: bundleMeta(null, "bundle-42") },
    });
    await expect(pillValue(page, "Bundle")).toHaveText("bundle-42");

    await seedIntuneResults(page, {
      metadata: { evidenceBundle: bundleMeta("Contoso case", "bundle-42") },
    });
    await expect(pillValue(page, "Bundle")).toHaveText("Contoso case");

    await seedIntuneResults(page, { metadata: { evidenceBundle: null } });
    await expect(pillValue(page, "Bundle")).toHaveText("Standalone logs");
    await expect(refresh).toBeDisabled();
  });
});
