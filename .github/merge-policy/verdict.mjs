// verdict — the reviewer's structured output contract and how it is judged.
//
// Only findings decide: a review fails iff it reports at least one blocker or
// major finding that names a concrete failure scenario. A free-text "fail"
// with no such finding does not block, and a "pass" with one does.

export const REVIEW_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["summary", "findings"],
  properties: {
    summary: { type: "string", description: "One or two sentences: what the change does and the overall risk." },
    findings: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["severity", "file", "title", "failure_scenario"],
        properties: {
          severity: { type: "string", enum: ["blocker", "major", "minor", "nit"] },
          file: { type: "string" },
          line: { type: "integer" },
          title: { type: "string" },
          failure_scenario: {
            type: "string",
            description: "Concrete inputs or state -> wrong output, crash, data loss or exposure. Empty if speculative.",
          },
          fix: { type: "string" },
        },
      },
    },
  },
};

const BLOCKING = new Set(["blocker", "major"]);
const MIN_SCENARIO = 20;

/**
 * @param {unknown} raw  the reviewer's structured_output (object or JSON string)
 * @returns {{ok: boolean, state: "success"|"failure"|"error", blocking: object[], other: object[], summary: string, error?: string}}
 */
export function judge(raw) {
  let out = raw;
  if (typeof out === "string") {
    try {
      out = JSON.parse(out);
    } catch {
      return errorResult("reviewer output is not valid JSON");
    }
  }
  if (!out || typeof out !== "object" || !Array.isArray(out.findings) || typeof out.summary !== "string") {
    return errorResult("reviewer output does not match the schema");
  }
  const blocking = [];
  const other = [];
  for (const f of out.findings) {
    if (!f || typeof f !== "object") continue;
    const concrete = typeof f.failure_scenario === "string" && f.failure_scenario.trim().length >= MIN_SCENARIO;
    if (BLOCKING.has(f.severity) && concrete) blocking.push(f);
    else other.push(BLOCKING.has(f.severity) ? { ...f, severity: "minor", downgraded: true } : f);
  }
  return {
    ok: blocking.length === 0,
    state: blocking.length === 0 ? "success" : "failure",
    blocking,
    other,
    summary: out.summary,
  };
}

function errorResult(error) {
  return { ok: false, state: "error", blocking: [], other: [], summary: "", error };
}

/** Commit-status description, <= 140 chars. */
export function describe(result) {
  if (result.state === "error") return `error: ${result.error}`.slice(0, 140);
  const minor = result.other.length;
  const head = result.ok ? "pass" : "fail";
  return `${head} · ${result.blocking.length} blocking · ${minor} non-blocking`.slice(0, 140);
}

// Credential shapes that must never reach a PR comment, a status or an
// artifact: Anthropic keys and OAuth tokens, GitHub tokens of every kind.
const SECRET_PATTERNS = [/sk-ant-[A-Za-z0-9_-]+/g, /gh[pousr]_[A-Za-z0-9]{20,}/g, /github_pat_[A-Za-z0-9_]{20,}/g];

/** Replaces anything shaped like a credential with "[redacted]". */
export function redact(text) {
  if (typeof text !== "string") return text;
  return SECRET_PATTERNS.reduce((t, re) => t.replace(re, "[redacted]"), text);
}

// Review verdicts are check runs `merge-review/<name>` that the merge-bot App
// posts on the head SHA from the review job, which runs in the merge-bot
// environment (default branch only). Nothing else holds the App's key there,
// so nothing else can create a check run with the App's id: commit statuses
// and workflow artifacts, which any workflow run can produce, are not evidence.
export const REVIEW_CHECK_PREFIX = "merge-review/";
const STATES = ["success", "failure", "error"];

/**
 * The check run (POST /repos/{repo}/check-runs body) carrying one verdict.
 * @param {{reviewer: string, pr: number, head: string, state: string, description?: string, detailsUrl?: string}} v
 */
export function verdictCheck({ reviewer, pr, head, state, description, detailsUrl }) {
  const s = STATES.includes(state) ? state : "error";
  const body = {
    name: `${REVIEW_CHECK_PREFIX}${reviewer}`,
    head_sha: head,
    status: "completed",
    conclusion: s === "success" ? "success" : "failure",
    output: {
      title: `${reviewer} review: ${s}`,
      summary: redact(description || s).slice(0, 60000),
      text: JSON.stringify({ pr, head, state: s, reviewer }),
    },
  };
  if (detailsUrl) body.details_url = detailsUrl;
  return body;
}

const bindingOf = (run) => {
  try {
    const b = JSON.parse(run.output?.text || "");
    return b && typeof b === "object" ? b : null;
  } catch {
    return null;
  }
};

/**
 * Newest verdict per reviewer among the App's own merge-review/* check runs
 * for this PR and head. A run from another App, on another SHA, for another
 * PR, or whose recorded head, state or conclusion disagree is ignored, i.e.
 * the reviewer counts as missing and the gate fails closed.
 * @param {object[]} runs  GET /repos/{repo}/commits/{sha}/check-runs check_runs
 * @param {{sha: string, prNumber: number, appId: number, onIgnore?: (run: object, why: string) => void}} o
 * @returns {Record<string, {state: string, description: string, url?: string}>}
 */
export function boundVerdicts(runs, { sha, prNumber, appId, onIgnore = () => {} }) {
  const newest = {};
  for (const run of runs || []) {
    if (typeof run?.name !== "string" || !run.name.startsWith(REVIEW_CHECK_PREFIX)) continue;
    const reviewer = run.name.slice(REVIEW_CHECK_PREFIX.length);
    const b = bindingOf(run);
    const why =
      !appId || Number(run.app?.id) !== Number(appId)
        ? `created by app ${run.app?.id ?? "?"}, not the merge bot`
        : run.head_sha !== sha
          ? "on another commit"
          : run.status !== "completed"
            ? "not completed"
            : !b
              ? "no binding in its output"
              : b.pr !== prNumber
                ? `for PR #${b.pr}`
                : b.head !== sha || b.reviewer !== reviewer
                  ? "binding names another head or reviewer"
                  : !STATES.includes(b.state) || (b.state === "success") !== (run.conclusion === "success")
                    ? "state and conclusion disagree"
                    : null;
    if (why) {
      onIgnore(run, why);
      continue;
    }
    const at = `${run.completed_at || run.started_at || ""}`;
    const cur = newest[reviewer];
    if (!cur || at > cur.at || (at === cur.at && Number(run.id) > Number(cur.id))) newest[reviewer] = { at, id: run.id, run, state: b.state };
  }
  return Object.fromEntries(
    Object.entries(newest).map(([name, { run, state }]) => [name, { state, description: run.output?.summary || "", url: run.details_url || run.html_url }]),
  );
}
