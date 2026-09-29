#!/usr/bin/env node
// run-gate — the merge-gate workflow's entry point.
//
//   node run-gate.mjs classify   -> outputs: pr, head_sha, tier, reviewers_needed, ...
//   node run-gate.mjs decide     -> arms / disarms / merges, labels, sticky comment, the App's merge-gate check
//   node run-gate.mjs fail-check -> classification did not complete: a failing merge-gate check
//
// Runs from the BASE branch checkout (pull_request_target / workflow_run /
// workflow_dispatch). PR content is read through the API as data and never
// executed.

import { randomUUID } from "node:crypto";
import { appendFileSync, existsSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { classify, needsHeadCommit, SQL_CONTENT_MAX, sqlContentNeeds, sqlModeNeeds } from "./classify.mjs";
import { APPROVAL_CHECK, approvalCheck, approvalRecord, approvalRunAllows, approvalToRecord, decide, keepOwnerArming, LABELS, ownerApproved } from "./gate.mjs";
import { GitHub } from "./github.mjs";
import { botAppId, loadPolicy } from "./policy.mjs";
import { boundVerdicts, redact } from "./verdict.mjs";

const env = process.env;
const repo = env.GITHUB_REPOSITORY;
const ACTIONS_BOT = "github-actions[bot]";
const GATE_CHECK = "merge-gate";
const STICKY = "<!-- merge-policy:gate -->";

/**
 * One GITHUB_OUTPUT entry in the heredoc form. A random delimiter per entry
 * means no value (a filename, a reason) can close the entry early and inject
 * another key: `key=value` lines let a newline in a filename set `tier=green`.
 */
export function outputEntry(key, value) {
  const text = typeof value === "string" ? value : JSON.stringify(value);
  let delim = `EOF_${randomUUID()}`;
  while (text.includes(delim)) delim = `EOF_${randomUUID()}`;
  return `${key}<<${delim}\n${text}\n${delim}\n`;
}

function output(key, value) {
  const entry = outputEntry(key, value);
  if (env.GITHUB_OUTPUT) appendFileSync(env.GITHUB_OUTPUT, entry);
  else process.stdout.write(entry);
}

function summary(md) {
  if (env.GITHUB_STEP_SUMMARY) appendFileSync(env.GITHUB_STEP_SUMMARY, `${md}\n`);
  else process.stdout.write(`${md}\n`);
}

function event() {
  return env.GITHUB_EVENT_PATH && existsSync(env.GITHUB_EVENT_PATH)
    ? JSON.parse(readFileSync(env.GITHUB_EVENT_PATH, "utf8"))
    : {};
}

async function resolvePrNumber(gh, ev) {
  if (env.PR_NUMBER) return Number(env.PR_NUMBER);
  if (ev.pull_request?.number) return ev.pull_request.number;
  if (ev.inputs?.pr) return Number(ev.inputs.pr);
  if (ev.workflow_run) {
    const direct = ev.workflow_run.pull_requests?.[0]?.number;
    if (direct) return direct;
    const pulls = await gh.get(`/repos/{repo}/commits/${ev.workflow_run.head_sha}/pulls`);
    return pulls.find((p) => p.state === "open")?.number ?? null;
  }
  return null;
}

async function isFrozen(gh) {
  const issues = await gh.get(`/repos/{repo}/issues?state=open&labels=${encodeURIComponent(LABELS.freeze)}&per_page=1`);
  return issues.length > 0;
}

/**
 * Newest bound verdict per reviewer: the merge-bot App's own merge-review/*
 * check runs on this head for this PR (see boundVerdicts). Statuses and
 * artifacts are not read: any workflow run can produce those.
 * @param {number} appId  botAppId(policy)
 */
export async function reviewVerdicts(gh, sha, pr, appId) {
  const runs = await gh.paginate(`/repos/{repo}/commits/${sha}/check-runs?filter=all&app_id=${appId}`, "check_runs");
  return boundVerdicts(runs, {
    sha,
    prNumber: pr.number,
    appId,
    onIgnore: (r, why) => console.log(`ignoring ${r.name} (${r.conclusion}) check run ${r.id}: ${why}`),
  });
}

const contentsPath = (path, sha) => `/repos/{repo}/contents/${path.split("/").map(encodeURIComponent).join("/")}?ref=${sha}`;

/**
 * Full head and base contents of the SQL files classify compares in full,
 * read as data through the contents API. A failed or oversized read is
 * recorded as an error, which classify turns into owner tier.
 */
export async function fetchSqlContents(gh, pr, files) {
  const out = {};
  for (const need of sqlContentNeeds(files)) {
    try {
      const head = await gh.raw(contentsPath(need.filename, pr.head.sha), SQL_CONTENT_MAX);
      const base = need.basePath ? await gh.raw(contentsPath(need.basePath, pr.base.sha), SQL_CONTENT_MAX) : "";
      out[need.filename] = { head, base };
    } catch (e) {
      out[need.filename] = { error: e.message };
    }
  }
  // The contents API follows symlinks (and lists them as files), so the git
  // mode comes from the head's trees.
  const trees = new Map();
  for (const path of sqlModeNeeds(files)) {
    const entry = (out[path] ??= {});
    if (entry.error) continue;
    try {
      entry.mode = await treeMode(gh, pr.head.sha, path, trees);
    } catch (e) {
      entry.error = e.message;
    }
  }
  return out;
}

/** The git mode ("100644", "120000", ...) of `path` in commit `sha`, walking one tree per directory. */
async function treeMode(gh, sha, path, cache) {
  const parts = path.split("/");
  let tree = sha;
  for (let i = 0; i < parts.length; i += 1) {
    if (!cache.has(tree)) cache.set(tree, gh.get(`/repos/{repo}/git/trees/${tree}`));
    const t = await cache.get(tree);
    const at = parts.slice(0, i + 1).join("/");
    if (t?.truncated) throw new Error(`tree listing truncated above ${at}`);
    const e = (t?.tree || []).find((x) => x.path === parts[i]);
    if (!e) throw new Error(`${at} not in the head tree`);
    if (i === parts.length - 1) return e.mode;
    if (e.type !== "tree") throw new Error(`${at} is not a directory (mode ${e.mode})`);
    tree = e.sha;
  }
  throw new Error("empty path");
}

/**
 * Is merge-gate a required check on `branch`, accepted only from the merge-bot
 * App? A pin to any other source (GitHub Actions, or none) would let any
 * workflow that can write checks shadow the gate, so it does not count.
 * @param {number|null} appId  policy.bot_app_id; without one, any merge-gate requirement counts
 */
export async function gateIsRequired(gh, branch, appId) {
  const pinned = (source) => !appId || Number(source) === Number(appId);
  const rules = await gh.get(`/repos/{repo}/rules/branches/${encodeURIComponent(branch)}`).catch(() => []);
  for (const r of rules || []) {
    if (r.type !== "required_status_checks") continue;
    for (const c of r.parameters?.required_status_checks || []) if (c.context === GATE_CHECK && pinned(c.integration_id)) return true;
  }
  const b = await gh.get(`/repos/{repo}/branches/${encodeURIComponent(branch)}`).catch(() => null);
  const classic = b?.protection?.required_status_checks;
  for (const c of classic?.checks || []) if (c.context === GATE_CHECK && pinned(c.app_id)) return true;
  if (!appId && (classic?.contexts || []).includes(GATE_CHECK)) return true;
  return false;
}

/**
 * The authoritative merge-gate check run, posted by the merge-bot App on the
 * head SHA. The ruleset accepts merge-gate from the App only, so no workflow
 * can shadow it; a run that never gets here leaves the check missing, which
 * keeps the required check pending (closed).
 */
export async function postGateCheck(app, { sha, conclusion, title, summary: text, detailsUrl }) {
  return app.post(`/repos/{repo}/check-runs`, {
    name: GATE_CHECK,
    head_sha: sha,
    status: "completed",
    conclusion,
    details_url: detailsUrl,
    output: { title: redact(title).slice(0, 250), summary: redact(text).slice(0, 60000) },
  });
}

const runLink = (vars) => `${vars.GITHUB_SERVER_URL || "https://github.com"}/${repo}/actions/runs/${vars.GITHUB_RUN_ID}`;

/** A failing merge-gate check for a run that could not decide (crash, classify
 * failure). Best effort: without an App token or a SHA, the check stays missing. */
export async function failGateCheck({ app, sha, reason, vars }) {
  if (!app || !sha) return false;
  await postGateCheck(app, {
    sha,
    conclusion: "failure",
    title: `merge-gate failed closed — ${reason}`.slice(0, 250),
    summary: `The gate run did not complete, so this head may not merge.\n\n- head: \`${sha}\`\n- reason: ${reason}\n- run: ${runLink(vars)}`,
    detailsUrl: runLink(vars),
  });
  return true;
}

/** Direct mode: true all required checks green, false any red, null pending. */
export async function ciState(gh, sha, required) {
  // No required CI: the review is the floor (classify never makes such a PR
  // green), so there is nothing left to wait for.
  if (!required.length) return true;
  const runs = await gh.paginate(`/repos/{repo}/commits/${sha}/check-runs`, "check_runs");
  let pending = false;
  for (const name of required) {
    const latest = runs.filter((r) => r.name === name).sort((a, b) => (b.started_at || "").localeCompare(a.started_at || ""))[0];
    if (!latest || latest.status !== "completed") pending = true;
    else if (!["success", "neutral", "skipped"].includes(latest.conclusion)) return false;
  }
  return pending ? null : true;
}

async function loadContext() {
  const policy = loadPolicy(env.MERGE_POLICY_PATH || ".github/merge-policy.json");
  const gh = new GitHub(env.GH_TOKEN, repo);
  const ev = event();
  const number = await resolvePrNumber(gh, ev);
  if (!number) return { policy, gh, ev, pr: null };
  const pr = await gh.get(`/repos/{repo}/pulls/${number}`);
  return { policy, gh, ev, pr };
}

async function cmdClassify() {
  const { policy, gh, ev, pr } = await loadContext();
  if (!pr) {
    output("skip", "true");
    summary("merge-gate: no open pull request for this event.");
    return;
  }
  // A push invalidates the owner's approval: it named the previous head. A
  // failure here fails classify, and with it the gate.
  if (ev.action === "synchronize" && pr.labels.some((l) => l.name === LABELS.approve)) {
    await gh.delete(`/repos/{repo}/issues/${pr.number}/labels/${encodeURIComponent(LABELS.approve)}`);
  }
  let c;
  try {
    const files = await gh.paginate(`/repos/{repo}/pulls/${pr.number}/files`);
    const repoInfo = await gh.get(`/repos/{repo}`);
    const botLogin = policy.bot_slug ? `${policy.bot_slug}[bot]` : undefined;
    // Dependabot's and the merge bot's tiers rest on the head commit, not on
    // an editable title or body.
    const headCommit = needsHeadCommit(pr, botLogin) ? await gh.get(`/repos/{repo}/commits/${pr.head.sha}`) : undefined;
    c = classify(policy, {
      headCommit,
      sqlContents: await fetchSqlContents(gh, pr, files),
      pr,
      files,
      repo,
      defaultBranch: repoInfo.default_branch,
      frozen: await isFrozen(gh),
      botLogin,
    });
  } finally {
    // A new head (or a retarget) invalidates any earlier arming; decide re-arms
    // if the new head earns it. The owner's own arming on an owner-tier PR is
    // his call and stays.
    if (["synchronize", "edited", "converted_to_draft"].includes(ev.action) && pr.auto_merge && !keepOwnerArming(c?.tier, pr, policy.owner_login)) {
      await disarm(gh, pr).catch((e) => console.log(`disarm failed: ${e.message}`));
    }
  }
  const cached = c.reviewers.length ? await reviewVerdicts(gh, pr.head.sha, pr, botAppId(policy)) : {};
  const needed = c.reviewers
    .filter((r) => !["success", "failure"].includes(cached[r]?.state))
    .map((name) => ({ name, model: policy.models[name], effort: policy.effort[name] || "high" }));

  output("skip", "false");
  output("pr", String(pr.number));
  output("head_sha", pr.head.sha);
  output("base_sha", pr.base.sha);
  output("tier", c.tier);
  output("reviewers", c.reviewers);
  output("reviewers_needed", needed);
  output("migration", String(c.migration));
  output("reasons", c.reasons.join("; ").slice(0, 900));
  summary(`### merge-gate classify — PR #${pr.number}\n\n- tier: **${c.tier}**\n- reasons: ${c.reasons.join("; ")}\n- reviewers: ${c.reviewers.join(", ") || "none"} (fresh: ${needed.map((n) => n.name).join(", ") || "none"})`);
}

const DISABLE = `mutation($id: ID!) { disablePullRequestAutoMerge(input: {pullRequestId: $id}) { clientMutationId } }`;
const ENABLE = `mutation($id: ID!, $method: PullRequestMergeMethod!, $oid: GitObjectID) {
  enablePullRequestAutoMerge(input: {pullRequestId: $id, mergeMethod: $method, expectedHeadOid: $oid}) { clientMutationId }
}`;

async function disarm(gh, pr) {
  if (!pr.auto_merge) return false;
  await gh.graphql(DISABLE, { id: pr.node_id });
  return true;
}

async function ensureLabels(gh, names) {
  const colors = { [LABELS.armed]: "0e8a16", [LABELS.owner]: "5319e7", [LABELS.changes]: "d93f0b" };
  for (const name of names) {
    await gh.post(`/repos/{repo}/labels`, { name, color: colors[name] || "ededed", description: "merge-policy" }).catch(() => {});
  }
}

async function applyLabels(gh, pr, add, remove) {
  const have = new Set(pr.labels.map((l) => l.name));
  const toAdd = add.filter((l) => !have.has(l));
  if (toAdd.length) {
    await ensureLabels(gh, toAdd);
    await gh.post(`/repos/{repo}/issues/${pr.number}/labels`, { labels: toAdd });
  }
  for (const l of remove.filter((x) => have.has(x))) {
    await gh.delete(`/repos/{repo}/issues/${pr.number}/labels/${encodeURIComponent(l)}`);
  }
}

function readReviewArtifacts(dir) {
  const out = {};
  if (!dir || !existsSync(dir)) return out;
  const walk = (d) => {
    for (const entry of readdirSync(d, { withFileTypes: true })) {
      const p = join(d, entry.name);
      if (entry.isDirectory()) walk(p);
      else if (/^review-.+\.json$/.test(entry.name)) {
        const r = JSON.parse(readFileSync(p, "utf8"));
        out[r.reviewer] = r;
      }
    }
  };
  walk(dir);
  return out;
}

/** Findings for the sticky comment. Reviewer text is untrusted: anything
 * shaped like a credential is redacted before it is rendered. */
export function renderFindings(artifacts) {
  const blocks = [];
  for (const [name, r] of Object.entries(artifacts)) {
    const lines = [`**${name}** (${r.model}) — ${r.description}`];
    if (r.summary) lines.push(`> ${r.summary.replace(/\n/g, " ")}`);
    for (const f of [...(r.blocking || []), ...(r.other || [])]) {
      const where = f.line ? `${f.file}:${f.line}` : f.file;
      lines.push(`- **[${f.severity}${f.downgraded ? ", downgraded: no concrete scenario" : ""}]** \`${where}\` — ${f.title}`);
      if (f.failure_scenario) lines.push(`  - scenario: ${f.failure_scenario}`);
      if (f.fix) lines.push(`  - fix: ${f.fix}`);
    }
    if (r.error) lines.push(`- error: ${r.error}`);
    blocks.push(lines.map(redact).join("\n"));
  }
  return redact(blocks.join("\n\n"));
}

/**
 * Owner tier: did the owner approve this head with the merge:approve label?
 * The run of his labeling records it first (an App check run on the head he
 * labeled); every run then needs that record on the current head.
 * @param {object|null} app  the merge-bot App client (null: nothing can be recorded)
 */
export async function ownerApprovalFor(gh, pr, policy, ev, app) {
  if (!approvalRunAllows(ev, pr.head.sha)) return false;
  const labels = pr.labels.map((l) => l.name);
  if (!labels.includes(LABELS.approve)) return false;
  const appId = botAppId(policy);
  const runs = [];
  if (app && approvalToRecord(ev, pr, policy.owner_login)) {
    const posted = await app
      .post(`/repos/{repo}/check-runs`, approvalCheck({ pr: pr.number, head: pr.head.sha, approver: policy.owner_login }))
      .catch((e) => console.log(`approval record not posted: ${e.message}`));
    if (posted) runs.push(posted);
  }
  const listed = await gh.paginate(`/repos/{repo}/commits/${pr.head.sha}/check-runs?filter=all&app_id=${appId}&check_name=${APPROVAL_CHECK}`, "check_runs");
  runs.push(...listed);
  const record = approvalRecord(runs, { sha: pr.head.sha, prNumber: pr.number, appId, ownerLogin: policy.owner_login });
  if (!record) return false;
  const events = await gh.paginate(`/repos/{repo}/issues/${pr.number}/events`);
  return ownerApproved(events, { ownerLogin: policy.owner_login, labels, record });
}

async function upsertSticky(gh, pr, body) {
  const comments = await gh.paginate(`/repos/{repo}/issues/${pr.number}/comments`);
  const mine = comments.find((c) => c.user?.login === ACTIONS_BOT && c.body?.startsWith(STICKY));
  if (mine) await gh.patch(`/repos/{repo}/issues/comments/${mine.id}`, { body });
  else await gh.post(`/repos/{repo}/issues/${pr.number}/comments`, { body });
  return mine?.body || "";
}

async function notifyOwnerOnce(gh, pr, policy, kind, text) {
  const marker = `<!-- merge-policy:owner sha=${pr.head.sha} kind=${kind} -->`;
  const comments = await gh.paginate(`/repos/{repo}/issues/${pr.number}/comments`);
  if (comments.some((c) => c.body?.includes(marker))) return;
  // A new comment (not an edit) so the mention reaches GitHub Mobile.
  await gh.post(`/repos/{repo}/issues/${pr.number}/comments`, { body: `${marker}\n@${policy.owner_login} ${text}` });
}

async function cmdDecide() {
  const { policy, gh, ev, pr } = await loadContext();
  if (!pr) return;
  let d;
  try {
    d = await decideAndApply({ policy, gh, pr, env, event: ev });
  } catch (e) {
    // The decision crashed: say so on the head, so an earlier success on the
    // same SHA cannot stand for this run.
    const app = env.MERGE_TOKEN ? new GitHub(env.MERGE_TOKEN, repo) : null;
    await failGateCheck({ app, sha: env.HEAD_SHA || pr.head.sha, reason: `decide crashed: ${e.message}`.slice(0, 200), vars: env }).catch((x) =>
      console.log(`posting the failing merge-gate check failed: ${x.message}`),
    );
    throw e;
  }
  if (d.conclusion === "failure") process.exitCode = 1;
}

/** Classification did not complete: post a failing merge-gate check where
 * possible, and fail the job either way. */
async function cmdFailCheck() {
  const reason = env.REASON || "classification did not complete";
  console.log(`::error::${reason}; refusing to pass`);
  const app = env.MERGE_TOKEN ? new GitHub(env.MERGE_TOKEN, repo) : null;
  const posted = await failGateCheck({ app, sha: env.HEAD_SHA, reason, vars: env }).catch((e) => {
    console.log(`posting the failing merge-gate check failed: ${e.message}`);
    return false;
  });
  if (!posted) console.log("no merge-bot token or head SHA: the merge-gate check stays missing (pending), which also blocks the merge");
  process.exitCode = 1;
}

/**
 * Decide for one PR and perform the side effects: arm/disarm/merge, labels,
 * sticky comment, owner mention. Everything external comes in through `gh`,
 * `vars` and `deps`, so tests drive it with fakes and no network.
 * @param {object} a
 * @param {object} a.policy  merged policy
 * @param {object} a.gh      GitHub client for the Actions token
 * @param {object} a.pr      the PR (REST shape)
 * @param {object} a.vars    HEAD_SHA, TIER, REASONS, REVIEWERS, MERGE_TOKEN, MERGE_BOT_LOGIN, REVIEW_DIR, GITHUB_SERVER_URL, GITHUB_RUN_ID
 * @param {object} [a.event] the workflow event payload (owner approval is bound to it)
 * @param {object} [a.deps]  { makeMerger(token), reviewVerdicts(gh, sha, pr, appId), log(md) }
 */
export async function decideAndApply({ policy, gh, pr, env: vars, event = {}, deps = {} }) {
  const makeMerger = deps.makeMerger || ((t) => new GitHub(t, repo));
  const verdicts = deps.reviewVerdicts || reviewVerdicts;
  const log = deps.log || summary;
  const mergeToken = vars.MERGE_TOKEN || "";
  // The App client posts the merge-gate check on every path and performs the
  // merge. Without an App token neither can happen: that mode already fails.
  const app = mergeToken ? makeMerger(mergeToken) : null;
  const classifiedSha = vars.HEAD_SHA;
  if (classifiedSha && pr.head.sha !== classifiedSha) {
    log(`merge-gate: head moved ${classifiedSha.slice(0, 7)} → ${pr.head.sha.slice(0, 7)}; the newer run decides.`);
    // Never report success for a head this run did not evaluate.
    await failGateCheck({ app, sha: classifiedSha, reason: `head moved to ${pr.head.sha.slice(0, 7)}; the newer run decides`, vars });
    return { conclusion: "failure", action: "none", add: [], remove: [], headline: "head moved", notifyOwner: false };
  }
  const c = {
    tier: vars.TIER,
    reasons: (vars.REASONS || "").split("; ").filter(Boolean),
    reviewers: JSON.parse(vars.REVIEWERS || "[]"),
  };
  const reviews = c.reviewers.length ? await verdicts(gh, pr.head.sha, pr, botAppId(policy)) : {};
  const approved = c.tier === "owner" ? await ownerApprovalFor(gh, pr, policy, event, app) : false;
  const d = decide(c, {
    ownerApproved: approved,
    reviews,
    mode: policy.mode,
    gateRequired: policy.mode === "native" ? await gateIsRequired(gh, pr.base.ref, botAppId(policy)) : undefined,
    ciGreen: policy.mode === "direct" ? await ciState(gh, pr.head.sha, policy.required_checks) : undefined,
    mergeBot: Boolean(mergeToken),
  });

  let actionNote = "";
  try {
    const ownerArmed = keepOwnerArming(c.tier, pr, policy.owner_login);
    if (d.action === "disarm") {
      if (ownerArmed) actionNote = "auto-merge enabled by the owner left as is";
      else if (await disarm(gh, pr)) actionNote = "auto-merge disarmed";
    } else if (d.action === "arm" && ownerArmed) {
      actionNote = "auto-merge enabled by the owner left as is";
    } else if (d.action === "arm") {
      // decide() never arms without a merge-bot token, so `app` exists here.
      const merger = app;
      const botArmed = pr.auto_merge && pr.auto_merge.enabled_by?.login === vars.MERGE_BOT_LOGIN;
      if (!botArmed) {
        // Re-arm under the merge bot so the eventual merge triggers push workflows.
        if (pr.auto_merge) await disarm(gh, pr);
        await merger.graphql(ENABLE, { id: pr.node_id, method: policy.merge_method.toUpperCase(), oid: pr.head.sha });
      }
      actionNote = `auto-merge armed (${policy.merge_method}) at ${pr.head.sha.slice(0, 7)}`;
    } else if (d.action === "merge") {
      await app.put(`/repos/{repo}/pulls/${pr.number}/merge`, { sha: pr.head.sha, merge_method: policy.merge_method });
      actionNote = `merged ${pr.head.sha.slice(0, 7)} (${policy.merge_method})`;
    }
  } catch (e) {
    d.conclusion = "failure";
    d.add = d.add.filter((l) => l !== LABELS.armed);
    d.remove = [...new Set([...d.remove, LABELS.armed])];
    d.headline = `${d.action} failed — ${e.message}`;
  }

  // The authoritative merge-gate check, with this run's final conclusion.
  if (app) {
    const reviewLine = c.reviewers.map((r) => `${r}: ${reviews[r] ? `${reviews[r].state} (${reviews[r].description})` : "missing"}`).join(" · ");
    try {
      await postGateCheck(app, {
        sha: pr.head.sha,
        conclusion: d.conclusion,
        title: `${c.tier} · ${d.headline}`,
        summary: [
          `- head: \`${pr.head.sha}\``,
          `- tier: **${c.tier}**${c.reasons.length ? ` (${c.reasons.join("; ")})` : ""}`,
          `- decision: ${d.headline}`,
          reviewLine ? `- reviews: ${reviewLine}` : "",
          `- run: ${runLink(vars)}`,
        ]
          .filter(Boolean)
          .join("\n"),
        detailsUrl: runLink(vars),
      });
    } catch (e) {
      d.conclusion = "failure";
      d.headline = `${d.headline} — merge-gate check not posted: ${e.message}`;
    }
  } else {
    log("merge-gate: no merge-bot App token, so the merge-gate check cannot be posted; the required check stays pending.");
  }

  await applyLabels(gh, pr, d.add, d.remove);

  const icon = d.conclusion === "failure" ? "🔴" : d.action === "arm" || d.action === "merge" ? "🟢" : c.tier === "owner" ? "🟣" : "⚪";
  const artifacts = readReviewArtifacts(vars.REVIEW_DIR);
  const findings = renderFindings(artifacts);
  const header = [
    STICKY,
    `### ${icon} merge-policy · tier \`${c.tier}\` · ${d.headline}`,
    "",
    `Head \`${pr.head.sha.slice(0, 7)}\`${actionNote ? ` · ${actionNote}` : ""} · [run](${vars.GITHUB_SERVER_URL}/${repo}/actions/runs/${vars.GITHUB_RUN_ID})`,
    c.reasons.length ? `Why this tier: ${c.reasons.join("; ")}` : "",
    c.reviewers.length
      ? `Reviews: ${c.reviewers.map((r) => `${r} ${reviews[r] ? `${reviews[r].state} (${reviews[r].description})` : "missing"}`).join(" · ")}`
      : "",
  ].filter(Boolean);
  const findingsStart = `<!-- findings sha=${pr.head.sha} -->`;
  let body = header.join("\n");
  if (findings) body += `\n\n${findingsStart}\n<details${d.conclusion === "failure" ? " open" : ""}><summary>Findings</summary>\n\n${findings}\n\n</details>`;
  body = redact(body);
  const previous = await upsertSticky(gh, pr, body);
  if (!findings && previous.includes(findingsStart)) {
    // Reviews were reused from an earlier run on this head: keep their findings.
    const kept = previous.slice(previous.indexOf(findingsStart));
    await upsertSticky(gh, pr, `${body}\n\n${kept}`);
  }

  if (d.notifyOwner) {
    await notifyOwnerOnce(gh, pr, policy, d.action, `${d.headline} (head \`${pr.head.sha.slice(0, 7)}\`)`);
  }

  log(`### merge-gate decide — PR #${pr.number}\n\n- tier: **${c.tier}**\n- decision: **${d.headline}**\n- action: ${d.action}${actionNote ? ` (${actionNote})` : ""}`);
  return d;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const cmd = process.argv[2];
  const run = { classify: cmdClassify, decide: cmdDecide, "fail-check": cmdFailCheck }[cmd];
  if (!run) {
    console.error("usage: run-gate.mjs classify|decide|fail-check");
    process.exit(2);
  }
  run().catch((e) => {
    console.error(e.stack || e.message);
    process.exit(1);
  });
}
