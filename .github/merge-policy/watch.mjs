#!/usr/bin/env node
// watch — the merge-watch workflow's entry point. See watch-core.mjs for the
// revert-or-alert rules.

import { existsSync, readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { LABELS } from "./gate.mjs";
import { GitHub } from "./github.mjs";
import { loadPolicy } from "./policy.mjs";
import { attribution, healthVerdict, openRevertFor, pickMergedPr, planResponse, previousDeploy, revertBody } from "./watch-core.mjs";

const env = process.env;
const repo = env.GITHUB_REPOSITORY;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function event() {
  return env.GITHUB_EVENT_PATH && existsSync(env.GITHUB_EVENT_PATH)
    ? JSON.parse(readFileSync(env.GITHUB_EVENT_PATH, "utf8"))
    : {};
}

async function mainWasRed(gh, run) {
  // The newest completed push run of the same workflow on the same branch
  // before this one, for a different commit.
  const runs = await gh.get(
    `/repos/{repo}/actions/workflows/${run.workflow_id}/runs?branch=${encodeURIComponent(run.head_branch)}&event=push&status=completed&per_page=20`,
  );
  const prev = runs.workflow_runs.find((r) => r.id !== run.id && r.head_sha !== run.head_sha && r.created_at < run.created_at);
  if (!prev) return null;
  return prev.conclusion !== "success";
}

/** One health poll: GET with redirects followed. The plan's install-time
 * check (cli.mjs) uses it too, so it vets URLs exactly as they are polled. */
export async function probeHealth(url) {
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(10_000), redirect: "follow" });
    await res.body?.cancel().catch(() => {});
    return { status: res.status, finalUrl: res.url };
  } catch (e) {
    return { error: e.name === "TimeoutError" ? "timeout" : e.message };
  }
}

/** Production was already broken before this deploy: the previous deployment
 * to the environment ended failure or error (null when unknown). */
async function deployWasRed(gh, dep) {
  const deps = await gh.get(`/repos/{repo}/deployments?environment=${encodeURIComponent(dep.environment)}&per_page=20`).catch(() => null);
  const prev = previousDeploy(deps, dep);
  if (!prev) return null;
  const st = await gh.get(`/repos/{repo}/deployments/${prev.id}/statuses?per_page=1`).catch(() => null);
  const state = Array.isArray(st) ? st[0]?.state : null;
  return state ? ["failure", "error"].includes(state) : null;
}

async function healthProblems(urls) {
  const problems = [];
  for (const url of urls) {
    const problem = healthVerdict(url, await probeHealth(url));
    if (problem) problems.push(problem);
  }
  return problems;
}

async function sentryProblems(cfg, since) {
  if (!cfg || !env.SENTRY_AUTH_TOKEN) return [];
  const host = cfg.host || "https://sentry.io";
  const q = encodeURIComponent(`is:unresolved firstSeen:>${since}`);
  const res = await fetch(`${host}/api/0/projects/${cfg.org}/${cfg.project}/issues/?query=${q}&statsPeriod=24h&limit=25`, {
    headers: { authorization: `Bearer ${env.SENTRY_AUTH_TOKEN}` },
    signal: AbortSignal.timeout(15_000),
  });
  if (!res.ok) return []; // monitoring must not revert on a Sentry outage
  const issues = await res.json();
  const minEvents = cfg.min_events ?? 5;
  const hot = issues.filter((i) => Number(i.count) >= minEvents);
  if (hot.length > (cfg.max_new_issues ?? 0)) {
    return hot.slice(0, 5).map((i) => `Sentry new issue: ${i.title} (${i.count} events, ${i.userCount} users) ${i.permalink}`);
  }
  return [];
}

/** Returns a failure string, or null when the deploy stayed healthy. */
async function watchDeploy(policy, deployedAt) {
  const minutes = policy.watch.watch_minutes;
  const deadline = Date.now() + minutes * 60_000;
  let strikes = 0;
  while (Date.now() < deadline) {
    const problems = [...(await healthProblems(policy.watch.health_urls)), ...(await sentryProblems(policy.watch.sentry, deployedAt))];
    // Two consecutive bad polls: a single blip is not a regression.
    strikes = problems.length ? strikes + 1 : 0;
    if (strikes >= 2) return problems.join("\n");
    await sleep(60_000);
  }
  return null;
}

async function mergedPrFor(gh, sha) {
  return pickMergedPr(await gh.get(`/repos/{repo}/commits/${sha}/pulls`), sha);
}

const botLoginOf = (policy) => (policy.bot_slug ? `${policy.bot_slug}[bot]` : null);

async function recentBotReverts(gh, policy) {
  const since = new Date(Date.now() - 24 * 3600_000).toISOString().slice(0, 19);
  // Only the App's own reverts: anyone with triage can add the label.
  const author = policy.bot_slug ? ` author:app/${policy.bot_slug}` : "";
  const q = encodeURIComponent(`repo:${repo} is:pr label:${LABELS.revert}${author} created:>${since}`);
  const r = await gh.get(`/search/issues?q=${q}&per_page=1`);
  return r.total_count || 0;
}

const REVERT = `mutation($id: ID!, $title: String!, $body: String!) {
  revertPullRequest(input: {pullRequestId: $id, title: $title, body: $body, draft: false}) {
    revertPullRequest { number url }
  }
}`;

async function alert(gh, policy, title, body) {
  const issue = await gh.post(`/repos/{repo}/issues`, {
    title: title.slice(0, 250),
    body: `@${policy.owner_login}\n\n${body}`,
    labels: ["merge:alert"],
  });
  return issue.html_url;
}

/**
 * Revert when the plan says so (unless a revert of this PR is already open),
 * comment on the PR, and always open a merge:alert issue for the owner.
 * Clients come in as arguments so tests drive it with fakes.
 */
export async function respond({ gh, bot, policy, failure, pr, plan, runUrl }) {
  let revertUrl = null;
  let revertNote = "";
  if (plan.action === "revert") {
    const already = openRevertFor(await gh.paginate(`/repos/{repo}/pulls?state=open`), pr.number, botLoginOf(policy));
    if (already) {
      revertUrl = already.html_url;
      revertNote = `a revert PR was already open (#${already.number} by ${already.user?.login || "unknown"}), so no second one was opened`;
    } else if (!bot) {
      plan.reason += " — but no merge-bot token, so no revert PR (a GITHUB_TOKEN PR would never trigger the gate)";
    } else {
      try {
        const body = `${revertBody(pr.number)}\nAutomatic revert by merge-watch.\n\nRegression: ${failure}\n\nWatch run: ${runUrl}`;
        const res = await bot.graphql(REVERT, { id: pr.node_id, title: `Revert "${pr.title}"`.slice(0, 250), body });
        const rp = res.revertPullRequest.revertPullRequest;
        revertUrl = rp.url;
        revertNote = `a revert PR was opened (#${rp.number}); it merges on green CI`;
        await bot.post(`/repos/{repo}/issues/${rp.number}/labels`, { labels: [LABELS.revert] }).catch(() => {});
      } catch (e) {
        plan.reason += ` — revert failed: ${e.message}`;
      }
    }
  }

  const lines = [
    `**Regression:** ${failure}`,
    pr ? `**PR:** #${pr.number} ${pr.title}` : "**PR:** none (direct push)",
    `**Response:** ${plan.action}${revertUrl ? ` → ${revertUrl}` : ""} — ${plan.reason}${revertNote ? `; ${revertNote}` : ""}`,
    `**Watch run:** ${runUrl}`,
  ];
  if (pr) await gh.post(`/repos/{repo}/issues/${pr.number}/comments`, { body: `merge-watch: ${lines.join("\n")}` }).catch(() => {});
  // Every regression reaches the owner, including one already being reverted:
  // a revert PR can stall (CI, a held gate), and the owner should know.
  const title = `merge-watch: ${revertUrl ? "reverting " : ""}${pr ? `#${pr.number} ` : ""}${failure.split("\n")[0]}`;
  await alert(gh, policy, title, lines.join("\n\n"));
  return { revertUrl, lines };
}

async function main() {
  const policy = loadPolicy(env.MERGE_POLICY_PATH || ".github/merge-policy.json");
  const gh = new GitHub(env.GH_TOKEN, repo);
  const bot = env.MERGE_TOKEN ? new GitHub(env.MERGE_TOKEN, repo) : null;
  const ev = event();
  const runUrl = `${env.GITHUB_SERVER_URL}/${repo}/actions/runs/${env.GITHUB_RUN_ID}`;

  let sha;
  let failure = null;
  let red = null;
  if (env.GITHUB_EVENT_NAME === "workflow_run") {
    const run = ev.workflow_run;
    sha = run.head_sha;
    if (!["failure", "timed_out"].includes(run.conclusion)) return console.log(`${run.name}: ${run.conclusion} — nothing to do`);
    failure = `CI "${run.name}" ${run.conclusion} on ${run.head_branch} at ${sha.slice(0, 7)} — ${run.html_url}`;
    red = await mainWasRed(gh, run);
  } else if (env.GITHUB_EVENT_NAME === "deployment_status") {
    const dep = ev.deployment;
    const st = ev.deployment_status;
    sha = dep.sha;
    if (!policy.watch.deploy_environments.includes(dep.environment)) return console.log(`environment ${dep.environment} not watched`);
    if (st.state === "success") {
      const problems = await watchDeploy(policy, st.created_at || new Date().toISOString());
      if (!problems) return console.log(`deploy of ${sha.slice(0, 7)} to ${dep.environment} stayed healthy for ${policy.watch.watch_minutes} min`);
      failure = `after deploying ${sha.slice(0, 7)} to ${dep.environment}:\n${problems}`;
    } else {
      failure = `deploy of ${sha.slice(0, 7)} to ${dep.environment} ended ${st.state} — ${st.target_url || st.log_url || ""}`;
    }
    red = await deployWasRed(gh, dep);
  } else {
    return console.log(`unsupported event ${env.GITHUB_EVENT_NAME}`);
  }

  const merged = await mergedPrFor(gh, sha);
  // The full PR: merged_by is not on the commit's pulls list.
  const pr = merged ? await gh.get(`/repos/{repo}/pulls/${merged.number}`) : null;
  let migration = false;
  if (pr) {
    const files = await gh.paginate(`/repos/{repo}/pulls/${pr.number}/files`);
    migration = files.some((f) => /(^|\/)migrations\//.test(f.filename) || /\.sql$/i.test(f.filename));
  }
  const { autoMerged, isRevert } = attribution(pr, botLoginOf(policy));
  const plan = planResponse({
    failure,
    pr,
    autoMerged,
    isRevert,
    migration,
    autoRevert: policy.watch.auto_revert,
    mainWasRed: red,
    recentReverts: await recentBotReverts(gh, policy),
    freezeAfter: policy.freeze_after_reverts,
  });

  const { lines } = await respond({ gh, bot, policy, failure, pr, plan, runUrl });
  if (plan.freeze) {
    await gh.post(`/repos/{repo}/issues`, {
      title: "merge-policy freeze: auto-merge paused after repeated reverts",
      body: `@${policy.owner_login}\n\nThe gate holds every PR while this issue is open. Close it to resume auto-merge.\n\n${lines.join("\n\n")}`,
      labels: [LABELS.freeze],
    });
  }
  console.log(lines.join("\n"));
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((e) => {
    console.error(e.stack || e.message);
    process.exit(1);
  });
}
