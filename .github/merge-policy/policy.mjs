// policy — loads a repo's .github/merge-policy.json over the defaults.

import { readFileSync, existsSync } from "node:fs";
import { DEFAULTS } from "./classify.mjs";

// The merge-bot GitHub App (dgz-merge-bot). Its check runs are the only
// evidence the gate accepts: merge-gate, and the merge-review/* verdicts.
export const DEFAULT_BOT_APP_ID = 5124966;

/** The App id whose check runs count: the policy's, else the default. */
export const botAppId = (p) => Number(p?.bot_app_id) || DEFAULT_BOT_APP_ID;

export const POLICY_DEFAULTS = {
  version: 1,
  mode: "native", // native: ruleset + GitHub auto-merge; direct: the gate merges when CI is green (Free-plan private repos)
  merge_method: "squash",
  owner_login: "dgonzap30",
  bot_slug: "", // the merge-bot GitHub App slug; its "<slug>[bot]" reverts are green
  bot_app_id: null, // the merge-bot App's id (null: DEFAULT_BOT_APP_ID): the only source of merge-gate and verdicts
  freeze_after_reverts: 2, // this many bot reverts in 24h opens a merge:freeze issue
  required_checks: [], // CI check-run names that must be green (also written into the ruleset by `merge-policy settings`)
  reviewers: {
    reviewed: ["standard"],
    critical: ["standard", "adversarial"],
  },
  models: {
    standard: "claude-opus-5-5",
    adversarial: "claude-fable-5-1",
  },
  effort: {
    standard: "high",
    adversarial: "high",
  },
  watch: {
    ci_workflows: [], // workflow names whose default-branch runs are watched
    deploy_environments: [], // GitHub deployment environments whose statuses are watched
    health_urls: [], // GET must return 2xx, without a redirect to another host, after a successful deploy
    watch_minutes: 10,
    auto_revert: true,
    sentry: null, // { org, project, max_new_issues: 0, min_events: 5 } — needs SENTRY_AUTH_TOKEN
  },
};

export function mergePolicy(raw = {}) {
  const p = { ...DEFAULTS, ...POLICY_DEFAULTS, ...raw };
  p.reviewers = { ...POLICY_DEFAULTS.reviewers, ...(raw.reviewers || {}) };
  p.models = { ...POLICY_DEFAULTS.models, ...(raw.models || {}) };
  p.effort = { ...POLICY_DEFAULTS.effort, ...(raw.effort || {}) };
  p.watch = { ...POLICY_DEFAULTS.watch, ...(raw.watch || {}) };
  // Additive path lists: a repo extends the defaults, and removes entries only
  // through an explicit `*_paths_remove` list (visible in review).
  for (const key of ["owner_paths", "critical_paths", "critical_overrides_green", "green_paths", "size_exempt_paths"]) {
    const extra = raw[`${key}_add`] || [];
    const drop = new Set(raw[`${key}_remove`] || []);
    const base = raw[key] || DEFAULTS[key];
    p[key] = [...base, ...extra].filter((x) => !drop.has(x));
  }
  // The gate's own files can never leave the owner tier.
  for (const locked of DEFAULTS.owner_paths) {
    if (!p.owner_paths.includes(locked)) p.owner_paths.push(locked);
  }
  return p;
}

export function loadPolicy(path = ".github/merge-policy.json") {
  if (!existsSync(path)) return mergePolicy({});
  return mergePolicy(JSON.parse(readFileSync(path, "utf8")));
}
