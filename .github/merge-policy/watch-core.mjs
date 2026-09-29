// watch-core — what to do about a post-merge regression. Pure.
//
// Revert only when all of these hold: the merge was armed by the gate (not a
// human merge), it carried no migration (a code revert cannot un-migrate a
// schema), main was green before it (otherwise the revert fixes nothing), and
// the repo is not already reverting in a loop. Everything else alerts.

import { REVERT_MARKER } from "./classify.mjs";

/**
 * @param {object} s
 * @param {string} s.failure         what regressed
 * @param {object|null} s.pr          merged PR for the commit, or null (direct push)
 * @param {boolean} s.autoMerged      the merge bot merged it (see attribution())
 * @param {boolean} s.isRevert        PR is itself a merge-bot revert
 * @param {boolean} s.migration       PR touched migrations/SQL
 * @param {boolean} s.autoRevert      policy.watch.auto_revert
 * @param {boolean|null} s.mainWasRed the previous default-branch run was red (null unknown)
 * @param {number} s.recentReverts    bot reverts opened in the last 24h, before this one
 * @param {number} s.freezeAfter      policy.freeze_after_reverts
 * @returns {{action: "revert"|"alert", freeze: boolean, reason: string}}
 */
export function planResponse(s) {
  const alert = (reason, freeze = false) => ({ action: "alert", freeze, reason });
  if (!s.pr) return alert("commit did not come from a pull request");
  if (s.isRevert) return alert("the regressing commit is itself a revert — stopping the loop", true);
  if (!s.autoMerged) return alert("merged by hand, not by the gate — not auto-reverting");
  if (s.migration) return alert("PR carried a migration — needs a forward fix, a revert would not un-migrate");
  if (!s.autoRevert) return alert("auto_revert is off for this repo");
  if (s.mainWasRed === true) return alert("default branch was already red before this merge");
  const freeze = s.recentReverts + 1 >= s.freezeAfter;
  return { action: "revert", freeze, reason: freeze ? `revert #${s.recentReverts + 1} in 24h — freezing auto-merge` : "regression after an auto-merge" };
}

/** The PR whose merge produced `sha`: an exact merge_commit_sha match only. A
 * looser match could blame, and revert, the wrong PR. */
export function pickMergedPr(pulls, sha) {
  return (pulls || []).find((p) => p.merged_at && p.merge_commit_sha === sha) || null;
}

/** The body merge-watch gives its revert of PR #n. */
export function revertBody(number) {
  return `${REVERT_MARKER} of #${number} -->`;
}

/** An open PR that already reverts PR #n, or null. With `botLogin`, only the
 * merge bot's own PRs count: anyone can put the marker in a PR body. */
export function openRevertFor(openPulls, number, botLogin) {
  const marker = revertBody(number);
  return (openPulls || []).find((p) => (p.body || "").includes(marker) && (!botLogin || p.user?.login === botLogin)) || null;
}

/**
 * Who merged the PR and whether it is a bot revert, from facts rather than
 * labels or body text that anyone with triage or write access can edit: the
 * gate merged it iff the merge bot is `merged_by` (the App arms auto-merge,
 * or merges directly); a bot revert is authored by the bot and carries the
 * marker.
 * @param {object} pr  GET /repos/{repo}/pulls/{n} (merged_by is only on the full object)
 * @param {string|null} botLogin  "<slug>[bot]", or null when no App is configured
 */
export function attribution(pr, botLogin) {
  if (!pr || !botLogin) return { autoMerged: false, isRevert: false };
  return {
    autoMerged: pr.merged_by?.login === botLogin,
    isRevert: pr.user?.login === botLogin && (pr.body || "").includes(REVERT_MARKER),
  };
}

// Health URLs. A deploy's environment_url on Vercel or Netlify is usually a
// per-deployment URL: frozen at install time it keeps probing an old build,
// often behind deployment protection. Only a stable production URL is worth
// polling; without one merge-watch watches deployment status alone.
const PER_DEPLOYMENT_HOST = [
  /^[a-z0-9-]+-[a-z0-9]{9}-[a-z0-9-]+\.vercel\.app$/, // <project>-<hash>-<scope>.vercel.app
  /^[a-z0-9-]+-git-[a-z0-9-]+\.vercel\.app$/, // <project>-git-<branch>-<scope>.vercel.app
  /^[a-z0-9-]+--[a-z0-9-]+\.netlify\.app$/, // <id>--<site>.netlify.app
  /^[a-f0-9]{8}\.[a-z0-9-]+\.pages\.dev$/, // <hash>.<project>.pages.dev (Cloudflare Pages)
  /^[a-z0-9-]+-pr-\d+\.onrender\.com$/, // <service>-pr-<n>.onrender.com (Render preview)
];

// A repo's homepage on a code host is not the deployed site.
const NOT_A_DEPLOY_HOST = /(^|\.)(github\.com|gitlab\.com|bitbucket\.org)$/;

function parseUrl(url) {
  try {
    return new URL(url);
  } catch {
    return null;
  }
}

/** True when `url` names one deployment rather than the production site. */
export function isPerDeploymentUrl(url) {
  const u = parseUrl(url);
  return !!u && PER_DEPLOYMENT_HOST.some((re) => re.test(u.hostname.toLowerCase()));
}

/**
 * The URLs merge-watch polls after a production deploy: the repo's homepage
 * when it is https, else the deployments' stable https environment URLs.
 * @param {object} s
 * @param {string|null} s.homepage        GET /repos/{repo} .homepage
 * @param {string[]} s.deploymentUrls     latest successful environment_url per production environment
 * @returns {{urls: string[], source: "homepage"|"deployment"|"none", skipped: string[]}}
 */
export function chooseHealthUrls({ homepage, deploymentUrls = [] }) {
  const https = (url) => parseUrl(url)?.protocol === "https:";
  const skipped = [...new Set(deploymentUrls.filter((u) => https(u) && isPerDeploymentUrl(u)))];
  const deployed = (url) => !NOT_A_DEPLOY_HOST.test(parseUrl(url)?.hostname.toLowerCase() || "");
  if (homepage && https(homepage) && !isPerDeploymentUrl(homepage) && deployed(homepage)) return { urls: [homepage], source: "homepage", skipped };
  const urls = [...new Set(deploymentUrls.filter((u) => https(u) && !isPerDeploymentUrl(u)))];
  return { urls, source: urls.length ? "deployment" : "none", skipped };
}

// Hosting domains where each subdomain is a different site, and two-level
// country suffixes (lojik.com.mx): the site is one label more than these.
const SHARED_SUFFIXES = [
  "vercel.app", "netlify.app", "pages.dev", "onrender.com", "github.io", "fly.dev", "herokuapp.com", "workers.dev",
  "web.app", "firebaseapp.com", "up.railway.app", "railway.app", "azurewebsites.net", "appspot.com", "cloudfront.net", "amplifyapp.com",
];
const COUNTRY_SLD = /^(com|co|org|net|gob|gov|edu|ac)$/;

/** The registrable site of a URL: wearelojik.com for www.wearelojik.com and
 * app.wearelojik.com, but x.vercel.app on its own. */
export function siteOf(u) {
  const host = u.hostname.toLowerCase().replace(/\.$/, "");
  if (/^[\d.]+$|:/.test(host)) return host;
  const labels = host.split(".");
  const shared = SHARED_SUFFIXES.filter((sfx) => host.endsWith(`.${sfx}`)).sort((a, b) => b.length - a.length)[0];
  let keep = 2;
  if (shared) keep = shared.split(".").length + 1;
  else if (labels.length >= 3 && labels.at(-1).length === 2 && COUNTRY_SLD.test(labels.at(-2))) keep = 3;
  return labels.slice(-keep).join(".");
}

/**
 * One health poll's problem, or null when it is healthy. A redirect that ends
 * on another site (a login wall on vercel.com, a parked domain) is a problem
 * whatever its final status; redirects within the site (http to https, / to
 * /en, apex to www, / to app.<domain>) are fine.
 * @param {string} url  the URL requested
 * @param {{status?: number, finalUrl?: string, error?: string}} r  the fetch outcome (redirects followed)
 */
export function healthVerdict(url, r) {
  const problem = healthProblem(url, r);
  return problem && `${url} -> ${problem}`;
}

function healthProblem(url, r) {
  if (r.error) return r.error;
  const asked = parseUrl(url);
  const landed = r.finalUrl ? parseUrl(r.finalUrl) : null;
  if (asked && landed && siteOf(asked) !== siteOf(landed)) return `redirected to ${landed.hostname}`;
  if (!(r.status >= 200 && r.status < 300)) return `HTTP ${r.status}`;
  return null;
}

/**
 * Install-time check of the chosen health URLs: a URL that fails a poll now
 * (a cross-host redirect, a 5xx, a timeout) would fail every poll after every
 * deploy and revert every auto-merge, so it is dropped. A dropped URL is never
 * replaced by where it redirected: that can be a login page. A repo override's
 * URLs are the owner's choice and are kept unprobed.
 * @param {string[]} urls  from chooseHealthUrls
 * @param {(url: string) => Promise<{status?: number, finalUrl?: string, error?: string}>} probe  one poll, as watch does it
 * @param {{override?: string[]}} [opts]  the repo override's watch.health_urls, when it sets them
 * @returns {Promise<{kept: string[], rejected: {url: string, problem: string}[]}>}
 */
export async function vetHealthUrls(urls, probe, { override } = {}) {
  if (Array.isArray(override)) return { kept: override, rejected: [] };
  const kept = [];
  const rejected = [];
  for (const url of urls) {
    let outcome;
    try {
      outcome = await probe(url);
    } catch (e) {
      outcome = { error: e?.message || String(e) };
    }
    const problem = healthProblem(url, outcome);
    if (problem) rejected.push({ url, problem });
    else kept.push(url);
  }
  return { kept, rejected };
}

/**
 * The production deployment before `dep` in the same environment, from a
 * newest-first deployments list, or null. Its last status tells merge-watch
 * whether production was already broken before this merge.
 */
export function previousDeploy(deployments, dep) {
  const at = Date.parse(dep.created_at);
  return (deployments || []).find((d) => d.id !== dep.id && d.environment === dep.environment && Date.parse(d.created_at) < at) || null;
}
