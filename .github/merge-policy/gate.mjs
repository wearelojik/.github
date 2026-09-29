// gate — turns a classification plus review evidence into one decision.
// Pure: no network. run-gate.mjs performs the side effects it returns.

export const LABELS = {
  armed: "merge:armed",
  owner: "merge:owner",
  changes: "merge:changes",
  hold: "merge:hold",
  revert: "merge:revert",
  freeze: "merge:freeze",
  approve: "merge:approve",
};

const MANAGED = [LABELS.armed, LABELS.owner, LABELS.changes];

/**
 * @param {{tier: string, reasons: string[], reviewers: string[]}} c
 * @param {object} ev
 * @param {Record<string, {state: string, description?: string}>} ev.reviews  by reviewer name
 * @param {"native"|"direct"} ev.mode
 * @param {boolean} [ev.gateRequired]  native: merge-gate is a required check on the base branch
 * @param {boolean|null} [ev.ciGreen]  direct: true all required checks green, false any red, null pending
 * @param {boolean} [ev.mergeBot]  a merge-bot App token is available (default true)
 * @param {boolean} [ev.ownerApproved]  owner tier: the owner approved this head (see ownerApproved())
 * @returns {{conclusion: "success"|"failure", action: "arm"|"merge"|"disarm"|"none", add: string[], remove: string[], headline: string, notifyOwner: boolean}}
 */
export function decide(c, ev) {
  const d = decideEvidence(c, ev);
  if ((d.action === "arm" || d.action === "merge") && ev.mergeBot === false) {
    // The Actions token cannot merge (contents: read), and a merge it armed
    // would skip push workflows and merge-watch. The check stays red: only the
    // owner can merge this, deliberately, with the ruleset's admin bypass.
    const keep = [LABELS.owner];
    return {
      conclusion: "failure",
      action: "none",
      add: keep,
      remove: MANAGED.filter((l) => !keep.includes(l)),
      headline: `evidence complete (${c.tier}) — no merge-bot App, so nothing merges automatically: merge with the admin bypass, or configure the App`,
      notifyOwner: true,
    };
  }
  return d;
}

function decideEvidence(c, ev) {
  const keep = (...labels) => ({ add: labels, remove: MANAGED.filter((l) => !labels.includes(l)) });

  // merge-gate is the one required check: it passes only for a PR that may
  // merge. Anything held or waiting on the owner stays red, so no other path
  // (`gh pr merge`, the API, a human's auto-merge) can merge it on a green gate.
  if (c.tier === "hold") {
    return {
      conclusion: "failure",
      action: "disarm",
      ...keep(),
      headline: `held, not eligible to merge — ${c.reasons.join("; ")}`,
      notifyOwner: false,
    };
  }

  const reviews = ev.reviews || {};
  const missing = c.reviewers.filter((r) => !reviews[r] || !["success", "failure", "error"].includes(reviews[r].state));
  const errored = c.reviewers.filter((r) => reviews[r]?.state === "error");
  const failed = c.reviewers.filter((r) => reviews[r]?.state === "failure");

  if (failed.length) {
    return {
      conclusion: "failure",
      action: "disarm",
      ...keep(LABELS.changes),
      headline: `changes needed — ${failed.join(", ")} review reported blocking findings`,
      notifyOwner: false,
    };
  }
  if (errored.length || missing.length) {
    const which = [...errored, ...missing].join(", ");
    return {
      conclusion: "failure",
      action: "disarm",
      ...keep(),
      headline: `review unavailable (${which}) — re-run the merge-gate workflow or push again`,
      notifyOwner: false,
    };
  }

  if (c.tier === "owner" && !ev.ownerApproved) {
    return {
      conclusion: "failure",
      action: "disarm",
      ...keep(LABELS.owner),
      headline: `owner approval needed — ${c.reasons.join("; ")}. Reviews passed; add the label \`${LABELS.approve}\` to merge this head`,
      notifyOwner: true,
    };
  }
  // An approved owner-tier PR arms like any other tier from here.

  if (ev.mode === "direct") {
    if (ev.ciGreen === true) {
      return { conclusion: "success", action: "merge", ...keep(LABELS.armed), headline: `merging (${c.tier})`, notifyOwner: false };
    }
    const why = ev.ciGreen === false ? "required CI is red" : "waiting for required CI";
    return { conclusion: "success", action: "none", ...keep(), headline: `eligible (${c.tier}) — ${why}`, notifyOwner: false };
  }

  if (!ev.gateRequired) {
    // Arming without merge-gate as a required check would let a later push
    // merge before it is reviewed. Refuse and say why.
    return {
      conclusion: "success",
      action: "disarm",
      ...keep(),
      headline: `eligible (${c.tier}) but NOT armed — merge-gate is not a required check on the base branch; run \`merge-policy settings\``,
      notifyOwner: false,
    };
  }

  return { conclusion: "success", action: "arm", ...keep(LABELS.armed), headline: `armed for auto-merge (${c.tier})`, notifyOwner: false };
}

// The owner's approval is an App check run `merge-approval` on the head he
// labeled, posted from the run that his merge:approve labeling triggered.
// A push makes a new head with no record, whatever happens to the push's own
// run (cancelled, replaced), and nothing but the merge bot can create one.
export const APPROVAL_CHECK = "merge-approval";

/**
 * Should this run record the owner's approval of the PR's current head? Only
 * the run of the owner's own merge:approve labeling, while the head in its
 * payload (the head he labeled) is still the head and the label still on.
 * @param {object} ev  the workflow event payload
 * @param {object} pr  the PR as read now
 */
export function approvalToRecord(ev, pr, ownerLogin) {
  return (
    Boolean(ownerLogin) &&
    ev?.action === "labeled" &&
    ev.label?.name === LABELS.approve &&
    ev.sender?.login === ownerLogin &&
    ev.pull_request?.number === pr?.number &&
    Boolean(pr?.head?.sha) &&
    ev.pull_request?.head?.sha === pr.head.sha &&
    (pr.labels || []).some((l) => l.name === LABELS.approve)
  );
}

/** The check run (POST /repos/{repo}/check-runs body) recording an approval. */
export function approvalCheck({ pr, head, approver }) {
  return {
    name: APPROVAL_CHECK,
    head_sha: head,
    status: "completed",
    conclusion: "success",
    output: {
      title: `approved by @${approver}`,
      summary: `@${approver} approved ${head.slice(0, 7)} with ${LABELS.approve}.`,
      text: JSON.stringify({ pr, head, approver }),
    },
  };
}

/**
 * The newest approval record for this PR's current head: a merge-approval
 * check run created by the merge bot on `sha`, whose JSON names this PR, this
 * head and the owner. Anything else is ignored.
 * @param {object[]} runs  check runs on the head
 * @returns {{at: string, id: number}|null}
 */
export function approvalRecord(runs, { sha, prNumber, appId, ownerLogin }) {
  let best = null;
  for (const r of runs || []) {
    if (r?.name !== APPROVAL_CHECK || !appId || Number(r.app?.id) !== Number(appId) || r.head_sha !== sha) continue;
    if (r.status !== "completed" || r.conclusion !== "success") continue;
    let b;
    try {
      b = JSON.parse(r.output?.text || "");
    } catch {
      continue;
    }
    if (!b || b.pr !== prNumber || b.head !== sha || !ownerLogin || b.approver !== ownerLogin) continue;
    const at = r.completed_at || r.started_at || "";
    if (!best || at > best.at || (at === best.at && Number(r.id) > Number(best.id))) best = { at, id: r.id };
  }
  return best;
}

/**
 * The owner approved the current head when:
 * - the merge:approve label is still on the PR;
 * - the newest merge:approve labeling was the owner's;
 * - a record of it exists on this head (approvalRecord), made no earlier than
 *   that labeling. Both times are GitHub's, so an older record (the owner's
 *   approval of an earlier head the PR was pushed back to) does not count
 *   after a newer labeling.
 * The commit's own dates are the pusher's to set and are never read.
 * @param {Array} events  GET /repos/{repo}/issues/{n}/events (any order)
 * @param {{ownerLogin: string, labels: string[], record: {at: string}|null}} o
 */
export function ownerApproved(events, { ownerLogin, labels, record }) {
  if (!ownerLogin || !(labels || []).includes(LABELS.approve) || !record) return false;
  const approvals = (events || [])
    .filter((e) => e?.event === "labeled" && e.label?.name === LABELS.approve)
    .sort((a, b) => Date.parse(a.created_at) - Date.parse(b.created_at) || (a.id || 0) - (b.id || 0));
  const last = approvals[approvals.length - 1];
  if (!last || last.actor?.login !== ownerLogin) return false;
  const labeledAt = Date.parse(last.created_at);
  const recordedAt = Date.parse(record.at);
  return Number.isFinite(labeledAt) && Number.isFinite(recordedAt) && recordedAt >= labeledAt;
}

/**
 * May this run accept the owner's approval at all? Belt and braces over the
 * record: a push run never does, and the owner's labeled run does only when
 * the head he labeled is still the head.
 * @param {object} ev  the workflow event payload ({} when there is none)
 * @param {string} headSha  the PR's current head
 */
export function approvalRunAllows(ev, headSha) {
  if (!ev) return true;
  if (ev.action === "synchronize") return false;
  if (ev.action === "labeled" && ev.label?.name === LABELS.approve) return Boolean(headSha) && ev.pull_request?.head?.sha === headSha;
  return true;
}

/** Owner tier: an auto-merge the owner enabled himself is his call, never disarmed. */
export function keepOwnerArming(tier, pr, ownerLogin) {
  return tier === "owner" && Boolean(ownerLogin) && pr?.auto_merge?.enabled_by?.login === ownerLogin;
}
