// classify — decides a PR's risk tier from trusted data (PR metadata + file
// list with patches). Pure: no network, no clock. Runs from the BASE branch in
// CI, so a PR can never change the rules that classify it.
//
// Tiers, lowest to highest:
//   green     merge on required CI alone (docs, tests, dependabot patch/minor)
//   reviewed  + one AI review verdict with no blocker/major finding
//   critical  + a second, adversarial review; post-merge watch is mandatory
//   owner     reviews still run; nothing arms until the owner adds merge:approve
//
// A PR that is not eligible at all (draft, held, untrusted, stacked, frozen)
// gets tier "hold": no review spend, no arming.

import { matchesAny } from "./glob.mjs";

export const TIERS = ["green", "reviewed", "critical", "owner"];
export const REVERT_MARKER = "<!-- merge-policy:revert";
const CONTROL = /[\x00-\x1f\x7f]/;
const FILE_LIST_CAP = 3000;

export const DEFAULTS = {
  owner_paths: [
    ".github/workflows/**",
    ".github/actions/**", // composite actions run inside workflows
    ".github/merge-policy/**",
    ".github/merge-policy.json",
    ".github/CODEOWNERS",
    "CODEOWNERS",
  ],
  critical_paths: [
    "**/migrations/**",
    "**/*.sql",
    "supabase/functions/**",
    // A keyword anywhere in a directory or file name.
    ...[
      "{auth,Auth,session,Session,rls,Rls,polic,Polic,permission,Permission}",
      "{payment,Payment,billing,Billing,stripe,Stripe,checkout,Checkout,revenuecat,RevenueCat,invoice,Invoice,payout,Payout}",
      "{secret,Secret,crypto,Crypto}",
    ].flatMap((kw) => [`**/*${kw}*/**`, `**/*${kw}*`]),
    "**/{middleware,proxy}.{ts,js}", // Next 16 renamed middleware to proxy
    "**/{vercel,render,railway,fly}.{json,yaml,yml,toml}",
    "**/Dockerfile",
    "**/.env*",
    "**/prompts/**",
    "AGENTS.md",
    "CLAUDE.md",
    // What a green dependabot PR may pull: registries, ecosystems, groups.
    ".github/dependabot.{yml,yaml}",
  ],
  // Critical even when the file is a pure doc: files that steer the coding
  // agents (commands, subagents, hooks, rules, prompts), which are Markdown.
  critical_overrides_green: [
    ".claude/**",
    ".cursor/**",
    ".codex/**",
    ".github/copilot-instructions.md",
    "**/prompts/**",
    "AGENTS.md",
    "CLAUDE.md",
    "**/AGENTS.md",
    "**/CLAUDE.md",
  ],
  // Content that never runs. MDX (JSX) and SVG (can carry script) are not here.
  green_paths: [
    "**/*.md",
    "docs/**",
    "**/*.{test,spec}.{ts,tsx,js,jsx,mjs,cjs}",
    "**/__tests__/**",
    "**/__snapshots__/**",
    "**/*.snap",
    "**/{test,tests}/**",
    "**/*Tests/**",
    ".gitignore",
    "**/*.{png,jpg,jpeg,webp,gif,ico}",
  ],
  // Excluded from the size count: generated and lock files.
  size_exempt_paths: [
    "**/{pnpm-lock.yaml,package-lock.json,yarn.lock,bun.lock,bun.lockb,Cargo.lock,Podfile.lock,Package.resolved,uv.lock,poetry.lock}",
    "**/*.snap",
    "**/*.generated.*",
    "**/database.types.ts",
    "**/*.pbxproj",
  ],
  // Above this many changed lines (excluding size_exempt_paths) a "reviewed"
  // PR is escalated to "critical": review quality drops on huge diffs.
  critical_line_threshold: 1500,
  trusted_bots: ["dependabot[bot]"],
  trusted_associations: ["OWNER", "MEMBER", "COLLABORATOR"],
};

// Files that are only read by people: on a green path they stay green even
// under a critical keyword (`docs/auth.md`, `tasks/session-state.md`), unless
// critical_overrides_green names them. Not a policy key, so a repo cannot
// widen it. MDX and SVG are not here.
const PURE_DOC = ["**/*.md", "**/*.txt", "**/*.{png,jpg,jpeg,webp,gif,ico}"];

// Added-line SQL that loses data or weakens access. Owner tier: an auto-revert
// cannot undo it. Replace-patterns (DROP POLICY x + CREATE POLICY x) are
// recognised and downgraded to critical. Patterns run on sqlCode() output:
// comments removed, literal data masked, quoted identifiers encoded, so
// `drop/**/table`, a `--` inside a string, a `;` inside a quoted name, or a
// commented-out CREATE POLICY cannot change the result.
//
// Postgres identifier characters: letters, digits, _, $ and every non-ASCII
// character. `ñe'...'` is an identifier followed by a plain string, not an E''
// string, and `drop ñame` drops a column.
// UTF-16 code units, so astral characters round-trip.
const hex = (raw) => Array.from({ length: raw.length }, (_, k) => raw.charCodeAt(k).toString(16).padStart(4, "0")).join("");
const unhex = (h) => (h.match(/.{4}/g) || []).map((x) => String.fromCharCode(parseInt(x, 16))).join("");
const IDCHAR = String.raw`A-Za-z0-9_$\u0080-\uFFFF`;
const ID_CHAR_RE = new RegExp(`[${IDCHAR}]`);
const isIdChar = (c) => c !== undefined && ID_CHAR_RE.test(c);
const DOLLAR_TAG = new RegExp(String.raw`^\$(?:[A-Za-z_\u0080-\uFFFF][A-Za-z0-9_\u0080-\uFFFF]*)?\$`);
// sqlCode() rewrites every quoted identifier to "x<hex of its raw content>":
// no keyword, `;` or space inside a name reaches the statement patterns, and
// equal names stay equal for the DROP/CREATE POLICY pairing.
const QUOTED = String.raw`"x[0-9a-f]*"`;
const IDENT = String.raw`(?:${QUOTED}|[${IDCHAR}]+)`;
const QUALIFIED = String.raw`${IDENT}(?:\s*\.\s*${IDENT})*`;
const OWNER_SQL = [
  [/\bdrop\s+table\b/i, "DROP TABLE"],
  [/\bdrop\s+schema\b/i, "DROP SCHEMA"],
  [/\bdrop\s+database\b/i, "DROP DATABASE"],
  [/\bdrop\s+owned\b/i, "DROP OWNED"],
  [/\bdrop\s+role\b/i, "DROP ROLE"],
  [/\bdrop\s+column\b/i, "DROP COLUMN"],
  [new RegExp(String.raw`\balter\s+table\b[^;]*\bdrop\s+(?!(?:constraint|default|not\s+null)(?![${IDCHAR}]))(?:if\s+exists\s+)?["${IDCHAR}]`, "i"), "ALTER TABLE ... DROP"],
  [new RegExp(String.raw`\balter\s+table\b[^;]*\balter\s+(?:column\s+)?${IDENT}\s+(?:set\s+data\s+)?type\b`, "i"), "ALTER COLUMN ... TYPE"],
  [/\btruncate\b/i, "TRUNCATE"],
  [/\bdelete\s+from\b/i, "DELETE FROM"],
  [/\bdisable\s+row\s+level\s+security\b/i, "DISABLE ROW LEVEL SECURITY"],
  [/\bno\s+force\s+row\s+level\s+security\b/i, "NO FORCE ROW LEVEL SECURITY"],
  [grantAllTo(["anon", "public", "authenticated"]), "GRANT ALL ... TO anon/public/authenticated"],
];

/** GRANT ALL ... TO one of `roles`, bare or quoted ("anon" is anon). */
function grantAllTo(roles) {
  const quoted = roles.map((r) => `"x${hex(r)}"`);
  return new RegExp(String.raw`\bgrant\s+all\b[^;]*\bto\b[^;]*(?:\b(?:${roles.join("|")})\b|${quoted.join("|")})`, "i");
}

const DROP_POLICY = new RegExp(String.raw`\bdrop\s+policy\s+(?:if\s+exists\s+)?(${IDENT})\s+on\s+(${QUALIFIED})`, "gi");
const CREATE_POLICY = new RegExp(String.raw`\bcreate\s+policy\s+(${IDENT})\s+on\s+(${QUALIFIED})`, "gi");

const QUOTED_OR_BARE = new RegExp(`${QUOTED}|[${IDCHAR}]+`, "g");

/** A (qualified) name as Postgres resolves it: a quoted part keeps its case,
 * a bare part folds to lower case; `public.` is dropped. */
function norm(name) {
  const parts = name.match(QUOTED_OR_BARE) || [];
  return parts
    .map((part) => (part.startsWith('"') ? unhex(part.slice(2, -1)).replace(/""/g, '"') : part.toLowerCase()))
    .join(".")
    .replace(/^public\./, "");
}

/** A name from sqlCode() output, readable and single-line for a reason string. */
function shown(name) {
  return name.replace(new RegExp(QUOTED, "g"), (q) => `"${unhex(q.slice(2, -1))}"`).replace(/[\x00-\x1f\x7f]/g, "?");
}

/** Added lines of a unified-diff patch, verbatim (sqlCode() strips comments). */
export function addedLines(patch = "") {
  return patch
    .split("\n")
    .filter((l) => l.startsWith("+") && !l.startsWith("+++"))
    .map((l) => l.slice(1));
}

/**
 * A small SQL lexer. Returns the code with comments removed (nested block
 * comments included) and each string literal replaced by '_'; the literals'
 * contents are returned separately. Code bodies are scanned as SQL, never
 * masked: a dollar-quoted body ($$ ... $$, $fn$ ... $fn$) and a single-quoted
 * body right after AS or DO (old-style function bodies) are inlined, so
 * `DO $$ BEGIN DROP TABLE t; END $$` still shows its DROP TABLE.
 * `unterminated` is set when the text ends inside a comment, string, quoted
 * identifier or dollar quote: the added lines alone cannot be trusted then.
 * @returns {{text: string, literals: string[], unterminated: boolean}}
 */
export function sqlCode(src = "") {
  let out = "";
  const literals = [];
  let unterminated = false;
  const n = src.length;
  let i = 0;
  const inline = (body) => {
    const inner = sqlCode(body);
    literals.push(...inner.literals);
    unterminated ||= inner.unterminated;
    out += ` ${inner.text} `;
  };
  while (i < n) {
    const ch = src[i];
    const nx = src[i + 1];
    if (ch === "-" && nx === "-") {
      // A -- comment ends at \n or \r (Postgres: non_newline is [^\n\r]).
      let e = i + 2;
      while (e < n && src[e] !== "\n" && src[e] !== "\r") e += 1;
      i = e;
      out += " ";
    } else if (ch === "/" && nx === "*") {
      let depth = 1;
      i += 2;
      while (i < n && depth) {
        const two = src.slice(i, i + 2);
        if (two === "/*" || two === "*/") {
          depth += two === "/*" ? 1 : -1;
          i += 2;
        } else i += 1;
      }
      if (depth) unterminated = true;
      out += " ";
    } else if (ch === "'") {
      // E'...' strings take backslash escapes; '' is a quote everywhere.
      const escapes = /[eE]/.test(src[i - 1] || "") && !isIdChar(src[i - 2]);
      let j = i + 1;
      let body = "";
      let closed = false;
      while (j < n) {
        if (escapes && src[j] === "\\") {
          body += src.slice(j, j + 2);
          j += 2;
        } else if (src[j] === "'" && src[j + 1] === "'") {
          body += "'";
          j += 2;
        } else if (src[j] === "'") {
          closed = true;
          j += 1;
          break;
        } else {
          body += src[j];
          j += 1;
        }
      }
      if (!closed) unterminated = true;
      if (/\b(?:as|do)\s*$/i.test(out.slice(-32))) inline(body);
      else {
        literals.push(body);
        out += "'_'";
      }
      i = j;
    } else if (ch === '"') {
      let j = i + 1;
      let closed = false;
      while (j < n) {
        if (src[j] === '"' && src[j + 1] === '"') j += 2;
        else if (src[j] === '"') {
          closed = true;
          j += 1;
          break;
        } else j += 1;
      }
      if (!closed) unterminated = true;
      out += `"x${hex(src.slice(i + 1, closed ? j - 1 : j))}"`;
      i = j;
    } else if (ch === "$" && !isIdChar(src[i - 1]) && DOLLAR_TAG.test(src.slice(i, i + 64))) {
      const tag = src.slice(i).match(DOLLAR_TAG)[0];
      const end = src.indexOf(tag, i + tag.length);
      if (end === -1) unterminated = true;
      inline(end === -1 ? src.slice(i + tag.length) : src.slice(i + tag.length, end));
      i = end === -1 ? n : end + tag.length;
    } else {
      out += ch;
      i += 1;
    }
  }
  return { text: out, literals, unterminated };
}

/** EXECUTE (PL/pgSQL or prepared) and format() build SQL from strings. The
 * privilege `GRANT/REVOKE EXECUTE` and a trigger's `EXECUTE FUNCTION f(...)`
 * run no string and are not dynamic. Returns each site's statement. */
function dynamicSqlSites(text) {
  const t = text
    .replace(/\b(?:grant|revoke)\s+execute\b/gi, " ")
    .replace(new RegExp(String.raw`\bexecute\s+(?:function|procedure)\s+${QUALIFIED}\s*\(`, "gi"), " ");
  return [...t.matchAll(/\bexecute\b|\bformat\s*\(|\\gexec\b/gi)].map((m) => statementAt(t, m.index));
}

/** The statement text from `index` to the next `;`, normalised, for telling
 * one hit from another when a whole file is compared with its base. */
function statementAt(text, index) {
  const end = text.indexOf(";", index);
  return text.slice(index, end === -1 ? index + 200 : Math.min(end, index + 200)).replace(/\s+/g, " ").trim().toLowerCase();
}

const globalOf = (re) => new RegExp(re.source, re.flags.includes("g") ? re.flags : `${re.flags}g`);
const OWNER_SQL_ALL = OWNER_SQL.map(([re, label]) => [globalOf(re), label]);

/** Policies a lexed text creates, as "name@table" keys. */
function createdPolicies(code) {
  return [...code.text.matchAll(CREATE_POLICY)].map((m) => `${norm(m[1])}@${norm(m[2])}`);
}

/**
 * Every destructive or dynamic hit in lexed SQL, one entry per occurrence:
 * {label, key}. `key` names the statement, so a full file can be compared
 * with its base occurrence by occurrence.
 */
function sqlHits(code, created) {
  const out = [];
  if (code.unterminated) out.push({ label: "unterminated string, comment or dollar quote", key: "unterminated" });
  // String contents are checked too: SQL kept in a string is SQL someone means to run.
  const literalCode = code.literals.map((l) => sqlCode(l).text);
  for (const [re, label] of OWNER_SQL_ALL) {
    for (const m of code.text.matchAll(re)) out.push({ label, key: `${label}|${statementAt(code.text, m.index)}` });
    for (const l of literalCode) {
      for (const m of l.matchAll(re)) out.push({ label: `${label} inside a string literal`, key: `${label} (string)|${statementAt(l, m.index)}` });
    }
  }
  for (const stmt of dynamicSqlSites(code.text)) out.push({ label: "dynamic SQL (EXECUTE or format())", key: `dynamic|${stmt}` });
  for (const m of code.text.matchAll(DROP_POLICY)) {
    const key = `${norm(m[1])}@${norm(m[2])}`;
    if (!created.has(key)) out.push({ label: `DROP POLICY ${shown(m[1])} without re-create`, key: `drop policy|${key}` });
  }
  return out;
}

const isSql = (name) => /\.sql$/i.test(name || "");
const isMigrationPath = (name) => /(^|\/)migrations\//.test(name || "");
/** Largest SQL file content (bytes) the gate reads in full; above it, owner. */
export const SQL_CONTENT_MAX = 1024 * 1024;

/**
 * SQL files whose added lines are not the whole story: deleting or adding a
 * comment delimiter can activate statements already in the file. For each,
 * the gate reads the full head content and the base content at `basePath`
 * (null: the file is new as SQL, so its base is empty).
 * @returns {{filename: string, basePath: string|null}[]}
 */
export function sqlContentNeeds(files) {
  return files
    .filter((f) => isSql(f.filename) && f.status !== "removed")
    .map((f) => {
      // An added file has no base; its full head content is still read, since
      // a symlink's patch is only its target's path.
      if (f.status === "added") return { filename: f.filename, basePath: null };
      // A copy's patch is against its source; a rename from a non-SQL file
      // (docs/x.txt -> migrations/9.sql) brings text that was never SQL.
      if (f.status === "copied") return { filename: f.filename, basePath: null };
      if (f.status === "renamed") return { filename: f.filename, basePath: isSql(f.previous_filename) ? f.previous_filename : null };
      return { filename: f.filename, basePath: f.filename };
    });
}

/**
 * SQL and migration paths at the head whose git file mode classify checks: a
 * symlink there makes deploy tooling run another file's text as SQL, and the
 * PR's patch shows only the link target's path.
 * @returns {string[]}
 */
export function sqlModeNeeds(files) {
  return files
    .filter((f) => f.status !== "removed" && (isSql(f.filename) || isMigrationPath(f.filename) || /(^|\/)migrations$/.test(f.filename)))
    .map((f) => f.filename);
}

const REGULAR_MODES = new Set(["100644", "100755"]);

/**
 * @param {Array} files  PR files (REST shape)
 * @param {Record<string, {head?: string, base?: string, mode?: string, error?: string}>} [sqlContents]
 *   full contents for every file sqlContentNeeds() names and the git mode for
 *   every path sqlModeNeeds() names; a missing entry is owner tier
 * @returns {string[]} owner-tier reasons
 */
export function destructiveSql(files, sqlContents = {}) {
  const hits = [];
  const sqlFiles = files.filter((f) => isSql(f.filename));
  const scanned = new Map(sqlFiles.map((f) => [f, f.patch === undefined || f.patch === null ? null : sqlCode(addedLines(f.patch).join("\n"))]));
  const created = new Set();
  for (const code of scanned.values()) if (code) for (const k of createdPolicies(code)) created.add(k);
  for (const f of sqlFiles) {
    const seen = new Set();
    const hit = (label) => {
      if (seen.has(label)) return;
      seen.add(label);
      hits.push(`${f.filename}: ${label}`);
    };
    const code = scanned.get(f);
    if (!code) {
      if (f.status !== "removed") hit("no patch available (too large or binary)");
    } else {
      // Statements can span lines: scan the joined added text per file.
      for (const h of sqlHits(code, created)) hit(h.key === "unterminated" ? `${h.label} in the added lines` : h.label);
    }
  }
  // Full files: a hit kind the head has more often than the base was
  // activated by this PR, even when no added line shows it.
  for (const need of sqlContentNeeds(files)) {
    const c = sqlContents[need.filename];
    const ok = (t) => typeof t === "string" && Buffer.byteLength(t) <= SQL_CONTENT_MAX;
    if (!c || c.error || !ok(c.head) || (need.basePath && !ok(c.base))) {
      hits.push(`${need.filename}: SQL content unavailable (${c?.error || "not fetched or too large"})`);
      continue;
    }
    const head = sqlCode(c.head);
    const base = sqlCode(need.basePath ? c.base : "");
    const count = (list) => list.reduce((m, h) => m.set(h.key, (m.get(h.key) || 0) + 1), new Map());
    const inFile = (code) => new Set([...created, ...createdPolicies(code)]);
    const before = count(sqlHits(base, inFile(base)));
    const labels = new Set();
    for (const h of sqlHits(head, inFile(head))) {
      const n = (before.get(h.key) || 0) - 1;
      before.set(h.key, n);
      if (n < 0) labels.add(h.label);
    }
    for (const label of labels) {
      const line = `${need.filename}: ${label}`;
      if (!hits.includes(line)) hits.push(`${line} (active in the full file, not in the base)`);
    }
  }
  // Symlinks (and anything else that is not a regular file) on SQL and
  // migration paths.
  for (const path of sqlModeNeeds(files)) {
    const c = sqlContents[path];
    if (c && !c.error && typeof c.mode === "string") {
      if (c.mode === "120000") hits.push(`${path}: symlinked SQL/migration`);
      else if (!REGULAR_MODES.has(c.mode)) hits.push(`${path}: SQL/migration path is not a regular file (mode ${c.mode})`);
    } else if (!hits.some((h) => h.startsWith(`${path}: SQL content unavailable`))) {
      hits.push(`${path}: SQL/migration file mode unavailable (${c?.error || "not fetched"})`);
    }
  }
  // A deleted, renamed or moved migration is history rewriting.
  for (const f of files) {
    if (f.status === "removed" && isMigrationPath(f.filename)) hits.push(`${f.filename}: migration file deleted`);
    else if (f.status === "renamed" && isMigrationPath(f.previous_filename)) hits.push(`${f.previous_filename}: migration file renamed or moved to ${f.filename}`);
  }
  return hits;
}

/**
 * Dependabot titles: "Bump x from 1.2.3 to 1.3.0" or "... in /dir".
 * Returns "patch" | "minor" | "major" | "unknown".
 */
export function dependabotUpdateType(title = "") {
  const m = title.match(/\bfrom\s+v?(\d+)(?:\.(\d+))?(?:\.(\d+))?\S*\s+to\s+v?(\d+)(?:\.(\d+))?(?:\.(\d+))?/i);
  if (!m) return "unknown";
  const [a1, a2, a3, b1, b2, b3] = m.slice(1).map((x) => (x === undefined ? 0 : Number(x)));
  if (b1 !== a1) return "major";
  // 0.x: a minor bump is breaking by semver convention.
  if (b2 !== a2) return a1 === 0 ? "major" : "minor";
  if (b3 !== a3) return a1 === 0 && a2 === 0 ? "major" : "patch";
  return "patch";
}

/**
 * A green dependabot PR needs more than its title, which anyone with write
 * access can edit: the head commit must be dependabot's own, committed and
 * signed by GitHub, and
 * every `update-type:` in its metadata must be semver-patch or semver-minor.
 * @returns {{ok: boolean, why?: string}}
 */
export function dependabotCommitProof(headCommit) {
  if (!headCommit) return { ok: false, why: "the head commit was not checked" };
  if (headCommit.author?.login !== "dependabot[bot]") return { ok: false, why: `the head commit's author is ${headCommit.author?.login || "unknown"}` };
  // Dependabot's commits are committed by GitHub itself (web-flow). A
  // GitHub-signed commit someone else made in the web UI as dependabot is not.
  if (headCommit.committer?.login !== "web-flow") return { ok: false, why: `the head commit's committer is ${headCommit.committer?.login || "unknown"}` };
  if (headCommit.commit?.verification?.verified !== true) return { ok: false, why: "the head commit is not signed by GitHub" };
  const types = [...(headCommit.commit?.message || "").matchAll(/^\s*update-type:\s*(\S+)\s*$/gm)].map((m) => m[1]);
  if (!types.length) return { ok: false, why: "the head commit lists no update-type" };
  const bad = types.filter((t) => t !== "version-update:semver-patch" && t !== "version-update:semver-minor");
  if (bad.length) return { ok: false, why: `the head commit lists ${bad.join(", ")}` };
  return { ok: true };
}

/**
 * A merge-bot revert is green only when every fact says the App made it: the
 * App opened the PR with the revert marker, the PR is one commit, and that
 * commit was authored by the App and committed and signed by GitHub
 * (revertPullRequest creates exactly that). Anyone with write access can push
 * to the revert branch; a pushed commit fails these checks.
 * @returns {{ok: boolean, why?: string}}
 */
export function botRevertProof(pr, headCommit, botLogin) {
  if (!botLogin || pr.user?.login !== botLogin) return { ok: false, why: "the author is not the merge bot" };
  if (!/^Revert "/.test(pr.title || "") || !(pr.body || "").includes(REVERT_MARKER)) return { ok: false, why: "no revert marker" };
  if (pr.commits !== 1) return { ok: false, why: `the PR has ${pr.commits ?? "an unknown number of"} commits, not 1` };
  if (!headCommit) return { ok: false, why: "the head commit was not checked" };
  if (pr.head?.sha && headCommit.sha && headCommit.sha !== pr.head.sha) return { ok: false, why: "the checked commit is not the head" };
  if (headCommit.author?.login !== botLogin) return { ok: false, why: `the head commit's author is ${headCommit.author?.login || "unknown"}` };
  if (headCommit.committer?.login !== "web-flow") return { ok: false, why: `the head commit's committer is ${headCommit.committer?.login || "unknown"}` };
  if (headCommit.commit?.verification?.verified !== true) return { ok: false, why: "the head commit is not signed by GitHub" };
  return { ok: true };
}

/** classify needs the head commit for these authors (dependabot, the merge bot). */
export function needsHeadCommit(pr, botLogin) {
  const author = pr.user?.login;
  return author === "dependabot[bot]" || (Boolean(botLogin) && author === botLogin);
}

function paths(files) {
  // Renames count on both sides: moving a file OUT of a protected path is
  // still a change to that path.
  return files.flatMap((f) => (f.previous_filename ? [f.filename, f.previous_filename] : [f.filename]));
}

/**
 * Changes owned by what they say, not where they sit (a price figure in
 * general copy). `owner_lines` is one rule or a list of rules
 * {why, paths, exempt, patterns}. Added and removed lines both count. A file
 * in scope whose diff GitHub does not show (binary, or too large) cannot be
 * read, and a file renamed out of an exempt path (a test fixture becoming
 * live copy) brings lines its diff does not show, so both count too.
 * @param {Array} files  PR files (REST shape)
 * @param {object} p     merged policy
 * @returns {string[]}   one reason per rule that hit, e.g. "price figure: a.ts, b.ts"
 */
export function ownerLineHits(files, p) {
  const reasons = [];
  for (const o of [].concat(p.owner_lines || [])) {
    if (!o?.patterns?.length) continue;
    const res = o.patterns.map((s) => new RegExp(s));
    const scope = o.paths?.length ? o.paths : ["**"];
    const skip = [...(o.exempt || []), ...(p.size_exempt_paths || [])];
    const inScope = (path) => matchesAny(path, scope) && !matchesAny(path, skip);
    const hits = [];
    for (const f of files) {
      const name = f.filename || "";
      if (!inScope(name)) continue;
      if (f.previous_filename && matchesAny(f.previous_filename, skip)) {
        hits.push(`${name} (moved from exempt ${f.previous_filename})`);
        continue;
      }
      if (typeof f.patch !== "string") {
        if ((f.additions || 0) + (f.deletions || 0) > 0) hits.push(`${name} (diff not shown)`);
        continue;
      }
      const changed = f.patch.split("\n").filter((l) => l[0] === "+" || l[0] === "-");
      if (changed.some((l) => res.some((re) => re.test(l.slice(1))))) hits.push(name);
    }
    if (hits.length) reasons.push(`${o.why || "owner line"}: ${hits.slice(0, 5).join(", ")}`);
  }
  return reasons;
}

/**
 * @param {object} policy  repo policy (merged over DEFAULTS by loadPolicy)
 * @param {object} input
 * @param {object} input.pr        GitHub PR object (REST shape)
 * @param {Array}  input.files     PR files (REST shape, fully paginated)
 * @param {string} input.repo      "owner/name"
 * @param {string} input.defaultBranch
 * @param {boolean} [input.frozen] an open merge:freeze issue exists
 * @param {string} [input.botLogin] login of the merge bot App (e.g. "x[bot]")
 * @param {object} [input.headCommit] GET /repos/{repo}/commits/{head sha} (needed for dependabot and merge-bot reverts)
 * @param {object} [input.sqlContents] full head/base contents of every file sqlContentNeeds(files) names
 * @returns {{tier: string, reasons: string[], reviewers: string[], migration: boolean}}
 */
export function classify(policy, input) {
  const p = { ...DEFAULTS, ...policy };
  const { pr, files, repo, defaultBranch, frozen = false, botLogin, headCommit, sqlContents } = input;
  const labels = (pr.labels || []).map((l) => (typeof l === "string" ? l : l.name));
  const author = pr.user?.login || "";
  const reasons = [];
  const hold = (why) => ({ tier: "hold", reasons: [why], reviewers: [], migration: false });

  if (pr.state && pr.state !== "open") return hold(`PR is ${pr.state}`);
  if (pr.draft) return hold("draft");
  if (labels.includes("merge:hold")) return hold("label merge:hold");
  if (frozen) return hold("repo frozen: an open merge:freeze issue exists");
  if (pr.head?.repo?.full_name !== repo) return hold("head branch is not in this repository (fork)");
  if (pr.base?.ref !== defaultBranch) return hold(`stacked on ${pr.base?.ref}; waits for retarget to ${defaultBranch}`);

  const isBot = author === botLogin;
  const isDependabot = author === "dependabot[bot]";
  const trusted =
    isBot ||
    p.trusted_bots.includes(author) ||
    (p.trusted_authors || []).includes(author) ||
    p.trusted_associations.includes(pr.author_association);
  if (!trusted) return hold(`author ${author} (${pr.author_association}) is not trusted`);

  if (!Array.isArray(files) || files.length === 0) return hold("no changed files enumerated");
  // The PR files API stops at 3000 entries, and changed_files may stop with
  // it: at the cap, the list cannot be shown to be complete.
  if (files.length >= FILE_LIST_CAP) return hold("file list at the API cap");
  if (typeof pr.changed_files === "number" && pr.changed_files !== files.length) {
    return hold(`enumerated ${files.length} of ${pr.changed_files} files; refusing a partial list`);
  }
  // A control character in a path can forge workflow outputs, log lines or
  // markdown. No legitimate change needs one.
  if (files.some((f) => CONTROL.test(f.filename || "") || CONTROL.test(f.previous_filename || ""))) {
    return hold("control character in a path");
  }

  const all = paths(files);
  const migration = all.some((f) => /(^|\/)migrations\//.test(f) || /\.sql$/i.test(f));
  const reviewersFor = (tier) => (p.reviewers?.[tier] ?? DEFAULT_REVIEWERS[tier]);

  const ownerHits = all.filter((f) => matchesAny(f, p.owner_paths));
  const lineHits = ownerLineHits(files, p);

  // Reverts the merge bot opened (merge-watch) restore a known-good state, but
  // only the App's own single signed commit counts (see botRevertProof). An
  // owner-path, owner-line or migration revert, or any other commit, is
  // classified on its content like every PR.
  if (isBot && !migration && !ownerHits.length && !lineHits.length && botRevertProof(pr, headCommit, botLogin).ok) {
    return { tier: "green", reasons: ["merge-bot revert of an auto-merged PR"], reviewers: [], migration };
  }

  // Owner tier.
  if (ownerHits.length) reasons.push(`owner path: ${ownerHits.slice(0, 5).join(", ")}`);
  reasons.push(...lineHits);
  const sqlReasons = destructiveSql(files, sqlContents);
  if (sqlReasons.length) reasons.push(...sqlReasons.slice(0, 5).map((h) => `destructive SQL: ${h}`));
  if (labels.includes("merge:owner-only")) reasons.push("label merge:owner-only");
  if (reasons.length) {
    return { tier: "owner", reasons, reviewers: reviewersFor("critical"), migration };
  }

  // Critical tier. A critical path is critical even when a green path also
  // matches: `supabase/functions/tests/index.ts` or `src/auth/tests/helper.ts`
  // is code that runs, whatever directory it sits in. The one exception is a
  // pure doc on a green path (`docs/auth.md`), unless it steers an agent.
  const pureDoc = (f) => matchesAny(f, PURE_DOC) && matchesAny(f, p.green_paths);
  const criticalHits = all.filter(
    // SQL in any case (X.SQL too): the globs are case-sensitive, the lexer is not.
    (f) => matchesAny(f, p.critical_overrides_green) || isSql(f) || (matchesAny(f, p.critical_paths) && !pureDoc(f)),
  );
  if (criticalHits.length) reasons.push(`critical path: ${criticalHits.slice(0, 5).join(", ")}`);
  const lines = files
    .filter((f) => !matchesAny(f.filename, p.size_exempt_paths))
    .reduce((n, f) => n + (f.additions || 0) + (f.deletions || 0), 0);
  if (lines > p.critical_line_threshold) reasons.push(`${lines} changed lines > ${p.critical_line_threshold}`);
  if (labels.includes("merge:critical")) reasons.push("label merge:critical");
  if (reasons.length) {
    return { tier: "critical", reasons, reviewers: reviewersFor("critical"), migration };
  }

  // Green tier. Without required CI there is nothing to be green on, so the
  // floor becomes one review.
  const noCi = !(p.required_checks || []).length;
  const green = (why) =>
    noCi
      ? { tier: "reviewed", reasons: [why, "no required CI checks: review is the floor"], reviewers: reviewersFor("reviewed"), migration }
      : { tier: "green", reasons: [why], reviewers: [], migration };
  if (isDependabot) {
    const kind = dependabotUpdateType(pr.title);
    const proof = dependabotCommitProof(headCommit);
    if ((kind === "patch" || kind === "minor") && proof.ok) return green(`dependabot ${kind} bump`);
    // "by title, but" only when the title claimed a green bump the commit did not back.
    const why =
      kind === "patch" || kind === "minor" ? `dependabot ${kind} bump by title, but ${proof.why}` : `dependabot ${kind} bump${proof.ok ? "" : `; ${proof.why}`}`;
    return { tier: "reviewed", reasons: [why], reviewers: reviewersFor("reviewed"), migration };
  }
  if (all.every((f) => matchesAny(f, p.green_paths))) return green("docs/tests/assets only");

  return { tier: "reviewed", reasons: ["application change"], reviewers: reviewersFor("reviewed"), migration };
}

export const DEFAULT_REVIEWERS = {
  green: [],
  reviewed: ["standard"],
  critical: ["standard", "adversarial"],
};
