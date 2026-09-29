# merge-policy (vendored)

These files are copied from `~/dev/_tools/merge-policy` by `merge-policy install`.
Do not edit them here: change the source, test it, and re-install.

- `run-gate.mjs` / `review.mjs` / `watch.mjs` are the workflow entry points.
- `../merge-policy.json` is this repo's policy (tiers, required checks, watch).
- Everything under `.github/merge-policy*` and `.github/workflows/` is **owner
  tier**: a PR that touches it runs the reviews but never merges itself.

Rules: `docs/policy.md` in the source repo.
