# Changelog: ironveil-license

One line per change: date — correction (quoted) — what changed.

- 2026-10-27 — Created from the repo audit (README.md v1.0–1.2.1 notes, readme.txt, tools/). No user corrections yet.
- 2026-10-27 — Test run: the tool already rejects schemes/paths; step 2 narrowed to the *.domain vs domain question.
- 2026-10-31 — Fixed my own wrong rule: `*.shop.com` covers the apex too (checked in `License::domain_allowed()`).
