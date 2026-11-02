# Changelog: ironveil-release

One line per change: date — correction (quoted) — what changed.

- 2026-10-27 — Created from the repo audit (README.md v1.0–1.2.1 notes, readme.txt, tools/). No user corrections yet.
- 2026-10-27 — Test run: fail count undercounted checksum failures; package.sh hashed a stray key file before refusing — both fixed.
- 2026-10-31 — User: source lives in Claude conversations; every zip is for distribution — placeholders now FAIL by default (`--dev` to warn), Plugin URI checked, step 1 updated.
- 2026-11-02 — 1.3.x layout: owner tools moved out of the plugin. Check now fails if they are inside it (was: require tools/.htaccess); package.sh finds build-checksums.php in ironveil-owner-tools/. Source now lives in the repo.
