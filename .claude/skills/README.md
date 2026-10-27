# IronVeil skills library

Skills Claude loads on its own when a request matches. One skill, one job.
Test evidence: `TEST-RESULTS.md`. Every skill has a `CHANGELOG.md`.

> **Frequencies and hours below are estimates from the repo history** (v1.0.0 → v1.2.1 between 30 Sep and 27 Oct 2026, about one release a week). Correct them. They decide the build order.

## 1. Work audit (from the repo, not from interviews)

| Repeated task | Evidence in repo | Est. frequency | What gets fixed by hand |
|---|---|---|---|
| Package a release | 4 versions in ~4 weeks; version in 3 places; "rebuild checksums after any edit" | Weekly | Forgotten version spot, stale `checksums.json`, placeholder URLs still in |
| Write release notes | readme.txt changelog + README design/test notes per version | Weekly | Two different voices; test claims; dropped items |
| Add malware detections | v1.2.1 added 3 backdoor names, `Signatures::VERSION` 3→4; signed feed tool | Weekly–monthly | Forgetting to raise the version; over-broad patterns |
| Triage a live-site report | v1.2.1 was driven entirely by one site's scan report | Per incident | Separating real compromise from false positives and plugin bugs |
| Issue / revoke licences | `tools/ironveil-license.php`, Free/Pro since v1.2.0 | Per sale | Domain mistakes; keeping the private key off servers |

## 2. Recommended skills

| Skill | Replaces | Est. hrs saved/wk | Doesn't fire for | Could overlap with |
|---|---|---|---|---|
| `ironveil-release` | Manual bump/checksum/zip | 0.5–1 | Writing notes, signatures, other plugins | ironveil-changelog (hands off) |
| `ironveil-changelog` | Writing readme.txt + README notes | 0.5–1 | Version bumps, SECURITY.md | ironveil-release |
| `ironveil-signature-update` | Hand-writing + testing rules, feed signing | 0.5–1.5 | WAF rules, FP triage, revocation alone | scan-triage, license (revocation) |
| `ironveil-scan-triage` | Reading reports finding by finding | 0.5–2 per incident | WAF logs, non-IronVeil sites | signature-update (hands off) |
| `ironveil-license` | Building issue commands, checking keys | 0.25 | Signature rules, licensing code changes | signature-update (revocation uses the feed) |
| `skill-feedback` | Re-explaining the same correction | — | One-off preferences | none (meta skill) |

## 3. Blueprints — what could go wrong / how to test today

- **release**: could ship a stray key or a placeholder URL. Test: `bash .claude/skills/ironveil-release/scripts/release_check.sh <unpacked>/ironveil-security`.
- **changelog**: could invent test results or drop an item. Test: give it your next fix list; count bullets vs items.
- **signature-update**: a false positive on every customer site. Test: `php .claude/skills/ironveil-signature-update/scripts/test_pattern.php '<re>' <sample> <plugin-dir> <a clean WP install>`.
- **scan-triage**: calling a hacked site clean. Test: paste the next real report; check the "not checked" line exists.
- **license**: an owner key for `*` issued by mistake; key leakage. Test: `inspect` on a key you already issued.

## 4. Learning loop

1. You correct an output ("no, always…").
2. `skill-feedback` names the skill at fault and shows a diff of its SKILL.md.
3. Applied only after your OK; a line goes into that skill's `CHANGELOG.md`.
4. The skill is re-run on the same input to prove the fix.

Four fixes have already gone through this loop during testing (see each CHANGELOG.md).

## 5. Next 3 skills to build (ranked by estimated hours saved)

1. **`ironveil-waf-regression`** — README says "WAF suite still 60/60", but the suite is not in this repo. Add it here first; then a skill can run it before every release. Biggest risk reducer.
2. **`ironveil-sandbox-test`** — rebuild the WP 6.5.5 + SQLite + PHP 8.4 + ClamAV sandbox and the mock core-checksum mu-plugins described in README.
3. **`ironveil-wporg-readme-check`** — validate readme.txt headers, "Tested up to", and the Free/Pro wording against wordpress.org trialware rules (README flags this as an open risk).

## 6. Open questions for you

1. Where does the plugin source live? This repo only holds the zip, so skills unpack it to a scratch folder.
2. Should the README.md design notes keep being written per version, or only readme.txt?
3. Is the 1.2.1 zip in this repo meant for distribution? It still has the `example.com` purchase URL and no feed URL.
4. `SECURITY.md` lists versions 5.1.x / 4.0.x as supported; the plugin is at 1.2.1. Intentional?
5. Real frequencies: how many releases, incidents and licence sales per week?
