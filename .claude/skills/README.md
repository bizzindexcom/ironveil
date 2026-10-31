# IronVeil skills library

Skills Claude loads on its own when a request matches. One skill, one job.
Test evidence: `TEST-RESULTS.md`. Every skill has a `CHANGELOG.md`.

> **Frequencies:** you said volume will depend on download requests once IronVeil is on wordpress.org, so the hours below are rough guesses until launch. Until then, the skills are ranked by risk, not hours.

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

## 5. Next 3 skills to build (re-ranked after your answers)

1. **`ironveil-wporg-check`**: the plugin is going to wordpress.org, so the plugin review there becomes the first gate. Check the readme.txt headers, `Tested up to`, `Contributors` (must be your wordpress.org username) and the guideline on locked features (see the risk below).
2. **`ironveil-waf-regression`**: README says "WAF suite still 60/60", but the suite isn't in this repo. Add it so the release check can run it.
3. **`ironveil-support-triage`**: once downloads start, sort support-forum posts into bug, false positive, how-to or licence question. Build it when real posts arrive, not before.

## 6. Your answers (2026-10-31)

| Question | Answer | What changed |
|---|---|---|
| Where is the source? | In Claude conversations | `ironveil-release` step 1 unpacks the zip. Recommended: commit the unpacked source here, so every change has a diff. |
| Keep README.md notes per version? | Yes | `ironveil-changelog` rule marked as confirmed |
| Is the zip for distribution? | Yes | Placeholder URLs and `Plugin URI` now **fail** the release check (`--dev` for test builds). The shipped 1.2.1 zip fails 3 checks. |
| SECURITY.md version table | Written by Claude | The table (5.1.x / 4.0.x) matches GitHub's sample SECURITY.md and doesn't describe IronVeil. Proposed fix: 1.2.x supported, older versions not. Waiting for your OK. |
| Weekly volume | Depends on downloads | Ranking switched to risk until launch |

## 7. Biggest risk before wordpress.org

Guideline 5 of the wordpress.org plugin guidelines says trialware isn't allowed: a plugin there may not ship features that are locked until someone pays. IronVeil 1.2.x ships its Pro features inside the plugin and unlocks them with a key (`Settings::get()` + `License::PRO_SETTINGS`); your own README flags this too. Expect the review to reject it in this form. The usual fix is two plugins: a free one on wordpress.org, and a separate Pro add-on sold from your site that contains the Pro code. That is a design decision for you; no skill changes it.
