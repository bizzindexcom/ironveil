# Skill test runs — 2026-10-27

Each skill was run on a real case from this repo. "Manual" = what was actually done by hand for v1.2.1.
Throwaway keys were generated in a scratch folder for signing/licence tests and deleted. The real private key was never touched.

| Skill | Real case | Result |
|---|---|---|
| ironveil-release | Repackage the shipped `ironveil-security-1.2.1.zip` | PASS — 37/37 checksums match, same 45-entry file list as the hand-built zip, 2 warnings (placeholder URLs) |
| ironveil-release | Header-only bump to 1.2.2 | PASS — caught: version mismatch + stale checksum |
| ironveil-release | Full bump, no changelog, stray `ironveil-owner-private.key` | PASS — 6 failures reported; `package.sh` refuses before rebuilding checksums, no zip produced |
| ironveil-signature-update | The v1.2.1 `accesson.php` backdoor (`eval(base64_decode(`) | PASS — sample matched, 0 false positives across the 37 plugin files |
| ironveil-signature-update | Too-broad pattern `base64_decode` | PASS — rejected, 9 false positives (licence + sign tools) |
| ironveil-signature-update | `(.*)*\$x` | PASS — rejected for catastrophic backtracking |
| ironveil-signature-update | Sign + verify a feed (version 2, rule + filename) | PASS — `VALID signature.` |
| ironveil-license | 1-year paid key for acme.com | PASS — `inspect` shows name, domain, type, 365-day expiry |
| ironveil-scan-triage | v1.2.1 live-site report (see below) | PASS, with caveat |
| ironveil-changelog | v1.2.1 fix list (see below) | PASS, with caveat |

**Caveat for the last two:** they produce prose, and I had already read the real v1.2.1 notes, so this is not a blind test. Re-test both on the next real report/release before trusting them.

## Bugs the test runs found in the skills (fixed in the skill, not the output)
1. `release_check.sh` counted all checksum failures as one. Now counts each.
2. `package.sh` rebuilt `checksums.json` before checking for key files, so a stray key got hashed into the manifest. Secret check now runs first.
3. `test_pattern.php` missed backtracking blow-ups because PCRE JIT ignores `backtrack_limit`. Probe now runs with JIT off.
4. Licence step 2 duplicated a check the tool already does; narrowed to the `*.domain` vs `domain` intent question.

## ironveil-scan-triage on the v1.2.1 report

| Finding | Path | Verdict | Evidence | Next step |
|---|---|---|---|---|
| suspicious_name / root_unknown | `accesson.php` (WP root) | **Compromise** | `eval(base64_decode(` + known backdoor name | Incident steps below; add filename (ironveil-signature-update) |
| core_modified ×5 | taxonomy.php, class-wp-query.php, post.php, class-wp-post.php, meta.php | Likely compromise — unconfirmed | Modified alongside a backdoor; compare mtimes and "View changes" diff | Reinstall core, then rescan |
| content_injection | oEmbed cache post | **False positive** | Rule matched `marginwidth="0"` in WP embed iframe | Rule fix + ironveil-changelog |
| Repair error | "File is not writable" | **IronVeil bug** | Repair needed wp-includes folder writable | Code fix in `Scanner::write_file()` |

Site is compromised: change all passwords and salts, check admin users, reinstall core, review files modified at the same time. Not checked: uploads, database users, cron.

Manual version (README v1.2.1) reached the same four verdicts. The skill adds the "not checked" line and the mtime comparison.

## ironveil-changelog on the v1.2.1 fix list (readme.txt draft)

```
= 1.2.1 =
* Fix: "Repair" no longer fails with "File is not writable" when the wp-includes folder is read-only. If the file still can't be written, the message says why and what to do.
* New: "View changes" compares a modified core file with the official WordPress copy.
* New: "Download original" gives you the verified official file.
* Fix: the oEmbed cache and WordPress embed iframes are no longer reported as suspicious scripts.
* New: PHP files in the WordPress root that are not part of WordPress are reported. Added known backdoor filenames (accesson.php and others).
```

Compared with the manual entry: same structure and voice, but the draft **dropped** one item that was in the input ("Repairing or quarantining a file now closes all findings for that file, and a failed repair no longer leaves a stray backup"). Fixed in the skill: new step 3 maps every input item to a bullet before drafting (see ironveil-changelog CHANGELOG.md). Re-run with the new step produces 6 bullets, matching the manual entry's count.
