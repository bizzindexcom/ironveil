---
name: ironveil-signature-update
description: Add or change an IronVeil malware detection — a backdoor filename, a PHP/JS/config regex signature — either as a built-in (class-signatures.php, raise Signatures::VERSION) or in the Ed25519-signed signature feed (rules.json → ironveil-sign.php sign). Use when the user found a new backdoor, web shell or injected script on a site, or says "add a signature/rule/filename" or "publish the feed". Do NOT use for firewall (WAF) rules in class-waf-rules.php, for false-positive triage (ironveil-scan-triage), or for license revocation alone (ironveil-license).
---

# IronVeil signature update

One job: get a new detection into the plugin or the feed, validated, without false positives.

## Steps
1. Ask: built-in (ships in next release) or feed (reaches Pro sites within a day)? Do not choose for the user.
2. Get a real sample or the exact matching line. Never write a pattern from a description alone.
3. Write the rule. Feed rule shape (see `tools/feed-example.json`): `id` `^[a-z0-9_]{3,40}$`, `severity` 1–4 (4 = critical), `description`, `pattern` ≤ 2000 chars. Filenames go in `filenames`, lowercase basenames.
4. Test it: `php .claude/skills/ironveil-signature-update/scripts/test_pattern.php '<pattern>' <malicious-sample> [clean-files-or-dirs...]`. It must hit the sample and miss clean WordPress/plugin files (run it on the plugin folder itself at minimum).
5. Built-in: edit `includes/class-signatures.php` and raise `const VERSION` by 1. Feed: raise the feed `version` by 1 (lower versions are refused as rollbacks).
6. Feed only: the user signs on their own machine with `php tools/ironveil-sign.php sign rules.json <secret-key-file> > signatures.json`, then `verify` with the public key. You never read, request or store the secret key.
7. Uploading the feed or pushing is the user's action, after their OK.

## Rules
- Rules only detect; never put anything executable in the feed.
- Prefer anchoring on code that only malware uses (`eval(base64_decode(`, known C2 domains) over generic words.
- No unbounded `.*` next to another quantifier — the signer rejects catastrophic backtracking.

## Examples
- Good: `accesson.php` found in site root → added to `builtin_filenames()`, `Signatures::VERSION` 3→4 (what v1.2.1 did).
- Good: new Balada domain → feed rule `js` with an escaped domain regex, sample hit, plugin folder 0 hits, feed version +1.
- Bad: pattern `eval\(` severity 4 — fires on legitimate libraries; no sample tested; version not raised.
