---
name: ironveil-scan-triage
description: Triage an IronVeil scan report or screenshot from a live WordPress site — sort every finding into compromise, false positive, or IronVeil bug, and say what to do next for each. Use when the user pastes scan results, a findings list, an error from Repair/Quarantine, or asks "is my site hacked?" about an IronVeil report. Do NOT use to write the fix itself (hand false positives and bugs to the right skill), for WAF/firewall block logs, or for sites not running IronVeil.
---

# IronVeil scan triage

One job: turn a raw report into a decision table. You do not touch the live site.

## Steps
1. List every finding with its type (`core_modified`, `root_unknown`, `suspicious_name`, `php_in_uploads`, `content_injection`, `self_modified`, …), path and severity.
2. Classify each one:
   - **Compromise** — known backdoor name or code (`eval(base64_decode(`, obfuscated loaders), PHP in uploads, unknown PHP in root.
   - **False positive** — WordPress or plugin behaviour the rule misread (e.g. oEmbed cache, `wp-embedded-content` iframes).
   - **IronVeil bug** — the plugin itself failed (e.g. Repair "File is not writable").
   - **Needs info** — say exactly what file content or log you need.
3. One confirmed backdoor means the whole site is compromised. Say so first, and list: change all passwords and salts, check admin users, reinstall core, review other files modified at the same time.
4. Several modified core files: check whether they changed at the same time as the backdoor before calling them malicious.
5. End with a hand-off list: false positives → rule fix + ironveil-changelog; new malware → ironveil-signature-update; bugs → a code fix.

## Output
A table: Finding | Path | Verdict | Evidence | Next step. Then the hand-off list. Mark anything you inferred without seeing the file as "unconfirmed".

## Rules
- Never tell the user a site is clean. Say what was and wasn't checked.
- Do not suggest deleting files; IronVeil's quarantine is reversible, deletion isn't.
- Do not log in to, or send anything to, the user's site.

## Examples
- Good: `accesson.php` + `eval(base64_decode(` → Compromise, site-wide incident steps, add filename to signatures.
- Good: oEmbed cache post flagged as hidden iframe → False positive, rule matched `marginwidth="0"`, hand to rule fix.
- Bad: "5 core files modified — restore them and you're safe." (ignores the backdoor, declares clean)
