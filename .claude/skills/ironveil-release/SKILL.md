---
name: ironveil-release
description: Package a new IronVeil Security plugin version into ironveil-security-X.Y.Z.zip — bump the version in all three places, rebuild checksums.json, lint, run release checks, and zip. Use when the user says "release", "ship", "package", "bump to 1.x.y" or "build the zip" for the IronVeil plugin. Do NOT use to write changelog text (ironveil-changelog), to add malware signatures (ironveil-signature-update), or for WordPress plugins other than IronVeil.
---

# IronVeil release

One job: turn an edited plugin folder into a verified release zip. It does not write release notes.

## Steps
1. Get the plugin folder. If only a zip exists, unpack it to the scratchpad (`unzip <zip> -d <dir>`). Never edit inside the repo's zip.
2. Ask for the new version if the user did not give one. Do not guess patch vs minor.
3. Bump the version in exactly these three places:
   - `ironveil-security.php` header line `Version:`
   - `define( 'IRONVEIL_VERSION', '…' )` in `ironveil-security.php`
   - `Stable tag:` in `readme.txt`
4. If any file under `includes/class-signatures.php` gained a pattern or filename, confirm `Signatures::VERSION` was raised (see ironveil-signature-update).
5. Make sure `readme.txt` has a `= X.Y.Z =` changelog entry. If it is missing, stop and hand off to ironveil-changelog.
6. Run `bash .claude/skills/ironveil-release/scripts/package.sh <plugin-dir> <out-dir>`. It rebuilds checksums, runs `release_check.sh`, and zips.
7. Show the user the check output and the zip path. Moving the zip into the repo, committing and pushing need the user's OK.

## Rules (from the repo's own notes)
- Rebuild `checksums.json` after ANY edit, last, or the plugin reports itself as tampered.
- The zip's top folder is `ironveil-security/`, named `ironveil-security-X.Y.Z.zip`.
- Never package a private key, `*.key`, or anything named `*owner-kit*` / `*PRIVATE*`. The check fails hard on these.
- `License::PURCHASE_URL` and `License::DEFAULT_FEED_URL` are placeholders; the check warns. Ask the user whether this build is for distribution before ignoring the warning.

## Examples
- Good: "Ship 1.2.2" → bumps 3 places, finds `= 1.2.2 =` in readme, package.sh prints `ALL CHECKS PASSED`, zip handed over, nothing pushed yet.
- Good: "Build the zip" with no version change → asks: "Same version 1.2.1 or a bump?"
- Bad: Bumping only the header, editing a file after rebuilding checksums, or writing the changelog entry itself.
