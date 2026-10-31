---
name: ironveil-changelog
description: Write the release notes for an IronVeil Security version — the user-facing "= X.Y.Z =" entry in readme.txt and the matching "## vX.Y.Z" design-and-test section in README.md — from a diff, a list of fixes, or a live-site report. Use when the user asks for a changelog, release notes, "what changed in 1.x.y", or "update the README/readme.txt for this version". Do NOT use to bump versions or build the zip (ironveil-release), or for SECURITY.md.
---

# IronVeil changelog

One job: describe a version in the user's two existing voices. Read the last two entries of each file first and copy their shape.

## Steps
1. Collect the changes: a diff between two unpacked versions (`diff -ru old/ new/`), the user's list, or the report that caused the fix.
2. Number every input item. Each one must end up in a bullet (merge related items, never drop one). Show the mapping if any item was merged.
3. Draft the `readme.txt` entry (for site owners), then the `README.md` section (for the author: design + test notes).
4. List every claim you could not verify from the diff (especially test results) as a question. Never write "Tests passed" unless the user gave the results.
5. Show both drafts. Write them into the files only after the user's OK.

## readme.txt rules (seen in 1.0.0–1.2.1)
- One bullet per change, starting `* New:` or `* Fix:`. Plain bullets are fine for other changes.
- Say what the site owner sees, not which class changed. Quote UI labels: "View changes", "Download original".
- For a Fix, name the symptom the user saw ("no longer fails with \"File is not writable\"").
- Newest version first, directly under `== Changelog ==`.

## README.md rules (the user confirmed: write this section for every version)
- Heading `## vX.Y.Z: <short theme>`.
- If a live site triggered it, start with "The user's live site reported:" and the findings.
- Name classes/methods in backticks (`Scanner::write_file()`), numbered lists for ordered fallbacks.
- End with "Tests" listing each case and its result, plus "WAF suite still N/N" when the user reports it.
- Short sentences. No marketing words ("robust", "seamless", "cutting-edge").

## Examples
- Good (readme): `* Fix: WordPress's own oEmbed cache and embed iframes are no longer reported as suspicious scripts.`
- Good (README): "`Scanner::core_original()` downloads the file for this version from core.svn and verifies its checksum."
- Bad: `* Improved Scanner::write_file() robustness with enhanced fallback logic.` (class name in readme.txt, vague, marketing tone)
