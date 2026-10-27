---
name: skill-feedback
description: Turn a correction into a permanent skill update. Use right after the user corrects an output that a skill in .claude/skills/ produced ("no, always…", "don't…", "that's wrong", "next time…", or when they edit the output by hand), or when they say "update the skill". Do NOT use for one-off preferences the user says apply only this time, or when no skill produced the output.
---

# Skill feedback loop

One job: find the skill at fault and propose the smallest rule change.

## Steps
1. Name the skill that produced the output. If none did, say so and stop (it may be a new-skill idea: add it to the "Next skills" list in `.claude/skills/README.md`).
2. Quote the user's correction word for word.
3. Decide the fix type: a missing rule, a wrong step, a better example, or a description that fired when it shouldn't have.
4. Show the change as a unified diff of that SKILL.md. Keep the file short: replace or merge lines rather than only adding.
5. Apply it only after the user says OK. Then add a line to that skill's `CHANGELOG.md`: date, the correction quoted, what changed.
6. Re-run the skill on the same input and show the new output is right.

## Rules
- Write the user's rule in their words. Do not generalise beyond what they said; ask if unsure.
- Fix the skill, not just the output.
- Never put passwords, keys or customer data into a skill.

## Examples
- Good: "Don't put class names in readme.txt" → diff adds that line to ironveil-changelog rules; CHANGELOG entry; re-run is clean.
- Bad: Silently fixing the output and moving on.
