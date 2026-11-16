<!--
Six sections, in this order. A reviewer should be able to read them top to
bottom and know what changed, why, how it was proven, what it can break,
and what it closes.
-->

## 1. What changed

<!--
The change itself, in two or three sentences. Say which files or subsystems
moved, and name the behavior that is different afterwards.
-->

## 2. Why

<!--
The problem this solves, and what happens if it is not solved. Link the
issue: Fixes #123, Closes #456.
-->

## 3. How it was verified

<!--
The commands you ran and their results — not a claim that it works. Name
the gate you ran and what it showed. A test that was not run is not a
verification.
-->

## 4. Risk and rollback

<!--
What could break, who is affected, and how to undo it. Say "low, docs only"
if that is the truth. For a behavior change, name the flag, config key, or
file that turns it back.
-->

## 5. Checklist

- [ ] Formatting check clean
- [ ] Lint check clean (deny warnings)
- [ ] Test suite passes
- [ ] Documentation build clean (public API changed)
- [ ] Documentation updated (if a claim, count, or contract changed)
- [ ] Patterns validated with the corpus harness (if a rule changed)
- [ ] No quality gate weakened (lint level, advisory waiver, license, coverage floor)
- [ ] Every `#[allow(...)]` added carries an `aegis-allow:` annotation with a reason, an expiry, and an approver

## 6. Related issues and notes

<!--
Issue links, follow-ups, and anything a reviewer should know but does not
need to act on. Screenshots or example output belong here.
-->
