"""Negative corpus: medical-privacy false-positive regression.

Regression entry for the 2026-09-22 false-positive audit (commit
e0abd61): the rule used to match three bare letters anywhere, so
"philosophy", "Phoenix", and "metaphor" flagged ordinary prose as a
medical-data reference. The corrected rule requires the standalone
word (as the Greek letter is used in clinical writing) or the full
three-word compliance phrase; every line below fired under the old
regex and must stay silent under the current one.
"""

# aegis:expect-none hipaa-phi

# The project philosophy is to fail loud rather than silently degrade.
PROJECT_PHILOSOPHY = "fail loud"

# Deployment region for the primary cluster (Phoenix metro data center).
DEPLOYMENT_REGION = "us-phoenix-1"

# Metaphor-free onboarding: the glossary keeps jargon out of the docs.
GLOSSARY_SECTIONS = ["concepts", "metaphors", "history"]
