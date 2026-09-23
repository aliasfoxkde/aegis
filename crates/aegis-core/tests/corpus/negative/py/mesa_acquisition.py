"""Negative corpus: alignment-risk false-positive regression.

Regression entry for the 2026-09-22 false-positive audit (commit
e0abd61): the rule used to match the bare "acquisit" stem, so any
mention of data or company acquisition was scored as an out-of-place
alignment risk. The corrected rule requires the textbook research
vocabulary, or an acquisition phrase followed within 24 characters by
one of three specific governance nouns; every line below fired under
the old regex and must stay silent under the current one.
"""

# aegis:expect-none mesa-optimization

# Sensor data acquisition runs on the instrument bus at 10 Hz.
ACQUISITION_RATE_HZ = 10

# The acquisition pipeline normalizes samples before storage.
def normalize(samples):
    return [round(value, 3) for value in samples]

# Quarterly report: the acquisition of the smaller vendor completed.
VENDOR_NOTES = ["due diligence", "integration plan", "retention"]
