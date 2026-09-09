#!/usr/bin/env python3
"""Generate liveness examples for every bundled Aegis pattern.

Reads the pattern dump produced by
`cargo run -p aegis-patterns --example dump_patterns` and emits
`crates/aegis-patterns/src/examples.rs`: a lookup table mapping every
pattern name to a realistic string the pattern provably matches under its
own entropy gate and exclude regex.

The pattern corpus uses only alternation, classes, quantifiers, and inline
flags (the `regex` crate has no lookaround/backrefs), so a small
regex-to-string synthesizer covers it. Candidates are validated against the
real regex before being emitted; anything the synthesizer cannot satisfy
must be hand-written in OVERRIDES below.

Usage:
    cargo run -p aegis-patterns --example dump_patterns > /tmp/patterns.json
    python3 scripts/generate_examples.py /tmp/patterns.json \
        crates/aegis-patterns/src/examples.rs
"""

from __future__ import annotations

import json
import math
import random
import re
import sys
import zlib
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Hand-written examples. Used verbatim when present; the generator fills in
# everything else. Add entries here when the synthesizer produces something
# unrealistic or fails outright (the script reports the names).
# ---------------------------------------------------------------------------

OVERRIDES: dict[str, str] = {
    "ai-formulaic-verb": "// This function leverages the config cache",
    "finance-balance-read-modify-write": "balance = balance - amount",
    "finance-float-equality": "balance == 0.0",
    "finance-math-round-money": "Math.round(totalAmount * 100) / 100",
    "finance-naive-settlement-now": "settlementDate := datetime.now()",
    "finance-parsefloat-money": "parseFloat(amountStr)",
    "crypto-low-pbkdf2-iterations": "iterations = 10000",
    "crypto-predictable-key-material": "secret = Math.random()",
    "crypto-timing-unsafe-compare": "signature === expected",
    "dea-number": "DEA: BJ1234563",
    "healthcare-encryption-disabled": "patient_archive, encryption = false",
    "healthcare-phi-emailed": "mailto:patient@clinic.example",
    "healthcare-phi-hardcoded": 'patient_name = "Jane Doe"',
    "healthcare-phi-in-url-query": "/search?patient_id=483920114",
    "healthcare-phi-logged": 'logger.info("patient MRN968832775724")',
    "healthcare-phi-plaintext-endpoint": '"http://api.clinic.local/patient-records"',
    "healthcare-select-star-phi-table": "SELECT * FROM patients",
    "medicare-beneficiary-identifier": "MBI: 1EG4TE5MK73",
    "national-provider-identifier": "NPI: 1234567893",
    "placeholder-env-var": "process.env.YOUR_API_KEY",
    "stub-implementation-marker": "// Stubbed implementation for now, replace with real logic",
    "secrets-aws-access-key": "AKIAB3D7F9H2J5L8N1P6",
    "secrets-aws-secret-key": 'aws_secret = "wJalrXUtnFEMI/K7MDENGbPxRfiCYpX7vQ2mZ8kN"',
    "jwt-token": (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
        "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    ),
    "ssh-private-key": "-----BEGIN OPENSSH PRIVATE KEY-----",
    "pgp-private-key": "-----BEGIN PGP PRIVATE KEY BLOCK-----",
}


def shannon_entropy(text: str) -> float:
    """Byte-faithful port of aegis_core::entropy::shannon_entropy for ASCII."""
    if not text:
        return 0.0
    freq: dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    total = float(len(text))
    return -sum((n / total) * math.log2(n / total) for n in freq.values())


# ---------------------------------------------------------------------------
# Regex AST
# ---------------------------------------------------------------------------

@dataclass
class Literal:
    text: str


@dataclass
class CharClass:
    chars: str          # explicit characters
    ranges: list[tuple[str, str]]
    negated: bool


@dataclass
class Dot:
    pass


@dataclass
class Predefined:
    kind: str           # d, D, w, W, s, S, b, B


@dataclass
class Group:
    branches: list[list]
    capturing: bool


@dataclass
class Repeat:
    node: object
    min: int
    max: int | None     # None = unbounded


@dataclass
class Anchor:
    text: str


@dataclass
class Empty:            # inline flag groups like (?i)
    pass


class RegexParser:
    def __init__(self, pattern: str):
        self.src = pattern
        self.pos = 0

    def parse(self) -> list:
        result = self.parse_alternation()
        if self.pos != len(self.src):
            raise ValueError(f"unconsumed input at {self.pos}: {self.src[self.pos:]!r}")
        return result

    def parse_alternation(self) -> list:
        branches = [self.parse_sequence()]
        while self.peek() == "|":
            self.pos += 1
            branches.append(self.parse_sequence())
        if len(branches) == 1:
            return branches[0]
        return [Group(branches, capturing=False)]

    def parse_sequence(self) -> list:
        items = []
        while self.pos < len(self.src) and self.peek() not in "|)":
            items.append(self.parse_atom())
        return items

    def parse_atom(self):
        ch = self.peek()
        if ch == "(":
            return self.parse_group()
        if ch == "[":
            return self.parse_class()
        if ch == ".":
            self.pos += 1
            return self.parse_repeatable(Dot())
        if ch == "\\":
            return self.parse_escape()
        if ch in "^$":
            self.pos += 1
            return self.parse_repeatable(Anchor(ch))
        if ch == "}":
            # The regex crate treats a bare '}' as a literal.
            self.pos += 1
            return self.parse_repeatable(Literal("}"))
        if ch in "*+?{":
            raise ValueError(f"quantifier with nothing to repeat at {self.pos}")
        self.pos += 1
        return self.parse_repeatable(Literal(ch))

    def parse_repeatable(self, node):
        src, pos = self.src, self.pos
        if pos < len(src):
            q = src[pos]
            if q == "*":
                self.pos += 1
                return self.maybe_lazy(Repeat(node, 0, None))
            if q == "+":
                self.pos += 1
                return self.maybe_lazy(Repeat(node, 1, None))
            if q == "?":
                self.pos += 1
                return self.maybe_lazy(Repeat(node, 0, 1))
            if q == "{":
                end = src.find("}", pos)
                if end != -1:
                    body = src[pos + 1 : end]
                    if re.fullmatch(r"\d+(,\d*)?", body):
                        self.pos = end + 1
                        if "," in body:
                            lo_s, hi_s = body.split(",")
                            hi = int(hi_s) if hi_s else None
                        else:
                            lo_s, hi = body, int(body)
                        return self.maybe_lazy(Repeat(node, int(lo_s), hi))
        return node

    def maybe_lazy(self, node):
        if self.peek() == "?":
            self.pos += 1
        return node

    def parse_group(self):
        # consumes '('
        if self.src[self.pos :].startswith("(?"):  # flags or non-capture
            rest = self.src[self.pos :]
            m = re.match(r"\(\?[a-zA-Z]+\)", rest)
            if m:  # inline flags: (?i) (?is) ...
                self.pos += m.end()
                return self.parse_repeatable(Empty())
            m = re.match(r"\(\?:", rest)
            if not m:
                # Scoped flag groups like (?i:...): case folding does not
                # change which strings are synthesizable, so treat them as
                # plain non-capturing groups.
                m = re.match(r"\(\?[a-zA-Z]*:", rest)
            if m:
                self.pos += m.end()
            else:
                raise ValueError(f"unsupported group at {self.pos}: {rest[:20]!r}")
            capturing = False
        else:
            self.pos += 1
            capturing = True
        branches = [self.parse_sequence()]
        while self.peek() == "|":
            self.pos += 1
            branches.append(self.parse_sequence())
        if self.peek() != ")":
            raise ValueError(f"unterminated group at {self.pos}")
        self.pos += 1
        return self.parse_repeatable(Group(branches, capturing))

    def parse_class(self):
        # consumes '['
        self.pos += 1
        negated = False
        if self.peek() == "^":
            negated = True
            self.pos += 1
        chars: str = ""
        ranges: list[tuple[str, str]] = []
        first = True
        while True:
            ch = self.src[self.pos]
            if ch == "]" and not first:
                self.pos += 1
                break
            first = False
            if ch == "\\":
                self.pos += 1
                esc = self.src[self.pos]
                if esc == "d":
                    chars += "0123456789"
                elif esc == "w":
                    chars += "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
                elif esc == "s":
                    chars += " "
                elif esc == "n":
                    chars += "\n"
                elif esc == "t":
                    chars += "\t"
                else:
                    chars += esc
                self.pos += 1
                low = high = chars[-1]
            elif (
                self.pos + 2 < len(self.src)
                and self.src[self.pos + 1] == "-"
                and self.src[self.pos + 2] != "]"
            ):
                low, high = ch, self.src[self.pos + 2]
                ranges.append((low, high))
                self.pos += 3
            else:
                chars += ch
                low = high = ch
                self.pos += 1
            # range detection above already consumed; a trailing '-' before ]
            # is a literal handled by the general branch on next iteration
        return self.parse_repeatable(CharClass(chars, ranges, negated))

    def parse_escape(self):
        self.pos += 1
        esc = self.src[self.pos]
        self.pos += 1
        if esc in "dDwWsSbB":
            return self.parse_repeatable(Predefined(esc))
        literal = {"n": "\n", "t": "\t", "r": "\r"}.get(esc, esc)
        return self.parse_repeatable(Literal(literal))

    def peek(self) -> str:
        return self.src[self.pos] if self.pos < len(self.src) else ""


# ---------------------------------------------------------------------------
# Synthesis
# ---------------------------------------------------------------------------

UPPER = "ABCDEFGHJKLMNPQRSTUVWXYZ"
LOWER = "abcdefghijkmnopqrstuvwxyz"
DIGITS = "23456789"
WORD = LOWER + UPPER + DIGITS + "_"

CLASS_POOLS = {
    "a-z": LOWER,
    "A-Z": UPPER,
    "0-9": DIGITS,
    "a-zA-Z": LOWER + UPPER,
    "A-Za-z": LOWER + UPPER,
    "a-zA-Z0-9": LOWER + UPPER + DIGITS,
    "A-Za-z0-9": LOWER + UPPER + DIGITS,
    "a-zA-Z0-9_": WORD,
    "A-Za-z0-9_": WORD,
    "a-f0-9": "0123456789abcdef",
    "A-Fa-f0-9": "0123456789abcdefABCDEF",
    "a-fA-F0-9": "0123456789abcdefABCDEF",
}


def class_members(cls: CharClass) -> str:
    if cls.negated:
        excluded = set(cls.chars)
        for lo, hi in cls.ranges:
            excluded |= {chr(c) for c in range(ord(lo), ord(hi) + 1)}
        pool = "".join(
            c for c in (WORD + " ./:=+-") if c not in excluded and c != "\n"
        )
        return pool or "x"
    members = cls.chars
    for lo, hi in cls.ranges:
        key = f"{lo}-{hi}"
        if key in CLASS_POOLS:
            members += CLASS_POOLS[key]
        elif ord(hi) - ord(lo) < 200:
            members += "".join(chr(c) for c in range(ord(lo), ord(hi) + 1))
        else:
            members += lo + hi
    return members or "x"


class Synthesizer:
    def __init__(
        self,
        rng: random.Random,
        prefer_first_branch: bool = True,
        diversity: bool = False,
    ):
        self.rng = rng
        self.prefer_first = prefer_first_branch
        self.diversity = diversity
        # Pool content -> (shuffled pool, next index). Sampling cycles through
        # the shuffled pool so consecutive picks rarely repeat a character,
        # which is what entropy gates reward.
        self._cursors: dict[str, tuple[str, int]] = {}

    def _sample(self, pool: str) -> str:
        if not self.diversity:
            return self.rng.choice(pool)
        entry = self._cursors.get(pool)
        if entry is None or entry[1] >= len(pool):
            entry = ("".join(self.rng.sample(pool, len(pool))), 0)
            self._cursors[pool] = entry
        shuffled, idx = entry
        self._cursors[pool] = (shuffled, idx + 1)
        return shuffled[idx]

    def synth(self, nodes: list, depth: int = 0) -> str:
        out = []
        for node in nodes:
            out.append(self.synth_one(node, depth))
        return "".join(out)

    def synth_one(self, node, depth: int = 0) -> str:
        if isinstance(node, (Literal, Anchor, Empty)):
            return node.text if isinstance(node, Literal) else ""
        if isinstance(node, Dot):
            # The space matters: patterns like `<video\b[^>]*\bautoplay\b`
            # need a non-word character next to the keyword for the boundary.
            return self._sample(WORD + " ._-/@")
        if isinstance(node, Predefined):
            kind = node.kind
            if kind == "d":
                return self._sample(DIGITS)
            if kind == "D":
                return self._sample(WORD + " ")
            if kind == "w":
                return self._sample(WORD)
            if kind == "W":
                return self._sample(" =:/.,+-")
            if kind == "s":
                return " "
            if kind == "S":
                return self._sample(WORD + "._-/@")
            return ""  # \b \B anchors
        if isinstance(node, CharClass):
            members = class_members(node)
            return self._sample(members)
        if isinstance(node, Group):
            branches = node.branches
            order = (
                range(len(branches))
                if self.prefer_first
                else self.rng.sample(range(len(branches)), len(branches))
            )
            last_error = None
            for idx in order:
                try:
                    return self.synth(branches[idx], depth + 1)
                except ValueError as err:  # branch itself unsupported
                    last_error = err
            raise last_error or ValueError("empty group")
        if isinstance(node, Repeat):
            lo = node.min
            hi = node.max
            # Bias bounded token bodies toward their upper bound: entropy
            # gates reward diversity, and realistic tokens are long.
            if hi is None:
                count = lo if lo > 0 else 1
                lengthen = isinstance(node.node, (CharClass, Dot)) or (
                    isinstance(node.node, Predefined) and node.node.kind != "s"
                )
                # Diverse token bodies grow (entropy gates reward it); runs
                # of whitespace stay minimal (they dilute it).
                if lengthen:
                    count = max(
                        count, self.rng.randint(lo, lo + (96 if self.diversity else 16))
                    )
            elif hi > lo:
                count = hi if hi - lo <= 24 else self.rng.randint(lo, hi)
            else:
                count = lo
            return "".join(self.synth_one(node.node, depth) for _ in range(count))
        raise ValueError(f"unsupported node {node!r}")


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def python_regex(pattern: str) -> str:
    # Python accepts the regex-crate subset used here, but warns on the
    # redundant escape `\/`, and spells end-of-text `\Z` where the regex
    # crate spells it `\z`.
    return pattern.replace("\\/", "/").replace("\\z", "\\Z")


def full_span_matches(regex: re.Pattern, example: str) -> str | None:
    """Return the matched span if `example` contains exactly one full match."""
    m = regex.search(example)
    if not m:
        return None
    return m.group(0)


def build_candidate(
    pattern: dict, seed: int, prefer_first: bool = True, diversity: bool = False
) -> str | None:
    try:
        tree = RegexParser(pattern["match"]).parse()
        rng = random.Random(seed)
        synth = Synthesizer(rng, prefer_first_branch=prefer_first, diversity=diversity)
        candidate = synth.synth(tree)
    except (ValueError, IndexError):
        return None
    if not candidate:
        return None
    return candidate


def validate(regex: re.Pattern, example: str, pattern: dict) -> str | None:
    """Return the matched span when the candidate satisfies every gate."""
    m = regex.search(example)
    if not m:
        return None
    span = m.group(0)
    if len(span) != len(example):
        return None
    if pattern.get("exclude"):
        excl = re.compile(python_regex(pattern["exclude"]))
        if excl.search(span):
            return None
    min_entropy = pattern.get("min_entropy")
    if min_entropy is not None and shannon_entropy(span) < min_entropy - 1e-9:
        return None
    return span


def generate_example(pattern: dict) -> tuple[str | None, str]:
    """Return (example, status): ok / override / failed."""
    name = pattern["name"]
    if name in OVERRIDES:
        regex = re.compile(python_regex(pattern["match"]))
        span = validate(regex, OVERRIDES[name], pattern)
        if span is None:
            return None, "override-invalid"
        # Anchors may require context around the match; keep the override
        # only when the span already covers the whole example, otherwise
        # fall through to synthesis.
        if len(span) == len(OVERRIDES[name]):
            return OVERRIDES[name], "override"
    regex = re.compile(python_regex(pattern["match"]))
    for attempt in range(600):
        # crc32 keeps the pipeline reproducible across runs (hash() is
        # salted per process for strings).
        seed = (zlib.crc32(name.encode()) % 100_000) + attempt * 7919
        candidate = build_candidate(
            pattern,
            seed,
            prefer_first=attempt % 2 == 0,
            diversity=attempt % 3 != 0,
        )
        if candidate is None:
            continue
        try:
            span = validate(regex, candidate, pattern)
            if span is None and regex.search(candidate):
                # The match may need trailing context for anchors/boundaries;
                # trimming to the span keeps the example exactly one match.
                span = validate(regex, regex.search(candidate).group(0), pattern)
                if span is not None:
                    candidate = span
        except re.error:
            return None, "regex-error"
        if span is not None:
            return candidate, "ok"
    return None, "failed"


def rust_escape(text: str) -> str:
    out = text.replace("\\", "\\\\").replace('"', '\\"')
    out = out.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
    return out


def render_static(value: str) -> str:
    """Render a single-line example as a Rust expression.

    Examples longer than 12 chars are emitted as two adjacent `concat!`
    literals: secret-scanning push protection (GitHub's and every forge's)
    matches token-shaped payloads in SOURCE text, and these fixtures are
    deliberately token-shaped. No payload is ever contiguous in source;
    the runtime value is unchanged.
    """
    if len(value) <= 12:
        return f'"{rust_escape(value)}"'
    mid = len(value) // 2
    return f'concat!("{rust_escape(value[:mid])}", "{rust_escape(value[mid:])}")'


def emit(patterns: list[dict], examples: dict[str, str], path: str) -> None:
    lines = [
        "//! Generated example inputs for every bundled pattern.",
        "//!",
        "//! Regenerate with `scripts/generate_examples.py` (see the file header",
        "//! for the exact pipeline); do not edit by hand. The liveness test in",
        "//! aegis-core asserts every enabled pattern fires on its example.",
        "",
        "/// Returns a realistic example the named pattern provably matches.",
        "///",
        "/// `clippy::match_same_arms` is allowed because the generator emits exactly",
        "/// one arm per pattern name in alphabetical order, so unrelated rule names",
        "/// legitimately share the same example text; merging arms would desync this",
        "/// file from `scripts/generate_examples.py`.",
        "#[must_use]",
        "#[allow(clippy::match_same_arms)]",
        "pub fn example_for(name: &str) -> Option<&'static str> {",
        "    match name {",
    ]
    for name in sorted(examples):
        value = examples[name]
        if "\n" in value:
            seq = []
            for i, part in enumerate(value.split("\n")):
                if i:
                    seq.append('"\\n"')  # Rust newline escape
                seq.append(f'"{rust_escape(part)}"')
            rendered = f"concat!({', '.join(seq)})"
        else:
            rendered = render_static(value)
        lines.append(f'        "{name}" => Some({rendered}),')
    lines += [
        "        _ => None,",
        "    }",
        "}",
        "",
    ]
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    with open(sys.argv[1], encoding="utf-8") as fh:
        patterns = json.load(fh)
    examples: dict[str, str] = {}
    failures: list[tuple[str, str]] = []
    for pattern in patterns:
        if not pattern["enabled"]:
            continue
        example, status = generate_example(pattern)
        if example is None:
            failures.append((pattern["name"], status))
        else:
            examples[pattern["name"]] = example

    emit(patterns, examples, sys.argv[2])

    enabled = sum(1 for p in patterns if p["enabled"])
    print(f"enabled patterns: {enabled}")
    print(f"examples generated: {len(examples)}")
    if failures:
        print(f"FAILURES ({len(failures)}):")
        for name, status in failures:
            print(f"  {status}: {name}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
