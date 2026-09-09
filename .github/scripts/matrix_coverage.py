#!/usr/bin/env python3
"""Check that every leakage-matrix row names a test that exists.

`docs/12-TESTING.md §4` opens with *"each row is at minimum one permanent test"*, and until
`ENC-989` nothing verified that the test named beside a row was real. That is `ENC-543` in a larger
place: `composite_fk_coverage.rs` did not exist, so the gate guarding `CLAUDE.md` rule 4 exited 0
and reported **pass** in green for a whole milestone while three single-column foreign keys sat in
the auth tables. The matrix is 216 rows and cites 100-odd files.

    python3 .github/scripts/matrix_coverage.py

# What it asserts

1. Every file path a row cites exists.
2. Every long identifier a row cites appears somewhere in the tree. Not "is a function" — the
   matrix legitimately names SQL constraints and constants beside tests — but a row citing a token
   that exists nowhere is a row nobody can follow.
3. Every row in `§4.1`-`§4.6` — the set M5's exit criterion names — carries either a citation or an
   explicit `Not testable` note. That convention is `§4.0`'s, written by `ENC-987`'s sweep.
4. The rows carrying that note are **exactly** the ten [`DEFERRED`] names M5's rescoped criterion
   excepts (`ENC-999`). Checked in both directions, so the exception can neither grow silently nor
   outlive the subsystem that caused it.

# Why the citation rule is what it is

A test name here is a sentence: `k5_a_token_epoch_bump_invalidates_every_outstanding_token_for_that_subject`.
A column is not: `tenant_id`. So a backticked identifier is checked when it has at least
[`MIN_UNDERSCORES`] underscores, and what is checked is that it **exists somewhere in the tree** —
not that it is a function.

The weaker assertion is the right one, and the first draft got it wrong. Demanding that every cited
token be a `fn` failed on three correct rows: `Q3` names `storage_quotas_within_budget`, a CHECK
constraint in `migrations/0018`; `A6` names a constant; and rows routinely cite a file for one
property and a test that lives elsewhere. Those are all fine. What is never fine is a row citing
something that exists nowhere at all — which is what this found in `A43`.

# Why this is a script and not a reading

Five findings in this repository's log were wrong because a person — me — inferred a test's absence
from a name that did not match a pattern (`ENC-988`, `ENC-985` §10, `ENC-998`, and the two `§3`
misses `ENC-997` caught). Every one was found by opening a file. This opens the files.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOC = ROOT / "docs" / "12-TESTING.md"

# The sections M5's exit criterion names, and therefore the ones that must be fully resolved.
CRITERION = ("4.1", "4.2", "4.3", "4.4", "4.5", "4.6")

# How many underscores make a backticked identifier worth checking at all. Below this a token is a
# column (`tenant_id`) or a flag, and above it a token is a name somebody chose: a test, a SQL
# constraint, a const. The check is that it **exists somewhere in the tree**, not that it is a test
# — see the module docstring.
MIN_UNDERSCORES = 3

# The note `§4.0` defines for a row whose subsystem does not exist yet.
NOT_TESTABLE = "not testable"

# The ten rows M5's exit criterion excepts, and the milestone that closes each (`ENC-999`).
#
# The criterion used to read "§4.1-4.6 green, zero skips" and was unmeetable: every row below needs
# a subsystem that is a five-line stub scheduled for M6 or M7. The repo owner rescoped it to "green
# except these ten, named individually" — and a named exception is only worth more than a waived one
# while the naming is enforced, which is what this list is for.
#
# It is checked in BOTH directions:
#
#   * a row marked `Not testable` that is NOT here means the exception grew, quietly, and a security
#     criterion got easier without anybody deciding it should;
#   * a row here that is NO LONGER marked `Not testable` means its subsystem landed — remove it from
#     this list and tick the row, because an exception nobody retires is a permanent hole with a
#     milestone written next to it.
DEFERRED: dict[str, str] = {
    "S7": "M7 — enclave-ai is a stub, so there is no RAG path to cite from",
    "S9": "M6 — nothing can set NO_INDEX; classification has no ceiling",
    "S10": "M6 — UnconfiguredBarriers has no segment to exclude",
    "H2": "share redemption — ENC-692/ENC-694, a link's conditions are enforced by nothing",
    "H5": "share redemption — there is no share context to enumerate from",
    "H6": "share redemption — a link's audience is enforced by nothing",
    "D5": "M6 — crates/legal_hold is a stub",
    "D6": "M6 — crates/records is a stub",
    "D7": "M7 — crates/mcp is a stub",
    "D8": "M6 — crates/incidents is a stub",
}

ROW = re.compile(r"^\|\s*\*{0,2}([A-Z]{1,2}\d+)\*{0,2}\s*\|\s*(.+?)\s*\|\s*$")
HEADING = re.compile(r"^### (4\.\d+)")
PATH = re.compile(r"(?:crates|web|\.github)/[A-Za-z0-9_./-]+\.(?:rs|tsx?|py|sql)")
IDENT = re.compile(r"`([a-z][a-z0-9_]*)`")


def fail(message: str) -> None:
    print(f"::error file=docs/12-TESTING.md,title=GATE FAILED: matrix coverage::{message}")


def main() -> int:
    text = DOC.read_text(encoding="utf-8")
    body = text[text.index("## 4. Security leakage matrix") : text.index("## 5. Structural CI gates")]

    rows: list[tuple[str, str, str, int]] = []
    section = ""
    for offset, line in enumerate(body.split("\n")):
        heading = HEADING.match(line)
        if heading:
            section = heading.group(1)
            continue
        match = ROW.match(line)
        if match:
            rows.append((match.group(1), match.group(2), section, offset))

    # A parse that found nothing must fail. This gate's whole subject is assertions that inspected
    # nothing and reported pass.
    if len(rows) < 100:
        fail(f"only {len(rows)} matrix rows parsed out of {DOC.name}; that is a broken parse, not a small matrix")
        return 1

    # Every identifier the tree contains, once. Deliberately **not** limited to `fn` names: the
    # matrix legitimately cites SQL constraints (`storage_quotas_within_budget`, a CHECK in
    # `migrations/0018`) and constants beside test names, and a gate that demanded every cited
    # token be a function would fail on correct rows. What must never happen is a row citing
    # something that exists **nowhere** — which is how this gate found that `A43` named a web test
    # in Rust style, `will_not_confirm_a_rejection_without_a_reason`, when the test is called
    # "will not confirm a rejection without a reason" and no grep for the row's own citation could
    # ever have found it.
    corpus: set[str] = set()
    globs = ("crates/**/*.rs", "migrations/*.sql", "web/src/**/*.ts", "web/src/**/*.tsx",
             "web/tests/**/*.ts", "web/tests/**/*.tsx", ".github/scripts/*.py", "xtask/src/*.rs")
    for pattern in globs:
        for source in ROOT.glob(pattern):
            if "node_modules" in source.parts:
                continue
            corpus.update(re.findall(r"[a-z][a-z0-9_]{6,}", source.read_text(encoding="utf-8")))

    problems: list[str] = []
    cited_rows = 0

    for rid, cell, section, offset in rows:
        paths = PATH.findall(cell)
        names = [n for n in IDENT.findall(cell) if n.count("_") >= MIN_UNDERSCORES]

        for path in paths:
            if not (ROOT / path).exists():
                problems.append(f"{rid} cites {path}, which does not exist")

        for name in names:
            if name not in corpus:
                problems.append(
                    f"{rid} cites `{name}`, which appears nowhere in the tree — so nobody reading "
                    f"this row can find what proves it"
                )

        deferred_here = NOT_TESTABLE in cell.lower()
        if section in CRITERION:
            if deferred_here and rid not in DEFERRED:
                problems.append(
                    f"{rid} is marked `Not testable` and is not in this script's DEFERRED list. M5's "
                    f"criterion excepts ten named rows (`ENC-999`); an eleventh means the exception "
                    f"grew without anybody deciding it should. Add it here with its milestone, or "
                    f"make the row testable."
                )
            if rid in DEFERRED and not deferred_here:
                problems.append(
                    f"{rid} is in the DEFERRED list but is no longer marked `Not testable` — its "
                    f"subsystem has landed. Remove it from `DEFERRED` and tick the row: an exception "
                    f"nobody retires is a permanent hole with a milestone written beside it."
                )

        if paths or names:
            cited_rows += 1
        elif section in CRITERION and not deferred_here:
            problems.append(
                f"{rid} is in §{section} — inside M5's exit criterion — and carries neither a test "
                f"nor a `Not testable` note (§4.0)"
            )

    print(f"matrix coverage: {len(rows)} rows, {cited_rows} citing a test, {len(corpus)} identifiers indexed.")

    if problems:
        for problem in problems:
            fail(problem)
        print(
            f"\nmatrix_coverage: {len(problems)} problem(s).\n"
            "\n"
            "A row in docs/12 §4 must name a test that exists, or — inside §4.1-§4.6 — say\n"
            "`Not testable` with the reason and the milestone. A matrix that cites a test nobody\n"
            "wrote is ENC-543: a gate reporting pass in green having inspected nothing.",
            file=sys.stderr,
        )
        return 1

    print("Every cited test exists, and every row inside M5's criterion is resolved.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
