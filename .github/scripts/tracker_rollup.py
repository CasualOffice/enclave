#!/usr/bin/env python3
"""Check that TRACKER.md's rollup agrees with its rows.

`TRACKER.md §5` says the table is "derived from the rows themselves, not maintained by hand". It
was not: it is edited by hand alongside the rows, and it has drifted three times — once reading
"Phase 1: 0 done" while twenty-four of its rows were merged, once nine rows behind, and once by six
P1s because increments were applied to an already-stale base.

Each time it was found by someone reading carefully, which is not a control. This is the control.

The rule it enforces is the one `CLAUDE.md` already states: update the row, the rollup and the log
in the same edit. A rollup nobody can trust is worse than no rollup, because a planning decision
gets made from it.

    python3 .github/scripts/tracker_rollup.py           # check, exit 1 on drift
    python3 .github/scripts/tracker_rollup.py --fix     # rewrite the table in place
"""

from __future__ import annotations

import collections
import re
import sys
from pathlib import Path

TRACKER = Path(__file__).resolve().parents[2] / "TRACKER.md"

# `| ENC-123 | title | P1 | DONE | notes |`
ROW = re.compile(r"\|\s*(ENC-[0-9a-z]+)\s*\|([^|]*)\|\s*(P[0-3])\s*\|\s*([A-Z]+)\s*\|")

PHASES = [
    ("D", "D — Specification"),
    ("0", "0 — Foundations"),
    ("1", "1 — MVP"),
    ("2", "2 — Enterprise V1"),
    ("3", "3 — Beyond V1"),
]

# §2.3: a row that appears only in §3 belongs to the phase in flight when it was raised.
PHASE_0_BELOW = 119


def collect(text: str) -> dict[str, list[str]]:
    """Every ENC row, deduplicated by id with §3 winning — it is the fresher of the two."""
    rows: dict[str, list[str]] = {}
    section_phase: str | None = None
    in_phase_trackers = False

    for line in text.split("\n"):
        if line.startswith("## 4. Phase trackers"):
            in_phase_trackers = True
        elif line.startswith("## 5. Rollup"):
            in_phase_trackers = False
        if in_phase_trackers and line.startswith("### Phase "):
            match = re.match(r"### Phase ([D0-9]+)", line)
            if match:
                section_phase = match.group(1)

        match = ROW.match(line)
        if not match:
            continue
        ident, _title, priority, status = match.groups()
        if ident in rows:
            # §3 comes first in the file and wins; a §4 restatement does not overwrite it.
            continue
        rows[ident] = [section_phase if in_phase_trackers else "", priority, status]

    for ident, row in rows.items():
        if not row[0]:
            digits = re.sub(r"[^0-9]", "", ident)
            number = int(digits) if digits else 0
            row[0] = "0" if number < PHASE_0_BELOW else "1"
    return rows


def table(rows: dict[str, list[str]]) -> list[str]:
    out = ["| Phase | P0 | P1 | P2 | P3 | Done | Open |", "|---|---|---|---|---|---|---|"]
    totals: collections.Counter[str] = collections.Counter()

    for key, name in PHASES:
        members = [r for r in rows.values() if r[0] == key]
        counts = collections.Counter(r[1] for r in members)
        done = sum(1 for r in members if r[2] == "DONE")
        out.append(
            f"| {name} | {counts['P0']} | {counts['P1']} | {counts['P2']} | {counts['P3']} "
            f"| {done} | {len(members) - done} |"
        )
        for level in ("P0", "P1", "P2", "P3"):
            totals[level] += counts[level]
        totals["done"] += done
        totals["open"] += len(members) - done

    out.append(
        f"| **Total** | **{totals['P0']}** | **{totals['P1']}** | **{totals['P2']}** "
        f"| **{totals['P3']}** | **{totals['done']}** | **{totals['open']}** |"
    )
    return out


def main() -> int:
    text = TRACKER.read_text(encoding="utf-8")
    lines = text.split("\n")
    expected = table(collect(text))

    try:
        start = next(i for i, l in enumerate(lines) if l.startswith("| Phase | P0 |"))
    except StopIteration:
        print("::error title=Tracker rollup::TRACKER.md §5 has no rollup table to check")
        return 1
    end = start
    while end < len(lines) and lines[end].startswith("|"):
        end += 1
    actual = lines[start:end]

    if actual == expected:
        print(f"OK — the rollup matches its rows ({len(collect(text))} rows).")
        return 0

    if "--fix" in sys.argv:
        TRACKER.write_text("\n".join(lines[:start] + expected + lines[end:]), encoding="utf-8")
        print("Rewrote TRACKER.md §5 from the rows.")
        return 0

    print(
        "::error title=Tracker rollup disagrees with its rows::"
        "TRACKER.md §5 was not updated in the same edit as the rows it counts "
        "(CLAUDE.md: the tracker being current is part of the task). "
        "Run `python3 .github/scripts/tracker_rollup.py --fix`."
    )
    print("\n--- the table says ---")
    print("\n".join(actual))
    print("\n--- the rows say ---")
    print("\n".join(expected))
    return 1


if __name__ == "__main__":
    sys.exit(main())
