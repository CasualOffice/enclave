#!/usr/bin/env python3
"""Every tracker ID appears exactly once.

`ENC-877`. The rollup gate (`tracker_rollup.py`) recomputes the summary table from the rows and
deduplicates by ID with `§3` winning, so a row that appears twice is invisible to it — and two rows
sharing an ID with *opposite statuses* are invisible while the board asserts both.

Twelve of them accumulated in a single evening, from two causes worth telling apart:

* **Exact duplicates.** Resolving a `TRACKER.md` merge conflict by keeping both sides is right for
  distinct rows and wrong for one row that appears on both. It was applied six times in one night.
  `ENC-579` is the same lesson from the other direction: keeping both sides let the *older* side's
  one-word status cell win, and six completed rows silently reverted.
* **ID collisions.** Parallel sessions allocate the next free number from the copy of the file they
  started with, so two sessions working the same evening reach for the same one. Seven pairs of
  unrelated rows shared an ID this way.

Neither is caught by reading carefully, which is what we were relying on.

Exit 1 on any repeat, naming the lines. `--fix` is deliberately not offered: an exact duplicate
should be deleted and a collision should be renumbered, and a script cannot tell which without
reading the rows.
"""

import collections
import pathlib
import re
import sys

ROW = re.compile(r"^\| (ENC-[0-9]+[a-zA-Z]?) \|(.*?)\|\s*(P[0-3])\s*\|\s*([A-Z]+)\s*\|")


def main() -> int:
    path = pathlib.Path(__file__).resolve().parents[2] / "TRACKER.md"
    if not path.exists():
        print(f"error: {path} not found", file=sys.stderr)
        return 1

    rows = collections.defaultdict(list)
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        match = ROW.match(line)
        if match:
            rows[match.group(1)].append((number, match.group(4), line))

    # The gate's own liveness check. A regex that stopped matching the table would report success
    # while inspecting nothing, which is `ENC-543` -- a gate that printed `pass` for a milestone
    # without ever looking at a foreign key.
    if len(rows) < 100:
        print(
            f"error: only {len(rows)} tracker rows matched; the row pattern no longer fits the "
            "table, so this gate is proving nothing",
            file=sys.stderr,
        )
        return 1

    failures = []
    for identifier, entries in sorted(rows.items()):
        if len(entries) == 1:
            continue
        statuses = {status for _, status, _ in entries}
        identical = len({line for _, _, line in entries}) == 1
        lines = ", ".join(f"L{number}" for number, _, _ in entries)
        if identical:
            kind = "the same row twice -- delete the copy"
        elif len(statuses) > 1:
            kind = (
                f"two rows, contradictory statuses {sorted(statuses)} -- the board asserts both; "
                "decide which is true from the code, not from the table"
            )
        else:
            kind = "two unrelated rows sharing an ID -- renumber the later one"
        failures.append(f"  {identifier} on {lines}: {kind}")

    if failures:
        print(f"{len(failures)} repeated tracker ID(s):\n" + "\n".join(failures), file=sys.stderr)
        print(
            "\nThe rollup gate cannot see this: it deduplicates by ID with §3 winning, so a "
            "duplicate is silently dropped from the count while both rows stay on the board.",
            file=sys.stderr,
        )
        return 1

    print(f"every tracker ID is unique ({len(rows)} rows)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
