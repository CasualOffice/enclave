#!/usr/bin/env python3
"""No tracked file carries an unresolved merge-conflict marker.

# Why this gate exists

Twice in one day a conflict marker was committed and pushed. Once into
`docs/12-TESTING.md`'s header, where it sat through several merges because the file is prose and
nobody reads a header. Once into four files at once — including `crates/cli/src/main.rs`, which
stopped the workspace compiling, and `crates/api/tests/reachability.rs`, the very test written to
prove the product is reachable.

Both came from the same habit: resolving a multi-file conflict by taking one side wholesale, then
verifying with a check that answers a *different* question. `python -c "yaml.safe_load(...)"` proves
a workflow parses, not that it still has its steps. `cargo build -p enclave-api` proves one crate
compiles, not that `crates/cli` does. A marker in a `.md` file passes every check this repository
has, because none of them read prose.

So the gate is the cheapest possible thing, and its value is entirely in running on *every* file
rather than the ones a compiler happens to visit.

# Why it looks for the whole marker

`<<<<<<< HEAD` and not `<<<<<<<`: the seven-character form appears in documentation *about*
conflicts, and a gate that fires on a file explaining merge conflicts is a gate people learn to
route around. The full opening marker with its ref is what git writes and what no author types on
purpose.
"""

import subprocess
import sys

# `git grep` rather than a walk: it sees exactly the tracked files, which is the set that can be
# pushed, and it costs nothing on a repository this size.
MARKERS = ("^<<<<<<< ", "^>>>>>>> ", "^=======$")


def main() -> int:
    found: list[str] = []
    for marker in MARKERS:
        result = subprocess.run(
            ["git", "grep", "-n", "-E", marker, "--", "."],
            capture_output=True,
            text=True,
            check=False,
        )
        found.extend(line for line in result.stdout.splitlines() if line.strip())

    # `=======` alone is a false positive in Markdown, where it underlines a setext heading. Only
    # count it when the same file also carries a real opening marker.
    opened = {line.split(":", 1)[0] for line in found if "<<<<<<< " in line}
    real = [line for line in found if "=======" not in line or line.split(":", 1)[0] in opened]

    if not real:
        print("no conflict markers in tracked files")
        return 0

    print("::error title=Unresolved merge-conflict markers::a tracked file carries a conflict marker")
    for line in real:
        print(f"  {line}")
    print(
        "\nThese were committed, which means a merge was resolved and never re-read. Note what "
        "does NOT catch them: `cargo build -p <one-crate>` misses every other crate, a YAML parse "
        "check misses a block that parses but lost its steps, and nothing at all reads prose."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
