#!/usr/bin/env python3
"""Check that CI's test shards partition the workspace exactly.

`ENC-1000`. `.github/workflows/ci.yml` runs the workspace tests in shards: some name their crates
with `-p`, and one is defined by subtraction — `--workspace` minus an `--exclude` list — so that a
newly added crate lands somewhere without anybody deciding. That only holds while the two lists
agree, and nothing checked that they did.

    python3 .github/scripts/shard_partition.py

# The two failure modes are not equally bad

A crate named in a shard **and** missing from the subtraction shard's exclusions runs **twice**.
That wastes a runner and is visible in the logs.

A crate excluded from the subtraction shard and named in **no** shard runs **nowhere**. Its tests
report nothing, and CI stays green — the `ENC-543` shape, where an assertion that inspected nothing
printed pass. That is the one this gate exists for.

# Why it reads `Cargo.toml` rather than asking cargo

`cargo metadata` is the obvious source and needs a toolchain and a resolved dependency graph. The
static-gates job has neither, and adding them to answer *which directories are workspace members*
would be a minute of setup per run for a question the manifest answers directly. The members list is
explicit paths, not globs, so there is nothing to expand.

# This check has been done by hand twice and got it wrong twice, in the same way

`bc4d8dc` verified the partition against `cargo metadata` — *forty-seven crates, forty-seven
covered* — and `ENC-980` verified it again after merging two shards.

The ad-hoc version written for `ENC-980` **reported four covered crates as uncovered**, because the
`services` shard writes its `args:` on one line where the others use a folded block scalar and the
parser only handled the folded form.

The first run of *this* script then **reported `enclave-sync` as running twice**, because the block
slice ends before `runs-on:` and the final `--exclude` line therefore has no trailing newline, which
a line-oriented regex drops.

Both were the parser silently discarding input and then answering confidently — the failure mode a
partition check can least afford, since a dropped `--exclude` reads as *runs twice* and a dropped
`-p` reads as *runs nowhere*. Neither raised an error. So [`parse_is_complete`] counts the same
tokens a second way, with no structure in it, and a disagreement fails the gate as broken rather
than reporting on the workflow.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CI = ROOT / ".github" / "workflows" / "ci.yml"
MANIFEST = ROOT / "Cargo.toml"


def workspace_members() -> set[str]:
    """Package names, read from each member manifest rather than assumed from its directory."""
    text = MANIFEST.read_text(encoding="utf-8")
    block = re.search(r"^members\s*=\s*\[(.*?)\]", text, re.S | re.M)
    if not block:
        return set()
    names = set()
    for path in re.findall(r'"([^"]+)"', block.group(1)):
        manifest = ROOT / path / "Cargo.toml"
        if not manifest.exists():
            print(f"::error file=Cargo.toml::workspace member {path} has no Cargo.toml")
            continue
        found = re.search(r'^\s*name\s*=\s*"([^"]+)"', manifest.read_text(encoding="utf-8"), re.M)
        if found:
            names.add(found.group(1))
    return names


def shards() -> dict[str, str]:
    """Each shard's `args`, whether written on one line or as a folded block.

    Handling only the folded form is the bug `ENC-980`'s ad-hoc check shipped: `services` writes its
    args inline and the parser silently returned nothing for it, which read as four uncovered
    crates.
    """
    text = CI.read_text(encoding="utf-8")
    start = text.find("        shard:")
    if start < 0:
        return {}
    end = text.find("\n    runs-on:", start)
    # The trailing newline matters: the slice ends *before* `runs-on`, so the final `--exclude`
    # line has no `\n` and a line-oriented regex silently drops it. That cost the first run of this
    # gate a false "enclave-sync runs twice", which is the same class of off-by-one-line bug as the
    # inline-`args` case above. `parse_is_complete` below is the belt to this brace.
    block = text[start : end if end > 0 else len(text)] + "\n"

    out: dict[str, str] = {}
    for chunk in re.split(r"\n\s*- name: ", block)[1:]:
        name, _, rest = chunk.partition("\n")
        name = name.strip()
        inline = re.match(r"\s*args:\s*(?!>)(\S.*)", rest)
        if inline:
            out[name] = inline.group(1)
            continue
        folded = re.search(r"\s*args:\s*>-\n((?:\s{14,}.*\n)+)", rest)
        out[name] = folded.group(1) if folded else ""
    return out


def parse_is_complete(parsed: dict[str, str]) -> str | None:
    """Cross-check the structured parse against a flat count of the same block.

    Both bugs this gate has had were the parser *silently dropping* entries — one shard whose
    `args` were inline, and one `--exclude` on the last line. Neither produced an error; both
    produced a confident wrong answer, which is exactly what a partition check must never do. So
    the totals are counted a second way, by a method with no structure in it, and disagreement is a
    failure of the gate rather than of the workflow.
    """
    text = CI.read_text(encoding="utf-8")
    start = text.find("        shard:")
    end = text.find("\n    runs-on:", start)
    block = text[start : end if end > 0 else len(text)] + "\n"

    for token, pattern in (("-p", r"-p (\S+)"), ("--exclude", r"--exclude (\S+)")):
        flat = len(re.findall(pattern, block))
        structured = sum(len(re.findall(pattern, a)) for a in parsed.values())
        if flat != structured:
            return (
                f"the shard matrix contains {flat} `{token}` entries and this script's parse "
                f"found {structured}. The parse is dropping entries, so its verdict cannot be "
                f"trusted in either direction."
            )
    return None


def main() -> int:
    members = workspace_members()
    parsed = shards()

    incomplete = parse_is_complete(parsed)
    if incomplete:
        print(f"::error file=.github/scripts/shard_partition.py,title=GATE BROKEN: shard partition::{incomplete}")
        return 1

    if len(members) < 10 or len(parsed) < 2:
        print(
            f"::error::shard_partition parsed {len(members)} workspace member(s) and "
            f"{len(parsed)} shard(s). That is a broken parse, not a small workspace — and a gate "
            f"that inspects nothing and reports pass is the failure this one exists to prevent."
        )
        return 1

    named: dict[str, set[str]] = {n: set(re.findall(r"-p (\S+)", a)) for n, a in parsed.items()}
    excludes: dict[str, set[str]] = {
        n: set(re.findall(r"--exclude (\S+)", a)) for n, a in parsed.items()
    }
    subtraction = [n for n, a in parsed.items() if "--workspace" in a]

    problems: list[str] = []

    if len(subtraction) != 1:
        problems.append(
            f"expected exactly one subtraction shard using `--workspace`, found {subtraction or 'none'}. "
            "That shard is what makes a newly added crate tested by default; without it, adding a "
            "crate and forgetting the matrix means its tests never run."
        )
        rest = ""
    else:
        rest = subtraction[0]

    explicit: set[str] = set()
    for name, crates in named.items():
        if name == rest:
            continue
        explicit |= crates

    for name, crates in named.items():
        for crate in crates:
            if crate not in members:
                problems.append(f"shard `{name}` names `{crate}`, which is not a workspace member")
    for crate in excludes.get(rest, set()):
        if crate not in members:
            problems.append(f"shard `{rest}` excludes `{crate}`, which is not a workspace member")

    if rest:
        twice = explicit - excludes[rest]
        nowhere = excludes[rest] - explicit
        for crate in sorted(twice):
            problems.append(
                f"`{crate}` is named in a shard and not excluded from `{rest}`, so its tests run "
                f"twice — a wasted runner"
            )
        for crate in sorted(nowhere):
            problems.append(
                f"`{crate}` is excluded from `{rest}` and named in no shard, so **its tests run "
                f"nowhere** and CI stays green regardless of what they would have said"
            )
        covered = explicit | (members - excludes[rest])
        for crate in sorted(members - covered):
            problems.append(f"`{crate}` is covered by no shard at all")

    print(
        f"shard partition: {len(members)} workspace crates, {len(parsed)} shards "
        f"({', '.join(f'{n}={len(named[n])}' for n in parsed)}), subtraction shard `{rest}`."
    )

    if problems:
        for problem in problems:
            print(f"::error file=.github/workflows/ci.yml,title=GATE FAILED: shard partition::{problem}")
        print(
            f"\nshard_partition: {len(problems)} problem(s).\n"
            "\n"
            "The shard matrix and the `--exclude` list have to be edited together: the excludes\n"
            "name the crates that run elsewhere, so every crate named in a shard must appear in\n"
            "them, and nothing else may.",
            file=sys.stderr,
        )
        return 1

    print("Every crate is tested by exactly one shard.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
