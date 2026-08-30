#!/usr/bin/env python3
"""Every workflow job declares `timeout-minutes`.

A job without one inherits GitHub's default of **360 minutes**. That is not a theoretical
limit: on 2026-08-29 the queue on this repository reached twenty-three runs deep while a
single job held the only slot the free-tier organisation was dispatching, and nothing in
the tree bounded how long it could hold it. Twenty-eight jobs, zero timeouts.

The failure mode is worth naming precisely, because it does not look like a CI problem.
A hung job never reports failure — it reports *nothing*, for six hours. Required checks
stay pending, the merge box stays grey, and the natural reading of a grey merge box is
"CI is slow today" rather than "one job wedged at 02:14 and every commit since is
untested". A timeout converts that silence into a red tick with a job name attached,
which is the difference between a defect somebody fixes and a defect somebody waits out.

This gate is deliberately structural rather than a review habit: the cost of a missing
timeout is paid by whoever pushes next, not by whoever omitted it.

It also enforces a **ceiling**. A timeout of ninety minutes bounds nothing anybody cares
about: it stops the six-hour case and permits an hour and a half of one runner held by a
job nobody is watching. On 2026-08-30 this repository's 29-job-per-push workflows starved
every other repository in the organisation for an afternoon (`ENC-974`), and the jobs at
the top of that queue were the ones allowed 45 and 90 minutes.

Thirty minutes is the ceiling, and it is a design constraint rather than a limit to raise
when something bumps it: a job that cannot finish in half an hour is a job to split, cache
or narrow. Raising the number is how a repository arrives back at ninety.
"""

from __future__ import annotations

import pathlib
import re
import sys

WORKFLOWS = pathlib.Path(".github/workflows")

# A job key sits at exactly two spaces of indentation under `jobs:`; `runs-on` and
# `timeout-minutes` sit at four. Parsed with a regex rather than a YAML library so the gate
# has no dependency to install — it runs in seconds on a runner with nothing set up.
JOB = re.compile(r"^  ([a-z0-9_-]+):\s*$")
KEY = re.compile(r"^    ([a-z0-9_-]+):")

#: No job may hold a runner longer than this. See the module docstring.
CEILING_MINUTES = 30

missing: list[tuple[str, str]] = []
over: list[tuple[str, str, int]] = []

for path in sorted(WORKFLOWS.glob("*.yml")):
    lines = path.read_text().splitlines()
    try:
        start = next(i for i, l in enumerate(lines) if l.rstrip() == "jobs:")
    except StopIteration:
        continue  # a workflow with no jobs is not this gate's business

    job: str | None = None
    seen: set[str] = set()
    for line in lines[start + 1 :]:
        m = JOB.match(line)
        if m:
            if job is not None and "timeout-minutes" not in seen:
                missing.append((path.name, job))
            job, seen = m.group(1), set()
            continue
        k = KEY.match(line)
        if k and job is not None:
            seen.add(k.group(1))
            if k.group(1) == "timeout-minutes":
                value = line.split(":", 1)[1].strip()
                if value.isdigit() and int(value) > CEILING_MINUTES:
                    over.append((path.name, job, int(value)))
    if job is not None and "timeout-minutes" not in seen:
        missing.append((path.name, job))

if over:
    for wf, job, value in over:
        print(
            f"::error file=.github/workflows/{wf},title=GATE FAILED: workflow timeouts::"
            f"job '{job}' allows {value} minutes, over the {CEILING_MINUTES}-minute ceiling. "
            f"A job that cannot finish in half an hour is one to split, cache or narrow — "
            f"raising the number is how a repository arrives back at ninety (ENC-974)."
        )
    print(
        f"\n{len(over)} job(s) over the {CEILING_MINUTES}-minute ceiling."
    )
    sys.exit(1)

if missing:
    for wf, job in missing:
        print(
            f"::error file=.github/workflows/{wf},title=GATE FAILED: workflow timeouts::"
            f"job '{job}' declares no timeout-minutes, so it inherits GitHub's 360-minute "
            f"default and can hold a runner slot for six hours without reporting anything."
        )
    print(
        f"\n{len(missing)} job(s) without a timeout. Add `timeout-minutes:` beside `runs-on:`, "
        f"sized from what the job actually takes plus headroom for a cold cache."
    )
    sys.exit(1)

total = sum(
    1
    for p in WORKFLOWS.glob("*.yml")
    for l in p.read_text().splitlines()
    if l.strip().startswith("timeout-minutes:")
)
print(
    f"every workflow job declares a timeout, none over {CEILING_MINUTES} minutes ({total} jobs)."
)
