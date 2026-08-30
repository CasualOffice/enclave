#!/usr/bin/env python3
"""Every workflow is a shape GitHub will actually run.

A workflow file that GitHub refuses to parse does not fail loudly. It fails as a red tick
with **zero jobs and no log** — `gh run view --log-failed` answers *"log not found"* — and
the natural reading of that is "something flaked", not "every gate in this file has been
off since the merge that broke it".

That is what happened on 2026-08-30. `ENC-974` merged eight jobs into one and, in doing so,
dropped a `- uses: actions/checkout@v7` line while keeping the `with:` block beneath it. The
orphaned `with:` attached itself to the preceding `run` step, which is a shape GitHub
rejects — so `structural-gates.yml` stopped running entirely, and thirteen gates including
the secrets scan and the RLS coverage check were silently absent from `main`.

**PyYAML parsed that file happily**, which is the point of this gate. A YAML parser answers
"is this YAML"; GitHub asks "is this a workflow". The four rules below are the gap between
those questions that a mechanical edit is most likely to fall into:

1. **A step has exactly one of `run` or `uses`.** Neither is a step that does nothing;
   both is the shape that broke `main`.
2. **`with:` belongs only to a `uses:` step.** This is the same failure seen from the other
   side, and it is the one an editor introduces by deleting a line rather than a block.
3. **Every `needs:` names a job that exists.** Renaming or merging a job and leaving the
   aggregator pointing at the old name invalidates the whole workflow — and the aggregator
   is usually the required check, so the failure lands on everybody.
4. **Step `id`s are unique within a job.** Merging jobs merges their steps, and two steps
   sharing an id makes `steps.<id>.outcome` ambiguous.

`actionlint` catches all of this and more, and is the better tool where it is available.
This exists because it needs nothing installed: it runs in the same job as the other static
gates, on a runner with Python and nothing else.
"""

from __future__ import annotations

import pathlib
import sys

import yaml

WORKFLOWS = pathlib.Path(".github/workflows")

problems: list[str] = []


def check(path: pathlib.Path) -> None:
    try:
        doc = yaml.safe_load(path.read_text())
    except yaml.YAMLError as error:
        problems.append(f"{path.name}: not valid YAML at all — {error}")
        return
    if not isinstance(doc, dict):
        problems.append(f"{path.name}: the file is not a mapping")
        return

    jobs = doc.get("jobs")
    if not isinstance(jobs, dict):
        problems.append(f"{path.name}: has no `jobs:` mapping")
        return

    for job, spec in jobs.items():
        if not isinstance(spec, dict):
            problems.append(f"{path.name}: job '{job}' is not a mapping")
            continue

        # Rule 3 — a `needs:` that names nothing invalidates the workflow.
        needs = spec.get("needs")
        if isinstance(needs, str):
            needs = [needs]
        for dependency in needs or []:
            if dependency not in jobs:
                problems.append(
                    f"{path.name}: job '{job}' needs '{dependency}', which is not a job in "
                    f"this workflow. GitHub refuses the whole file, so every job in it stops "
                    f"running."
                )

        seen_ids: set[str] = set()
        for index, step in enumerate(spec.get("steps") or []):
            if not isinstance(step, dict):
                problems.append(f"{path.name}: job '{job}' step {index} is not a mapping")
                continue
            where = f"{path.name}: job '{job}' step {index} ({step.get('name', 'unnamed')!r})"

            # Rule 1 — exactly one of `run` or `uses`.
            has_run, has_uses = "run" in step, "uses" in step
            if has_run and has_uses:
                problems.append(f"{where} has both `run` and `uses`.")
            elif not has_run and not has_uses:
                problems.append(f"{where} has neither `run` nor `uses`, so it does nothing.")

            # Rule 2 — `with:` is for `uses:` steps.
            if "with" in step and not has_uses:
                problems.append(
                    f"{where} carries a `with:` block and no `uses:`. This is the shape a "
                    f"deleted `- uses:` line leaves behind, and it stopped every gate in "
                    f"structural-gates.yml on 2026-08-30 (ENC-975)."
                )

            # Rule 4 — ids are unique within a job.
            step_id = step.get("id")
            if step_id is not None:
                if step_id in seen_ids:
                    problems.append(
                        f"{where} reuses the step id '{step_id}', which makes "
                        f"`steps.{step_id}.outcome` ambiguous."
                    )
                seen_ids.add(str(step_id))


for workflow in sorted(WORKFLOWS.glob("*.yml")):
    check(workflow)

if problems:
    for problem in problems:
        name = problem.split(":", 1)[0]
        print(
            f"::error file=.github/workflows/{name},title=GATE FAILED: workflow shape::{problem}"
        )
    print(
        f"\n{len(problems)} problem(s). A workflow GitHub cannot parse reports no jobs and no "
        f"log, so the gates inside it are off and nothing says so."
    )
    sys.exit(1)

total = len(list(WORKFLOWS.glob("*.yml")))
print(f"every workflow is a shape GitHub will run ({total} files).")
