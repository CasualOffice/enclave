# Implementation plans

> Enclave · Casual Office

One plan per milestone. Each turns a milestone from [`ROADMAP.md`](../ROADMAP.md) into task-level
work: the design decisions that must be locked, the files touched, the acceptance criteria per task,
and the order.

| Plan | Milestone | Status |
|---|---|---|
| [`M0-FOUNDATIONS.md`](M0-FOUNDATIONS.md) | M0 — Foundations (Phase 0) | Complete |
| [`G0-GATE.md`](G0-GATE.md) | Gate G0 — foundations assessment | Held, PASS |
| [`M1-CONTENT-CORE.md`](M1-CONTENT-CORE.md) | M1 — Content core (Phase 1) | Complete |
| [`M2-ACCESS-DELIVERY.md`](M2-ACCESS-DELIVERY.md) | M2 — Access & delivery (Phase 1) | Complete |
| [`M2-CLOSEOUT.md`](M2-CLOSEOUT.md) | M2 — what it cost and what it taught | Written |
| [`M3-DISCOVERY.md`](M3-DISCOVERY.md) | M3 — Discovery (Phase 1) | Active |
| — | M4 … M10 | Written at the start of each milestone |

## Why plans are written one milestone ahead, not all at once

A task-level plan for M7 written today would be fiction. It would assume the shape of code that does
not exist, and it would be obsolete by the time anyone read it — but it would still look
authoritative, which is worse than having no plan at all.

[`ROADMAP.md`](../ROADMAP.md) commits to *what each milestone must satisfy to be called complete*, for
every milestone, now. That is the part that can be decided in advance and should not drift. The
task-level decomposition is written when the milestone starts, informed by what the previous one
actually taught us — and the roadmap says plainly that confidence beyond M5 is low.

## Plan structure

Every plan carries the same sections, so they are comparable and reviewable:

1. **Objective and exit criteria** — lifted verbatim from the roadmap; the plan may not weaken them.
2. **Design decisions to lock** — the choices that are expensive to reverse later, decided up front
   with the reasoning recorded.
3. **Task breakdown** — one entry per tracker ID: scope, files, design notes, acceptance, tests.
4. **Sequencing** — week by week, showing what the critical path is and what runs alongside it.
5. **Definition of done** — the gate for the milestone.
6. **Open questions** — what is genuinely undecided, and who decides it.

## Rules

- A plan never introduces scope that is not in [`TRACKER.md`](../TRACKER.md). If planning reveals new
  work, it gets a tracker row first.
- A plan never weakens a roadmap exit criterion. If a criterion turns out to be wrong, it is changed
  in the roadmap, deliberately and visibly.
- Design decisions recorded here that change the specification are also written back into `docs/` —
  the plan is not a parallel source of truth.
