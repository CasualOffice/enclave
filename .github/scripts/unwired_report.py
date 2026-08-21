#!/usr/bin/env python3
"""Report public functions whose only callers are tests.

A **report, not a gate.** Most of what it lists is legitimate: a repository method whose
endpoint has not been built yet is unwired on purpose, and `crates/api` currently serves
six surfaces, so most domain crates have no caller by design. Failing a build on that
would be failing it on the project's own phasing.

What it is for is the *other* kind, which cost this project four separate incidents in one
session:

  * `composite_fk_coverage.rs` did not exist, so the gate guarding `CLAUDE.md` rule 4
    exited 0 and reported **pass** in green for a milestone (`ENC-543`) — while three
    single-column foreign keys sat in the auth tables.
  * `render_prometheus()` produced an exposition nothing served, so the metrics read as
    zero forever and no alert could fire (`ENC-521`).
  * `index_pass`, `sweep`, `probe_pass` and the epoch reconciler each had exactly one
    caller and it was its own test — the worker binary was a `println!` (`ENC-548`).
  * `platform_connection` documented itself as covered by a lint that did not exist, and
    nobody noticed because it had zero callers (`ENC-564`).

The difference is not "unwired" versus "wired". It is **visibly** unwired versus
**invisibly** unwired. A repository method with no endpoint is obvious to everyone. Those
four had something asserting they were connected — a green check, an alert rule, a doc
comment — so the absence read as presence.

So the value here is the diff over time. A name appearing in this list *after* something
started claiming it was reachable is the signal. Run it when wiring a milestone:

    python3 .github/scripts/unwired_report.py
"""

import re, subprocess, pathlib, collections

# Public async/sync fns declared in crate sources.
decls = collections.defaultdict(list)
for p in pathlib.Path('crates').rglob('src/**/*.rs'):
    for m in re.finditer(r'^\s*pub (?:async )?fn ([a-z_][a-z0-9_]*)', p.read_text(), re.M):
        decls[m.group(1)].append(str(p))

skip = re.compile(r'^(new|default|from|into|as_|is_|len|fmt|clone|drop|next|poll|to_|get|id|name|kind|status|build|with_|try_)')
report = []
for fn, where in sorted(decls.items()):
    if skip.match(fn) or len(fn) < 6:
        continue
    hits = subprocess.run(['grep','-rn','--include=*.rs',f'{fn}(', 'crates/'],
                          capture_output=True, text=True).stdout.splitlines()
    prod, test = 0, 0
    for h in hits:
        f = h.split(':', 1)[0]
        if re.search(r'^\s*(pub )?(async )?fn ' + fn, h.split(':', 2)[-1]):
            continue                      # the declaration itself
        if '/tests/' in f or 'mod tests' in h or f.endswith('_test.rs'):
            test += 1
        else:
            prod += 1
    if test > 0 and prod == 0:
        report.append((fn, where[0], test))

print(f"public functions whose only callers are tests: {len(report)}\n")
for fn, where, n in report[:40]:
    print(f"  {fn:<38} {where.replace('crates/','')}   ({n} test refs)")
