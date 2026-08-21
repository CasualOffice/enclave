#!/usr/bin/env python3
"""Structural gate: no database access bypasses `TenantScoped`.

The rule this enforces (CLAUDE.md "all database access through the db crate's TenantScoped
wrapper", docs/12-TESTING.md §5) is about *how a query is executed*, not about which types a
crate is allowed to name. A repository legitimately holds a pool handle in order to hand it to
`TenantScoped::begin`; what it must never do is run a tenant query straight off that pool, because
a pooled connection has no `app.tenant_id` set and therefore no row-level security context.

So this checks two things:

1. No query is executed against a pool. `.fetch_*(&pool)`, `.execute(&self.pool)`,
   `pool.begin()`, `pool.acquire()` — these bypass the wrapper and, under FORCE ROW LEVEL
   SECURITY, either fail or silently return nothing.
2. No compile-time `sqlx::query!` family macros outside the db crate. They bind to a schema at
   build time and encourage handlers to talk to the database directly.
3. No `platform_connection()` outside the db crate. That accessor hands back a connection RLS does
   not apply to; its three legitimate callers all live inside `crates/db`, so keeping the call site
   there keeps one grep a complete list of where tenant isolation is bypassed.

Runtime `sqlx::query(...)` on a caller-supplied `&mut PgConnection` is fine and expected: that is
what a `TenantScoped` transaction derefs to.

Comments and `#[cfg(test)]` modules are excluded. Tests connect to throwaway databases; that is
what tests are for, and a gate that fails on them teaches people to disable the gate.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# Paths exempt from the pool rule, each with the reason it is exempt. Adding to this list is a
# reviewable act: it means "this is one of the platform paths that is cross-tenant by design".
ALLOW: dict[str, str] = {
    "crates/db/": "the wrapper itself — the code the rule funnels everything else into",
    "crates/events/src/publisher.rs": (
        "outbox publisher: drains every tenant's rows and holds the advisory lock, so it cannot "
        "run inside one tenant's transaction (plans/M0-FOUNDATIONS.md ENC-108)"
    ),
}

# Executing a statement against a pool rather than a scoped connection.
POOL_EXEC = re.compile(
    r"""\.(?:fetch_all|fetch_one|fetch_optional|fetch|execute|execute_many)\s*\(\s*&\s*(?:self\.|mut\s+)?\w*pool\w*\s*\)"""
    r"""|(?:self\.)?\w*pool\w*\.(?:begin|acquire)\s*\(\s*\)""",
    re.IGNORECASE,
)

# Compile-time macros — the `!` is the whole point.
QUERY_MACRO = re.compile(r"\bsqlx::query(?:_as|_scalar|_file|_file_as|_file_scalar)?!")

# Checking out the BYPASSRLS connection. `DbPool::platform_connection`'s own documentation says it
# "is on the deny-list of the ENC-110 routing lint" — it was not, until ENC-548 wrote the first real
# caller and went looking for the gate that was supposed to be guarding it.
#
# The rule is *outside crates/db*, not "nowhere": the three legitimate callers (migration runner,
# outbox publisher, tenant enumerator) are written inside the crate that owns the hatch, so the
# accessor has no caller anywhere else. That is a stronger and much cheaper property to check than
# per-caller review, and it is the one that keeps `grep -rn platform_connection crates/` a complete
# list of the places row-level security is bypassed.
#
# A fourth caller is a design decision, and the way to make it is to move the query into
# `crates/db` beside the other three — where its `WHERE` clause is reviewed once and cannot drift —
# rather than to add a path here.
PLATFORM_CONNECTION = re.compile(r"\.platform_connection\s*\(")


def strip_comments(src: str) -> str:
    """Blank out comments, preserving line numbering and string literals."""
    out, i, n = [], 0, len(src)
    while i < n:
        ch = src[i]
        if ch == '"':
            out.append(ch)
            i += 1
            while i < n:
                out.append(src[i])
                if src[i] == "\\":
                    i += 1
                    if i < n:
                        out.append(src[i])
                        i += 1
                    continue
                if src[i] == '"':
                    i += 1
                    break
                i += 1
            continue
        if src.startswith("//", i):
            while i < n and src[i] != "\n":
                out.append(" ")
                i += 1
            continue
        if src.startswith("/*", i):
            depth = 1
            out.append("  ")
            i += 2
            while i < n and depth:
                if src.startswith("/*", i):
                    depth += 1
                    out.append("  ")
                    i += 2
                elif src.startswith("*/", i):
                    depth -= 1
                    out.append("  ")
                    i += 2
                else:
                    out.append("\n" if src[i] == "\n" else " ")
                    i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def strip_test_modules(src: str) -> str:
    """Blank out `#[cfg(test)] mod ... { ... }` blocks by brace matching."""
    out = list(src)
    for m in re.finditer(r"#\[cfg\(test\)\]", src):
        brace = src.find("{", m.end())
        if brace == -1:
            continue
        # Only a module or block directly following the attribute.
        if not re.fullmatch(r"[\s\w()=,\"]*", src[m.end() : brace]):
            continue
        depth, i = 0, brace
        while i < len(src):
            if src[i] == "{":
                depth += 1
            elif src[i] == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        for j in range(m.start(), min(i + 1, len(src))):
            if out[j] != "\n":
                out[j] = " "
    return "".join(out)


def exempt(rel: str) -> bool:
    return any(rel == a or rel.startswith(a) for a in ALLOW)


def main() -> int:
    root = Path(__file__).resolve().parents[2]
    findings: list[tuple[str, int, str, str]] = []

    for path in sorted((root / "crates").rglob("*.rs")):
        rel = path.relative_to(root).as_posix()
        if exempt(rel):
            continue
        cleaned = strip_test_modules(strip_comments(path.read_text(encoding="utf-8")))
        for lineno, line in enumerate(cleaned.splitlines(), start=1):
            if POOL_EXEC.search(line):
                findings.append((rel, lineno, line.strip(), "query executed against a pool"))
            if QUERY_MACRO.search(line):
                findings.append((rel, lineno, line.strip(), "compile-time sqlx::query! macro"))
            if PLATFORM_CONNECTION.search(line):
                findings.append(
                    (rel, lineno, line.strip(), "BYPASSRLS connection checked out outside crates/db")
                )

    if not findings:
        print("OK — no query bypasses TenantScoped.")
        return 0

    print("GATE FAILED — database access bypasses TenantScoped:\n")
    for rel, lineno, text, why in findings:
        print(f"  {rel}:{lineno}: {why}\n      {text}")
        print(
            f"::error file={rel},line={lineno},title=GATE FAILED: no raw pool::"
            f"{why}. Open a TenantScoped transaction and run the query on that, so RLS has a "
            f"tenant. If this is genuinely a cross-tenant platform path, write the query in "
            f"crates/db beside the other three (see enclave_db::active_tenants) rather than "
            f"adding a path to ALLOW in .github/scripts/no_raw_pool.py."
        )
    print(f"\n{len(findings)} finding(s).")
    return 1


if __name__ == "__main__":
    sys.exit(main())
