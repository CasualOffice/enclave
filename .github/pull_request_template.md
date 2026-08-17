<!--
The checklist below is CONTRIBUTING.md "Rules that reviewers will hold you to",
in the order a reviewer reads them. Every line exists because it has, somewhere,
been a real vulnerability in a real system.

Tick what applies. Strike through what does not, WITH A REASON — "n/a" on a line
about tenant isolation is the sentence a reviewer will stop on. An unticked box
is fine and often correct; an unticked box with no explanation is what gets a PR
sent back.
-->

## What and why

<!-- What changed, and the reason it needed to change. The "what" is in the diff;
     the "why" is only ever here. -->

## Tracker

- Item: `ENC-___`
- [ ] The tracker row, the rollup and the log are updated **in this PR**
      (`TRACKER.md §2` — keeping the tracker current is part of the task, not admin afterwards)

## Type of change

- [ ] `feat` · [ ] `fix` · [ ] `docs` · [ ] `refactor` · [ ] `test` · [ ] `perf` · [ ] `build` · [ ] `ci` · [ ] `chore`
- [ ] Breaking change (`!` in the title **and** a `BREAKING CHANGE:` footer)
- [ ] **Security-relevant.** If so, say so here and name the tests that cover it:

## Policy chain

- [ ] Every entry point this PR adds or changes calls `PolicyEngine::enforce`
      (`docs/03-LLD.md §12`) — no hand-rolled ACL check, no fast path around DLP
- [ ] The chain order is unchanged: tenant isolation → auth → conditional access →
      authorization → barriers → classification → DLP → retention → execute → audit
- [ ] Obligations returned by the decision are **satisfied**, not dropped or logged and ignored
- [ ] Preview / download / print / export / sync remain distinct permissions; no preview path
      issues an original object-storage URL
- [ ] Cross-tenant and barrier denials return `404`, never `403`
- [ ] Any handler added to the `enforce` allowlist carries a comment giving the reason

## Tenant isolation and data access

- [ ] Tenant identity comes from the verified token or custom-domain routing — never from a body
      field, query parameter or header
- [ ] All database access goes through the `db` crate's `TenantScoped` wrapper
- [ ] New tenant-scoped tables have `tenant_id` first, RLS **enabled and forced**, a policy in the
      same migration, and composite FKs that include `tenant_id`
- [ ] Search results, if touched, are still confirmed against PostgreSQL — the post-filter is not
      conditional and was not weakened

## Tests

- [ ] Tests exist that **fail without this change**
- [ ] New enforcement point ⇒ a new row in the leakage matrix (`docs/12-TESTING.md §4`) **and** the
      test that proves it. Rows added:
- [ ] Cross-tenant assertions use the seeded `tenant-alpha` / `tenant-beta` fixtures
- [ ] No security test was skipped, `#[ignore]`d or quarantined to get this build green
- [ ] Ignored tests, if any, are infrastructure-bound only — listed here with the reason:

## Handling of sensitive data

- [ ] No secret literals — `vault://` / `env://` references only, in code, config and fixtures
- [ ] Nothing logged or audited contains passwords, tokens, refresh cookies, DLP match values or
      file content
- [ ] Nothing is served before antivirus completes; no read path serves `SCANNING` content

## Documentation

- [ ] Updated in the **authoritative** document, not a convenient nearby one
      (DDL only in `04-DATA-MODEL.md`, endpoint contracts only in `05-API.md`, the crate list only
      in `02-HLD.md`)
- [ ] Version line bumped and a change-log row added, if the change is substantive
- [ ] Cross-references written in the `04-DATA-MODEL.md §7` form

## Frontend (delete if not applicable)

- [ ] User-facing strings go through the i18n catalog; no literals in `web/src`, no manual date or
      number formatting, no physical `left`/`right` CSS
- [ ] Actions render from the server-provided `capabilities` object — permissions are not re-derived
      client side
- [ ] Empty, loading, error and success states all defined; lists that can exceed 100 rows are
      virtualized

## Local gate

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

- [ ] Run, and green, on this branch

## Anything incomplete, deferred or uncertain

<!-- Say it here. A known gap flagged in review costs an hour; found in production it costs a
     weekend. If bending one of the rules above was genuinely required, that is a design
     discussion for an issue — link it rather than resolving it in review. -->
