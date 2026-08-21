-- Three foreign keys in the auth tables did not carry `tenant_id`. This adds it.
--
-- Found by `crates/db/tests/composite_fk_coverage.rs` on its first run (`ENC-543`), which is the
-- point of the row: the gate enforcing `CLAUDE.md` rule 4 had never executed, because the workflow
-- guarded its assertion on that file existing and the file did not. CI reported it as **pass**.
--
-- The three:
--
--   user_credentials(user_id)  -> users(id)
--   user_mfa_methods(user_id)  -> users(id)
--   refresh_tokens(parent_id)  -> refresh_tokens(id)
--
-- All three are from `0001_foundations.sql`. The `UNIQUE (tenant_id, id)` convention that makes a
-- composite key expressible arrives in `0005_files.sql`, so these predate it rather than having
-- ignored it — which is exactly the class of drift a gate catches and review does not.
--
-- # Why this is a real hole and not a tidiness fix
--
-- `docs/04-DATA-MODEL.md §3.3`, and the reason is specific: **PostgreSQL performs referential
-- integrity checks with row security deliberately not enforced.** The key's own lookup therefore
-- sees every tenant's rows, so `REFERENCES users (id)` accepts a `user_id` belonging to another
-- tenant. Both rows are individually well-formed and RLS refuses neither.
--
-- Concretely, before this migration:
--
--   * a `user_credentials` row — the password hash, the lockout counter — could be attached to
--     another tenant's user;
--   * a `user_mfa_methods` row — a TOTP secret reference, a WebAuthn public key — likewise;
--   * a refresh token could name a parent in another tenant's token family, and reuse detection
--     walks that chain.
--
-- Nothing is known to have written such a row: every write goes through `TenantScoped`, which sets
-- `app.tenant_id`, and RLS then constrains what the *statement* can see. The hole is that the
-- database would have accepted one — from a bug, a migration, a repair script, or any path that
-- reaches the table with the wrong id in hand. A control that depends on every caller being correct
-- is the thing composite keys exist to replace.
--
-- # Order matters here
--
-- The `UNIQUE (tenant_id, id)` on each parent must exist before a key can reference it, so it comes
-- first. Dropping and recreating a foreign key takes a brief `ACCESS EXCLUSIVE` lock on both tables;
-- these are small tables and `CLAUDE.md`'s warning is about populated ones, but an operator with a
-- large `refresh_tokens` should run this in a maintenance window rather than mid-day.
--
-- The recreated keys are `NOT VALID`-free — they validate on creation, so a pre-existing
-- cross-tenant row (none is known to exist) would fail this migration rather than being silently
-- carried forward. That is the intended behaviour: discovering one is a security finding, and a
-- migration that hid it would be worse than one that stops.
--
-- Forward-only: a new migration, never an edit to 0001.

-- ---------------------------------------------------------------------------
-- The targets a composite key can name
-- ---------------------------------------------------------------------------

-- `users.id` is already the primary key, so this adds no new uniqueness guarantee — it exists so
-- that `(tenant_id, id)` is a referenceable target. That is the same reason `files` and
-- `file_versions` carry theirs, and `0006_versions_and_uploads.sql` says so at the column.
ALTER TABLE users
    DROP CONSTRAINT IF EXISTS users_tenant_id_id_key;
ALTER TABLE users
    ADD CONSTRAINT users_tenant_id_id_key UNIQUE (tenant_id, id);

ALTER TABLE refresh_tokens
    DROP CONSTRAINT IF EXISTS refresh_tokens_tenant_id_id_key;
ALTER TABLE refresh_tokens
    ADD CONSTRAINT refresh_tokens_tenant_id_id_key UNIQUE (tenant_id, id);

-- ---------------------------------------------------------------------------
-- The keys themselves
-- ---------------------------------------------------------------------------

-- `user_credentials.user_id` is the primary key of its own table, so the row is one-per-user; what
-- was missing is that the user had to be *this tenant's* user.
ALTER TABLE user_credentials
    DROP CONSTRAINT IF EXISTS user_credentials_user_id_fkey;
ALTER TABLE user_credentials
    ADD CONSTRAINT user_credentials_user_fkey
        FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, id)
        ON DELETE CASCADE;

ALTER TABLE user_mfa_methods
    DROP CONSTRAINT IF EXISTS user_mfa_methods_user_id_fkey;
ALTER TABLE user_mfa_methods
    ADD CONSTRAINT user_mfa_methods_user_fkey
        FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, id)
        ON DELETE CASCADE;

-- Self-referential: a rotated token names the one it replaced, and reuse detection walks the chain
-- (`docs/03-LLD.md §5`). A chain that could cross tenants is one where a detection walk leaves the
-- tenant it started in.
--
-- `ON DELETE SET NULL` rather than `CASCADE`, matching the original: deleting an old token must not
-- delete the tokens issued after it, which are the live ones.
ALTER TABLE refresh_tokens
    DROP CONSTRAINT IF EXISTS refresh_tokens_parent_id_fkey;
ALTER TABLE refresh_tokens
    ADD CONSTRAINT refresh_tokens_parent_fkey
        FOREIGN KEY (tenant_id, parent_id) REFERENCES refresh_tokens (tenant_id, id)
        ON DELETE SET NULL;
