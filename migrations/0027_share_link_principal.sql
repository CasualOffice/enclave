-- ENC-879 — `acl_entries` can name the bearer of a share link.
--
-- A redemption arrives with a credential and no principal. Before this migration nothing in the
-- schema could express a grant to one: `principal_type` admitted `USER`, `GROUP`, `GUEST`,
-- `SERVICE_ACCOUNT` and `EVERYONE`, so the only rows that could have matched a redemption were the
-- `EVERYONE` ones — which is precisely the match `enclave_authorization::PrincipalSet` now refuses,
-- because an `EVERYONE` grant is a statement about the people of a tenant and a link bearer is not
-- one of them. Without `SHARE_LINK` the two halves together mean *no row can ever grant a
-- redemption*, which is the state `ENC-879` found and this migration ends.
--
-- The value is a **principal** kind, not a resource kind. `resource_type` is untouched and still has
-- no `SHARE` member: a share link carries no ACL of its own, because the permission that governs a
-- link is the permission on the thing the link exposes (`crates/api/src/routes/shares.rs`
-- `governing_resource` states the same rule at the handler). What this adds is the ability for a row
-- on a *file* to say "whoever holds link L may preview it".
--
-- ## The sibling constraint at `migrations/0004_content_and_acl.sql:73` is deliberately left alone
--
-- `workspace_members.principal_type` carries the same five-value-minus-`EVERYONE` vocabulary and is
-- *not* widened here. The two constraints look alike and mean different things: `acl_entries` says
-- who a permission was granted to, `workspace_members` says who belongs to a workspace. Membership
-- is a directory fact — it drives navigation, the member list an administrator reads, and the
-- notifications a workspace sends — and a share link belongs to nothing. A link bearer that could be
-- stored as a member would appear in a tenant's member list as a row nobody provisioned and nobody
-- can put a name to.
--
-- `group_members.member_type` (`0001_foundations.sql:203`) is left alone for the stronger version of
-- the same reason, and `enclave_authorization` depends on it: `PrincipalSet::can_hold_group
-- _memberships` skips the group-closure walk for a link bearer *because* that `CHECK` makes a share
-- link in a group unwritable, including from `psql`. Widening it would silently turn that skip into
-- a hole.
--
-- ## Shape
--
-- Expand-then-contract, in the one form that applies to a widened `CHECK`. The new constraint is a
-- strict superset of the old one, so every existing row already satisfies it and the validation scan
-- cannot fail — but it is still added `NOT VALID` and validated separately, because `ADD CONSTRAINT`
-- with validation holds `ACCESS EXCLUSIVE` for the length of a full table scan, while `NOT VALID`
-- holds it for a catalog update and `VALIDATE CONSTRAINT` takes only `SHARE UPDATE EXCLUSIVE`.
-- `acl_entries` is on the read path of every authorization decision in the product; it is not a
-- table to lock out.
--
-- No new grant and no new policy. `acl_entries` already has row-level security, `FORCE`d, from
-- `0002_rls_policies.sql`, and `enclave_app`'s privileges on it from `0003`. Widening a `CHECK`
-- changes neither, which is why this file has no `GRANT` and why the assertion below checks the
-- constraint rather than a privilege.

ALTER TABLE acl_entries DROP CONSTRAINT acl_entries_principal_type_check;

ALTER TABLE acl_entries ADD CONSTRAINT acl_entries_principal_type_check
    CHECK (principal_type IN ('USER','GROUP','GUEST','SERVICE_ACCOUNT','SHARE_LINK','EVERYONE'))
    NOT VALID;

ALTER TABLE acl_entries VALIDATE CONSTRAINT acl_entries_principal_type_check;

COMMENT ON COLUMN acl_entries.principal_type IS
    'SHARE_LINK names share_links.id: the grant a redemption is authorized against, since a share-link bearer is deliberately outside EVERYONE (ENC-879, docs/04 §9).';

-- Asserted at apply time, in the shape `0002` and `0026` use: a constraint that silently failed to
-- widen would leave every redemption unauthorizable, and the failure would surface as a policy
-- refusal rather than as a migration error.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conrelid = 'acl_entries'::regclass
           AND conname = 'acl_entries_principal_type_check'
           AND convalidated
           AND pg_get_constraintdef(oid) LIKE '%SHARE_LINK%'
    ) THEN
        RAISE EXCEPTION 'acl_entries.principal_type does not admit SHARE_LINK: no ACL row can grant a share-link redemption';
    END IF;

    -- The widening must not have dropped a value on the way through. A constraint listing only
    -- SHARE_LINK would pass the check above and refuse every grant in the product.
    IF NOT (
        SELECT pg_get_constraintdef(oid) LIKE '%USER%'
           AND pg_get_constraintdef(oid) LIKE '%GROUP%'
           AND pg_get_constraintdef(oid) LIKE '%GUEST%'
           AND pg_get_constraintdef(oid) LIKE '%SERVICE_ACCOUNT%'
           AND pg_get_constraintdef(oid) LIKE '%EVERYONE%'
          FROM pg_constraint
         WHERE conrelid = 'acl_entries'::regclass
           AND conname = 'acl_entries_principal_type_check'
    ) THEN
        RAISE EXCEPTION 'acl_entries.principal_type lost a principal kind while gaining SHARE_LINK';
    END IF;

    -- The sibling constraints stay narrow, and that is a property worth failing on rather than
    -- rediscovering: see the header for why a share link is not a workspace member and must not be
    -- a group member.
    IF (SELECT pg_get_constraintdef(oid) LIKE '%SHARE_LINK%'
          FROM pg_constraint
         WHERE conrelid = 'group_members'::regclass
           AND conname = 'group_members_member_type_check')
    THEN
        RAISE EXCEPTION 'group_members.member_type admits SHARE_LINK: the authorization resolver skips the group walk for a link bearer on the grounds that it cannot';
    END IF;
END
$$;
