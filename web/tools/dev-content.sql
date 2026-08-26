-- Development content for the web client, and why it is written in SQL.
--
-- `enclave-cli seed --profile dev` writes tenants, users, groups and memberships and stops there:
-- it creates no workspace, no library and no file. The only way to create content through the API
-- is the upload path, and `crates/api/src/main.rs` binds `Delivery::unconfigured()`
-- unconditionally, so `POST /api/v1/uploads` answers 503 in this build whatever `storage:` says in
-- `enclave.yaml`. With no seed and no upload, a developer running the client against a real API
-- sees an empty product and cannot tell a wired screen from an unwired one.
--
-- So this file writes the rows the browse and metadata endpoints read. It is **not** a client-side
-- fixture and it is the opposite of one: nothing here is imported by `web/src`, the client still
-- learns everything from `GET /api/v1/libraries/{id}/items`, and every row below is subject to the
-- real policy chain, the real ACL resolver and real row-level security. What it removes is the
-- absence of data, not the enforcement over it.
--
-- Shapes are taken from `migrations/0004_content_and_acl.sql`, `0005_files.sql` and
-- `0006_versions_and_uploads.sql`, which remain the only place DDL is defined (`CLAUDE.md`).
--
--   docker exec -i enclave-test-pg psql -U enclave -d enclave < web/tools/dev-content.sql
--
-- Idempotent: every insert is ON CONFLICT DO NOTHING, so re-running it changes nothing.

BEGIN;

-- Every table below has RLS enabled *and forced*, so even the owner is subject to the policy and a
-- session that never set this gets an error rather than a silent zero rows.
SET LOCAL app.tenant_id = '2647ea9a-3503-586e-af07-ba3911b17dd6';

-- tenant-alpha, and its admin — both from the `dev` fixture profile, ids derived by the UUIDv5
-- scheme in `crates/testing/src/lib.rs`. Named here rather than looked up so this file fails loudly
-- if the fixture ever changes, instead of quietly attaching content to nobody.
\set tenant '2647ea9a-3503-586e-af07-ba3911b17dd6'
\set admin  'fd54f946-2130-5b3e-9769-6f8bc5a441e2'
\set ws     '11111111-0000-4000-8000-000000000001'
\set lib    '22222222-0000-4000-8000-000000000001'
\set lib2   '22222222-0000-4000-8000-000000000002'

INSERT INTO workspaces (id, tenant_id, name, slug, description, visibility, created_by, created_at, updated_at)
VALUES (:'ws', :'tenant', 'Finance', 'finance', 'Quarterly reporting, board material and contracts.',
        'MEMBERS_ONLY', :'admin', now(), now())
ON CONFLICT (id) DO NOTHING;

INSERT INTO libraries (id, tenant_id, workspace_id, name, slug, inherit_permissions, versioning_mode,
                       external_sharing, sync_enabled, created_at, updated_at)
VALUES
  (:'lib',  :'tenant', :'ws', 'Board Documents', 'board-documents', TRUE, 'MAJOR_MINOR', 'DISABLED', TRUE, now(), now()),
  (:'lib2', :'tenant', :'ws', 'Contracts',       'contracts',       TRUE, 'MAJOR',       'EXISTING_GUESTS', TRUE, now(), now())
ON CONFLICT (id) DO NOTHING;

-- `browse` orders by `id ASC` and applies no other sort, so the ids below are chosen to put folders
-- above files. That is a property of the fixture, not of the client: the list component does its own
-- grouping and must not be written to depend on the server's order.
INSERT INTO files (id, tenant_id, workspace_id, library_id, parent_id, node_type, name, normalized_name,
                   mime_type, size_bytes, status, inherit_permissions, created_by, modified_by,
                   created_at, modified_at)
VALUES
  ('30000000-0000-4000-8000-000000000001', :'tenant', :'ws', :'lib', NULL, 'FOLDER', 'Board Meetings 2026', 'board meetings 2026', 'application/x-directory', 0, 'AVAILABLE', TRUE, :'admin', :'admin', now() - interval '61 days', now() - interval '3 days'),
  ('30000000-0000-4000-8000-000000000002', :'tenant', :'ws', :'lib', NULL, 'FOLDER', 'Quarterly Reporting', 'quarterly reporting', 'application/x-directory', 0, 'AVAILABLE', TRUE, :'admin', :'admin', now() - interval '90 days', now() - interval '9 days'),
  ('30000000-0000-4000-8000-000000000003', :'tenant', :'ws', :'lib', NULL, 'FOLDER', 'Audit',               'audit',               'application/x-directory', 0, 'AVAILABLE', TRUE, :'admin', :'admin', now() - interval '120 days', now() - interval '31 days'),

  ('40000000-0000-4000-8000-000000000001', :'tenant', :'ws', :'lib', NULL, 'FILE', 'FY26 Board Pack.pdf',            'fy26 board pack.pdf',            'application/pdf', 4718592, 'AVAILABLE', TRUE, :'admin', :'admin', now() - interval '14 days', now() - interval '2 hours'),
  ('40000000-0000-4000-8000-000000000002', :'tenant', :'ws', :'lib', NULL, 'FILE', 'Treasury Position.xlsx',         'treasury position.xlsx',         'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 1183744, 'AVAILABLE', TRUE, :'admin', :'admin', now() - interval '30 days', now() - interval '1 day'),
  ('40000000-0000-4000-8000-000000000003', :'tenant', :'ws', :'lib', NULL, 'FILE', 'Remuneration Committee.docx',    'remuneration committee.docx',    'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 286720, 'AVAILABLE', TRUE, :'admin', :'admin', now() - interval '21 days', now() - interval '4 days'),
  ('40000000-0000-4000-8000-000000000004', :'tenant', :'ws', :'lib', NULL, 'FILE', 'Investor Update Q3.pptx',        'investor update q3.pptx',        'application/vnd.openxmlformats-officedocument.presentationml.presentation', 8912896, 'AVAILABLE', TRUE, :'admin', :'admin', now() - interval '7 days', now() - interval '7 days'),
  ('40000000-0000-4000-8000-000000000005', :'tenant', :'ws', :'lib', NULL, 'FILE', 'Cash Flow Forecast.xlsx',        'cash flow forecast.xlsx',        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 962560, 'AVAILABLE', TRUE, :'admin', :'admin', now() - interval '45 days', now() - interval '12 days'),
  ('40000000-0000-4000-8000-000000000006', :'tenant', :'ws', :'lib', NULL, 'FILE', 'Statutory Accounts 2025.pdf',    'statutory accounts 2025.pdf',    'application/pdf', 2359296, 'AVAILABLE', TRUE, :'admin', :'admin', now() - interval '200 days', now() - interval '96 days'),
  ('40000000-0000-4000-8000-000000000007', :'tenant', :'ws', :'lib', NULL, 'FILE', 'Bank Covenants.pdf',             'bank covenants.pdf',             'application/pdf', 1572864, 'AVAILABLE', TRUE, :'admin', :'admin', now() - interval '150 days', now() - interval '40 days'),
  ('40000000-0000-4000-8000-000000000008', :'tenant', :'ws', :'lib', NULL, 'FILE', 'Risk Register.xlsx',             'risk register.xlsx',             'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 524288, 'AVAILABLE', TRUE, :'admin', :'admin', now() - interval '60 days', now() - interval '5 days'),

  -- Inside `Board Meetings 2026`, so the folder is not an empty click.
  ('41000000-0000-4000-8000-000000000001', :'tenant', :'ws', :'lib', '30000000-0000-4000-8000-000000000001', 'FILE', 'Minutes 2026-02.docx', 'minutes 2026-02.docx', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 143360, 'AVAILABLE', TRUE, :'admin', :'admin', now() - interval '55 days', now() - interval '55 days'),
  ('41000000-0000-4000-8000-000000000002', :'tenant', :'ws', :'lib', '30000000-0000-4000-8000-000000000001', 'FILE', 'Minutes 2026-05.docx', 'minutes 2026-05.docx', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 151552, 'AVAILABLE', TRUE, :'admin', :'admin', now() - interval '20 days', now() - interval '20 days'),
  ('41000000-0000-4000-8000-000000000003', :'tenant', :'ws', :'lib', '30000000-0000-4000-8000-000000000001', 'FILE', 'Agenda 2026-08.pdf',   'agenda 2026-08.pdf',   'application/pdf', 98304, 'AVAILABLE', TRUE, :'admin', :'admin', now() - interval '3 days', now() - interval '3 days'),

  -- A second library, so the client is exercised against more than one container.
  ('50000000-0000-4000-8000-000000000001', :'tenant', :'ws', :'lib2', NULL, 'FILE', 'MSA — Northwind Ltd.pdf',   'msa — northwind ltd.pdf',   'application/pdf', 786432, 'AVAILABLE', TRUE, :'admin', :'admin', now() - interval '300 days', now() - interval '17 days'),
  ('50000000-0000-4000-8000-000000000002', :'tenant', :'ws', :'lib2', NULL, 'FILE', 'DPA — Contoso.pdf',         'dpa — contoso.pdf',         'application/pdf', 425984, 'AVAILABLE', TRUE, :'admin', :'admin', now() - interval '110 days', now() - interval '110 days')
ON CONFLICT (id) DO NOTHING;

-- One readable version per file. Rule 9 lives here and not on `files`: `READABLE_PREDICATE` in
-- `crates/versions/src/model.rs` is `status = 'AVAILABLE' AND av_status = 'CLEAN'`, and the delivery
-- paths use it. `object_key` is globally unique, not tenant-scoped, so it is derived from the
-- version id.
INSERT INTO file_versions (id, tenant_id, file_id, object_key, storage_profile_id, size_bytes,
                           checksum_sha256, mime_type, major, minor, status, av_status, av_engine,
                           av_signature_version, av_scanned_at, encryption_mode, created_by, created_at, comment)
SELECT
  ('6' || substr(f.id::text, 2))::uuid,
  f.tenant_id,
  f.id,
  'tenants/' || f.tenant_id || '/blobs/6' || substr(f.id::text, 2),
  '00000000-0000-4000-8000-0000000000ff',
  f.size_bytes,
  encode(sha256(f.id::text::bytea), 'hex'),
  f.mime_type,
  1, 0,
  'AVAILABLE', 'CLEAN', 'clamav', 'dev', f.modified_at,
  'PROVIDER', f.created_by, f.created_at, NULL
FROM files f
WHERE f.tenant_id = :'tenant' AND f.node_type = 'FILE'
ON CONFLICT (id) DO NOTHING;

UPDATE files f
SET current_version_id = ('6' || substr(f.id::text, 2))::uuid
WHERE f.tenant_id = :'tenant' AND f.node_type = 'FILE' AND f.current_version_id IS NULL;

-- The grants. `users.is_admin` buys nothing on a content route — `PgAdminRoles` only answers
-- `Action::Admin(..)`, and every `container.*` / `file.*` verdict comes from `acl_entries` alone.
--
-- Granted on the WORKSPACE rather than per library, because both libraries set
-- `inherit_permissions = TRUE` and the resolver walks file → folders → library → workspace. One row
-- per action; the unique index is (tenant, resource, principal, action).
--
-- **`file.download`, `file.print`, `file.export` and `file.share_external` are deliberately not
-- granted.** Not an oversight and not laziness: it is the only way to see the capability contract
-- actually working. With every action allowed, `capabilities` is ten `true`s and a client that
-- ignored the object entirely would look identical to one that renders from it. Withholding four
-- makes the difference visible on screen — and makes the "never re-derive a permission" rule
-- testable against a real server rather than against a fixture.
INSERT INTO acl_entries (id, tenant_id, resource_type, resource_id, principal_type, principal_id,
                         action, effect, granted_by, granted_at, expires_at)
SELECT
  ('70000000-0000-4000-8000-' || lpad(row_number() OVER (ORDER BY action)::text, 12, '0'))::uuid,
  :'tenant', 'WORKSPACE', :'ws', 'USER', :'admin', action, 'ALLOW', :'admin', now(), NULL
FROM unnest(ARRAY[
  'container.read',
  'file.metadata_read',
  'file.version_read',
  'file.content_read',
  'file.preview',
  'file.edit',
  'file.copy',
  'file.move',
  'file.share',
  'file.delete',
  'file.sync'
]) AS action
ON CONFLICT DO NOTHING;

COMMIT;

\echo ''
\echo 'dev content written. Counts for tenant-alpha:'
SELECT
  (SELECT count(*) FROM workspaces  WHERE tenant_id = '2647ea9a-3503-586e-af07-ba3911b17dd6') AS workspaces,
  (SELECT count(*) FROM libraries   WHERE tenant_id = '2647ea9a-3503-586e-af07-ba3911b17dd6') AS libraries,
  (SELECT count(*) FROM files       WHERE tenant_id = '2647ea9a-3503-586e-af07-ba3911b17dd6') AS files,
  (SELECT count(*) FROM acl_entries WHERE tenant_id = '2647ea9a-3503-586e-af07-ba3911b17dd6') AS grants;
