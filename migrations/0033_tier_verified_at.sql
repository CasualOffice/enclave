-- =================================================================================================
-- 0033 — when the object store last confirmed where a version's bytes are.
--
-- `ENC-951`. `ENC-946` made the product honest about `storage_tier` and `ENC-947` resolved the two
-- transient states. Neither closes the case that actually happens most: **an operator writes a
-- bucket lifecycle rule** — *ninety days after last access, transition to Deep Archive* — the
-- provider moves the objects, and nothing tells this product. Those rows still say `HOT`, so a
-- download mints a signed URL that fails at S3 with `InvalidObjectState`: precisely the failure
-- `ENC-946` was built to prevent, arriving through the door it did not close.
--
-- ## Why a column and not a bigger sweep
--
-- Detecting that drift means asking the store about versions this product has no reason to suspect
-- — one `HeadObject` per version of every file in the deployment. That cost is unbounded in the
-- corpus, so the scan has to be *bounded per tick* and *fair across rows*, and both need a column
-- to order by. Without one the only options are scanning everything every pass (impossible) or
-- picking rows at random (unmeasurable: nobody can say how stale the worst row is).
--
-- `NULL` means never verified, and sorts first. Every existing row backfills to `NULL`, which is
-- true — nothing has ever asked the store about them — and puts the whole existing corpus at the
-- front of the queue rather than pretending it was checked at migration time.
--
-- ## What this column is not
--
-- It is **not** evidence the tier is correct *now*. It is the moment it was last correct, which is
-- the only thing an observation can establish. The number an operator actually needs is the oldest
-- value in the table — the worst-case staleness of the deployment — and `crates/worker/src/tiering.rs`
-- reports it every pass for exactly that reason. A scan whose coverage nobody can state is a scan
-- nobody can trust.
-- =================================================================================================

ALTER TABLE file_versions
    ADD COLUMN IF NOT EXISTS tier_verified_at TIMESTAMPTZ;

COMMENT ON COLUMN file_versions.tier_verified_at IS
    'When the object store last confirmed storage_tier (ENC-951). NULL means never asked. Not evidence the tier is correct now — only that it was then; the oldest value in the table is the deployment worst-case staleness, which the tier-reconciler reports every pass.';

-- The drift scan's index: least-recently-verified `HOT` rows first.
--
-- Partial on `HOT` alone, and that is what keeps it small in the dimension that matters. The other
-- three tiers are handled by `idx_file_versions_in_transition` (`ARCHIVING`, `RESTORING`) or are
-- already cold and have nothing to drift *into* — an `ARCHIVED` row the store reports warm is a
-- restore that landed, which `ENC-947`'s pass sees through `RESTORING`, not here.
--
-- `NULLS FIRST` is written explicitly rather than left to the default. PostgreSQL's default for
-- `ASC` *is* `NULLS LAST`, so an index built without it would order never-verified rows — the
-- entire existing corpus after this migration — **last**, and the scan would work through everything
-- it had already checked before reaching anything it had not.
--
-- Not `CONCURRENTLY`: sqlx runs each migration in a transaction. The `SHARE` lock blocks writes to
-- `file_versions` for the scan, and unlike `0032`'s partial index this one covers most of the
-- table, so on a large deployment it is the expensive half of this migration. Build it out of band
-- first if that matters; `migrations/0030` carries the same warning.
CREATE INDEX IF NOT EXISTS idx_file_versions_tier_unverified
    ON file_versions (tenant_id, tier_verified_at ASC NULLS FIRST)
    WHERE storage_tier = 'HOT';
