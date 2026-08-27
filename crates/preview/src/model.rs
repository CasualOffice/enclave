//! The records this crate reads and writes, and the closed vocabularies their columns hold.
//!
//! `RenditionProfile` mirrors the `CHECK` constraint in `migrations/0007_renditions.sql`
//! (`docs/04-DATA-MODEL.md §7`) — same members, same spellings.
//!
//! # The cache key is the security boundary
//!
//! `docs/06-SECURITY-DLP-ACCESS.md §5.1` splits a preview in two: an identity-free **base
//! rendition**, which is cached, and a **watermark layer** naming the viewer, which is composed per
//! request and never stored. The split only holds if a base rendition cannot be keyed by anything
//! that identifies a viewer — otherwise a watermarked artefact becomes cacheable, and the fourth
//! M2 exit criterion becomes a matter of discipline rather than a property.
//!
//! [`RenditionKey`] is therefore a closed struct of three fields, none of which can hold a
//! principal: the version, the profile and the generator version. There is no constructor that
//! accepts a `UserId`, and `assert_impl_all`-style tests would not help here — the guarantee is that
//! the type has nowhere to put one. `crates/storage`'s `ObjectKey::rendition` has the same shape,
//! so the guarantee survives the trip to object storage.

use core::fmt;

use chrono::{DateTime, Utc};
use enclave_core::{TenantId, UnknownVariant, VersionId};
use enclave_storage::{KeyError, ObjectKey};

/// Generates a closed vocabulary that mirrors a database `CHECK` constraint.
///
/// The same macro `enclave_versions::model` and `enclave_files::model` carry: `as_str` and
/// `from_str` come from one list, so a writer and a reader cannot fall out of step.
macro_rules! db_enum {
    (
        $(#[$meta:meta])*
        pub enum $name:ident { $( $(#[$vmeta:meta])* $variant:ident => $wire:literal ),+ $(,)? }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum $name {
            $( $(#[$vmeta])* $variant ),+
        }

        impl $name {
            /// The stored form, exactly as the `CHECK` constraint spells it.
            #[must_use]
            pub const fn as_str(&self) -> &'static str {
                match self { $( Self::$variant => $wire ),+ }
            }

            /// Every variant, so a test can assert the Rust set against the constraint's set
            /// rather than trusting that both were updated together.
            #[must_use]
            pub const fn all() -> &'static [Self] {
                &[ $( Self::$variant ),+ ]
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl core::str::FromStr for $name {
            type Err = UnknownVariant;

            fn from_str(s: &str) -> core::result::Result<Self, Self::Err> {
                match s {
                    $( $wire => Ok(Self::$variant), )+
                    other => Err(UnknownVariant::new(stringify!($name), other)),
                }
            }
        }
    };
}

db_enum! {
    /// Which derived form of a version this is (`renditions.profile`).
    ///
    /// A closed vocabulary rather than the free text `docs/04 §8` shows, because an open one turns
    /// a typo into a permanent cache miss: every request regenerates, nothing ever hits, and the
    /// only symptom is a rendering worker that never idles.
    pub enum RenditionProfile {
        /// A small identity-free preview image, for listings and cards.
        Thumb => "thumb",
        /// Page images at nominal resolution.
        PagePng1x => "page-png-1x",
        /// Page images for high-density displays.
        PagePng2x => "page-png-2x",
        /// A sanitized PDF — re-encoded, scripts and embedded files stripped.
        PdfSanitized => "pdf-sanitized",
        /// Sanitized HTML, for formats that render better as markup than as pixels.
        HtmlSanitized => "html-sanitized",
    }
}

impl RenditionProfile {
    /// Whether this profile is paginated, and therefore subject to the page cap.
    ///
    /// A thumbnail is one image of the first page whatever the document's length, so capping its
    /// pages would refuse a 5,000-page book whose thumbnail costs the same as any other.
    #[must_use]
    pub const fn is_paginated(self) -> bool {
        match self {
            Self::PagePng1x | Self::PagePng2x | Self::PdfSanitized | Self::HtmlSanitized => true,
            Self::Thumb => false,
        }
    }
}

/// Which build of the rendering pipeline produced an artefact.
///
/// Compared on every cache read: a row written by a different generator is a **miss**, not a hit,
/// so an upgrade that fixes a rendering bug takes effect without anyone having to remember to purge
/// a cache. It is stored as a column rather than as part of the primary key for the reason
/// `migrations/0007_renditions.sql` gives — as a key component, every upgrade would strand the
/// previous generation as unreachable rows that nothing would ever evict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GeneratorVersion(&'static str);

impl GeneratorVersion {
    /// Names a generator.
    #[must_use]
    pub const fn new(version: &'static str) -> Self {
        Self(version)
    }

    /// The stored form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

impl fmt::Display for GeneratorVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

/// What a cached base rendition is looked up by.
///
/// `docs/06 §5.1`'s cache key, as a type. Three fields, and **none of them can name a principal** —
/// see the module documentation for why that is the point rather than an accident of the current
/// fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RenditionKey {
    /// The version rendered. Not the file: a rendition of version 3 is not a rendition of version 4,
    /// and keying by file would serve the wrong bytes after any edit.
    pub version: VersionId,
    /// Which derived form.
    pub profile: RenditionProfile,
    /// Which build produced it.
    pub generator: GeneratorVersion,
}

impl RenditionKey {
    /// Builds a key.
    #[must_use]
    pub const fn new(
        version: VersionId,
        profile: RenditionProfile,
        generator: GeneratorVersion,
    ) -> Self {
        Self { version, profile, generator }
    }
}

/// The single artefact name under a rendition's profile prefix.
///
/// Fixed rather than derived from anything about the request, because [`ObjectKey::rendition`]
/// treats this segment as the one place a `../` could reach the key space, and a constant cannot
/// carry one. Multi-artefact profiles — a page-per-file pyramid — will name pages by index here,
/// which is still not caller-controlled.
const ARTIFACT: &str = "base";

/// The object a base rendition's bytes live at, and the only thing the pipeline's store port
/// accepts.
///
/// # Why this is a type rather than a `&str`
///
/// `CLAUDE.md` rule 6: never issue an original object-storage URL on a preview path, and — the same
/// rule read from the other side — never let the preview path *reach* an original at all. The
/// pipeline holds a store port, so it holds the capability the handler above it was deliberately
/// denied ([`crate::service::PreviewPipeline`] explains why the handler holds none). This newtype
/// is what keeps that capability narrow: both constructors produce a key in the
/// `tenant/{t}/renditions/…` layout, so a version's key cannot be expressed. A rendition write
/// cannot clobber an original, and a rendition read cannot fetch one, because there is no value of
/// this type that names one.
///
/// [`Self::parse`] is the half that matters at run time: the object key on a `renditions` row is
/// data, and data can be wrong — a bad migration, a restored backup, a tenant-crossing edit. It is
/// re-validated against the layout *and* against the reading tenant before a byte is fetched, so a
/// row that named `tenant/{other}/files/…` would be refused rather than served as a preview.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenditionObject(ObjectKey);

impl RenditionObject {
    /// The key this tenant's rendition of `version` under `profile` is written to.
    ///
    /// Deliberately not keyed by the generator, matching `renditions`' primary key: an upgraded
    /// pipeline overwrites the artefact it replaces rather than leaving the old one unreachable
    /// with nothing to evict it (`migrations/0007_renditions.sql`).
    ///
    /// # Errors
    ///
    /// [`KeyError`] if the profile's stored form is not a usable key segment, which no member of
    /// the closed vocabulary is — the fallibility comes from [`ObjectKey::rendition`], whose
    /// segments are checked because *other* callers can supply arbitrary ones.
    pub fn new(
        tenant: TenantId,
        version: VersionId,
        profile: RenditionProfile,
    ) -> Result<Self, KeyError> {
        ObjectKey::rendition(tenant, version, profile.as_str(), ARTIFACT).map(Self)
    }

    /// Re-validates a key that came back from a row.
    ///
    /// # Errors
    ///
    /// [`KeyError::Malformed`] when the key is not canonical, does not name a rendition, or names
    /// another tenant's. All three are the same answer on purpose: each means the row cannot be
    /// trusted to say where a rendition of *this* version for *this* tenant lives, and the
    /// difference between them is of interest to whoever is reading the logs, not to the caller.
    pub fn parse(raw: &str, tenant: TenantId) -> Result<Self, KeyError> {
        let key = ObjectKey::parse(raw)?;
        let malformed = || KeyError::Malformed { key: raw.to_owned() };

        if !key.belongs_to(tenant) {
            return Err(malformed());
        }
        // `ObjectKey::parse` accepts both canonical layouts and does not report which one it
        // matched, so the discriminating segment is checked here. A version key reaching this
        // function is the case the whole type exists for.
        if key.as_str().split('/').nth(2) != Some(RENDITIONS_SEGMENT) {
            return Err(malformed());
        }
        Ok(Self(key))
    }

    /// The key as the store sees it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Display for RenditionObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The segment `docs/02-HLD.md §7` puts between the tenant and the version in a rendition key.
///
/// Spelled here rather than imported because `enclave_storage` keeps it private; the test below
/// asserts it against a key that crate built, so the two cannot drift silently.
const RENDITIONS_SEGMENT: &str = "renditions";

/// A stored base rendition — one row of `renditions`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rendition {
    /// The version it was derived from.
    pub version_id: VersionId,
    /// Which derived form.
    pub profile: RenditionProfile,
    /// Where the bytes live. Never handed to a caller: `docs/06 §5.1` composes the watermark over
    /// these bytes in the response stream, so the key stays server-side.
    pub object_key: String,
    /// How large the artefact is.
    pub size_bytes: i64,
    /// Pages, for paginated profiles.
    pub page_count: Option<i32>,
    /// Which build produced it.
    pub generator_version: String,
    /// When it was generated.
    pub created_at: DateTime<Utc>,
    /// When it was last served, for LRU eviction. `None` means never served since it was written.
    pub last_access_at: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use core::str::FromStr as _;

    use super::*;

    #[test]
    fn profile_strings_match_the_database_check_constraint() {
        // Read from the migration rather than restated here: a test that carries its own copy of
        // the list passes when both copies are wrong together.
        let migration = include_str!("../../../migrations/0007_renditions.sql");
        let check = migration
            .split_once("profile           TEXT NOT NULL CHECK (profile IN (")
            .expect("the profile CHECK constraint")
            .1
            .split_once("))")
            .expect("the constraint's closing paren")
            .0;

        for profile in RenditionProfile::all() {
            assert!(
                check.contains(&format!("'{}'", profile.as_str())),
                "`{profile}` is not in the CHECK constraint, so writing one would be refused"
            );
        }
        let in_constraint = check.matches('\'').count() / 2;
        assert_eq!(
            in_constraint,
            RenditionProfile::all().len(),
            "the constraint permits a profile this crate cannot name, which would read back as an \
             unknown variant"
        );
    }

    #[test]
    fn every_profile_round_trips_through_its_stored_form() {
        for profile in RenditionProfile::all() {
            assert_eq!(RenditionProfile::from_str(profile.as_str()), Ok(*profile));
        }
        assert!(RenditionProfile::from_str("page-png-3x").is_err());
    }

    /// The store port cannot be handed a key that names an original — the rule 6 half that is
    /// about *reaching* originals rather than about publishing URLs to them.
    ///
    /// The positive control is the last assertion: a genuine rendition key of the reading tenant
    /// parses. Without it every refusal below would hold against a function that refused
    /// everything, which is `docs/12-TESTING.md §1.2`'s recurring shape.
    #[test]
    fn no_value_of_this_type_can_name_an_original() {
        let tenant = TenantId::new_v7();
        let other = TenantId::new_v7();
        let file = enclave_core::FileId::new_v7();
        let version = VersionId::new_v7();

        let original = ObjectKey::version(tenant, file, version);
        assert!(
            RenditionObject::parse(original.as_str(), tenant).is_err(),
            "a version's key parsed as a rendition object, so a tampered row could make the \
             preview path fetch the original bytes and serve them as a preview"
        );

        // Another tenant's rendition, which row-level security should never have produced and
        // which is refused here anyway: object storage has no RLS, so this is where the equivalent
        // check happens.
        let theirs = RenditionObject::new(other, version, RenditionProfile::Thumb).expect("key");
        assert!(RenditionObject::parse(theirs.as_str(), tenant).is_err());

        assert!(RenditionObject::parse("../../etc/passwd", tenant).is_err());
        assert!(RenditionObject::parse("", tenant).is_err());

        let mine = RenditionObject::new(tenant, version, RenditionProfile::Thumb).expect("key");
        assert_eq!(
            RenditionObject::parse(mine.as_str(), tenant).expect("this tenant's own rendition"),
            mine
        );
    }

    /// The key names the version and the profile, and nothing that could identify a viewer.
    ///
    /// `docs/06 §5.1` again, one layer out from [`RenditionKey`]: a cache key with nowhere to put a
    /// principal is only half the guarantee if the *object* it names can carry one.
    #[test]
    fn the_object_key_names_the_version_and_the_profile_and_nothing_else() {
        let tenant = TenantId::new_v7();
        let version = VersionId::new_v7();
        let object = RenditionObject::new(tenant, version, RenditionProfile::PagePng1x)
            .expect("a profile's stored form is always a usable segment");

        assert_eq!(
            object.as_str(),
            format!("tenant/{tenant}/renditions/{version}/page-png-1x/base"),
            "the layout is `docs/02-HLD.md §7`'s, and the segment `parse` discriminates on"
        );
        for profile in RenditionProfile::all() {
            assert!(
                RenditionObject::new(tenant, version, *profile).is_ok(),
                "`{profile}` cannot be written to an object key, so it could never be cached"
            );
        }
    }

    #[test]
    fn a_generator_change_changes_the_key() {
        let version = VersionId::from(uuid::Uuid::nil());
        let old = RenditionKey::new(
            version,
            RenditionProfile::Thumb,
            GeneratorVersion::new("preview/1.0"),
        );
        let new = RenditionKey::new(
            version,
            RenditionProfile::Thumb,
            GeneratorVersion::new("preview/1.1"),
        );
        // If these compared equal, upgrading the pipeline would keep serving artefacts produced by
        // the build the upgrade was meant to replace — including, in the worst case, one produced
        // by a renderer since found to mis-sanitize.
        assert_ne!(old, new);
    }
}
