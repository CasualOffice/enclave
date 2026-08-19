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
use enclave_core::{UnknownVariant, VersionId};

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
