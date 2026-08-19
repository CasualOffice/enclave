//! `enclave-sharing` — share links: minting, redemption, and the budget that has to hold.
//!
//! A share link is often the only credential protecting a document that has left the organisation.
//! That single sentence sets every design decision in this crate.
//!
//! # The four properties, and where each is enforced
//!
//! **1. The token is unguessable and never stored.** 256 bits from the OS CSPRNG; the database
//! holds SHA-256 of it and nothing else, so a backup, a replica or a support export yields no
//! working link. Mirrors `enclave_auth::RefreshToken` deliberately — two token primitives that make
//! different choices about the same problem is how one of them ends up wrong. See [`token`].
//!
//! **2. The download budget holds under concurrency.** The limit lives in the `WHERE` clause of the
//! `UPDATE` that spends it, so the read and the write are one statement and contenders serialise on
//! the row lock. A zero-row result is the refusal. `docs/12 §4.4` H3 asks for fifty concurrent
//! redemptions against a limit of N and exactly N successes; the obvious implementation passes
//! every single-threaded test and fails that. See [`redeem`].
//!
//! **3. Every refusal looks the same.** Unknown, malformed, expired, revoked and exhausted are one
//! answer to a redeemer. Separate answers would tell an attacker whether a guessed token ever
//! existed, which turns a 256-bit search into an oracle. See [`error`].
//!
//! **4. Refusals are recorded, not just successes.** `AUTH_FAILED` and `BLOCKED` rows are the
//! evidence somebody probed a link, and migration 0008 grants no `UPDATE` or `DELETE` on
//! `share_link_events` so that evidence cannot be edited away.
//!
//! # What this crate is not
//!
//! **It makes no authorization decision.** The policy chain is called from the handler, before a
//! domain service is reached (`plans/M1-CONTENT-CORE.md` D11). Creating a link is an authorization
//! question about the resource; redeeming one is a question about the token *and then* about the
//! resource. This crate answers the token half and hands the caller what they need for the rest.
//!
//! **It does not check passwords, OTPs, domains or MFA.** Those are `ENC-149`'s remaining half and
//! belong beside the rest of authentication in `crates/auth`, not duplicated here. What this crate
//! does is carry the requirements — `has_password`, `require_otp`, `require_mfa`, `allowed_domains`
//! — so a caller cannot redeem a link without being told what it demands. `docs/12 §4.4` H2 is the
//! row that will assert they are enforced server-side rather than merely prompted.

pub mod error;
pub mod model;
pub mod redeem;
pub mod repo;
pub mod token;

pub use error::{Result, SharingError};
pub use model::{ShareAudience, ShareEventKind, ShareLink, SharePermission, ShareResourceKind};
pub use redeem::{record_event, redeem, EventContext, Redemption};
pub use repo::NewShareLink;
pub use token::{ShareToken, ShareTokenDigest, SHARE_TOKEN_BYTES};
