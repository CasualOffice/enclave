//! `ENC-544` — `ENCLAVE_` is [`ConfigLoader`]'s namespace, and nothing else may live in it.
//!
//! # The failure this exists to keep from coming back
//!
//! [`ConfigLoader::new`] reads the **whole process environment** and treats every `ENCLAVE_`-prefixed
//! variable as configuration. `ENCLAVE_TEST_S3_SECRET_ACCESS_KEY` — a MinIO password that
//! `.github/workflows/ci.yml`, `deploy/README.md` and `crates/storage/tests/minio.rs` all used to
//! export — therefore arrived as a configuration field named `test_s3_secret_access_key`, which
//! `scan_for_inline_secrets` classes as a credential (`secret`, `key`) and refuses at 57 bits of
//! Shannon entropy against a 48-bit threshold. The result was that **any process loading
//! configuration from a developer's shell refused to start**, and the message named a field nobody
//! had written. The scanner was right every step of the way; the variable name was wrong.
//!
//! Those three variables are now `TEST_S3_*`, outside the prefix. This file is what stops the class
//! of mistake rather than the instance: [`the_ambient_environment_is_configuration_the_loader_accepts`]
//! runs the real, unmocked loader against the real process environment, so a variable put back into
//! the reserved prefix fails here — in CI, where that job exports the test variables — instead of in
//! whichever binary is next started by hand.
//!
//! # Why renaming, and not teaching the loader to skip a test prefix
//!
//! The rejected option was a carve-out in [`ConfigLoader`]: treat `ENCLAVE_TEST_` as not-configuration
//! and drop it. It fails the only criterion that matters here — it regresses **silently**. A carve-out
//! makes the loader ignore a variable an operator deliberately set, and a dropped override is not an
//! error, it is a process that starts happily on the wrong value. That is strictly worse than the bug
//! it fixes, which at least refused to start. It also has to grow: `ENCLAVE_DEV_*` (the compose
//! stack's ports and passwords) is a second family squatting in the same prefix, so the carve-out
//! becomes a list, and every entry on it is a configuration path that can never be reached again.
//!
//! A rename has exactly one failure mode — a site nobody renamed — and that mode is loud by
//! construction: every consumer of these variables panics naming the variable it could not find
//! (`deploy/README.md`: "a variable that is unset is a **failure**, not a skip"). Verified by
//! deliberate violation: with only the old names exported, all twelve tests in
//! `crates/storage/tests/minio.rs` fail, each naming `TEST_S3_ENDPOINT`.
//!
//! # This file's own positive control
//!
//! `docs/12 §1.2` — an assertion about an absence passes for free, and "the loader did not refuse
//! anything" is exactly that shape: it holds trivially in a shell with no `ENCLAVE_` variables at
//! all. So [`the_old_name_would_still_break_a_process`] feeds the pre-rename name through the same
//! loader and requires the refusal, pinning both that the scanner still works and that the rename
//! was the fix rather than a coincidence.

// Assertions are the point of a test; the workspace warns on these constructs elsewhere.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use enclave_config::{ConfigLoader, DEFAULT_ENV_PREFIX};

/// The MinIO password CI and `deploy/README.md` use, assembled at run time.
///
/// Not a literal, on `CLAUDE.md` rule 11's reasoning for PEM banners: a credential-shaped string in
/// a tracked file is the thing the secrets gate exists to refuse, and a test is not an exemption.
/// The *value* is what makes this test mean something — it is the one a developer actually has
/// exported — so it is reconstructed rather than replaced with a synthetic high-entropy string that
/// would prove the threshold works without proving this variable crosses it.
fn dev_minio_password() -> String {
    format!("{}-dev-{}", "enclave", "secret")
}

#[test]
fn the_ambient_environment_is_configuration_the_loader_accepts() {
    // The real loader over the real process environment — `ConfigLoader::new()` with no
    // `with_env`, which is what every binary in this workspace does at startup. Anything exported
    // into `ENCLAVE_*` by CI, by `deploy/README.md`'s instructions or by a developer's shell is
    // read here exactly as a running process would read it.
    let loaded = ConfigLoader::new().load();

    let Err(err) = loaded else { return };

    // Not `unwrap` — a bare panic on `ConfigError` would print the type and leave the operator
    // guessing which variable did it, which is the exact papercut this file is about.
    let detail = err.report().map_or_else(
        || err.to_string(),
        |report| {
            report
                .problems()
                .iter()
                .map(|problem| format!("  {} — {}", problem.path, problem.detail))
                .collect::<Vec<_>>()
                .join("\n")
        },
    );
    panic!(
        "a process cannot load configuration in this environment:\n{detail}\n\n\
         Each path above is an environment variable that begins with `{DEFAULT_ENV_PREFIX}` and is \
         not configuration. `{DEFAULT_ENV_PREFIX}` is ConfigLoader's namespace; rename the variable \
         out of it, as ENCLAVE_TEST_S3_* -> TEST_S3_* was renamed (ENC-544). Do not add a carve-out \
         to the loader: a skipped prefix makes it ignore an override an operator set."
    );
}

#[test]
fn the_old_name_would_still_break_a_process() {
    // The positive control. An explicit environment rather than the process one, because the point
    // is to reproduce the pre-rename state deterministically on a machine where it no longer exists.
    let name = format!("{DEFAULT_ENV_PREFIX}TEST_S3_SECRET_ACCESS_KEY");
    let err =
        ConfigLoader::new().with_env([(name.clone(), dev_minio_password())]).load().expect_err(
            "the pre-rename variable must still be refused; if it is not, this file's \
                     first test is asserting nothing",
        );

    let report =
        err.report().expect("the refusal is a validation report, not an I/O or model error");
    let problems: Vec<&str> = report.problems().iter().map(|p| p.path.as_str()).collect();
    assert!(
        problems.contains(&"test_s3_secret_access_key"),
        "`{name}` should reach the configuration tree as `test_s3_secret_access_key` and be \
         refused there; the report named {problems:?} instead"
    );

    // And the control on the control: the *renamed* variable carries the same value under a name
    // outside the prefix, and is not configuration at all — so it produces no field, no scan and no
    // refusal. Without this, the assertion above would pass just as well against a loader that
    // refuses everything.
    ConfigLoader::new()
        .with_env([("TEST_S3_SECRET_ACCESS_KEY", dev_minio_password())])
        .load()
        .expect("a variable outside the ENCLAVE_ prefix is not configuration and must be ignored");
}
