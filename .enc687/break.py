"""Deliberate-break harness for ENC-687 (docs/12-TESTING.md §1.2).

Patches one file, runs one named test, restores, and prints the failure line.
"""
import subprocess
import sys

def run(path, old, new, test_target, test_name, label):
    src = open(path).read()
    if old not in src:
        print(f"[{label}] PATCH DID NOT APPLY — the anchor is gone")
        return
    open(path, 'w').write(src.replace(old, new, 1))
    try:
        cmd = ["cargo", "test", "-p", test_target[0]]
        if test_target[1] == "lib":
            cmd += ["--lib"]
        elif test_target[1] == "bin":
            cmd += ["--bin", test_target[0]]
        else:
            cmd += ["--test", test_target[1]]
        cmd += ["--", test_name, "--include-ignored", "--exact", "--nocapture"]
        out = subprocess.run(
            cmd, capture_output=True, text=True,
            env={**__import__("os").environ,
                 "DATABASE_URL": "postgres://enclave:enclave@127.0.0.1:55432/enclave"},
        )
        text = out.stdout + out.stderr
        print(f"===== {label} =====")
        if "test result: FAILED" in text or "error[" in text or "error: could not compile" in text:
            for line in text.splitlines():
                if ("panicked at" in line or "assertion" in line or "left:" in line
                        or "right:" in line or line.startswith("test ") or "error" in line
                        or line.strip().startswith("a ") or "must" in line):
                    print("   " + line.strip())
        else:
            print("   !!! DID NOT FAIL — the test does not hold this property")
            print("   " + "\n   ".join(l for l in text.splitlines() if l.startswith("test ")))
    finally:
        open(path, 'w').write(src)

BREAKS = sys.argv[1] if len(sys.argv) > 1 else "all"

DB = "crates/db/src/auth_tokens.rs"
MAIN = "crates/api/src/main.rs"

if BREAKS in ("all", "1"):
    run(DB,
        "WHERE id = $1 AND tenant_id = $3 AND consumed_at IS NULL AND revoked_at IS NULL",
        "WHERE id = $1 AND tenant_id = $3",
        ("enclave-api", "auth_postgres"),
        "k3_two_concurrent_rotations_of_one_token_produce_exactly_one_successor",
        "1. rotate() stops requiring the presented row to be unconsumed")

if BREAKS in ("all", "2"):
    run(DB,
        "            epoch,\n            max_classification: None,",
        "            epoch: 1,\n            max_classification: None,",
        ("enclave-api", "auth_postgres"),
        "the_token_epoch_is_re_read_at_rotation_rather_than_copied_forward",
        "2. PgSessionFacts returns a constant epoch instead of re-reading it")

if BREAKS in ("all", "3"):
    run(DB,
        "auth_time: record.absolute_expires_at - self.absolute_ttl,",
        "auth_time: record.issued_at,",
        ("enclave-api", "auth_postgres"),
        "auth_time_is_unchanged_by_a_rotation",
        "3. auth_time is taken from the rotation instead of the authentication")

if BREAKS in ("all", "4"):
    run(DB,
        "WHERE actor_id = $1 AND revoked_at IS NULL AND consumed_at IS NULL",
        "WHERE ($1 IS NOT NULL) AND revoked_at IS NULL AND consumed_at IS NULL",
        ("enclave-api", "auth_postgres"),
        "revoking_a_subject_reaches_every_family_and_leaves_other_subjects_alone",
        "4. revoke_all_for_subject loses its actor_id predicate")

if BREAKS in ("all", "5"):
    run(DB,
        'Actor::User(_) => Ok("USER"),',
        'Actor::User(_) => Ok("user"),',
        ("enclave-api", "auth_postgres"),
        "a_login_writes_a_refresh_row_and_issues_a_token_that_another_endpoint_accepts",
        "5. actor_type writes ActorKind's spelling rather than the column's")

if BREAKS in ("all", "6"):
    run(DB,
        "        self.deny(tenant_id, session_id.as_uuid(), expires_at, reason).await\n",
        "        let _ = (tenant_id, session_id, expires_at, reason);\n        Ok(())\n",
        ("enclave-api", "auth_postgres"),
        "k4_a_replayed_token_revokes_every_row_in_the_family",
        "6. deny_session becomes a no-op, so a destroyed family's access tokens live on")

if BREAKS in ("all", "7"):
    run(MAIN,
        "        if !bind.is_loopback() {",
        "        if false {",
        ("enclave-api", "bin"),
        "tests::a_generated_key_is_unreachable_for_anything_but_a_loopback_community_deployment",
        "7. the loopback condition is removed from SigningKeys::choose")

if BREAKS in ("all", "8"):
    run(MAIN,
        "        if !matches!(profile, enclave_config::DeploymentProfile::Community) {",
        "        if false {",
        ("enclave-api", "bin"),
        "tests::a_generated_key_is_unreachable_for_anything_but_a_loopback_community_deployment",
        "8. the profile condition is removed from SigningKeys::choose")


CLI = "crates/cli/src/cli.rs"
PW = "crates/cli/src/password.rs"

if BREAKS in ("all", "9"):
    run(CLI,
        '    #[arg(long, value_name = "EMAIL")]\n    pub(crate) email: String,',
        '    #[arg(long, value_name = "EMAIL")]\n    pub(crate) email: String,\n\n    /// A convenience nobody should have.\n    #[arg(long, short = \'p\', value_name = "PASSWORD")]\n    pub(crate) password: Option<String>,',
        ("enclave-cli", "bin"),
        "cli::tests::a_password_cannot_be_passed_as_an_argument",
        "9. set-password grows a --password flag")

if BREAKS in ("all", "10"):
    run(PW,
        "    raw.strip_suffix('\\n').map_or(raw, |line| line.strip_suffix('\\r').unwrap_or(line))",
        "    raw.trim()",
        ("enclave-cli", "bin"),
        "password::tests::exactly_one_trailing_line_ending_is_removed",
        "10. the stdin reader trims instead of stripping one newline")
