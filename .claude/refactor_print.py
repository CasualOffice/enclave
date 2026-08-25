"""One-shot edit: fold the stampable check into `satisfy_print`.

Written to a file rather than piped as a heredoc because the shell wrapper refuses long inline
scripts. Deleted after it runs.
"""

import re

PATH = "crates/api/src/routes/delivery.rs"
s = open(PATH).read()


def sub(old, new, count=1):
    global s
    assert s.count(old) == count, (old[:70], s.count(old))
    s = s.replace(old, new, count)


sub(
    """    let obligations = decision.into_obligations();
    let required = match satisfy_print(&obligations, request.justification.as_deref()) {
        Ok(required) => required,
        Err(refused) => return Err(state.audit.refuse(&ctx, PRINT, &resource, refused).await),
    };

    // A mark exists to attribute a leak to a person, and a print carries it onto paper, where the
    // only forensic trace is what was drawn. So a grant that would have to be marked is refused
    // unless the principal is somebody the mark can name — refused, not stamped "system", which
    // satisfies the obligation on paper and not in fact.
    if required.watermark {
        if let Err(refused) = stampable(&ctx) {
            return Err(state.audit.refuse(&ctx, PRINT, &resource, refused).await);
        }
    }
""",
    """    let obligations = decision.into_obligations();
    let required = match satisfy_print(&obligations, request.justification.as_deref(), &ctx) {
        Ok(required) => required,
        Err(refused) => return Err(state.audit.refuse(&ctx, PRINT, &resource, refused).await),
    };
""",
)

sub(
    """/// # Errors
///
/// [`Refused`] when an obligation cannot be satisfied here — recorded before it reaches the caller.
fn satisfy_print(
    obligations: &Obligations,
    justification: Option<&str>,
) -> Result<crate::preview::Required, Refused> {""",
    """/// # Errors
///
/// [`Refused`] when an obligation cannot be satisfied here — including a watermark required of a
/// principal that is not a person. Recorded before it reaches the caller (`ENC-606`).
fn satisfy_print(
    obligations: &Obligations,
    justification: Option<&str>,
    ctx: &RequestContext,
) -> Result<crate::preview::Required, Refused> {""",
)

sub(
    """            // Recorded onto the capability. Nothing is served here, so nothing can be served
            // unmarked; what must not happen is a grant that is redeemable without the mark, and
            // the flag on the stored capability is what stops it.
            Obligation::Watermark => required.watermark = true,""",
    """            // Recorded onto the capability. Nothing is served here, so nothing can be served
            // unmarked; what must not happen is a grant that is redeemable without the mark, and
            // the flag on the stored capability is what stops it.
            //
            // The principal is checked *here*, inside the function that decides the obligations,
            // rather than at the call site the preview and export paths use — and that is the
            // finding rather than a preference. With the check at the call site, deleting it
            // entirely failed **nothing**: every caller in every HTTP test is a signed-in person,
            // and no unit test can reach a line inside an `async fn` taking `State`, three
            // extractors and a database.
            //
            // A mark exists to attribute a leak to a person, and a print carries it onto paper
            // where the only forensic trace is what was drawn. So a grant that would have to be
            // marked is refused unless the principal is somebody the mark can name — refused, not
            // stamped "system", which satisfies the obligation on paper and not in fact.
            Obligation::Watermark => {
                let _actor = stampable(ctx)?;
                required.watermark = true;
            }""",
)

sub(
    """    Action, Actor, Error, FileAction, FileId, Obligation, Obligations, RequestId, ResourceRef,
    SessionId, TenantId, VersionId,
};""",
    """    Action, Actor, Error, FileAction, FileId, Obligation, Obligations, RequestContext, RequestId,
    ResourceRef, SessionId, TenantId, VersionId,
};""",
)

sub(
    """    fn obligations(list: impl IntoIterator<Item = Obligation>) -> Obligations {
        list.into_iter().collect()
    }""",
    """    fn obligations(list: impl IntoIterator<Item = Obligation>) -> Obligations {
        list.into_iter().collect()
    }

    /// A request from an ordinary signed-in person — the principal a watermark can name.
    fn person() -> RequestContext {
        let mut ctx = RequestContext::system(TenantId::new_v7());
        ctx.actor = Actor::User(UserId::new_v7());
        ctx
    }""",
)

# Thread the context through the existing print tests.
s = re.sub(
    r"satisfy_print\((&[a-z_]+(?:\(\[[^\]]*\]\))?), (None|Some\([^()]*\))\)",
    r"satisfy_print(\1, \2, &person())",
    s,
)
s = re.sub(
    r"satisfy_print\(\n(\s+)(&obligations\(\[[^\]]*\]\)),\n(\s+)(Some\([^()]*\))\n(\s*)\)",
    r"satisfy_print(\n\1\2,\n\3\4,\n\3&person()\n\5)",
    s,
)

sub(
    """    fn capability(now: DateTime<Utc>) -> PrintCapability {""",
    '''    /// A print grant that would have to be marked names a person, or is refused.
    ///
    /// `ENC-720`'s own finding, and the reason the check moved into [`satisfy_print`]: while it sat
    /// at the handler's call site, deleting it entirely failed **nothing** — the whole workspace
    /// stayed green, because every caller in every HTTP test is a signed-in person.
    ///
    /// The last case is the control that keeps this from being "refuse every machine": a service
    /// account with no watermark obligation may hold a print grant. The refusal is about an
    /// obligation this principal cannot discharge, not about the principal.
    #[test]
    fn a_watermarked_print_grant_names_a_person_or_is_refused() {
        let tenant = TenantId::new_v7();

        let system = RequestContext::system(tenant);
        assert_eq!(
            refused(satisfy_print(&obligations([Obligation::Watermark]), None, &system)),
            Some(ReasonCode::AccessDenied),
            "the system actor has no name to stamp onto a printed page"
        );

        let mut machine = RequestContext::system(tenant);
        machine.actor = Actor::ServiceAccount(enclave_core::ServiceAccountId::new_v7());
        assert_eq!(
            refused(satisfy_print(&obligations([Obligation::Watermark]), None, &machine)),
            Some(ReasonCode::AccessDenied),
            "a service account is not a person either"
        );

        // The controls. A real viewer is granted, or nothing prints at all...
        assert!(
            satisfy_print(&obligations([Obligation::Watermark]), None, &person()).is_ok(),
            "a person must be able to hold a watermarked print grant"
        );
        // ...and the same machine is granted an *unmarked* print, so the refusal above is about an
        // obligation this principal cannot discharge rather than about the principal.
        assert!(
            satisfy_print(&Obligations::none(), None, &machine).is_ok(),
            "a service account was refused a print grant that required no mark"
        );
    }

    fn capability(now: DateTime<Utc>) -> PrintCapability {''',
)

open(PATH, "w").write(s)
print("ok")
