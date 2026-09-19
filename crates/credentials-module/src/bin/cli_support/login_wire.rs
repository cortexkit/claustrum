//! Which wire the interactive browser login uses, and the operator text that
//! matches it.
//!
//! WHY THIS IS ONE PLACE. Two values have to agree for a login to complete, and
//! they are read at opposite ends of the flow: the `redirect_uri` sent in the
//! authorize URL, and the `redirect_uri` replayed in the PKCE token exchange. The
//! provider compares them byte for byte and refuses the exchange on any difference
//! — AFTER the operator has already approved in the browser, which is the most
//! expensive place to fail. So the choice is made once, here, and handed back as a
//! single plan the caller uses everywhere.
//!
//! CLI-ONLY, like the listener beside it. The daemon never opens a browser and
//! never prompts.

use std::time::Duration;

use credentials_core::catalog::LoginProvider;
use credentials_core::oauth_login::build_authorize_url;

/// The wire choices for ONE login flow: the URL the operator opens, the redirect
/// that URL carries, and the paste prompt describing what that redirect produces.
pub struct LoginWirePlan {
    /// The authorize URL to print and open. Carries [`Self::redirect_uri`].
    pub authorize_url: String,
    /// The redirect in the authorize URL, which the token exchange MUST replay
    /// unchanged.
    pub redirect_uri: &'static str,
    /// The prompt to print when the callback has to be pasted, describing the
    /// artifact this redirect actually leaves the operator looking at.
    pub paste_prompt: &'static str,
}

/// Resolve the redirect and its matching paste prompt for one login, then build the
/// authorize URL from that single choice.
///
/// `listener_bound` is whether a CLI-local loopback listener is holding the
/// provider's redirect socket. When nothing is listening, a redirect to that socket
/// can only produce a failed page, so a provider that also registers a code-display
/// redirect is asked for that one instead: an operator approving on a second
/// machine then has a short code to carry back rather than the address bar of a
/// connection error.
pub fn plan_login_wire(
    wire: &LoginProvider,
    listener_bound: bool,
    challenge: &str,
    state: &str,
    extra_authorize_params: &[(&str, &str)],
) -> Result<LoginWirePlan, String> {
    let (redirect_uri, paste_prompt) = resolve_redirect(wire, listener_bound);
    let authorize_url = build_authorize_url(
        wire.authorize_url,
        wire.client_id,
        redirect_uri,
        wire.scopes,
        challenge,
        state,
        extra_authorize_params,
    )
    .map_err(|e| e.to_string())?;
    Ok(LoginWirePlan {
        authorize_url,
        redirect_uri,
        paste_prompt,
    })
}

/// The redirect choice itself, without building anything: which redirect this login
/// sends and the prompt that describes what it leaves behind.
///
/// The two are taken as a PAIR, so a catalog row that filled in only one of them
/// falls back to the loopback redirect whole rather than sending a code-display
/// redirect with address-bar instructions. The catalog test asserts the pair is
/// always complete, which makes this a floor rather than the expected shape.
fn resolve_redirect(wire: &LoginProvider, listener_bound: bool) -> (&'static str, &'static str) {
    match (
        listener_bound,
        wire.code_redirect_uri,
        wire.code_paste_prompt,
    ) {
        (false, Some(code_redirect), Some(code_prompt)) => (code_redirect, code_prompt),
        _ => (wire.redirect_uri, wire.paste_prompt),
    }
}

/// What the operator is told while a bound listener waits for the redirect.
///
/// THE BANNER MUST NOT PROMISE MORE THAN THE BIND GIVES. A bound listener completes
/// the login automatically only when the browser that follows the redirect is on
/// THIS machine. An operator who opens the printed URL on a second computer — the
/// usual case when the account to custody is signed in elsewhere — approves
/// successfully and then sees nothing happen here for the whole wait. That wait does
/// end in a paste prompt, so the flow is recoverable; an operator who was told the
/// login completes automatically reads the silence as a hang and interrupts it
/// instead.
///
/// The seconds come from the caller's timeout rather than the text, so the promise
/// cannot drift away from the code that enforces it.
pub fn listener_wait_banner(wait: Duration) -> String {
    format!(
        "Approve in the browser.\n\
         \u{b7} If that browser is on THIS machine, the login completes here automatically.\n\
         \u{b7} If it is on another machine, nothing happens here for up to {secs} seconds \u{2014} \
         then this command asks you to paste the callback from that browser.",
        secs = wait.as_secs()
    )
}

#[cfg(test)]
mod tests {
    use credentials_core::catalog::{login_provider, LOGIN_PROVIDERS};

    use super::*;

    /// The `cmd_login` source, for the assertions below that are about WHERE a value
    /// is read. A behavioral test can prove the authorize URL and the plan agree; it
    /// cannot reach the exchange arms without a live provider, and those arms are
    /// exactly where a re-derived redirect costs the operator an approval already
    /// given.
    fn cmd_login_source() -> &'static str {
        const CLI: &str = include_str!("../credentials_cli.rs");
        let start = CLI.find("\nfn cmd_login(").expect("cmd_login is defined");
        let body = &CLI[start + 1..];
        let end = body[1..]
            .find("\nfn ")
            .map(|offset| offset + 1)
            .unwrap_or(body.len());
        &body[..end]
    }

    /// Pull `redirect_uri` back out of a built authorize URL and undo the
    /// percent-encoding the query serializer applied. Written here because the CLI
    /// binary has no URL crate, and comparing against a hand-encoded expectation
    /// would test the test's encoder.
    fn redirect_param(authorize_url: &str) -> String {
        let query = authorize_url
            .split_once('?')
            .expect("an authorize URL carries a query")
            .1;
        let raw = query
            .split('&')
            .find_map(|pair| pair.strip_prefix("redirect_uri="))
            .expect("the authorize URL carries redirect_uri");
        let bytes = raw.as_bytes();
        let mut decoded = Vec::with_capacity(bytes.len());
        let mut index = 0;
        while index < bytes.len() {
            match bytes[index] {
                b'%' => {
                    let hex =
                        std::str::from_utf8(&bytes[index + 1..index + 3]).expect("hex digits");
                    decoded.push(u8::from_str_radix(hex, 16).expect("hex escape"));
                    index += 3;
                }
                b'+' => {
                    decoded.push(b' ');
                    index += 1;
                }
                byte => {
                    decoded.push(byte);
                    index += 1;
                }
            }
        }
        String::from_utf8(decoded).expect("a redirect is utf-8")
    }

    /// THE LOAD-BEARING ONE. The provider refuses the token exchange unless the
    /// `redirect_uri` it replays byte-matches the one in the authorize URL, and that
    /// refusal lands after the operator has approved — so one redirect has to reach
    /// the authorize build and both exchange arms. The first half proves the built
    /// URL carries the plan's own value on both the listener and no-listener paths;
    /// the second proves the exchange arms read that plan rather than re-deriving
    /// the redirect from the catalog row.
    #[test]
    fn the_authorize_url_and_both_exchange_arms_replay_one_redirect() {
        for key in ["anthropic", "openai", "xai", "google"] {
            let wire = login_provider(key).expect("a catalog row");
            for listener_bound in [true, false] {
                let plan = plan_login_wire(wire, listener_bound, "challenge", "state", &[])
                    .expect("authorize url");
                assert_eq!(
                    redirect_param(&plan.authorize_url),
                    plan.redirect_uri,
                    "{key} (listener_bound={listener_bound}): the authorize URL must carry the \
                     exact redirect the exchange replays, or the exchange fails with \
                     invalid_grant after the operator has already approved"
                );
            }
        }

        let source = cmd_login_source();
        assert_eq!(
            source.matches("plan.redirect_uri").count(),
            2,
            "both exchange arms (AnthropicJson and RfcForm) must pass plan.redirect_uri; \
             a re-derived redirect there is an invalid_grant after browser approval"
        );
        assert_eq!(
            source.matches("wire.redirect_uri").count(),
            1,
            "the ONLY read of wire.redirect_uri left in cmd_login is the loopback bind \
             (the socket is always the loopback one); everything on the wire comes from \
             the plan"
        );
        assert!(
            source.contains("loopback_bind_addr(wire.redirect_uri)"),
            "the single wire.redirect_uri read must be the listener bind"
        );
        assert!(
            source.contains("listener_wait_banner(login_listener::LISTEN_TIMEOUT)"),
            "the wait the banner names must be the constant the listener actually waits"
        );
    }

    /// Defect the operator hit: with no listener the authorize URL still pointed at a
    /// socket nobody was holding, so approving on a second machine produced a failed
    /// page and no usable artifact.
    #[test]
    fn a_provider_with_a_code_redirect_uses_it_only_when_no_listener_is_bound() {
        let anthropic = login_provider("anthropic").expect("the anthropic row");

        let pasting = plan_login_wire(anthropic, false, "challenge", "state", &[]).expect("url");
        assert_eq!(
            pasting.redirect_uri,
            "https://platform.claude.com/oauth/code/callback"
        );
        assert!(
            !pasting.authorize_url.contains("54545"),
            "no listener means no socket to redirect to: {}",
            pasting.authorize_url
        );
        assert_eq!(pasting.paste_prompt, anthropic.code_paste_prompt.unwrap());

        let listening = plan_login_wire(anthropic, true, "challenge", "state", &[]).expect("url");
        assert_eq!(listening.redirect_uri, anthropic.redirect_uri);
        assert!(
            listening.authorize_url.contains("54545"),
            "a bound listener must be sent the loopback redirect it is holding: {}",
            listening.authorize_url
        );
        assert_eq!(listening.paste_prompt, anthropic.paste_prompt);
    }

    /// Every other row has no verified code-display redirect, so both paths keep the
    /// loopback redirect and the address-bar prompt. Asserted on the choice rather
    /// than on a built URL, so it covers the rows whose authorize endpoint is a
    /// template or empty (snowflake, kimi) alongside the rest.
    #[test]
    fn a_provider_without_a_code_redirect_keeps_its_loopback_redirect_on_both_paths() {
        let without_a_code_redirect: Vec<_> = LOGIN_PROVIDERS
            .iter()
            .filter(|entry| entry.code_redirect_uri.is_none())
            .collect();
        assert!(
            without_a_code_redirect.len() >= 10,
            "most of the table has no code-display redirect; a shrunken population here \
             would make this assertion cover nothing"
        );
        for wire in without_a_code_redirect {
            for listener_bound in [true, false] {
                assert_eq!(
                    resolve_redirect(wire, listener_bound),
                    (wire.redirect_uri, wire.paste_prompt),
                    "{} (listener_bound={listener_bound})",
                    wire.key
                );
            }
        }
    }

    /// The banner's wait is derived, not typed: a literal would keep promising 300
    /// seconds after someone changed the timeout, and the operator's whole reason to
    /// keep waiting is that the number is true.
    #[test]
    fn the_listener_banner_derives_its_wait_from_the_timeout_it_is_given() {
        let short = listener_wait_banner(Duration::from_secs(7));
        assert!(
            short.contains("up to 7 seconds"),
            "the banner must name the wait it was given: {short}"
        );
        assert!(
            !short.contains("300"),
            "a hardcoded wait survives a timeout change and lies from then on: {short}"
        );

        let shipped = listener_wait_banner(crate::login_listener::LISTEN_TIMEOUT);
        assert!(shipped.contains(&format!(
            "up to {} seconds",
            crate::login_listener::LISTEN_TIMEOUT.as_secs()
        )));
        // The banner is printed when a listener bound, which does NOT mean the
        // browser is here. It must not claim the completion is unconditional, and it
        // must not tell the operator to ignore the page — on a second machine that
        // page is the only thing they can carry back.
        assert!(
            shipped.contains("THIS machine") && shipped.contains("another machine"),
            "the banner must state the condition the automatic completion depends on: {shipped}"
        );
        assert!(
            !shipped.to_lowercase().contains("ignore"),
            "nothing in the browser is safe to ignore: {shipped}"
        );
    }
}
