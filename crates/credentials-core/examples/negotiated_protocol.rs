//! Report the HTTP version this workspace's client negotiates with each provider.
//!
//! The workspace enables reqwest's `http2` feature for one caller, and cargo unions
//! features across the graph, so the OAuth refresh client gets it too. Whether that
//! changes anything depends on a claim about ALPN: that a client offering h2 still
//! speaks HTTP/1.1 to a server that does not offer it, and that a server offering h2
//! is spoken to over h2 whether or not that was intended.
//!
//! That claim is about a library's behaviour against servers neither is ours, so it
//! is measured here rather than asserted in a comment. It exists because the answer
//! decides whether enabling the feature is inert for credential refresh or a change
//! to how every provider token is fetched.
//!
//! Each request is a deliberately empty POST to a token endpoint. The response is a
//! refusal in every case -- that is the point, since the protocol is negotiated
//! before the body is read, so a 400 reports the version just as well as a 200 and
//! costs the provider nothing.
//!
//! Run with: cargo run -p credentials-core --example negotiated_protocol

use credentials_core::http::ReqwestTransport;
use credentials_core::refresh_adapters::HttpTransport;

#[tokio::main]
async fn main() {
    // An UNPINNED client, built here rather than taken from the library.
    //
    // This used to be described as the construction the daemon ships, and that stopped
    // being true when `ReqwestTransport` was pinned to HTTP/1.1 -- so the arm below is
    // now a measurement of what the workspace's feature set MAKES AVAILABLE, not of
    // what production does. Both are worth knowing and they are no longer the same
    // thing: this arm says what would happen if the pin were removed, which is the
    // question anyone removing it will have.
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
    {
        Ok(client) => client,
        Err(why) => {
            eprintln!("could not build client: {why}");
            std::process::exit(1);
        }
    };

    // The token endpoints the refresh adapters actually post to.
    let endpoints = [
        ("anthropic", "https://platform.claude.com/v1/oauth/token"),
        ("google", "https://oauth2.googleapis.com/token"),
        ("openai", "https://auth.openai.com/oauth/token"),
        ("xai", "https://api.x.ai/v1/oauth2/token"),
        (
            "github-copilot",
            "https://github.com/login/oauth/access_token",
        ),
    ];

    println!("negotiated protocol per provider token endpoint");
    println!("(the client offers h2; the server decides)");
    println!();

    let mut h2_count = 0usize;
    let mut h1_count = 0usize;

    for (name, url) in endpoints {
        match client.post(url).body(Vec::new()).send().await {
            Ok(resp) => {
                let version = format!("{:?}", resp.version());
                match resp.version() {
                    reqwest::Version::HTTP_2 => h2_count += 1,
                    _ => h1_count += 1,
                }
                println!("  {name:<16} {version:<10} (status {})", resp.status());
            }
            Err(why) => {
                // A transport error means no response arrived at all, so there is no
                // negotiated protocol to report. Unlike an HTTP refusal such as 400,
                // which is a normal outcome here, it says the connection or the
                // protocol negotiation itself failed.
                println!("  {name:<16} TRANSPORT ERROR: {why}");
            }
        }
    }

    println!();
    println!("  {h2_count} endpoint(s) negotiated HTTP/2, {h1_count} negotiated HTTP/1.x");

    // THE CONTROL, and without it the run above establishes nothing about the
    // feature. Observing h2 everywhere is equally consistent with "the feature
    // changed this" and with "these endpoints were always reached over h2" -- the
    // second would mean something else in the graph had already enabled it and my
    // change was inert. Forcing HTTP/1.1 reproduces the pre-change client against
    // the same servers in the same run.
    println!();
    println!("control: the same client restricted to HTTP/1.1 (the pre-change shape)");
    let control = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .http1_only()
        .build()
    {
        Ok(client) => client,
        Err(why) => {
            eprintln!("could not build control client: {why}");
            std::process::exit(1);
        }
    };
    for (name, url) in endpoints {
        match control.post(url).body(Vec::new()).send().await {
            Ok(resp) => println!("  {name:<16} {:?}", resp.version()),
            Err(why) => println!("  {name:<16} TRANSPORT ERROR: {why}"),
        }
    }
    println!();

    // THE PRODUCTION TRANSPORT ITSELF, which neither arm above exercises.
    //
    // Both arms above build a client here, so both measure a construction that lives
    // in this file. The pin they exist to reason about lives in `ReqwestTransport`,
    // and nothing else reaches it against a real server: `reqwest::ClientBuilder`
    // offers the setting with no getter, a built client cannot be interrogated, and
    // the unit test asserts the call is PRESENT IN THE SOURCE rather than effective.
    //
    // So this arm closes the gap between "the pin is written" and "the pinned client
    // completes a real exchange". It cannot report the negotiated version -- the
    // transport returns a status and a body, deliberately, since adapters have no
    // business knowing the protocol -- but a completed request over a pinned client
    // is the property that matters: a pin that broke connectivity would fail here,
    // and nothing else would notice until a token needed refreshing.
    println!("production transport (ReqwestTransport, HTTP/1.1-pinned):");
    let transport = match ReqwestTransport::new() {
        Ok(t) => t,
        Err(why) => {
            eprintln!("could not build the production transport: {why}");
            std::process::exit(1);
        }
    };
    let mut completed = 0usize;
    for (name, url) in endpoints {
        match transport
            .post(url, &[], "application/x-www-form-urlencoded", Vec::new())
            .await
        {
            Ok(resp) => {
                completed += 1;
                // A 411 here is an artifact of the empty probe body, not a fault: over
                // HTTP/1.1 a POST without a body carries no Content-Length, and at
                // least one provider requires it. The same endpoint answers 400 once a
                // form body is present, which is what every real refresh sends.
                // Measured, because a status that appears only on the pinned arm looks
                // exactly like the pin having broken something.
                let note = if resp.status == 411 {
                    "  (length required: the empty probe body, not the pin)"
                } else {
                    ""
                };
                println!("  {name:<16} completed, status {}{note}", resp.status);
            }
            Err(why) => println!("  {name:<16} FAILED: {why}"),
        }
    }
    println!(
        "  {completed}/{} completed over the pinned client",
        endpoints.len()
    );

    println!();
    println!("Both outcomes are conformant: ALPN lets each server choose. The first two");
    println!("arms measure what the workspace's features make available; the third is");
    println!("what production actually uses, and only the third proves the pinned");
    println!("client can still reach these providers at all.");
}
