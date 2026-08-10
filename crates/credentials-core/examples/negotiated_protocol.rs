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

#[tokio::main]
async fn main() {
    // The same construction the daemon ships: a default client with a timeout. Not a
    // hand-tuned one, because the question is what the PRODUCTION path negotiates.
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
    println!("Both outcomes are conformant: ALPN lets each server choose. What this");
    println!("run establishes is which providers ACTUALLY move to h2 when the feature");
    println!("is enabled -- i.e. how much of the refresh path changes behaviour at the");
    println!("next release build, rather than how much could in principle.");
}
