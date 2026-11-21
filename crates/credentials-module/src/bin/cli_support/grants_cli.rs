//! Grant, category, and declared-grant commands and rendering.

use super::{
    commit_admin, format_ts_ms, live_enrollment_named, optional, print_store_behind_note,
    request_admin_status_with_schema, required, store_path, AdminOpBody, CliError, GlobalArgs,
    GrantOperation, SelectorKind, ADMIN_OP_SCHEMA_V2,
};

#[derive(Debug)]
pub(super) struct GrantRow {
    pub(super) principal_kind: String,
    pub(super) principal_id: String,
    pub(super) selector_kind: String,
    pub(super) credential_prefix: String,
    pub(super) operation: String,
    created_at_ms: i64,
}

/// Credential id -> its assigned member-local categories, including remote copies,
/// read from the same `admin.status` reply the grant table is rendered from.
///
/// Tolerant by design: a reply without the inventory yields an empty map and every grant
/// renders `reaches 0`. That is honest rather than silent -- an operator seeing every row
/// at zero will question the reading, where a missing column would just be absent.
fn parse_credential_categories(
    result: &serde_json::Value,
) -> std::collections::BTreeMap<String, Vec<String>> {
    let mut map = std::collections::BTreeMap::new();
    // Scoped coverage prefers local metadata if both tables contain an id. Preserve
    // that precedence while counting each id only once.
    for row in ["remote_credentials", "credentials"]
        .iter()
        .filter_map(|member| result.get(member).and_then(serde_json::Value::as_array))
        .flatten()
    {
        let Some(id) = row.get("id").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let categories = row
            .get("categories")
            .and_then(serde_json::Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        map.insert(id.to_owned(), categories);
    }
    map
}

pub(super) fn parse_grants(result: &serde_json::Value) -> Result<Vec<GrantRow>, CliError> {
    let rows = result
        .get("read_grants")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            CliError::StatusReportInvalid("admin.status omitted grant inventory".into())
        })?;
    let mut grants = Vec::with_capacity(rows.len());
    for (index, grant) in rows.iter().enumerate() {
        // RENDER WHAT IS THERE; REFUSE ONLY WHAT IS ABSENT.
        //
        // This filter used to require `reserved` exactly, which was true when reserved
        // modules were the only principals that could hold a grant. Enrollment added
        // `enrolled`, and the CLI could CREATE one (`parse_grant_principal`) while being
        // unable to display one -- so `ck auth grants` and `ck auth status` both died on
        // a row this same binary had written.
        //
        // The worse half was the blast radius: ONE UNRENDERABLE ROW REFUSED THE ENTIRE
        // INVENTORY, so a single grant took down the only surface an operator has for
        // seeing grants at all. That is the shape of issue #45 in this repo -- one
        // tenant's bad row denying every other tenant -- reached independently in my own
        // CLI.
        //
        // So an unknown kind now RENDERS, carrying its literal text. A grant an operator
        // cannot see is strictly more dangerous than one that displays with an unfamiliar
        // label, because the label is a prompt to investigate and the absence is not.
        // A missing or empty kind is still a refusal: that is a malformed reply rather
        // than an unfamiliar one, and it would render as a blank column.
        let principal_kind = grant
            .get("principal_kind")
            .and_then(serde_json::Value::as_str)
            .filter(|kind| !kind.is_empty())
            .ok_or_else(|| {
                CliError::StatusReportInvalid(format!(
                    "admin.status returned a grant with no principal kind at row {index}"
                ))
            })?;
        let principal_id = grant
            .get("principal_id")
            .and_then(serde_json::Value::as_str)
            .filter(|id| !id.is_empty())
            .ok_or_else(|| {
                CliError::StatusReportInvalid(format!(
                    "admin.status returned an invalid grant principal at row {index}"
                ))
            })?;
        let selector_kind = grant
            .get("selector_kind")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("exact");
        if !matches!(selector_kind, "exact" | "category" | "audience") {
            return Err(CliError::StatusReportInvalid(format!(
                "admin.status returned an invalid selector kind at row {index}"
            )));
        }
        let credential_prefix = grant
            .get("credential_prefix")
            .and_then(serde_json::Value::as_str)
            .filter(|prefix| !prefix.is_empty())
            .ok_or_else(|| {
                CliError::StatusReportInvalid(format!(
                    "admin.status returned an invalid grant prefix at row {index}"
                ))
            })?;
        let operation = grant
            .get("operation")
            .and_then(serde_json::Value::as_str)
            .filter(|operation| operation.parse::<GrantOperation>().is_ok())
            .ok_or_else(|| {
                CliError::StatusReportInvalid(format!(
                    "admin.status returned an invalid grant operation at row {index}"
                ))
            })?;
        let created_at_ms = grant
            .get("created_at_ms")
            .and_then(serde_json::Value::as_i64)
            .ok_or_else(|| {
                CliError::StatusReportInvalid(format!(
                    "admin.status returned an invalid grant creation time at row {index}"
                ))
            })?;
        grants.push(GrantRow {
            principal_kind: principal_kind.to_string(),
            principal_id: principal_id.to_string(),
            selector_kind: selector_kind.to_string(),
            credential_prefix: credential_prefix.to_string(),
            operation: operation.to_string(),
            created_at_ms,
        });
    }

    let mut prior: Option<(String, String, String, String, String)> = None;
    for grant in &grants {
        let order_key = (
            grant.principal_kind.clone(),
            grant.principal_id.clone(),
            grant.selector_kind.clone(),
            grant.credential_prefix.clone(),
            grant.operation.clone(),
        );
        if prior
            .as_ref()
            .is_some_and(|previous| previous >= &order_key)
        {
            return Err(CliError::StatusReportInvalid(
                "admin.status returned grants out of stable order".into(),
            ));
        }
        prior = Some(order_key);
    }
    grants.sort_by(|left, right| {
        let key = |grant: &GrantRow| {
            (
                grant.principal_kind.clone(),
                grant.principal_id.clone(),
                grant.selector_kind.clone(),
                grant.credential_prefix.clone(),
                grant
                    .operation
                    .parse::<GrantOperation>()
                    .expect("validated grant operation"),
            )
        };
        key(left).cmp(&key(right))
    });
    Ok(grants)
}

/// Print one stable row per principal-scoped grant, including the creation time.
///
/// WIDTHS ARE MEASURED FROM THE ROWS, NOT FIXED. The fixed `{:<24}` this replaced was
/// narrower than a measured 26-character selector, so that row pushed its last two
/// columns right while every other row stayed aligned. A table where one row is offset
/// reads as a rendering fault in the VALUE -- I misread a correct selector as truncated
/// output on the strength of it, and only the store settled it.
///
/// The header is here for the same reason. Without it the operation column (`read` /
/// `sign`) and the principal kind are both short lowercase words, and nothing on screen
/// says which is which.
fn render_grants(result: &serde_json::Value) -> Result<Vec<String>, CliError> {
    let grants = parse_grants(result)?;
    if grants.is_empty() {
        return Ok(vec!["no grants".to_owned()]);
    }
    // Include the header in the width so a long heading cannot overrun its own column.
    let w = |head: &str, f: &dyn Fn(&GrantRow) -> &str| {
        grants
            .iter()
            .map(|g| f(g).chars().count())
            .chain(std::iter::once(head.chars().count()))
            .max()
            .unwrap_or(head.len())
    };
    let wk = w("KIND", &|g| g.principal_kind.as_str());
    let wp = w("PRINCIPAL", &|g| g.principal_id.as_str());
    let ws = w("SELECTOR KIND", &|g| g.selector_kind.as_str());
    let wc = w("SELECTOR", &|g| g.credential_prefix.as_str());
    let wo = w("OP", &|g| g.operation.as_str());

    // REACH IS THE COLUMN THAT MAKES A WRONG GRANT VISIBLE.
    //
    // Every other column renders what the operator TYPED, so a grant that authorizes
    // nothing looks identical to one that works. That is not hypothetical: a
    // `category:llm-provider` grant was created on this vault while no credential
    // carried that category, because registry defaults apply at CREATION and every
    // credential predated the migration that introduced categories. It was
    // syntactically valid, accepted without complaint, reached zero credentials, and
    // read as correct in this exact table. A consumer asking me to double-check a
    // selector is the only reason it was caught.
    //
    // `reaches 0` stays LEGAL rather than a refusal: granting an empty category is how
    // an operator prepares reach for a module about to be installed. The column is what
    // keeps that honest -- a permanent visible statement rather than a one-time warning
    // that scrolls past.
    //
    // Both output paths use the same status inventory, including member-local
    // categories for remote copies when the vault supplies them.
    let inventory = parse_credential_categories(result);
    let reach = |g: &GrantRow| -> usize {
        let selector = g
            .credential_prefix
            .strip_prefix("category:")
            .filter(|_| g.selector_kind == "category")
            .unwrap_or(&g.credential_prefix);
        grant_reach(&inventory, &g.selector_kind, selector)
    };

    let mut lines = vec![format!(
        "{:<wk$}  {:<wp$}  {:<ws$}  {:<wc$}  {:<wo$}  {:>7}  GRANTED",
        "KIND", "PRINCIPAL", "SELECTOR KIND", "SELECTOR", "OP", "REACHES"
    )];
    for grant in grants {
        lines.push(format!(
            "{:<wk$}  {:<wp$}  {:<ws$}  {:<wc$}  {:<wo$}  {:>7}  {}",
            grant.principal_kind,
            grant.principal_id,
            grant.selector_kind,
            grant
                .credential_prefix
                .strip_prefix("category:")
                .filter(|_| grant.selector_kind == "category")
                .unwrap_or(&grant.credential_prefix),
            grant.operation,
            if grant.selector_kind == "audience" {
                "token".to_owned()
            } else {
                reach(&grant).to_string()
            },
            format_ts_ms(grant.created_at_ms)
        ));
    }
    Ok(lines)
}

/// How many credentials a grant reaches NOW, from the credential-id -> categories map
/// `parse_credential_categories` reads out of `admin.status`.
///
/// One function for both places that report reach (the REACHES column of `ck auth grants`
/// and the line `ck auth grant` prints), so the two can never disagree about the same
/// grant. `selector` is the bare value: a category name without any `category:` marker.
fn grant_reach(
    inventory: &std::collections::BTreeMap<String, Vec<String>>,
    selector_kind: &str,
    selector: &str,
) -> usize {
    match selector_kind {
        "audience" => 0,
        "category" => inventory
            .values()
            .filter(|categories| categories.iter().any(|c| c == selector))
            .count(),
        // `exact` is byte equality, deliberately: a grant whose reach can grow when
        // someone else names a credential is not a grant anyone can reason about.
        _ => inventory.contains_key(selector) as usize,
    }
}

/// Credentials that carry NO category at all but whose registry defaults include
/// `category`.
///
/// These are almost always credentials created before categories existed: defaults are
/// stamped at creation and no migration backfills old rows. `ck auth reclassify
/// --from-registry` (without `--force`) fills exactly these empty sets and removes
/// nothing. Nothing here fills them automatically, because an operator may have emptied a
/// set on purpose to keep a credential out of every category grant, and silently putting
/// it back would widen access.
fn credentials_awaiting_category(
    inventory: &std::collections::BTreeMap<String, Vec<String>>,
    category: &str,
) -> Vec<String> {
    inventory
        .iter()
        .filter(|(id, categories)| {
            categories.is_empty()
                && credentials_core::catalog::category_defaults(id)
                    .iter()
                    .any(|default| default == category)
        })
        .map(|(id, _)| id.clone())
        .collect()
}

/// What `ck auth grant` says about a grant's reach, split into the stdout line and the
/// stderr advisory so a test drives the real wording rather than a copy of it.
#[derive(Debug, Default)]
pub(super) struct GrantReachReport {
    pub(super) stdout: Vec<String>,
    pub(super) stderr: Vec<String>,
}

/// At most this many credential ids are named in the reclassify advisory; the rest are
/// counted. Enough to recognise the family, short enough to read in a terminal.
const AWAITING_CATEGORY_IDS_SHOWN: usize = 5;

/// Describe what a just-created grant reaches, from the `admin.status` reply read after it.
///
/// A grant that reaches nothing is LEGAL (a category can be granted before any credential
/// carries it), so this never refuses. It warns instead, because the case that prompted
/// it was a consumer granted a category none of its credentials carried: the grant
/// printed `granted` and nothing else, and the consumer could only report an empty vault.
/// `deposit` is exempt from the warning: it is category-only and its reach is about
/// cookies a module has not written yet, so zero is the normal starting state.
pub(super) fn render_grant_reach(
    result: &serde_json::Value,
    selector_kind: SelectorKind,
    selector: &str,
    operation: GrantOperation,
) -> GrantReachReport {
    if selector_kind == SelectorKind::Audience {
        return GrantReachReport {
            stdout: vec![format!("  exchanges tokens for audience {selector}")],
            stderr: Vec::new(),
        };
    }
    let inventory = parse_credential_categories(result);
    let kind = selector_kind.as_str();
    let reach = grant_reach(&inventory, kind, selector);
    let plural = |n: usize| if n == 1 { "credential" } else { "credentials" };
    let mut report = GrantReachReport::default();
    report
        .stdout
        .push(format!("  reaches {reach} {}", plural(reach)));

    let awaiting = if kind == "category" {
        credentials_awaiting_category(&inventory, selector)
    } else {
        Vec::new()
    };
    let warn = reach == 0 && operation != GrantOperation::Deposit;
    if warn {
        report
            .stderr
            .push("warning: this grant is valid but reaches no credential now.".to_owned());
        if kind == "category" {
            report
                .stderr
                .push(format!("  No credential carries category '{selector}'."));
        } else {
            report
                .stderr
                .push(format!("  No credential has the id '{selector}'."));
        }
    }
    // Named even when the grant reaches some credentials: older credentials that belong
    // in the category may still be left out because their category set is empty.
    if !awaiting.is_empty() {
        let mut named = awaiting
            .iter()
            .take(AWAITING_CATEGORY_IDS_SHOWN)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        if awaiting.len() > AWAITING_CATEGORY_IDS_SHOWN {
            named.push_str(&format!(
                ", and {} more",
                awaiting.len() - AWAITING_CATEGORY_IDS_SHOWN
            ));
        }
        report.stderr.push(format!(
            "  {} {} would join '{selector}' but {} no categories yet (created before \
             categories existed): {named}",
            awaiting.len(),
            plural(awaiting.len()),
            if awaiting.len() == 1 { "has" } else { "have" },
        ));
        report
            .stderr
            .push("  Run: ck auth reclassify --from-registry".to_owned());
    }
    if warn && kind == "category" {
        let fix = format!("ck auth set-category <credential-id> --add {selector}");
        if awaiting.is_empty() {
            report
                .stderr
                .push(format!("  To put a credential in it: {fix}"));
        } else {
            report
                .stderr
                .push(format!("  Or assign one by hand: {fix}"));
        }
        // The same table `ck auth categories` prints, so the operator can see whether the
        // selector is a typo for a category that does exist.
        match render_categories(result) {
            Ok(lines) => {
                report
                    .stderr
                    .push("  Categories in this vault (ck auth categories):".to_owned());
                report
                    .stderr
                    .extend(lines.into_iter().map(|line| format!("    {line}")));
            }
            Err(error) => report
                .stderr
                .push(format!("  (could not list categories: {error})")),
        }
    } else if warn {
        report.stderr.push(
            "  It reaches that credential once one with exactly this id exists; \
             `ck auth list` shows the ids that do."
                .to_owned(),
        );
    }
    report
}

/// Print what `render_grants` produced.
///
/// The split exists so a test can drive the REAL formatter rather than a copy of it. A
/// test that rebuilt these rows by hand would assert its own arithmetic and pass with the
/// production renderer deleted.
fn print_grants(result: &serde_json::Value) -> Result<(), CliError> {
    for line in render_grants(result)? {
        println!("{line}");
    }
    Ok(())
}

/// Render the server's sorted grant set instead of asking an operator to mentally
/// expand prefixes. A newly covered id is a security-relevant status diff.
pub(super) fn print_read_grants(result: &serde_json::Value) -> Result<(), CliError> {
    let Some(raw_grants) = result.get("read_grants") else {
        // An older daemon cannot have created a grant, so there is no access set to
        // hide while a newly upgraded CLI is still talking to it.
        return Ok(());
    };
    let raw_grants = raw_grants.as_array().ok_or_else(|| {
        CliError::StatusReportInvalid("admin.status returned malformed read grants".into())
    })?;
    let grants = parse_grants(result)?;
    println!();
    if grants.is_empty() {
        println!("read grants: none");
        return Ok(());
    }
    println!("read grants:");
    for (index, grant) in grants.iter().enumerate() {
        let raw_grant = &raw_grants[index];
        let covered = raw_grant
            .get("covered_credential_ids")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| {
                CliError::StatusReportInvalid(format!(
                    "admin.status omitted covered credentials at grant row {index}"
                ))
            })?;
        println!(
            "  {}:{} {} {} {}",
            grant.principal_kind,
            grant.principal_id,
            grant.operation,
            grant.selector_kind,
            grant
                .credential_prefix
                .strip_prefix("category:")
                .filter(|_| grant.selector_kind == "category")
                .unwrap_or(&grant.credential_prefix)
        );
        let mut prior_id: Option<&str> = None;
        for (covered_index, id) in covered.iter().enumerate() {
            let id = id.as_str().filter(|id| !id.is_empty()).ok_or_else(|| {
                CliError::StatusReportInvalid(format!(
                    "admin.status returned an invalid covered credential at grant row {index}, row {covered_index}"
                ))
            })?;
            if grant.selector_kind == "exact" && !id.starts_with(&grant.credential_prefix) {
                return Err(CliError::StatusReportInvalid(format!(
                    "admin.status listed a credential outside its grant selector at grant row {index}"
                )));
            }
            if prior_id.is_some_and(|prior| prior >= id) {
                return Err(CliError::StatusReportInvalid(format!(
                    "admin.status returned covered credentials out of stable order at grant row {index}"
                )));
            }
            prior_id = Some(id);
            println!("    {id}");
        }
    }
    Ok(())
}

/// Parse a grant principal into its `(kind, id)` pair.
///
/// TWO KINDS, AND THE BARE SPELLING MEANS `reserved` FOR COMPATIBILITY. `reserved:<id>`
/// names a supervised module, attested by the supervisor's launch nonce. `enrolled:<name>`
/// names a consumer this vault admitted through the enrollment ceremony. A bare `<id>`
/// with no colon is read as `reserved`, because that was the only kind when the flag was
/// introduced and every existing script spells it that way.
///
/// The bare default is deliberately the NARROWER of the two to fail safe: a typo that
/// drops the prefix grants to a module principal that probably does not exist, reaching
/// nothing, rather than to an enrolled name that might.
fn parse_grant_principal(principal: &str) -> Result<(String, String), CliError> {
    if principal.contains('|') {
        return Err(CliError::Usage("invalid_principal: '|' is reserved".into()));
    }
    match principal.split_once(':') {
        None if !principal.is_empty() => Ok(("reserved".to_string(), principal.to_string())),
        Some(("reserved", id)) if !id.is_empty() && !id.contains(':') => {
            Ok(("reserved".to_string(), id.to_string()))
        }
        Some(("enrolled", name)) if !name.is_empty() && !name.contains(':') => {
            Ok(("enrolled".to_string(), name.to_string()))
        }
        Some((kind, _)) => Err(CliError::Usage(format!(
            "invalid_principal: expected reserved:<module> or enrolled:<name> (got {kind})"
        ))),
        None => Err(CliError::Usage("invalid_principal: empty principal".into())),
    }
}

fn parse_grant_selector(args: &[String]) -> Result<(SelectorKind, String), CliError> {
    // `--prefix` IS REFUSED RATHER THAN ALIASED, and `--selector-kind` has no default.
    //
    // The tempting version of this migration keeps `--prefix` as a deprecated alias for
    // `exact`. That is worse than removing it, and the reason is the same one the whole
    // selector change exists for: it SUCCEEDS while silently changing what the operator
    // granted. `--prefix apikey:` used to reach every credential under `apikey:` — on my
    // vault, seventeen of them. Aliased to `exact` it reaches the credential LITERALLY
    // NAMED `apikey:`, which does not exist, so the command prints success and creates a
    // grant covering nothing while the operator believes they granted a family.
    //
    // `ck auth grants` would eventually show `reaches 0`, but that is a different command
    // read at a different time. A refusal at the point of creation is the only version
    // where the operator's belief and the stored row cannot diverge.
    //
    // Defaulting `--selector-kind` to `exact` has the same defect in a quieter form: an
    // operator who omits it gets a decision made for them about reach. Requiring it makes
    // them state the intent, which is cheap exactly once per grant.
    if optional(args, "--prefix").is_some() {
        return Err(CliError::Usage(
            "--prefix is gone: a prefix grant's reach changed whenever someone named a \
             new credential. Use --selector-kind exact --selector <credential-id> for one \
             credential, or --selector-kind category --selector <category> for a set that \
             moves deliberately. A former --prefix that named a family is a category now, \
             not an exact selector."
                .into(),
        ));
    }
    let selector_kind = optional(args, "--selector-kind")
        .ok_or_else(|| {
            CliError::Usage(
                "grant requires --selector-kind exact|category|audience (no default: the kind \
                 decides whether this grant's reach can change without you)"
                    .into(),
            )
        })?
        .parse::<SelectorKind>()
        .map_err(CliError::Usage)?;
    let selector = optional(args, "--selector")
        .ok_or_else(|| CliError::Usage("grant requires --selector".into()))?;
    Ok((selector_kind, selector))
}

pub(super) fn cmd_grant(global: &GlobalArgs, args: &[String]) -> Result<(), CliError> {
    let (principal_kind, principal_id) = parse_grant_principal(&required(args, "--principal")?)?;
    // A grant to a name `enroll approve` can never accept would sit unusable forever, so
    // creation applies the approval grammar. Revocation deliberately does not: it must
    // still remove grants that older builds created without this check.
    if principal_kind == "enrolled"
        && !credentials_core::enrollment::valid_enrollment_name(&principal_id)
    {
        return Err(CliError::Usage(format!(
            "invalid_principal: enrolled name '{principal_id}' is not one `enroll approve` \
             accepts. Names are 2 to 32 lowercase letters, digits and dashes; pick a \
             shorter name and use it for both approve and grant"
        )));
    }
    let (selector_kind, selector) = parse_grant_selector(args)?;
    let operation = required(args, "--operation")?
        .parse::<GrantOperation>()
        .map_err(CliError::Usage)?;
    if selector_kind != SelectorKind::Exact
        || !credentials_core::federation::is_bus_seal_key_id(&selector)
    {
        selector_kind
            .validate_operation(operation)
            .map_err(CliError::Usage)?;
    }
    // The CLI refuses before it contacts the daemon, so an operator gets the reason as
    // usage text instead of a daemon refusal, using the same allowlist as the store.
    if selector_kind == SelectorKind::Exact {
        credentials_core::federation::transfer_key_admits_grant(
            &selector,
            &format!("{principal_kind}:{principal_id}"),
            operation,
        )
        .map_err(CliError::Usage)?;
    }
    let result = commit_admin(
        global,
        AdminOpBody::GrantCreateV2 {
            v: ADMIN_OP_SCHEMA_V2,
            principal_kind: principal_kind.clone(),
            principal_id: principal_id.clone(),
            selector_kind,
            selector: selector.clone(),
            operation,
        },
    )?;
    let verb = if result.get("already_granted").and_then(|v| v.as_bool()) == Some(true) {
        "already granted (no change)"
    } else {
        "granted"
    };
    println!(
        "{verb} {principal_kind}:{principal_id} {} {}:{selector}",
        operation.as_str(),
        selector_kind.as_str()
    );
    if result
        .get("declared_covers")
        .and_then(serde_json::Value::as_bool)
        == Some(true)
    {
        println!("  the last-seen declaration also lists this tuple");
    }
    if principal_kind == "enrolled" {
        // Enrollment liveness is advisory, just like credential reach: the grant already
        // exists, and granting a name before approval is allowed.
        match credentials_core::store::list_enrollments_read_only(&store_path(global)) {
            Ok(rows) if !live_enrollment_named(&rows, &principal_id) => {
                eprintln!(
                    "warning: no live enrollment holds the name '{principal_id}', so nothing \
                     can use this grant now.\n  Approval under exactly this name requires \
                     --keep-grants to explicitly inherit it."
                );
                eprintln!(
                    "  If this was a mistake: ck auth revoke-grant --principal \
                     enrolled:{principal_id} --selector-kind {} --selector '{}' --operation {}",
                    selector_kind.as_str(),
                    selector.replace('\'', "'\\''"),
                    operation.as_str()
                );
            }
            Ok(_) => {}
            Err(error) => {
                eprintln!("  (enrollment not checked: could not read enrollments: {error})")
            }
        }
    }
    // The grant is committed by now. Reading reach back is advisory: if the status read
    // fails, say so in one line and still succeed, because failing here would report a
    // grant that exists as one that does not.
    match request_admin_status_with_schema(global) {
        Ok((status, store_schema)) => {
            let report = render_grant_reach(&status, selector_kind, &selector, operation);
            for line in report.stdout {
                println!("{line}");
            }
            for line in report.stderr {
                eprintln!("{line}");
            }
            // A store one migration behind has no categories yet, so its reach reads
            // zero for a reason the note names.
            print_store_behind_note(store_schema);
        }
        Err(error) => eprintln!("  (reach not checked: could not read vault status: {error})"),
    }
    Ok(())
}

pub(super) fn cmd_revoke_grant(global: &GlobalArgs, args: &[String]) -> Result<(), CliError> {
    let (principal_kind, principal_id) = parse_grant_principal(&required(args, "--principal")?)?;
    let (selector_kind, selector) = parse_grant_selector(args)?;
    let operation = required(args, "--operation")?
        .parse::<GrantOperation>()
        .map_err(CliError::Usage)?;
    selector_kind
        .validate_operation(operation)
        .map_err(CliError::Usage)?;
    if selector_kind == SelectorKind::Exact {
        credentials_core::federation::transfer_key_admits_grant(
            &selector,
            &format!("{principal_kind}:{principal_id}"),
            operation,
        )
        .map_err(CliError::Usage)?;
    }
    let result = commit_admin(
        global,
        AdminOpBody::GrantRevokeV2 {
            v: ADMIN_OP_SCHEMA_V2,
            principal_kind: principal_kind.clone(),
            principal_id: principal_id.clone(),
            selector_kind,
            selector: selector.clone(),
            operation,
        },
    )?;
    println!(
        "revoked {principal_kind}:{principal_id} {} {}:{selector}",
        operation.as_str(),
        selector_kind.as_str()
    );
    if result
        .get("declared_still_listed")
        .and_then(serde_json::Value::as_bool)
        == Some(true)
    {
        println!("  the last-seen declaration still lists this tuple");
    }
    Ok(())
}

/// Render every category that exists, what it covers, and which grants name it.
///
/// THE OTHER HALF OF THE REACH COLUMN. That column tells an operator a grant reaches
/// nothing AFTER they create it; this tells them what is there BEFORE. Both exist because
/// a category selector fails CLOSED and SILENTLY: a grant naming a category nothing
/// carries is syntactically valid, accepted without complaint, and authorizes zero
/// credentials, which is indistinguishable from a working grant by reading it.
///
/// Not hypothetical: registry defaults apply at CREATION, so credentials older than the
/// migration that introduced categories carry none of them. A `category:llm-provider`
/// grant on such a vault reaches nothing, and nothing on either side says so.
///
/// UNCATEGORIZED IS A ROW, not an omission. Some credentials carry no category
/// deliberately, so hiding the count would make a FORGOTTEN assignment indistinguishable
/// from an INTENDED one -- the same silence one level up.
///
/// Lease-free, like every other read verb, and for the same reason: the moment an operator
/// asks is the moment the vault is running.
pub(super) fn cmd_categories(global: &GlobalArgs) -> Result<(), CliError> {
    let (result, store_schema) = request_admin_status_with_schema(global)?;
    for line in render_categories(&result)? {
        println!("{line}");
    }
    print_store_behind_note(store_schema);
    Ok(())
}

/// Build the category table. Split from printing so a test drives the real formatter
/// rather than a hand-built copy of its arithmetic.
fn render_categories(result: &serde_json::Value) -> Result<Vec<String>, CliError> {
    let inventory = parse_credential_categories(result);
    if inventory.is_empty() {
        return Ok(vec!["no credentials".to_owned()]);
    }
    let grants = parse_grants(result)?;

    let mut counts: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    let mut uncategorized = 0usize;
    for categories in inventory.values() {
        if categories.is_empty() {
            uncategorized += 1;
            continue;
        }
        for category in categories {
            *counts.entry(category.clone()).or_default() += 1;
        }
    }

    // A category NAMED BY A GRANT but carried by no credential must appear, at zero.
    // Omitting it hides exactly the row an operator is looking for: the reach column says
    // a grant reaches nothing, and this is where they come to find out why.
    for grant in &grants {
        if grant.selector_kind == "category" {
            let name = grant
                .credential_prefix
                .strip_prefix("category:")
                .unwrap_or(&grant.credential_prefix);
            counts.entry(name.to_owned()).or_insert(0);
        }
    }

    let namers = |category: &str| -> String {
        let mut who: Vec<String> = grants
            .iter()
            .filter(|g| {
                g.selector_kind == "category"
                    && g.credential_prefix
                        .strip_prefix("category:")
                        .unwrap_or(&g.credential_prefix)
                        == category
            })
            .map(|g| format!("{}:{}", g.principal_kind, g.principal_id))
            .collect();
        who.sort();
        who.dedup();
        if who.is_empty() {
            "-".to_owned()
        } else {
            who.join(" ")
        }
    };

    let wn = counts
        .keys()
        .map(|c| c.chars().count())
        .chain(std::iter::once("CATEGORY".len()))
        .chain(std::iter::once("(uncategorized)".len()))
        .max()
        .unwrap_or(8);
    let mut lines = vec![format!(
        "{:<wn$}  {:>11}  GRANTED TO",
        "CATEGORY", "CREDENTIALS"
    )];
    for (category, count) in &counts {
        lines.push(format!(
            "{:<wn$}  {:>11}  {}",
            category,
            count,
            namers(category)
        ));
    }
    if uncategorized > 0 {
        lines.push(format!(
            "{:<wn$}  {:>11}  {}",
            "(uncategorized)", uncategorized, "-"
        ));
    }
    Ok(lines)
}

pub(super) fn cmd_grants(global: &GlobalArgs, args: &[String]) -> Result<(), CliError> {
    // Grant inventory is part of the same authenticated admin.status response as the
    // credential inventory. A discovered daemon is queried online; otherwise the same
    // sorted rows come from the lease-free plaintext reader.
    let (result, store_schema) = request_admin_status_with_schema(global)?;
    let declared = render_declared_grants(&result);
    if args.iter().any(|arg| arg == "--declared") {
        for line in declared.lines {
            println!("{line}");
        }
    } else {
        print_grants(&result)?;
        if declared.count > 0 {
            eprintln!(
                "{} declared grant(s) from first-party modules; see ck auth grants --declared",
                declared.count
            );
        }
    }
    if declared.incomplete {
        eprintln!("declared grants could not be read completely");
    }
    print_store_behind_note(store_schema);
    Ok(())
}

#[derive(serde::Deserialize)]
struct DeclaredGrantRow {
    module_id: String,
    selector_kind: SelectorKind,
    selector: String,
    operation: GrantOperation,
    first_seen_ms: i64,
}

struct DeclaredGrantReport {
    lines: Vec<String>,
    count: usize,
    incomplete: bool,
}

fn render_declared_grants(result: &serde_json::Value) -> DeclaredGrantReport {
    let mut report = DeclaredGrantReport {
        lines: Vec::new(),
        count: 0,
        incomplete: result
            .get("declared_grants_incomplete")
            .and_then(serde_json::Value::as_bool)
            == Some(true),
    };
    let Some(raw) = result.get("declared_grants") else {
        return report;
    };
    let Some(raw) = raw.as_array() else {
        report.incomplete = true;
        return report;
    };
    let mut rows = Vec::new();
    for value in raw {
        let row = serde_json::from_value::<DeclaredGrantRow>(value.clone())
            .ok()
            .filter(|row| {
                let tuple = serde_json::json!([{
                    "selector_kind": row.selector_kind.as_str(),
                    "selector": row.selector,
                    "operation": row.operation.as_str(),
                }]);
                credentials_core::store::DeclaredGrantSet::from_grants_json(
                    &row.module_id,
                    &tuple.to_string(),
                )
                .is_ok()
            });
        if let Some(row) = row {
            rows.push(row);
        } else {
            report.incomplete = true;
        }
    }
    report.count = rows.len();
    if rows.is_empty() {
        return report;
    }
    let width = |head: &str, field: &dyn Fn(&DeclaredGrantRow) -> &str| {
        rows.iter()
            .map(|row| field(row).chars().count())
            .chain(std::iter::once(head.chars().count()))
            .max()
            .unwrap_or(head.len())
    };
    let wm = width("MODULE", &|row| &row.module_id);
    let wk = width("SELECTOR KIND", &|row| row.selector_kind.as_str());
    let ws = width("SELECTOR", &|row| &row.selector);
    let wo = width("OP", &|row| row.operation.as_str());
    report
        .lines
        .push("declared grants (last declaration each module presented):".into());
    report.lines.push(format!(
        "{:<wm$}  {:<wk$}  {:<ws$}  {:<wo$}  {:>7}  FIRST SEEN",
        "MODULE", "SELECTOR KIND", "SELECTOR", "OP", "REACHES"
    ));
    let inventory = parse_credential_categories(result);
    for row in rows {
        let reach = if row.selector_kind == SelectorKind::Audience {
            "token".into()
        } else {
            grant_reach(&inventory, row.selector_kind.as_str(), &row.selector).to_string()
        };
        report.lines.push(format!(
            "{:<wm$}  {:<wk$}  {:<ws$}  {:<wo$}  {:>7}  {}",
            row.module_id,
            row.selector_kind.as_str(),
            row.selector,
            row.operation.as_str(),
            reach,
            format_ts_ms(row.first_seen_ms)
        ));
    }
    report
}

#[cfg(test)]
mod taxonomy_cli_tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    /// A CATEGORY NAMED BY A GRANT BUT CARRIED BY NOBODY IS LISTED, AT ZERO.
    ///
    /// That row is the whole point of the verb. The reach column on `grants` says a grant
    /// reaches nothing; this is where an operator comes to find out WHY, and omitting the
    /// empty category would send them away with a correct-looking grant and no
    /// explanation -- the exact silence that let a `category:llm-provider` grant be
    /// created on the live vault while no credential carried it.
    ///
    /// The uncategorized arm matters for the mirror reason: some credentials carry no
    /// category deliberately, so hiding the count would make a FORGOTTEN assignment
    /// indistinguishable from an INTENDED one.
    #[test]
    fn the_category_table_lists_an_empty_category_a_grant_names() {
        let reply = serde_json::json!({
            "credentials": [
                { "id": "apikey:one", "state": "active", "categories": ["llm-provider"] },
                { "id": "apikey:two", "state": "active", "categories": ["llm-provider"] },
                { "id": "apple:bare", "state": "active", "categories": [] },
            ],
            "read_grants": [
                { "principal_kind": "reserved", "principal_id": "m", "selector_kind": "category",
                  "credential_prefix": "llm-provider", "operation": "read", "created_at_ms": 0 },
                { "principal_kind": "reserved", "principal_id": "m", "selector_kind": "category",
                  "credential_prefix": "no-such-category", "operation": "read", "created_at_ms": 0 },
            ],
        });
        let lines = render_categories(&reply).expect("render");
        let row = |name: &str| -> String {
            lines
                .iter()
                .find(|l| l.starts_with(name))
                .unwrap_or_else(|| panic!("no row for {name:?} in:\n{}", lines.join("\n")))
                .clone()
        };
        assert!(
            row("llm-provider").split_whitespace().nth(1) == Some("2"),
            "two credentials carry it: {}",
            row("llm-provider")
        );
        assert!(
            row("llm-provider").contains("reserved:m"),
            "and the principal holding the grant is named: {}",
            row("llm-provider")
        );
        // The load-bearing row: present, at zero, because a grant names it.
        let empty = row("no-such-category");
        assert!(
            empty.split_whitespace().nth(1) == Some("0"),
            "a category a grant names but nothing carries must be listed at zero, not \
             omitted: {empty}"
        );
        assert!(
            row("(uncategorized)").split_whitespace().nth(1) == Some("1"),
            "one credential carries no category: {}",
            row("(uncategorized)")
        );
    }

    /// A GRANT THAT REACHES NOTHING SAYS SO.
    ///
    /// Written because it happened on the live vault: a `category:llm-provider` grant was
    /// created while NO credential carried that category, because registry defaults apply
    /// at creation and every credential predated the migration that introduced
    /// categories. It was syntactically valid, accepted without complaint, authorized
    /// nothing, and rendered identically to a working grant — every other column shows
    /// what the operator TYPED. A consumer asking me to double-check a selector is the
    /// only reason it was caught.
    ///
    /// Both arms matter and they fail differently. Without the zero arm, a renderer that
    /// hardcoded a plausible count passes. Without the non-zero arm, a renderer that
    /// printed 0 for everything passes — and that is the likelier defect, because a reach
    /// computation that silently matches nothing is what a selector-format change would
    /// produce.
    #[test]
    fn the_grant_table_reports_what_each_row_actually_reaches() {
        let reply = serde_json::json!({
            "credentials": [
                { "id": "apikey:one", "state": "active", "categories": ["llm-provider"] },
                { "id": "apikey:two", "state": "active", "categories": ["llm-provider"] },
                { "id": "signing:x:1", "state": "active", "categories": [] },
            ],
            "read_grants": [
                { "principal_kind": "reserved", "principal_id": "m", "selector_kind": "category",
                  "credential_prefix": "llm-provider", "operation": "read", "created_at_ms": 0 },
                { "principal_kind": "reserved", "principal_id": "m", "selector_kind": "category",
                  "credential_prefix": "no-such-category", "operation": "read", "created_at_ms": 0 },
                // Sorted, because an existing guard refuses an unsorted grant set: the
                // order is the operator's reach audit and a shuffled one hides a diff.
                { "principal_kind": "reserved", "principal_id": "m", "selector_kind": "exact",
                  "credential_prefix": "signing:x", "operation": "sign", "created_at_ms": 0 },
                { "principal_kind": "reserved", "principal_id": "m", "selector_kind": "exact",
                  "credential_prefix": "signing:x:1", "operation": "sign", "created_at_ms": 0 },
            ],
        });
        let lines = render_grants(&reply).expect("render");
        let reaches = |selector: &str| -> String {
            let line = lines
                .iter()
                .find(|l| l.split_whitespace().nth(3) == Some(selector) && !l.starts_with("KIND"))
                .unwrap_or_else(|| panic!("no row for {selector:?} in:\n{}", lines.join("\n")));
            line.split_whitespace()
                .nth(5)
                .unwrap_or_default()
                .to_owned()
        };
        assert_eq!(reaches("llm-provider"), "2", "two credentials carry it");
        assert_eq!(
            reaches("no-such-category"),
            "0",
            "the defect this exists for: valid, accepted, authorizes nothing"
        );
        assert_eq!(reaches("signing:x:1"), "1");
        assert_eq!(
            reaches("signing:x"),
            "0",
            "exact is byte equality: a prefix of a real id reaches nothing, which is the \
             narrowing the selector vocabulary exists to make visible"
        );
    }

    #[test]
    fn remote_grant_reach_merges_optional_inventory_once_and_keeps_local_metadata() {
        let local = serde_json::json!({
            "credentials": [{"id": "oauth:duplicate", "categories": ["local-category"]}]
        });
        let legacy = parse_credential_categories(&local);
        assert_eq!(legacy.len(), 1);
        assert_eq!(grant_reach(&legacy, "exact", "oauth:duplicate"), 1);
        let mut reply = local.clone();
        reply["remote_credentials"] = serde_json::json!([
            {"id": "oauth:duplicate", "categories": ["remote-category"]},
            {"id": "oauth:only-remote", "categories": ["shared-category"]},
            {"categories": ["ignored-without-id"]}
        ]);
        let inventory = parse_credential_categories(&reply);
        assert_eq!(inventory.len(), 2);
        assert_eq!(grant_reach(&inventory, "exact", "oauth:duplicate"), 1);
        assert_eq!(grant_reach(&inventory, "category", "local-category"), 1);
        assert_eq!(grant_reach(&inventory, "category", "remote-category"), 0);
        assert_eq!(grant_reach(&inventory, "category", "shared-category"), 1);
        reply.as_object_mut().unwrap().remove("credentials");
        assert_eq!(parse_credential_categories(&reply).len(), 2);
        reply.as_object_mut().unwrap().remove("remote_credentials");
        assert!(parse_credential_categories(&reply).is_empty());
        assert_eq!(parse_credential_categories(&local), legacy);
    }

    #[test]
    fn grant_reach_names_at_most_five_uncategorized_ids_and_counts_the_rest() {
        let credentials: Vec<_> = ["a", "b", "c", "d", "e", "f"]
            .iter()
            .map(|s| serde_json::json!({ "id": format!("cookie:{s}"), "state": "active", "categories": [] }))
            .collect();
        let reply = serde_json::json!({ "credentials": credentials, "read_grants": [] });
        let report = render_grant_reach(
            &reply,
            SelectorKind::Category,
            "browser-session",
            GrantOperation::Read,
        );
        assert_eq!(report.stdout, ["  reaches 0 credentials"]);
        assert!(
            report.stderr.iter().any(|line| line
                == "  6 credentials would join 'browser-session' but have no categories yet \
                    (created before categories existed): cookie:a, cookie:b, cookie:c, \
                    cookie:d, cookie:e, and 1 more"),
            "{:#?}",
            report.stderr
        );
    }

    #[test]
    fn grant_principal_and_selector_parsers_pin_legacy_and_v2_forms() {
        // A BARE ID MEANS `reserved`, which is the narrower of the two kinds. A typo
        // that drops the prefix must not silently grant to an enrolled consumer.
        assert_eq!(
            parse_grant_principal("agent").unwrap(),
            ("reserved".to_string(), "agent".to_string())
        );
        assert_eq!(
            parse_grant_principal("reserved:agent").unwrap(),
            ("reserved".to_string(), "agent".to_string())
        );
        assert_eq!(
            parse_grant_principal("enrolled:anthropic-auth").unwrap(),
            ("enrolled".to_string(), "anthropic-auth".to_string())
        );
        // `direct` is refused rather than merely unknown: a grant to an unattested
        // caller is a grant to every same-UID process, with nothing to revoke.
        for invalid in [
            "direct:agent",
            "reserved:a|b",
            "enrolled:a|b",
            "enrolled:",
            "",
        ] {
            assert!(parse_grant_principal(invalid).is_err(), "{invalid:?}");
        }

        // `--prefix` is REFUSED, not aliased to exact. Aliasing would succeed while
        // granting nothing: `apikey:` reached seventeen credentials as a prefix and
        // names none of them exactly, so the operator would believe they granted a
        // family and hold a row covering zero.
        let legacy = args(&["--prefix", "apikey:"]);
        let refusal = parse_grant_selector(&legacy).expect_err("--prefix must refuse");
        assert!(
            format!("{refusal}").contains("--prefix is gone"),
            "the refusal must name the flag and route to the replacement, not fail \
             generically: got {refusal}"
        );

        let category = args(&["--selector-kind", "category", "--selector", "llm-provider"]);
        assert_eq!(
            parse_grant_selector(&category).unwrap(),
            (SelectorKind::Category, "llm-provider".to_string())
        );
        let exact = args(&["--selector-kind", "exact", "--selector", "apikey:exa"]);
        assert_eq!(
            parse_grant_selector(&exact).unwrap(),
            (SelectorKind::Exact, "apikey:exa".to_string())
        );

        // No default: omitting the kind must refuse rather than choose reach for the
        // operator.
        let no_kind = args(&["--selector", "apikey:exa"]);
        let kind_refusal = parse_grant_selector(&no_kind)
            .expect_err("--selector-kind is required with no default");
        assert!(
            format!("{kind_refusal}").contains("--selector-kind"),
            "got {kind_refusal}"
        );
        assert!(parse_grant_selector(&args(&["--selector-kind", "exact"])).is_err());
    }

    #[test]
    fn grant_rows_accept_v1_without_selector_kind_and_v2_with_it() {
        let v1 = serde_json::json!({
            "read_grants": [{
                "principal_kind": "reserved",
                "principal_id": "agent",
                "credential_prefix": "apikey:",
                "operation": "read",
                "created_at_ms": 1,
                "covered_credential_ids": []
            }]
        });
        assert_eq!(parse_grants(&v1).unwrap()[0].selector_kind, "exact");
        let v2 = serde_json::json!({
            "read_grants": [{
                "principal_kind": "reserved",
                "principal_id": "agent",
                "selector_kind": "category",
                "credential_prefix": "llm-provider",
                "operation": "read",
                "created_at_ms": 1,
                "covered_credential_ids": []
            }]
        });
        assert_eq!(parse_grants(&v2).unwrap()[0].selector_kind, "category");
    }

    /// AN UNFAMILIAR PRINCIPAL KIND MUST NOT TAKE DOWN THE INVENTORY.
    ///
    /// A parser that required `reserved` exactly made `ck auth grants` and `ck auth
    /// status` both refuse with "invalid grant principal kind at row 0" once an
    /// `enrolled:` grant existed -- one THIS BINARY creates, since it accepts `enrolled:`
    /// at `parse_grant_principal`. The CLI could write a row it could not read back.
    ///
    /// The blast radius is the part this test defends. One row refused the WHOLE table,
    /// so a single grant removed the only surface an operator has for seeing grants at
    /// all -- and `status` died AFTER printing the inventory, so it exited non-zero with
    /// most of its output looking correct.
    #[test]
    fn one_unfamiliar_principal_kind_does_not_deny_the_whole_grant_inventory() {
        let mixed = serde_json::json!({
            "read_grants": [
                {
                    "principal_kind": "enrolled",
                    "principal_id": "anthropic-auth-opencode",
                    "selector_kind": "category",
                    "credential_prefix": "anthropic-native",
                    "operation": "read",
                    "created_at_ms": 1,
                    "covered_credential_ids": []
                },
                {
                    // A kind no version of this binary has ever written. It must still
                    // reach the operator's eyes: an unfamiliar label prompts a question,
                    // an absent row does not. Placed here because the parser also
                    // enforces a STABLE ORDER over the rows, which is its own defence --
                    // a reordered inventory would hide a reach change in a diff.
                    "principal_kind": "from-a-newer-daemon",
                    "principal_id": "whoever",
                    "selector_kind": "exact",
                    "credential_prefix": "apikey:thing",
                    "operation": "read",
                    "created_at_ms": 3,
                    "covered_credential_ids": []
                },
                {
                    "principal_kind": "reserved",
                    "principal_id": "insula",
                    "selector_kind": "category",
                    "credential_prefix": "llm-provider",
                    "operation": "read",
                    "created_at_ms": 2,
                    "covered_credential_ids": []
                }
            ]
        });
        let rows = parse_grants(&mixed).expect("an unfamiliar kind must not refuse the table");
        assert_eq!(
            rows.len(),
            3,
            "every row must survive, not just the known ones"
        );
        assert_eq!(rows[0].principal_kind, "enrolled");
        assert_eq!(rows[1].principal_kind, "from-a-newer-daemon");
        assert_eq!(rows[2].principal_kind, "reserved");

        // A MISSING kind is still a refusal: that is a malformed reply rather than an
        // unfamiliar one, and it would render as a blank column that reads like a bug in
        // the table instead of a fact about the grant.
        let headless = serde_json::json!({
            "read_grants": [{
                "principal_id": "agent",
                "credential_prefix": "apikey:",
                "operation": "read",
                "created_at_ms": 1,
                "covered_credential_ids": []
            }]
        });
        assert!(
            parse_grants(&headless).is_err(),
            "an absent kind is malformed"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn declared_inventory_renderer_drops_malformed_elements_without_hiding_hand_grants() {
        let mut reply = serde_json::json!({
            "read_grants": [],
            "credentials": [],
            "declared_grants": [
                {"module_id":"agent","selector_kind":"category","selector":"llm-provider","operation":"read","first_seen_ms":0},
                {"module_id":"agent","selector_kind":"category","selector":"llm-provider","operation":"sign","first_seen_ms":0},
                {"module_id":"agent","selector_kind":"category","selector":"llm-provider","operation":"read","first_seen_ms":"wrong"},
                null
            ]
        });
        let report = render_declared_grants(&reply);
        assert_eq!(report.count, 1);
        assert!(report.incomplete);
        assert_eq!(report.lines.len(), 3);
        assert!(report.lines[2].ends_with("1970-01-01 00:00:00"));
        assert_eq!(render_grants(&reply).unwrap(), ["no grants"]);
        reply["declared_grants"] = serde_json::json!([false]);
        reply["declared_grants_incomplete"] = serde_json::json!(true);
        let report = render_declared_grants(&reply);
        assert!(report.lines.is_empty());
        assert_eq!(report.count, 0);
        assert!(report.incomplete);
        for absent in [
            serde_json::json!({}),
            serde_json::json!({"declared_grants":[]}),
        ] {
            let report = render_declared_grants(&absent);
            assert!(report.lines.is_empty());
            assert!(!report.incomplete);
        }
        reply["declared_grants"] = serde_json::json!({});
        assert!(render_declared_grants(&reply).incomplete);
    }

    /// A status report this CLI will not trust must not be blamed on the running module.
    ///
    /// The same report arrives from the running module or from this CLI's own lease-free
    /// read, and in neither case did anything refuse: this side checked the report and
    /// rejected it. "The running module refused the op" sent an operator to inspect a
    /// daemon that had answered correctly -- measured when an out-of-order grant listing
    /// printed that text on the offline path, with no module involved at all.
    #[test]
    fn a_report_that_fails_this_clis_check_does_not_blame_the_module() {
        let row = |kind: &str, operation: &str| {
            serde_json::json!({
                "principal_kind": "reserved",
                "principal_id": "agent",
                "selector_kind": kind,
                "credential_prefix": "a:",
                "operation": operation,
                "created_at_ms": 1,
            })
        };
        // Grants must arrive sorted by their field text, so "category" sorts before
        // "exact"; this exact-then-category pair is out of order and must be refused.
        let report = serde_json::json!({
            "read_grants": [row("exact", "read"), row("category", "read")]
        });
        let error = super::parse_grants(&report).expect_err("out-of-order report is refused");
        let text = error.to_string();
        assert!(
            !text.contains("running module"),
            "a local check must not name the module: {text}"
        );
        assert!(text.contains("failed this CLI's check"), "{text}");
        assert!(text.contains("out of stable order"), "{text}");
    }
}
