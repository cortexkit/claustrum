//! Status, inventory, audit, event, and usability-report commands.

use super::{
    admin_client, has_flag, optional, print_read_grants, resolve_store_key, resolver,
    resolver_config, store_path, AdminOpBody, CliError, EncryptedStore, GlobalArgs, StoreOpError,
    ADMIN_OP_SCHEMA_V1,
};

pub(super) fn request_admin_status(global: &GlobalArgs) -> Result<serde_json::Value, CliError> {
    request_admin_status_with_schema(global).map(|(result, _)| result)
}

/// The store's recorded schema version when the report came from the lease-free
/// readers, or `None` when a live module answered.
///
/// A live module has already migrated on boot, so there is nothing behind to report;
/// only the offline path can meet a store the binary is ahead of.
type StoreSchemaVersion = Option<u32>;

/// Build the status report, and say which schema the store was read at.
///
/// The version is threaded out rather than printed here because the note belongs AFTER
/// the verb's own output: a caller that printed it first would put a diagnostic above
/// the inventory an operator is reading, and a script capturing stdout would still be
/// fine but a human tailing the transcript would not.
pub(super) fn request_admin_status_with_schema(
    global: &GlobalArgs,
) -> Result<(serde_json::Value, StoreSchemaVersion), CliError> {
    let op = AdminOpBody::Status {
        v: ADMIN_OP_SCHEMA_V1,
    };
    if let Some(conn_path) = &global.subc_conn {
        match admin_client::commit(
            &global.data_dir,
            &resolver_config(global),
            conn_path,
            &op,
            None,
        ) {
            admin_client::RouteCommit::Committed(mut v) => {
                // Creator display is advisory: a metadata read failure must not hide inventory.
                if let Ok((metas, _)) =
                    credentials_core::store::list_meta_read_only_with_schema(&store_path(global))
                {
                    attach_inventory_creators(&mut v, &metas);
                }
                return Ok((v, None));
            }
            admin_client::RouteCommit::Refused(m) => return Err(CliError::RouteRefused(m)),
            admin_client::RouteCommit::LocalFailure(m) => return Err(CliError::LocalFailure(m)),
            admin_client::RouteCommit::Indeterminate(m) => {
                return Err(CliError::RouteIndeterminate(m))
            }
            admin_client::RouteCommit::NoLiveModule(m) => {
                // NOT the lease path: read verbs do not take the writer lease, and the
                // message must not say they do. The test pins stdout AND stderr
                // byte-for-byte against the online run, so a wrong sentence here would
                // stay pinned. A diagnostic that describes a mechanism the read does not
                // use is how an operator concludes a read is unsafe to run beside a live
                // daemon.
                eprintln!("(no live module: {m}; reading plaintext metadata directly)");
            }
        }
    }

    let db = store_path(global);
    if !db.exists() {
        return Err(CliError::Usage(format!(
            "no vault at {} (run 'ck auth bootstrap' first)",
            global.data_dir.display()
        )));
    }
    let (metas, meta_schema) = match credentials_core::store::list_meta_read_only_with_schema(&db) {
        Ok((metas, schema)) => (metas, Some(schema)),
        Err(StoreOpError::NotFound) => (Vec::new(), None),
        Err(error) => return Err(CliError::Store(error)),
    };
    // A store below the selector migration still holds legacy prefix grants, which the
    // grant reader refuses rather than misreport. `list` and `status` must keep working
    // during the placement window anyway, so they show no grants and let the store-behind
    // note say why; `ck auth grants` itself still surfaces the refusal.
    let behind_selectors =
        meta_schema.is_some_and(|schema| schema < credentials_core::store::SELECTOR_SCHEMA_VERSION);
    let (grants, grant_schema) = if behind_selectors {
        (Vec::new(), meta_schema)
    } else {
        match credentials_core::store::list_read_grants_read_only_with_schema(&db) {
            Ok((grants, schema)) => (grants, Some(schema)),
            Err(StoreOpError::NotFound) => (Vec::new(), None),
            Err(error) => return Err(CliError::Store(error)),
        }
    };
    let open_intents = match credentials_core::store::count_refresh_intents_read_only(&db) {
        Ok(count) => count,
        Err(StoreOpError::NotFound) => 0,
        Err(error) => return Err(CliError::Store(error)),
    };
    let mut result =
        credentials_core::admin_ops::status_result(&metas, &grants, open_intents, false);
    let remote = EncryptedStore::remote_inventory_read_only(&db).map_err(CliError::Store)?;
    credentials_core::admin_ops::attach_remote_credentials(&mut result, &remote);
    let read_condition = |id: &str, incarnation: &str| {
        credentials_core::store::condition_read_only(&db, id, incarnation)
    };
    credentials_core::admin_ops::attach_login_conditions(
        &mut result,
        &remote,
        read_condition,
        read_condition,
    )
    .map_err(CliError::Store)?;
    if let Ok(key) = resolve_store_key(global) {
        if let Ok(plans) = credentials_core::store::detected_plans_read_only(&db, &key) {
            credentials_core::admin_ops::attach_detected_plans(&mut result, &plans);
        }
    }
    attach_inventory_creators(&mut result, &metas);
    credentials_core::admin_ops::attach_declared_grants(
        &mut result,
        credentials_core::store::declared_grant_sets_read_only(&db),
    );
    Ok((result, meta_schema.or(grant_schema)))
}

/// Say, once, that the store this read met is behind the binary.
///
/// *** THE WINDOW THIS DESCRIBES IS THE PLACEMENT WINDOW. *** A CLI-only change is
/// placed first and the daemon, which migrates on boot, is restarted later. Between the
/// two the offline readers meet a store one migration behind: no categories exist yet,
/// and its legacy prefix grants are left out rather than misreported. Without this
/// line the reduced view is indistinguishable from a vault that genuinely has no
/// categories, which is the reading that would send an operator looking for a bug in
/// their classification rather than at the restart they have not done yet.
///
/// STDERR, and stdout is untouched, so a script parsing the inventory keeps working.
pub(super) fn print_store_behind_note(store_schema: StoreSchemaVersion) {
    let Some(store_schema) = store_schema else {
        return;
    };
    if let Some(note) = store_behind_note(store_schema) {
        eprintln!("{note}");
    }
}

fn print_inventory_store_behind_note(schema: StoreSchemaVersion) {
    print_store_behind_note(schema);
    if let Some(note) = schema.and_then(provider_store_behind_note) {
        eprintln!("{note}");
    }
}

pub(super) fn provider_store_behind_note(schema: u32) -> Option<String> {
    let provider_schema = credentials_core::store::PROVIDER_ID_SCHEMA_VERSION;
    (schema < provider_schema).then(|| format!(
        "note: store schema {schema} is behind this binary's {}; provider ids appear after the daemon restarts (migration {provider_schema})",
        credentials_core::store::newest_migration_version()
    ))
}

/// The note text, or `None` when the store already has what the note says is missing.
///
/// Gated on the CATEGORY migration, not on "any migration behind": a store that has
/// categories but lacks a later migration would otherwise be told its categories are
/// missing, which is false and points the operator at the wrong thing.
pub(super) fn store_behind_note(store_schema: u32) -> Option<String> {
    let category_schema = credentials_core::store::CATEGORY_SCHEMA_VERSION;
    if store_schema >= category_schema {
        return None;
    }
    Some(format!(
        "note: store schema {store_schema} is behind this binary's {}; \
         categories and category grants appear after the daemon restarts (migration {category_schema})",
        credentials_core::store::newest_migration_version()
    ))
}

pub(super) fn attach_inventory_creators(
    result: &mut serde_json::Value,
    metas: &[(String, credentials_core::store::RecordMeta)],
) {
    if let Some(rows) = result
        .get_mut("credentials")
        .and_then(serde_json::Value::as_array_mut)
    {
        for row in rows {
            let creator = metas
                .iter()
                .find(|(id, _)| row["id"].as_str() == Some(id.as_str()))
                .and_then(|(_, meta)| meta.created_by.as_deref());
            row["created_by"] = serde_json::json!(creator);
        }
    }
}

type InventoryRow = (String, u64, String, Vec<String>, Vec<String>);

pub(super) fn parse_inventory(result: &serde_json::Value) -> Result<Vec<InventoryRow>, CliError> {
    let rows = result
        .get("credentials")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            CliError::StatusReportInvalid("admin.status omitted credential inventory".into())
        })?;
    rows.iter()
        .enumerate()
        .map(|(index, row)| {
            let state = row
                .get("state")
                .and_then(serde_json::Value::as_str)
                .filter(|state| matches!(*state, "active" | "needs_reauth" | "retired" | "corrupt"))
                .ok_or_else(|| {
                    CliError::StatusReportInvalid(format!(
                        "admin.status returned an invalid state at credential row {index}"
                    ))
                })?;
            let version = row
                .get("record_version")
                .and_then(serde_json::Value::as_u64)
                .filter(|version| *version > 0)
                .ok_or_else(|| {
                    CliError::StatusReportInvalid(format!(
                        "admin.status returned an invalid version at credential row {index}"
                    ))
                })?;
            let id = row
                .get("id")
                .and_then(serde_json::Value::as_str)
                .filter(|id| !id.is_empty())
                .ok_or_else(|| {
                    CliError::StatusReportInvalid(format!(
                        "admin.status returned an invalid id at credential row {index}"
                    ))
                })?;
            let categories = row
                .get("categories")
                .and_then(serde_json::Value::as_array)
                .and_then(|values| {
                    values
                        .iter()
                        .map(|value| value.as_str().map(str::to_string))
                        .collect::<Option<Vec<_>>>()
                })
                .unwrap_or_default();
            let mut providers = row
                .get("provider_ids")
                .and_then(serde_json::Value::as_array)
                .and_then(|values| {
                    values
                        .iter()
                        .map(|v| v.as_str().map(str::to_owned))
                        .collect::<Option<Vec<_>>>()
                })
                .unwrap_or_default();
            if row.get("plan_tier").is_some_and(|tier| {
                !tier.is_null()
                    && !tier
                        .as_str()
                        .is_some_and(credentials_core::plan_tier::valid_plan_tier)
            }) {
                return Err(CliError::StatusReportInvalid(format!(
                    "admin.status returned an invalid plan tier at credential row {index}"
                )));
            }
            providers.sort();
            Ok((
                state.to_string(),
                version,
                id.to_string(),
                categories,
                providers,
            ))
        })
        .collect()
}

pub(super) fn render_inventory_row(
    (state, version, id, categories, providers): &InventoryRow,
    result: &serde_json::Value,
) -> String {
    let entry = result["credentials"].as_array().and_then(|rows| {
        rows.iter()
            .find(|row| row["id"].as_str() == Some(id.as_str()))
    });
    let creator = entry
        .and_then(|row| row["created_by"].as_str())
        .filter(|by| by.starts_with("reserved:") || by.starts_with("enrolled:"));
    let categories = if categories.is_empty() {
        "-".to_string()
    } else {
        categories.join(",")
    };
    let creator = creator.map(|by| format!("  by={by}")).unwrap_or_default();
    let providers = if providers.is_empty() {
        "-".into()
    } else {
        providers.join(",")
    };
    let plan = if inventory_has_plan(result) {
        let row = result["credentials"].as_array().and_then(|rows| {
            rows.iter()
                .find(|row| row["id"].as_str() == Some(id.as_str()))
        });
        let tier = row.and_then(|row| row["plan_tier"].as_str()).unwrap_or("-");
        let marker = if row.is_some_and(|row| row["plan_tier_source"] == "detected") {
            "*"
        } else {
            ""
        };
        let since = row
            .filter(|row| row["plan_tier_source"] == "operator")
            .and_then(|row| row["plan_tier_since_ms"].as_i64())
            .and_then(chrono::DateTime::from_timestamp_millis)
            .map(|date| {
                format!(
                    " since={}",
                    date.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
                )
            })
            .unwrap_or_default();
        format!("  {tier}{marker}{since}")
    } else {
        String::new()
    };
    let gateway = entry
        .and_then(|row| row["base_url"].as_str().map(|base_url| (row, base_url)))
        .map(|(row, base_url)| {
            let mut names: Vec<&str> = row["headers"]
                .as_object()
                .map(|headers| headers.keys().map(String::as_str).collect())
                .unwrap_or_default();
            names.sort_unstable();
            let headers = if names.is_empty() {
                "-".into()
            } else {
                names.join(",")
            };
            format!("  method=gateway  base_url={base_url}  headers={headers}")
        })
        .unwrap_or_default();
    let condition = entry.and_then(inventory_condition_text).unwrap_or_default();
    format!("{state:<14} v{version:<4} {id}  {categories}  {providers}{plan}{creator}{gateway}{condition}")
}

fn inventory_condition_text(row: &serde_json::Value) -> Option<String> {
    let condition = &row["condition"];
    let reason = condition["reason"].as_str()?;
    let since = condition["since_ms"].as_u64()?;
    let link = condition["action_url"]
        .as_str()
        .map(|link| format!("  action_url={link}"))
        .unwrap_or_default();
    Some(format!("  condition={reason} since_ms={since}{link}"))
}

fn inventory_has_plan(result: &serde_json::Value) -> bool {
    result["credentials"]
        .as_array()
        .is_some_and(|rows| rows.iter().any(|row| row["plan_tier"].is_string()))
}

fn print_inventory(rows: &[InventoryRow], result: &serde_json::Value) {
    let plan_header = if inventory_has_plan(result) {
        "  PLAN_TIER"
    } else {
        ""
    };
    println!("STATE          VER   CREDENTIAL  CATEGORIES  PROVIDERS{plan_header}");
    for row in rows {
        println!("{}", render_inventory_row(row, result));
    }
    if let Some(remote) = result["remote_credentials"].as_array() {
        for row in remote {
            if let (Some(id), Some(condition)) = (row["id"].as_str(), inventory_condition_text(row))
            {
                println!("shared copy   {id}{condition}  (clear at the home vault)");
            }
        }
    }
    if result["credentials"]
        .as_array()
        .is_some_and(|rows| rows.iter().any(|row| row["plan_tier_source"] == "detected"))
    {
        println!("\n* detected subscription tier; an operator set-plan override always wins.");
    }

    // Keep this caveat unconditional: stored lifecycle state and subscription
    // observations cannot prove that a provider currently accepts a token.
    // Only an actual credential read or consumer request can establish that.
    if !rows.is_empty() {
        println!(
            "\n(`active` = nothing has reported it dead. Not a check that the provider \
             still accepts it;\n that costs a real call. `ck auth usable` opens the \
             envelopes; only a get proves service.)"
        );
    }
}

pub(super) fn cmd_status(global: &GlobalArgs) -> Result<(), CliError> {
    let (result, store_schema) = request_admin_status_with_schema(global)?;
    let inventory = parse_inventory(&result)?;

    let status = result["status"].as_str().unwrap_or("unknown");
    let total = result["credentials_total"].as_u64().unwrap_or(0);
    let active = result["active"].as_u64().unwrap_or(0);
    println!("vault: {status} ({active}/{total} serving)");
    if result["fenced_out"].as_bool() == Some(true) {
        println!("FENCED OUT: this writer lost the single-writer lease to a newer instance");
    }
    let open_intents = result["open_intents"].as_u64().unwrap_or(0);
    if open_intents > 0 {
        println!("open refresh intents: {open_intents}");
    }
    println!();
    print_inventory(&inventory, &result);
    print_read_grants(&result)?;
    // Actionable tail: name what needs the operator, like the health probe does.
    let needs: Vec<&str> = result["needs_reauth_ids"]
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();
    if !needs.is_empty() {
        println!();
        println!(
            "needs re-login: {} (fix: `login --provider <p> --replace`, or `import --replace`)",
            needs.join(", ")
        );
    }
    let retired: Vec<&str> = result["retired_ids"]
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();
    if !retired.is_empty() {
        println!();
        println!(
            "retired: {} (intentionally not serving; not counted as degraded)",
            retired.join(", ")
        );
    }
    print_inventory_store_behind_note(store_schema);
    Ok(())
}

pub(super) fn cmd_audit(global: &GlobalArgs, args: &[String]) -> Result<(), CliError> {
    let limit = optional(args, "--limit")
        .map(|s| s.parse::<usize>())
        .transpose()
        .map_err(|e| CliError::Usage(format!("--limit not an integer: {e}")))?;
    // Lease-free, like `verify-audit` and `events`: the audit_log columns are all
    // plaintext, so this needs neither the lease nor a master key. It used to take the
    // lease, which meant the forensic log was unreadable while the vault ran -- i.e.
    // whenever anyone actually wanted it.
    let db = store_path(global);
    if !db.exists() {
        return Err(CliError::Usage(format!(
            "no vault at {} (run 'ck auth bootstrap' first)",
            global.data_dir.display()
        )));
    }
    let entries =
        credentials_core::store::read_audit_read_only(&db, limit).map_err(CliError::Store)?;
    for e in entries {
        // PRINT THE REASON, NOT A BARE "ALARM".
        //
        // The alarm column is set on every admin write by design, so admin activity is
        // loud -- 169 of the 172 flagged rows in this vault are ordinary mints and
        // revokes, and 3 are the real detection signal (fetch_rate_anomaly). Rendering
        // both as the same word makes the routine 98% look like faults and buries the
        // one thing an operator scans for. The reason already distinguishes them; the
        // renderer was discarding it.
        let alarm = match (e.alarm, e.alarm_reason.as_deref()) {
            (true, Some(reason)) => format!(" [{reason}]"),
            // Flagged with no reason recorded: say so rather than printing nothing,
            // because a silent flag is indistinguishable from an unflagged row.
            (true, None) => " [alarm: reason not recorded]".to_string(),
            (false, _) => String::new(),
        };
        println!(
            "{:>5} {} {} {}{}",
            e.seq,
            e.op,
            e.credential_id.as_deref().unwrap_or("-"),
            e.actor,
            alarm
        );
    }
    Ok(())
}

/// Print recent authentication events.
///
/// Deliberately does NOT go through `open_for_admin`, which takes the single-writer
/// lease and therefore requires the daemon stopped. These rows exist to explain a
/// credential that just stopped working, and the moment an operator wants them is the
/// moment the vault is running -- a diagnostic that requires an outage to read would
/// be useless exactly when it is needed.
///
/// Every column is plaintext (no envelope, no master key), so a read-only connection
/// is sufficient and takes nothing the daemon holds.
///
/// *** AN EMPTY RESULT IS AMBIGUOUS, AND IT READS LIKE GOOD NEWS. ***
///
/// This table fills only when a consumer calls `credential.report_auth_failure`. So
/// "no rows for this credential" is equally consistent with:
///
///   - the credential works and no consumer has ever been refused, and
///   - the credential is dead and its consumer does not report.
///
/// The vault cannot tell those apart from here. It never observes a provider's verdict
/// -- it hands over bytes, and only the consumer that spends them learns whether they
/// were honoured. Nothing readable in the store distinguishes a live credential from
/// one revoked an hour ago.
///
/// So an empty result establishes something about a credential ONLY for consumers
/// KNOWN to report. Establishing that is a question for the consumer's source, not for
/// this table: the reporting hook is a trait method that a consumer can leave
/// unimplemented and still compile and run, which fails silently in exactly this
/// direction. When it matters, ask the consumer and get the answer from their call
/// site rather than inferring from this table's silence.
///
/// Recorded because I nearly made that inference myself while investigating whether a
/// credential was behind a downstream failure: the empty table was the first thing I
/// reached for, and reading it as "fine" would have been wrong for a reason invisible
/// in the output.
pub(super) fn cmd_events(global: &GlobalArgs, args: &[String]) -> Result<(), CliError> {
    let limit: u32 = optional(args, "--limit")
        .map(|s| s.parse::<u32>())
        .transpose()
        .map_err(|e| CliError::Usage(format!("--limit not an integer: {e}")))?
        .unwrap_or(20);

    let db = store_path(global);
    if !db.exists() {
        return Err(CliError::Usage(format!(
            "no vault at {} (run 'ck auth bootstrap' first)",
            global.data_dir.display()
        )));
    }

    let events = match credentials_core::store::read_auth_events_read_only(&db, limit) {
        Ok(events) => events,
        // The table is absent, not empty: this store predates the migration that adds
        // it. Distinguished because "no events" would claim nothing has gone wrong,
        // when in fact nothing CAN be recorded until the daemon restarts and migrates.
        Err(credentials_core::store::StoreOpError::NotFound) => {
            println!("this vault has no authentication-event table yet");
            println!("  (it arrives with a schema migration the daemon applies on restart;");
            println!("   until then no events can be recorded, which is not the same as none)");
            return Ok(());
        }
        Err(e) => return Err(CliError::Store(e)),
    };

    // AN EMPTY TABLE READS AS GOOD NEWS AND IS NOT. It fills only when a consumer
    // calls report_auth_failure, so silence here is equally consistent with a working
    // credential and with a dead one whose consumer does not report -- and the vault
    // cannot tell those apart, because it never sees a provider's verdict. Said in the
    // OUTPUT rather than only in the source, since an operator reads this at the
    // moment they are deciding whether a credential is the cause of something.
    if events.is_empty() {
        println!("no authentication events recorded");
        println!();
        println!("  This is NOT evidence that every credential is being honoured. Rows");
        println!("  appear only when a consumer reports a refusal, so an empty table");
        println!("  also describes a dead credential whose consumer never reports. The");
        println!("  vault hands over bytes and never learns the provider's verdict.");
        println!();
        println!("  To rule a credential in or out, ask the consumer that spends it");
        println!("  whether it calls credential.report_auth_failure -- the hook can be");
        println!("  left unimplemented and still compile and run.");
        return Ok(());
    }

    // *** THIS TABLE RECORDS FAILURES. A SUCCESSFUL REFRESH IS INVISIBLE HERE. ***
    //
    // Said in the OUTPUT because the empty-table caveats above do not cover it, and a
    // NON-empty table is the more misleading case: rows are present, so the reader
    // trusts the view, and then reasons from which kinds are absent.
    //
    // That is not hypothetical. An external operator ran this verb on my advice, saw
    // consumer_report rows and no refresh_failed rows for a credential, and concluded
    // the vault had never attempted a refresh -- a claim this table cannot support. A
    // refresh that SUCCEEDS writes `refresh_commit` to the audit chain and nothing
    // here. Absence of refresh rows means "no refresh FAILED", never "no refresh ran".
    //
    // The fault was mine: I handed over an instrument without saying what it cannot
    // contain, which is the half of a recommendation that decides what conclusions it
    // licenses.
    println!("these are FAILURES and state transitions only -- a refresh that succeeded");
    println!("writes refresh_commit to the audit chain and appears nowhere below, so the");
    println!("absence of a refresh row means 'none failed', not 'none was attempted'.");
    println!();

    type EventRow = (
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
    );
    let mut rows: Vec<EventRow> = Vec::with_capacity(events.len());
    for e in &events {
        let when = format_ts_ms(e.ts_ms);
        let what = match (e.provider_status, e.detail.as_deref()) {
            (Some(s), Some(d)) => format!("{s} {d}"),
            (Some(s), None) => s.to_string(),
            (None, Some(d)) => d.to_string(),
            (None, None) => "-".to_string(),
        };
        let principal = match (e.principal_kind.as_deref(), e.principal_id.as_deref()) {
            (Some(kind), Some(id)) => format!("{kind}:{id}"),
            (Some(kind), None) => kind.to_string(),
            (None, _) => "-".to_string(),
        };
        let version = e
            .record_version
            .map(|v| format!("v{v}"))
            .unwrap_or_else(|| "-".into());
        // The consumer-asserted source rides at the end and only when present, so
        // legacy NULL rows render exactly as before this column existed.
        let source = e
            .reporter_source
            .as_deref()
            .map(|s| format!(" src={s}"))
            .unwrap_or_default();
        rows.push((
            when,
            e.credential_id.clone(),
            e.kind.clone(),
            principal,
            what,
            version,
            if e.applied { "yes" } else { "no" }.to_string(),
            source,
        ));
    }

    // MEASURED WIDTHS, for the same reason as `grants`. The fixed `{:34} {:16} {:24} {:22}`
    // this replaced rendered every row at 155 columns against 90 of actual content -- 65
    // columns of padding for values that are never that wide. At 155 the row wraps on any
    // ordinary terminal, and a wrapped table is harder to read than an unaligned one.
    let w = |f: &dyn Fn(&EventRow) -> &str, head: &str| {
        rows.iter()
            .map(|r| f(r).chars().count())
            .chain(std::iter::once(head.chars().count()))
            .max()
            .unwrap_or(head.len())
    };
    let wc = w(&|r| r.1.as_str(), "CREDENTIAL");
    let wk = w(&|r| r.2.as_str(), "KIND");
    let wp = w(&|r| r.3.as_str(), "PRINCIPAL");
    let ww = w(&|r| r.4.as_str(), "DETAIL");
    let wv = w(&|r| r.5.as_str(), "VER");
    println!(
        "{:19}  {:wc$} {:wk$} {:wp$} {:ww$} {:wv$} APPLIED",
        "WHEN", "CREDENTIAL", "KIND", "PRINCIPAL", "DETAIL", "VER"
    );
    for (when, cred, kind, principal, what, version, applied, source) in &rows {
        println!(
            "{when}  {cred:wc$} {kind:wk$} {principal:wp$} {what:ww$} {version:wv$} applied={applied}{source}"
        );
    }
    // DISCLOSE THE TRIM. The per-credential cap is enforced by a silent DELETE, so a
    // reader cannot otherwise distinguish "this is everything that happened" from "this
    // is what survived" -- and those close an investigation in opposite directions.
    match credentials_core::store::auth_events_at_cap_read_only(&db) {
        Ok(ids) if !ids.is_empty() => {
            println!();
            println!(
                "note: {} credential(s) are at the {}-event retention cap, so older events",
                ids.len(),
                credentials_core::store::AUTH_EVENTS_PER_CREDENTIAL
            );
            println!("      for them have been discarded:");
            for id in &ids {
                println!("        {id}");
            }
        }
        // Absent table or a read problem is not worth failing the command over: the
        // events themselves already printed, and this is a footnote about them.
        Ok(_) | Err(_) => {}
    }

    // To see whether refreshes are happening at all, read the chain rather than this
    // table -- named here because the reader asking that question is looking at this
    // output, not at a runbook.
    println!();
    println!("to see whether a credential is being REFRESHED (as opposed to failing),");
    println!("read the audit chain for refresh_commit rows:");
    println!("  ck auth audit --limit 100     (lease-free; safe against a running vault)");

    Ok(())
}

/// Render a millisecond timestamp as UTC `YYYY-MM-DD HH:MM:SS`.
///
/// The arithmetic is the civil-from-days algorithm, independent of the local timezone.
pub(super) fn format_ts_ms(ts_ms: i64) -> String {
    let secs = ts_ms.div_euclid(1000);
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let (h, m, s) = (tod / 3600, (tod % 3600) / 60, tod % 60);

    // Civil date from a days-since-epoch count (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };
    format!("{year:04}-{month:02}-{d:02} {h:02}:{m:02}:{s:02}")
}

pub(super) fn cmd_list(global: &GlobalArgs, args: &[String]) -> Result<(), CliError> {
    // A discovered daemon still supplies authenticated `admin.status`; when none is
    // reachable, the same report is built from lease-free plaintext metadata readers.
    let (result, store_schema) = request_admin_status_with_schema(global)?;
    if has_flag(args, "--json") {
        print_inventory_json(&result, global)?;
        print_inventory_store_behind_note(store_schema);
        return Ok(());
    }
    let rows = parse_inventory(&result)?;
    print_inventory(&rows, &result);
    print_inventory_store_behind_note(store_schema);
    Ok(())
}

/// Print the stable machine-readable inventory for operator scripts.
///
/// One JSON document on stdout, `{"v":1,"credentials":[...]}`, rows sorted by
/// id. The existing keys keep their order and absent optionals render null.
/// Only gateway rows add `base_url` and a name-to-value `headers` object;
/// ordinary rows omit both keys. Nothing secret is printed: the rows
/// come from the same `admin.status` report the human table renders, plus the
/// `auth_method` derived below without exposing any payload.
fn print_inventory_json(result: &serde_json::Value, global: &GlobalArgs) -> Result<(), CliError> {
    let rows = inventory_json_rows(result, global)?;
    println!("{}", serde_json::json!({ "v": 1, "credentials": rows }));
    Ok(())
}

/// Build the `--json` rows from the `admin.status` report.
///
/// Shared fields reuse [`parse_inventory`]'s validation so a malformed report is
/// refused the same way in both renderings; `plan_tier_source` and `creator` are
/// passed through as strings with null for unset, matching the report's own
/// vocabulary (`created_by` on the wire is `creator` here).
fn inventory_json_rows(
    result: &serde_json::Value,
    global: &GlobalArgs,
) -> Result<Vec<serde_json::Value>, CliError> {
    let rows = parse_inventory(result)?;
    let registered = credentials_core::store::registered_providers_read_only(&store_path(global))
        .map_err(CliError::Store)?;
    let methods = if rows.is_empty() {
        std::collections::BTreeMap::new()
    } else {
        inventory_auth_methods(global)?
    };
    let mut out: Vec<serde_json::Value> = rows
        .iter()
        .map(
            |(state, version, id, categories, providers): &InventoryRow| {
                let entry = result["credentials"].as_array().and_then(|entries| {
                    entries
                        .iter()
                        .find(|row| row["id"].as_str() == Some(id.as_str()))
                });
                let plan_tier = entry
                    .and_then(|row| row.get("plan_tier"))
                    .and_then(serde_json::Value::as_str);
                let plan_tier_source = entry
                    .and_then(|row| row.get("plan_tier_source"))
                    .and_then(serde_json::Value::as_str);
                let creator = entry
                    .and_then(|row| row.get("created_by"))
                    .and_then(serde_json::Value::as_str);
                let auth_method = methods
                    .get(id)
                    .copied()
                    .flatten()
                    .map(|method| method.as_str());
                let condition = entry.and_then(|row| row["condition"].as_object()).map(|condition| {
                    serde_json::json!({
                        "reason": condition.get("reason"),
                        "since_ms": condition.get("since_ms"),
                        "action_url": condition.get("action_url"),
                    })
                });
                let mut row = serde_json::json!({
                    "id": id,
                    "state": state,
                    "record_version": version,
                    "categories": categories,
                    "provider_ids": providers,
                    "auth_method": auth_method,
                    "plan_tier": plan_tier,
                    "plan_tier_source": plan_tier_source,
                    "provider": credentials_core::store::RegisteredProvider::service_for_id(&registered, id),
                    "incarnation": entry.and_then(|row| row.get("incarnation")).cloned().unwrap_or(serde_json::Value::Null),
                    "plan_tier_observed_at_ms": entry.and_then(|row| row.get("plan_tier_observed_at_ms")).cloned().unwrap_or(serde_json::Value::Null),
                    "plan_tier_since_ms": entry.and_then(|row| row.get("plan_tier_since_ms")).cloned().unwrap_or(serde_json::Value::Null),
                    "creator": creator,
                    "condition": condition,
                });
                if let Some(gateway) = entry.filter(|row| row.get("base_url").is_some()) {
                    row["base_url"] = gateway["base_url"].clone();
                    row["headers"] = gateway["headers"].clone();
                }
                row
            },
        )
        .collect();
    out.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    Ok(out)
}

/// Map each inventory id to its listed `auth_method`, derived without seeing a
/// payload: gateway metadata takes precedence; otherwise the record's kind and
/// refresh adapter (the stored choice of token-refresh flow) select through the
/// same [`credentials_core::list_auth_method::list_auth_method`] table that
/// `credential.list_scoped` rows use, never parsed from the credential id.
///
/// Lease-free and read-only (the same property `ck auth list` already keeps):
/// the store file is opened `SQLITE_OPEN_READ_ONLY` and no lease is taken, so
/// this works beside a running daemon and against a stopped one.
///
/// A missing store, an unresolvable master key or a failed read refuses the whole
/// listing. Scripts treat a null `auth_method` as "this credential has none", so
/// printing null for every row when the key was simply unreachable would read as a
/// fact about the credentials rather than about this shell. Only a single envelope
/// that will not open degrades its own row to null; that row's state already says
/// what is wrong with it.
fn inventory_auth_methods(
    global: &GlobalArgs,
) -> Result<
    std::collections::BTreeMap<String, Option<credentials_core::list_auth_method::ListAuthMethod>>,
    CliError,
> {
    let db = store_path(global);
    if !db.exists() {
        return Err(CliError::Usage(format!(
            "--json needs the local store to derive auth_method, and {} does not exist",
            db.display()
        )));
    }
    let key = resolve_store_key(global)?;
    credentials_core::store::auth_methods_read_only(&db, &key).map_err(|error| {
        CliError::Usage(format!(
            "--json could not read auth_method from the store: {error}"
        ))
    })
}

/// Report whether each credential still holds material the engine can work with.
///
/// The only command that OPENS EVERY ENVELOPE. `status` and `list` read plaintext
/// metadata, so neither can see a record that decrypts to nothing usable -- the one
/// state that needs an operator login and that no gauge can infer from the outside.
///
/// Lease-free like `events`, and for the same reason: the moment an operator asks is
/// the moment the vault is running, and a diagnostic that needs an outage to read is
/// useless exactly when it is needed. Unlike `events` this needs the master key, so it
/// resolves one WITHOUT opening an `EncryptedStore` (which would take the lease).
pub(super) fn cmd_usable(global: &GlobalArgs) -> Result<(), CliError> {
    use credentials_core::usable::{self, ScanError, Usability};

    let db = store_path(global);
    if !db.exists() {
        return Err(CliError::Usage(format!(
            "no vault at {} (run 'ck auth bootstrap' first)",
            global.data_dir.display()
        )));
    }
    let conn = usable::open_store_read_only(&db).map_err(|e| CliError::Io(e.to_string()))?;

    // Resolve the slot the STORE names, exactly as the daemon does. A rotation that
    // crashed after the rewrap and before the promote leaves the store sealed under
    // `next`; loading `current` would report every record unreadable on a vault that is
    // serving perfectly well.
    let cfg = resolver_config(global);
    let key = match usable::read_db_key_id_read_only(&conn) {
        Some(db_key_id) => resolver::resolve_for_db(&cfg, db_key_id),
        None => resolver::resolve(&cfg, None),
    }
    .map_err(CliError::MasterKey)?;

    let rows = match usable::scan(&conn, &key) {
        Ok(rows) => rows,
        // Bootstrapped but never written: the schema arrives with the first write, not
        // with `bootstrap`. Said plainly, because the raw sqlite error reads as a
        // corrupt store when the store is merely empty.
        Err(ScanError::NoSchema) => {
            println!("{} holds no credentials yet", global.data_dir.display());
            println!("  (the vault is bootstrapped; its schema is created by the first write)");
            return Ok(());
        }
        Err(e) => return Err(CliError::Io(e.to_string())),
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    let (mut serviceable, mut stranded, mut unreadable, mut bad_identity) = (0, 0, 0, 0);
    let mut declared_expired = 0;
    for row in &rows {
        let id = &row.credential_id;
        if row.unservable_identity {
            println!(
                "  {id:34} IDENTITY    email with no account_id: serves a label that \
                 resolves nothing (re-login or re-import to repair)"
            );
            bad_identity += 1;
        }
        match &row.usability {
            Usability::Unreadable { why } => {
                println!("  {id:34} UNREADABLE  {why}");
                unreadable += 1;
            }
            Usability::Stranded => {
                println!(
                    "  {id:34} oauth   {}  account={}  STRANDED: no access token and no refresh token",
                    row.state,
                    row.account_id.as_deref().unwrap_or("none")
                );
                stranded += 1;
            }
            Usability::Static {
                expires_at_ms,
                written_at_ms,
            } => {
                // AGE, not a lifetime claim. For a static record nothing but an
                // operator write moves this column -- no refresh touches the row -- so
                // elapsed time since it is exactly "how long since a human last put
                // this". It says nothing about whether the provider still honours the
                // credential, and deliberately does not try to.
                let age_days = (now - written_at_ms) / 86_400_000;
                // A declared expiry is the ONLY forward-looking signal a
                // non-refreshable credential can carry, and it is the operator's own
                // statement rather than the provider's -- so a key past it is called
                // out as DECLARED dead, not proven dead. Counted separately from
                // serviceable because an audit that folds it in tells an operator
                // everything is fine while a credential they themselves marked
                // short-lived sits a day past its date.
                if credentials_core::usable::static_past_declared_expiry(*expires_at_ms, now) {
                    let mins = (now - expires_at_ms.unwrap_or(now)) / 60_000;
                    println!(
                        "  {id:34} static  {}  DECLARED EXPIRED {mins}m ago: no refresh \
                         path, so only a re-put replaces it",
                        row.state
                    );
                    declared_expired += 1;
                } else {
                    let ttl = match expires_at_ms {
                        Some(exp) => format!("declared good for {}m", (exp - now) / 60_000),
                        None => "no expiry declared".to_string(),
                    };
                    println!(
                        "  {id:34} static  {}  written {age_days}d ago, {ttl}",
                        row.state
                    );
                    serviceable += 1;
                }
            }
            Usability::Cookie { written_at_ms } => {
                let age_days = (now - written_at_ms) / 86_400_000;
                println!(
                    "  {id:34} cookie  {}  session cookie captured {age_days}d ago; \
                     age is a staleness signal, re-capture after provider rejection",
                    row.state
                );
                serviceable += 1;
            }
            Usability::Serviceable { expires_at_ms } => {
                // Expiry is printed as context and never scored: an expired access
                // token is the routine state of a healthy credential, so counting it
                // would report normal operation as a problem.
                // "refreshes on next get" is TRUE OF THE MATERIAL AND FALSE OF THE
                // RECORD once the state is needs_reauth. EncryptedStore::get refuses at
                // the state check, before decrypting and long before the engine could
                // attempt a refresh -- so there is no next get, and the phrase invites
                // an operator to wait for a recovery that cannot arrive.
                //
                // Live instance: oauth:anthropic:ufuk3 sat needs_reauth for five hours
                // reading "refreshes on next get", while three sibling anthropic
                // accounts refreshed normally around it.
                let refresh_reachable = row.state != "needs_reauth";
                let ttl = match expires_at_ms {
                    Some(exp) => {
                        let mins = (exp - now) / 60_000;
                        if mins >= 0 {
                            format!("access good for {mins}m")
                        } else if refresh_reachable {
                            format!("access expired {}m ago, refreshes on next get", -mins)
                        } else {
                            format!(
                                "access expired {}m ago; refresh material is intact but \
                                 UNREACHABLE while the state is {} -- only a login clears it",
                                -mins, row.state
                            )
                        }
                    }
                    None => "no expiry recorded".to_string(),
                };
                println!(
                    "  {id:34} oauth   {}  account={}{}  {ttl}",
                    row.state,
                    row.account_id.as_deref().unwrap_or("none"),
                    // Only when it says something the account id does not -- the scan
                    // suppresses an email equal to it, so this appends exactly where a
                    // provider uuid would otherwise leave five accounts indistinguishable.
                    row.email
                        .as_deref()
                        .map(|email| format!(" ({email})"))
                        .unwrap_or_default()
                );
                serviceable += 1;
            }
        }
    }

    println!();
    println!(
        "  serviceable: {serviceable}   declared expired: {declared_expired}   \
         stranded: {stranded}   unreadable: {unreadable}   \
         unservable identity: {bad_identity}"
    );
    println!();
    println!("  Serviceable means the record decrypts under the current master key and");
    println!("  holds material the engine can either serve or refresh from. It is NOT a");
    println!("  claim that the provider will still honour it: only spending a token");
    println!("  answers that, and for rotating providers spending it invalidates the copy");
    println!("  we hold, so no dry run exists even in principle. The authoritative signal");
    println!("  for a provider-rejected credential is the `needs_reauth` state, which a");
    println!("  consumer sets via report_auth_failure and the health gauge already counts.");
    Ok(())
}

/// Verify the tamper-evidence chain, WITHOUT stopping the daemon.
///
/// This used to go through `open_for_admin`, which takes the single-writer lease and
/// therefore required the vault offline. That made it unrunnable in practice: nobody
/// takes the credential vault down to run an integrity check, so the check that
/// justifies the whole HMAC chain had never once run against the live store. A
/// tamper-evidence mechanism nobody can afford to invoke provides evidence of nothing.
///
/// The verification is a pure read -- fetch the entries, recompute each MAC over its
/// predecessor -- and needs the master key only to unseal the stored audit key. So it
/// resolves the key the way the daemon does (matching the slot the store's own
/// fingerprint names, so a vault left mid-rotation still verifies) and reads through a
/// lease-free connection, exactly like `events` and `usable`.
pub(super) fn cmd_verify_audit(global: &GlobalArgs) -> Result<(), CliError> {
    let db = store_path(global);
    if !db.exists() {
        return Err(CliError::Usage(format!(
            "no vault at {} (run 'ck auth bootstrap' first)",
            global.data_dir.display()
        )));
    }

    let conn = credentials_core::usable::open_store_read_only(&db)
        .map_err(|e| CliError::Io(e.to_string()))?;
    let cfg = resolver_config(global);
    let key = match credentials_core::usable::read_db_key_id_read_only(&conn) {
        Some(db_key_id) => resolver::resolve_for_db(&cfg, db_key_id),
        None => resolver::resolve(&cfg, None),
    }
    .map_err(CliError::MasterKey)?;
    drop(conn);

    match credentials_core::store::verify_audit_chain_read_only(&db, &key) {
        Ok(None) => {
            println!("audit chain verified: intact");
            Ok(())
        }
        Ok(Some(seq)) => Err(CliError::Io(format!(
            "audit chain BROKEN at seq {seq} (tamper detected)"
        ))),
        // An absent audit key is not an empty chain. Reporting "intact" for a store
        // whose key cannot be found would be the exact false green the chain exists to
        // prevent.
        Err(credentials_core::store::StoreOpError::NotFound) => Err(CliError::Io(
            "this vault has no audit key, so the chain cannot be verified \
             (it predates the sealed-audit-key scheme, or the row was removed)"
                .to_string(),
        )),
        Err(e) => Err(CliError::Store(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The categories note fires only on a store that lacks categories. A store past the
    /// category migration but behind a later one must not be told categories are missing.
    #[test]
    fn the_categories_note_fires_only_below_the_category_migration() {
        let category = credentials_core::store::CATEGORY_SCHEMA_VERSION;
        assert!(super::store_behind_note(category - 1).is_some());
        assert_eq!(super::store_behind_note(category), None);
        assert_eq!(
            super::store_behind_note(credentials_core::store::newest_migration_version() - 1),
            None,
            "one migration behind, but categories already exist"
        );
    }

    #[test]
    fn inventory_parser_accepts_exact_rows_and_rejects_malformed_status() {
        let valid = serde_json::json!({
            "credentials": [
                {"id": "apikey:test", "state": "active", "record_version": 7}
            ]
        });
        assert_eq!(
            parse_inventory(&valid).expect("valid inventory"),
            vec![(
                "active".to_string(),
                7,
                "apikey:test".to_string(),
                Vec::new(),
                Vec::new(),
            )]
        );

        for malformed in [
            serde_json::json!({}),
            serde_json::json!({"credentials": [{"id": "apikey:test", "state": "unknown", "record_version": 7}]}),
            serde_json::json!({"credentials": [{"id": "apikey:test", "state": "active", "record_version": 0}]}),
            serde_json::json!({"credentials": [{"id": "", "state": "active", "record_version": 7}]}),
        ] {
            assert!(
                parse_inventory(&malformed).is_err(),
                "malformed admin status must fail closed: {malformed}"
            );
        }
    }
}
