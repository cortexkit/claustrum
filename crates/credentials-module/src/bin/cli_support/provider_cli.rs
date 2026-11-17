//! Provider registration, metadata, and coverage-report commands.

#[cfg(test)]
use super::{
    admin_client, check_deposit_provider_flags, commit_login_deposit, provider_deposit_error_lines,
    provider_route_result, provider_store_behind_note, reject_unknown_args, store_behind_note,
    store_op, AdminAuditOp, CredentialKind, ExitCode, KeySource, MasterKey, StoreMode, VaultRecord,
};
use super::{
    catalog_default_provider_ids, check_cli_provider_ids, commit_admin, help_verb, optional,
    parse_inventory, provider_deposit_error, provider_id_flags, request_admin_status, required,
    set_providers_op, store_path, AdminOpBody, CliError, GlobalArgs, ParsedOptions,
    SetProvidersMode, StoreOpError, ADMIN_OP_SCHEMA_V2, ADMIN_OP_SCHEMA_V3,
};

pub(super) fn cmd_set_plan(global: &GlobalArgs, args: &[String]) -> Result<(), CliError> {
    let id = required(args, "--id")?;
    let tier = optional(args, "--tier");
    let clear = args.iter().any(|arg| arg == "--clear");
    if tier.is_some() == clear
        || args
            .iter()
            .filter(|arg| arg.as_str() == "--tier" || arg.as_str() == "--clear")
            .count()
            != 1
    {
        return Err(CliError::Usage(
            "choose exactly one of --tier <id> and --clear".into(),
        ));
    }
    if tier
        .as_deref()
        .is_some_and(|tier| !credentials_core::plan_tier::valid_plan_tier(tier))
    {
        return Err(CliError::Store(StoreOpError::InvalidPlanTier));
    }
    let since_ms = optional(args, "--since")
        .map(|value| parse_plan_since(&value))
        .transpose()?;
    if since_ms.is_some() && tier.is_none() {
        return Err(CliError::Store(StoreOpError::InvalidPlanTier));
    }
    let reply = commit_admin(
        global,
        AdminOpBody::SetPlan {
            v: ADMIN_OP_SCHEMA_V2,
            credential_id: id.clone(),
            plan_tier: tier,
            since_ms: since_ms.map(serde_json::Value::from),
        },
    )?;
    let tier = match reply.get("plan_tier") {
        Some(serde_json::Value::Null) => "-",
        Some(serde_json::Value::String(tier))
            if credentials_core::plan_tier::valid_plan_tier(tier) =>
        {
            tier
        }
        _ => {
            return Err(CliError::StatusReportInvalid(
                "set-plan returned an invalid tier".into(),
            ))
        }
    };
    println!("{id}  {tier}");
    Ok(())
}

pub(super) fn parse_plan_since(value: &str) -> Result<u64, CliError> {
    let invalid = || CliError::Store(StoreOpError::InvalidPlanTier);
    let since = if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) {
        value.parse::<u64>().map_err(|_| invalid())?
    } else {
        let timestamp = if value.len() == 10 {
            chrono::NaiveDate::parse_from_str(value, "%Y-%m-%d")
                .map_err(|_| invalid())?
                .and_hms_opt(0, 0, 0)
                .ok_or_else(invalid)?
                .and_utc()
                .timestamp_millis()
        } else {
            chrono::DateTime::parse_from_rfc3339(value)
                .map_err(|_| invalid())?
                .timestamp_millis()
        };
        u64::try_from(timestamp).map_err(|_| invalid())?
    };
    if !credentials_core::plan_tier::valid_plan_tier_since_ms(
        since,
        chrono::Utc::now().timestamp_millis() as u64,
    ) {
        return Err(invalid());
    }
    Ok(since)
}

pub(super) fn cmd_set_providers(global: &GlobalArgs, args: &[String]) -> Result<(), CliError> {
    let id = required(args, "--id")?;
    let modes: Vec<_> = args
        .iter()
        .filter(|s| matches!(s.as_str(), "--set" | "--add" | "--remove"))
        .collect();
    if modes.len() != 1 {
        return Err(CliError::Usage(
            "choose exactly one of --set, --add, --remove".into(),
        ));
    }
    let mode = match modes[0].as_str() {
        "--set" => SetProvidersMode::Set,
        "--add" => SetProvidersMode::Add,
        _ => SetProvidersMode::Remove,
    };
    let mut ids = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--id" {
            i += 2;
        } else if args[i].starts_with("--") {
            i += 1;
        } else {
            ids.push(args[i].clone());
            i += 1;
        }
    }
    if mode != SetProvidersMode::Set && ids.is_empty() {
        return Err(CliError::Usage(
            "--add and --remove need at least one provider id".into(),
        ));
    }
    check_cli_provider_ids(&ids, mode != SetProvidersMode::Remove)?;
    let reply = commit_admin(global, set_providers_op(&id, mode, &ids))?;
    let providers = reply["provider_ids"].as_array().ok_or_else(|| {
        CliError::StatusReportInvalid("set-providers omitted provider ids".into())
    })?;
    let mut providers = providers
        .iter()
        .map(|v| v.as_str().map(str::to_owned))
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| {
            CliError::StatusReportInvalid("set-providers returned invalid provider ids".into())
        })?;
    providers.sort();
    println!(
        "{id}  {}",
        if providers.is_empty() {
            "-".into()
        } else {
            providers.join(",")
        }
    );
    Ok(())
}

pub(super) fn finish_provider_deposit(
    global: &GlobalArgs,
    id: &str,
    ids: &[String],
) -> Result<(), CliError> {
    if ids.is_empty() {
        print_missing_provider_note(global, id);
    } else {
        commit_admin(global, set_providers_op(id, SetProvidersMode::Add, ids))
            .map_err(|error| provider_deposit_error(id, ids, error))?;
    }
    Ok(())
}

fn missing_provider_note(result: &serde_json::Value, id: &str) -> Option<String> {
    let row = result["credentials"]
        .as_array()?
        .iter()
        .find(|row| row["id"].as_str() == Some(id))?;
    let categories = row["categories"].as_array()?;
    let providers = row["provider_ids"].as_array()?;
    if categories
        .iter()
        .any(|value| value.as_str() == Some("llm-provider"))
        && providers.is_empty()
    {
        Some(format!("note: {id} has no catalog provider ids; attach them with ck auth set-providers --id {id} --add <provider-id>"))
    } else {
        None
    }
}

pub(super) fn print_missing_provider_note(global: &GlobalArgs, id: &str) {
    if let Ok(status) = request_admin_status(global) {
        if let Some(note) = missing_provider_note(&status, id) {
            eprintln!("{note}");
        }
    }
}

fn repeated_values(args: &[String], flag: &str) -> Vec<String> {
    args[1..]
        .as_chunks::<2>()
        .0
        .iter()
        .filter(|pair| pair[0] == flag)
        .map(|pair| pair[1].clone())
        .collect()
}

fn canonical_provider_hosts(values: &[String]) -> Vec<String> {
    let mut hosts: Vec<_> = values
        .iter()
        .flat_map(|value| value.split(','))
        .map(|host| host.trim().to_ascii_lowercase())
        .collect();
    hosts.sort();
    hosts.dedup();
    hosts
}

pub(super) fn provider_set_op(
    service: String,
    categories: Vec<String>,
    provider_ids: Vec<String>,
    mut settings: credentials_core::store::RegisteredProviderSettings,
) -> Result<AdminOpBody, CliError> {
    credentials_core::store::validate_registered_provider_service(&service)
        .map_err(CliError::Store)?;
    check_cli_provider_ids(&provider_ids, true)?;
    settings.hosts = canonical_provider_hosts(&settings.hosts);
    settings.auth_header = settings
        .auth_header
        .map(|header| header.to_ascii_lowercase());
    credentials_core::store::validate_registered_provider_settings(&settings)
        .map_err(CliError::Store)?;
    Ok(AdminOpBody::ProviderSet {
        v: ADMIN_OP_SCHEMA_V3,
        service,
        categories,
        provider_ids,
        hosts: Some(serde_json::json!(settings.hosts)),
        auth_header: Some(serde_json::json!(settings.auth_header)),
        auth_scheme: Some(serde_json::json!(settings.auth_scheme)),
        fusiform_provider_id: Some(serde_json::json!(settings.fusiform_provider_id)),
    })
}

pub(super) fn cmd_provider(
    global: &GlobalArgs,
    args: &[String],
    options: ParsedOptions,
) -> Result<(), CliError> {
    let action = args.first().map(String::as_str);
    let service_flags = ["--service"];
    let flags: &[&str] = match action {
        Some("list") if args.len() == 1 => &[],
        Some("set") => &[
            "--service",
            "--category",
            "--provider-id",
            "--host",
            "--auth-header",
            "--auth-scheme",
            "--fusiform-id",
        ],
        Some("remove") => &service_flags,
        _ => return Err(CliError::Usage(help_verb("provider"))),
    };
    let (pairs, remainder) = args[1..].as_chunks::<2>();
    if !remainder.is_empty()
        || !pairs
            .iter()
            .all(|pair| flags.contains(&pair[0].as_str()) && !pair[1].starts_with("--"))
        || (action != Some("list")
            && args
                .iter()
                .filter(|arg| arg.as_str() == "--service")
                .count()
                != 1)
    {
        return Err(CliError::Usage(help_verb("provider")));
    }
    match args.first().map(String::as_str) {
        Some("list") if args.len() == 1 => {
            let rows = credentials_core::store::registered_providers_read_only(&store_path(global))
                .map_err(CliError::Store)?;
            println!("SERVICE\tGROUPS\tPROVIDER IDS\tHOSTS\tAUTH\tFUSIFORM ID");
            for row in rows {
                let auth = row.auth_header.zip(row.auth_scheme).map(
                    |(header, scheme)| serde_json::json!({"header": header, "scheme": scheme}),
                );
                println!(
                    "{}\t{}\t{}\t{}\t{}\t{}",
                    row.service,
                    serde_json::to_string(&row.categories).unwrap(),
                    serde_json::to_string(&row.provider_ids).unwrap(),
                    serde_json::to_string(&row.hosts).unwrap(),
                    serde_json::to_string(&auth).unwrap(),
                    serde_json::to_string(&row.fusiform_provider_id).unwrap()
                );
            }
        }
        Some("set") => {
            let service = options.required("--service")?;
            let provider_ids = provider_id_flags(args)?;
            let op = provider_set_op(
                service.clone(),
                repeated_values(args, "--category"),
                provider_ids,
                credentials_core::store::RegisteredProviderSettings {
                    hosts: repeated_values(args, "--host"),
                    auth_header: options.optional("--auth-header"),
                    auth_scheme: options.optional("--auth-scheme"),
                    fusiform_provider_id: options.optional("--fusiform-id"),
                },
            )?;
            commit_admin(global, op)?;
            println!("set provider {service}");
        }
        Some("remove") if args.len() == 3 && args[1] == "--service" => {
            let service = options.required("--service")?;
            commit_admin(
                global,
                AdminOpBody::ProviderRemove {
                    v: ADMIN_OP_SCHEMA_V2,
                    service: service.clone(),
                },
            )?;
            println!("removed provider {service}");
        }
        _ => return Err(CliError::Usage(help_verb("provider"))),
    }
    Ok(())
}

fn missing_provider_report_lines(
    missing: &[&credentials_core::fusiform_providers::FusiformProvider],
    skips: &[(&str, &str)],
) -> Vec<String> {
    let mut lines: Vec<_> = missing.iter().map(|provider| provider.id.clone()).collect();
    lines.push("Skipped:".to_owned());
    let mut skips = skips.to_vec();
    skips.sort_by_key(|(id, _)| *id);
    lines.extend(skips.iter().map(|(id, reason)| format!("{id}\t{reason}")));
    lines
}

pub(super) fn cmd_provider_report(
    global: &GlobalArgs,
    options: ParsedOptions,
) -> Result<(), CliError> {
    if options.has_flag("--missing") {
        for line in missing_provider_report_lines(
            &credentials_core::catalog::missing_fusiform_providers(),
            credentials_core::catalog::FUSIFORM_PROVIDER_SKIPS,
        ) {
            println!("{line}");
        }
        return Ok(());
    }
    let result = request_admin_status(global)?;
    println!("ID\tSTORED\tTABLE");
    for (_, _, id, _, mut stored) in parse_inventory(&result)? {
        if credentials_core::catalog::provider(&id).is_none() {
            continue;
        }
        let mut defaults: Vec<_> = catalog_default_provider_ids(&id)
            .iter()
            .map(|s| s.to_string())
            .collect();
        stored.sort();
        defaults.sort();
        if stored != defaults {
            println!(
                "{id}\t{}\t{}",
                serde_json::to_string(&stored).unwrap(),
                serde_json::to_string(&defaults).unwrap()
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod provider_cli_tests {
    use super::*;

    #[test]
    fn ordinary_deposit_provider_flag_usage_checks_only_the_service_marker() {
        let ordinary = vec!["openai".to_string()];
        for id in ["apikey:openai", "apikey:openai:label-gw-x"] {
            check_deposit_provider_flags(Some(id), &ordinary).unwrap();
        }
        for id in ["apikey:anthropic-gw-x", "apikey:anthropic-gw-x:team"] {
            assert!(matches!(
                check_deposit_provider_flags(Some(id), &ordinary),
                Err(CliError::Usage(message)) if message.contains("ck auth set-providers")
            ));
            check_deposit_provider_flags(Some(id), &[]).unwrap();
        }
        assert!(matches!(
            check_deposit_provider_flags(None, &["anthropic-gw-x".to_string()]),
            Err(CliError::Usage(message)) if message.contains("rule=reserved")
        ));
    }

    #[test]
    fn ordinary_deposit_help_explains_reserved_ids_and_default_repairs() {
        for verb in ["put", "login"] {
            let help = help_verb(verb);
            assert!(help.contains("-gw-"));
            assert!(help.contains("ck auth provider set"));
            assert!(help.contains("before storing") || help.contains("before\nstoring"));
        }
        assert!(help_verb("put").contains("--provider-id is a usage error"));
    }

    #[test]
    fn provider_missing_report_places_skips_and_reasons_after_uncovered_ids() {
        let provider = &credentials_core::fusiform_providers::fusiform_providers()[0];
        assert_eq!(
            missing_provider_report_lines(
                &[provider],
                &[
                    ("z-skip", "OAuth only"),
                    ("a-skip", "no API key in its documentation")
                ],
            ),
            [
                provider.id.as_str(),
                "Skipped:",
                "a-skip\tno API key in its documentation",
                "z-skip\tOAuth only"
            ]
        );
        assert_eq!(missing_provider_report_lines(&[], &[]), ["Skipped:"]);
        let options = reject_unknown_args("provider-report", &["--missing".to_owned()]).unwrap();
        assert!(options.has_flag("--missing"));
        assert!(reject_unknown_args("provider-report", &["--missng".to_owned()]).is_err());
    }

    #[test]
    fn provider_set_body_is_v3_and_canonical() {
        let op = provider_set_op(
            "custom-service".into(),
            vec!["llm-provider".into()],
            vec!["custom-models".into()],
            credentials_core::store::RegisteredProviderSettings {
                hosts: vec![
                    " B.example.com, a.example.com ".into(),
                    "b.example.com".into(),
                ],
                auth_header: Some("X-API-Key".into()),
                auth_scheme: Some("raw".into()),
                fusiform_provider_id: None,
            },
        )
        .unwrap();
        assert_eq!(
            serde_json::to_value(op).unwrap(),
            serde_json::json!({
                "op": "admin.provider_set", "v": 3, "service": "custom-service",
                "categories": ["llm-provider"], "provider_ids": ["custom-models"],
                "hosts": ["a.example.com", "b.example.com"],
                "auth_header": "x-api-key", "auth_scheme": "raw",
                "fusiform_provider_id": null
            })
        );
    }

    #[test]
    fn provider_set_empty_registration_is_a_v3_clear() {
        let op = provider_set_op(
            "custom-service".into(),
            vec![],
            vec![],
            credentials_core::store::RegisteredProviderSettings::default(),
        )
        .unwrap();
        assert_eq!(
            serde_json::to_value(op).unwrap(),
            serde_json::json!({
                "op": "admin.provider_set", "v": 3, "service": "custom-service",
                "categories": [], "provider_ids": [], "hosts": [],
                "auth_header": null, "auth_scheme": null, "fusiform_provider_id": null
            })
        );
    }

    #[test]
    fn provider_registration_help_explains_complete_replacement_and_new_flags() {
        for page in ["provider", "provider set"] {
            let help = help_verb(page);
            for flag in ["--host", "--auth-header", "--auth-scheme", "--fusiform-id"] {
                assert!(help.contains(flag), "{page}: {flag}");
            }
            assert!(help.contains(
                "set states the whole registration; omitted optional settings are cleared."
            ));
            assert!(help.lines().all(|line| line.len() <= 80), "{page}");
        }
        assert!(help_verb("provider list")
            .contains("Columns: SERVICE, GROUPS, PROVIDER IDS, HOSTS, AUTH, FUSIFORM ID."));
    }

    #[test]
    fn provider_flags_do_not_parse_another_flags_value_as_a_flag() {
        let args: Vec<String> = [
            "--id",
            "apikey:test",
            "--payload-file",
            "--provider-id",
            "--provider-id",
            "aa",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        assert_eq!(provider_id_flags(&args).unwrap(), vec!["aa"]);
        let payload_only: Vec<String> = ["--payload-file", "--provider-id"]
            .into_iter()
            .map(str::to_owned)
            .collect();
        assert!(provider_id_flags(&payload_only).unwrap().is_empty());
    }

    #[test]
    fn provider_second_op_failures_preserve_the_error_and_always_retry_add() {
        let ids = vec!["aa".into(), "bb".into()];
        let failures = [
            CliError::Store(StoreOpError::InvalidProviderId {
                rule: credentials_core::provider_ids::ProviderIdRule::Count,
                value: "bb".into(),
            }),
            CliError::RouteRefused("invalid_provider_id/permanent: rule=count value=bb".into()),
            CliError::LocalFailure("key unavailable".into()),
            CliError::RouteIndeterminate("connection dropped".into()),
            CliError::Io("read failed".into()),
        ];
        for error in failures {
            let lines = provider_deposit_error_lines("apikey:zai", &ids, &error);
            assert_eq!(
                lines[0],
                format!(
                    "note: deposit of apikey:zai stood; provider ids were not confirmed: {error}"
                )
            );
            assert_eq!(
                lines[1],
                "retry: ck auth set-providers --id apikey:zai --add aa bb"
            );
            let code = error.exit_code();
            let returned = provider_deposit_error("apikey:zai", &ids, error);
            assert_eq!(returned.exit_code(), code);
        }
    }

    #[test]
    fn every_second_route_outcome_keeps_the_add_retry_and_indeterminate_exit_code() {
        use admin_client::RouteCommit;
        let ids = vec!["aa".into()];
        for outcome in [
            RouteCommit::Refused("count refusal".into()),
            RouteCommit::LocalFailure("local failure".into()),
            RouteCommit::NoLiveModule("gone".into()),
            RouteCommit::Indeterminate("unknown".into()),
        ] {
            let error = provider_route_result(outcome).unwrap_err();
            let expected_code = if matches!(error, CliError::RouteIndeterminate(_)) {
                ExitCode::from(5)
            } else {
                ExitCode::FAILURE
            };
            assert_eq!(
                provider_deposit_error_lines("oauth:cursor", &ids, &error)[1],
                "retry: ck auth set-providers --id oauth:cursor --add aa"
            );
            assert_eq!(
                provider_deposit_error("oauth:cursor", &ids, error).exit_code(),
                expected_code
            );
        }
        assert!(provider_route_result(RouteCommit::Committed(serde_json::json!({}))).is_ok());
    }

    #[test]
    fn missing_provider_advisory_requires_explicit_llm_category_and_empty_ids() {
        let status = serde_json::json!({"credentials": [
            {"id":"apikey:zai", "categories":["llm-provider", "web-search"], "provider_ids":[]},
            {"id":"apikey:kimi-code", "categories":["coding-agent"], "provider_ids":[]},
            {"id":"apikey:bound", "categories":["llm-provider"], "provider_ids":["aa"]},
            {"id":"apikey:old", "categories":["llm-provider"]},
            {"id":"apikey:unknown", "provider_ids":[]}
        ]});
        assert!(missing_provider_note(&status, "apikey:zai")
            .unwrap()
            .contains("ck auth set-providers"));
        for id in [
            "apikey:kimi-code",
            "apikey:bound",
            "apikey:old",
            "apikey:unknown",
            "missing",
        ] {
            assert!(missing_provider_note(&status, id).is_none(), "{id}");
        }
    }

    #[test]
    fn special_login_two_op_helper_uses_the_preflighted_key_without_resolving_again() {
        let root = credentials_core::test_support::TestTempDir::new("special-provider-key");
        let global = GlobalArgs {
            data_dir: root.join("vault"),
            key_source: KeySource::OperatorPath {
                path: root.join("absent-master.key"),
            },
            subc_conn: None,
        };
        std::fs::create_dir_all(&global.data_dir).unwrap();
        let id = "oauth:cursor";
        let record =
            VaultRecord::new_static(CredentialKind::ApiKey, "login", b"secret".to_vec(), None);
        commit_login_deposit(
            &global,
            store_op(id, record, AdminAuditOp::Login, StoreMode::Create),
            MasterKey::from_bytes([11; 32]),
            id,
            &["aa".into()],
        )
        .unwrap();
        let status = request_admin_status(&global).unwrap();
        assert_eq!(
            status["credentials"][0]["provider_ids"],
            serde_json::json!(["aa"])
        );
        assert_eq!(status["credentials"][0]["record_version"], 1);
        assert!(!root.join("absent-master.key").exists());
    }

    #[test]
    fn provider_schema_note_is_independent_of_category_schema() {
        let categories = credentials_core::store::CATEGORY_SCHEMA_VERSION;
        let providers = credentials_core::store::PROVIDER_ID_SCHEMA_VERSION;
        assert!(store_behind_note(categories - 1).is_some());
        assert!(provider_store_behind_note(categories - 1).is_some());
        assert!(store_behind_note(categories).is_none());
        assert_eq!(provider_store_behind_note(providers - 1).unwrap(), format!(
            "note: store schema {} is behind this binary's {}; provider ids appear after the daemon restarts (migration {providers})",
            providers - 1, credentials_core::store::newest_migration_version()
        ));
        assert!(provider_store_behind_note(providers).is_none());
    }
}
