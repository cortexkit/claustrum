#[cfg(feature = "import-prompt-seam")]
use std::collections::VecDeque;
use std::collections::{BTreeMap, BTreeSet};
use std::io::IsTerminal;

use credentials_core::record::VaultRecord;
#[cfg(feature = "import-prompt-seam")]
use serde::Deserialize;
use serde_json::Value;

use super::cli_support::import_detect::slice2_contract::{
    self, CommitAction, CommitSeam, PromptRequest, PromptResponse, PromptSeam, PromptSource,
};
use super::cli_support::import_detect::{
    self, classify_inventory_row, DetectedRow, EntrySelection, ImportAction, InventoryTuple,
};
use super::{
    attach_import_identity, build_import_record, commit_admin, created_id_is_already_reachable,
    login_id_is_valid, resolve_store_key, store_op, CliError, GlobalArgs, IdentityFlags,
};
use credentials_core::admin_ops::{AdminAuditOp, AdminOpBody, StoreMode, ADMIN_OP_SCHEMA_V1};

const FLAG_FORM: &str = "ck auth import --source <harness> --id <id> --json <file>";

struct PickerRow {
    detected: DetectedRow,
    label: String,
    initial_action: Option<ImportAction>,
    final_id: Option<String>,
    prompt_opens: usize,
}

impl PickerRow {
    fn proposed_id(&self) -> Option<&str> {
        self.detected.metadata.proposed_id.as_deref()
    }

    fn selectable(&self) -> bool {
        self.detected.is_selectable()
    }
}

fn action_text(action: ImportAction) -> String {
    match action {
        ImportAction::Create => "create".to_string(),
        ImportAction::Replace { record_version } => format!("replace v{record_version}"),
    }
}

fn render_row(row: &DetectedRow, inventory: &[InventoryTuple]) -> (String, Option<ImportAction>) {
    let source = row.metadata.source.token();
    match row.metadata.proposed_id.as_deref() {
        Some(id) if row.is_selectable() => {
            let action = classify_inventory_row(inventory, id);
            (
                format!("{source}: {id} — {}", action_text(action)),
                Some(action),
            )
        }
        _ => (
            format!(
                "{source}: {} — not importable",
                row.non_selectable_text()
                    .unwrap_or_else(|| "unknown entry".to_string())
            ),
            None,
        ),
    }
}

struct TerminalPrompts {
    labels: Vec<String>,
    defaults: Vec<bool>,
}

impl PromptSeam for TerminalPrompts {
    type Error = CliError;

    fn prompt(&mut self, request: PromptRequest) -> Result<PromptResponse, Self::Error> {
        use dialoguer::{theme::ColorfulTheme, Confirm, Input, MultiSelect};

        match request {
            PromptRequest::PickRows => {
                let picked = MultiSelect::with_theme(&ColorfulTheme::default())
                    .with_prompt("Detected accounts ([all] and [none] apply at submit)")
                    .items(&self.labels)
                    .defaults(&self.defaults)
                    .interact_opt()
                    .map_err(|error| CliError::Io(format!("opening import picker: {error}")))?;
                Ok(match picked {
                    Some(indices) => PromptResponse::Picked(
                        indices
                            .into_iter()
                            .filter_map(|index| self.labels.get(index).cloned())
                            .collect(),
                    ),
                    None => PromptResponse::Cancel,
                })
            }
            PromptRequest::EditId { initial, .. } => {
                Input::<String>::with_theme(&ColorfulTheme::default())
                    .with_prompt("Credential id")
                    .default(initial)
                    .interact_text()
                    .map(PromptResponse::Id)
                    .map_err(|error| CliError::Io(format!("editing import id: {error}")))
            }
            PromptRequest::ConfirmSummary => Confirm::with_theme(&ColorfulTheme::default())
                .with_prompt("Import this batch?")
                .default(false)
                .interact_opt()
                .map(|answer| {
                    answer
                        .map(PromptResponse::Confirm)
                        .unwrap_or(PromptResponse::Cancel)
                })
                .map_err(|error| CliError::Io(format!("confirming import batch: {error}"))),
        }
    }
}

#[cfg(feature = "import-prompt-seam")]
#[derive(Deserialize)]
#[serde(untagged)]
enum ScriptPrompt {
    Pick { pick: Vec<String> },
    Id { id: String },
    Confirm { confirm: bool },
    Cancel { cancel: bool },
}

#[cfg(feature = "import-prompt-seam")]
struct ScriptPrompts {
    responses: VecDeque<ScriptPrompt>,
}

#[cfg(feature = "import-prompt-seam")]
impl ScriptPrompts {
    fn from_env() -> Result<Self, CliError> {
        let path = std::env::var(slice2_contract::PROMPT_SCRIPT_ENV).map_err(|_| {
            CliError::Usage("import prompt script environment variable is missing".to_string())
        })?;
        let bytes = std::fs::read(&path).map_err(|error| {
            CliError::Io(format!("reading import prompt script {path}: {error}"))
        })?;
        let responses = serde_json::from_slice::<Vec<ScriptPrompt>>(&bytes)
            .map_err(|_| CliError::Usage("import prompt script is invalid JSON".to_string()))?;
        Ok(Self {
            responses: responses.into(),
        })
    }
}

#[cfg(feature = "import-prompt-seam")]
impl PromptSeam for ScriptPrompts {
    type Error = CliError;

    fn prompt(&mut self, request: PromptRequest) -> Result<PromptResponse, Self::Error> {
        let response = self.responses.pop_front().ok_or_else(|| {
            CliError::Usage(slice2_contract::ScriptExhausted { seam: "prompt" }.to_string())
        })?;
        let response = match (request, response) {
            (PromptRequest::PickRows, ScriptPrompt::Pick { pick }) => PromptResponse::Picked(pick),
            (PromptRequest::EditId { .. }, ScriptPrompt::Id { id }) => PromptResponse::Id(id),
            (PromptRequest::ConfirmSummary, ScriptPrompt::Confirm { confirm }) => {
                PromptResponse::Confirm(confirm)
            }
            (_, ScriptPrompt::Cancel { cancel: true }) => PromptResponse::Cancel,
            _ => {
                return Err(CliError::Usage(
                    "import prompt script response does not match the opened prompt".to_string(),
                ))
            }
        };
        Ok(response)
    }
}

struct RealCommit<'a> {
    global: &'a GlobalArgs,
}

impl CommitSeam for RealCommit<'_> {
    type Error = CliError;

    fn commit(
        &mut self,
        final_id: &str,
        record: VaultRecord,
        action: CommitAction,
    ) -> Result<Value, Self::Error> {
        let op = match action {
            CommitAction::Create => {
                store_op(final_id, record, AdminAuditOp::Import, StoreMode::Create)
            }
            CommitAction::Replace => AdminOpBody::StoreWithIdentityPolicy {
                v: ADMIN_OP_SCHEMA_V1,
                id: final_id.to_string(),
                record: Box::new(record),
                audit_op: AdminAuditOp::Import,
                clear_identity: false,
            },
        };
        commit_admin(self.global, op)
    }
}

#[cfg(feature = "import-prompt-seam")]
#[derive(Deserialize)]
#[serde(untagged)]
enum ScriptCommit {
    Stored { stored: bool },
    Refused { refused: bool },
}

#[cfg(feature = "import-prompt-seam")]
struct InjectedCommit<'a> {
    outcomes: VecDeque<ScriptCommit>,
    real: RealCommit<'a>,
}

#[cfg(feature = "import-prompt-seam")]
impl<'a> InjectedCommit<'a> {
    fn from_env(global: &'a GlobalArgs) -> Result<Option<Self>, CliError> {
        let Ok(path) = std::env::var(slice2_contract::COMMIT_SCRIPT_ENV) else {
            return Ok(None);
        };
        let bytes = std::fs::read(&path).map_err(|error| {
            CliError::Io(format!("reading import commit script {path}: {error}"))
        })?;
        let outcomes = serde_json::from_slice::<Vec<ScriptCommit>>(&bytes)
            .map_err(|_| CliError::Usage("import commit script is invalid JSON".to_string()))?;
        Ok(Some(Self {
            outcomes: outcomes.into(),
            real: RealCommit { global },
        }))
    }
}

#[cfg(feature = "import-prompt-seam")]
impl CommitSeam for InjectedCommit<'_> {
    type Error = CliError;

    fn commit(
        &mut self,
        final_id: &str,
        record: VaultRecord,
        action: CommitAction,
    ) -> Result<Value, Self::Error> {
        match self.outcomes.pop_front().ok_or_else(|| {
            CliError::Usage(slice2_contract::ScriptExhausted { seam: "commit" }.to_string())
        })? {
            ScriptCommit::Stored { stored: true } => self.real.commit(final_id, record, action),
            ScriptCommit::Refused { refused: true } => {
                Err(CliError::RouteRefused("injected refusal".to_string()))
            }
            _ => Err(CliError::Usage(
                "import commit script outcome must be true".to_string(),
            )),
        }
    }
}

fn resolve_selection(
    rows: &[PickerRow],
    picked: &[String],
) -> Result<(Vec<usize>, Vec<usize>), CliError> {
    let all = picked.iter().any(|value| value == "[all]");
    let none = picked.iter().any(|value| value == "[none]");
    if all && none {
        return Err(CliError::Usage(
            "[all] and [none] cannot both be checked; choose again".to_string(),
        ));
    }
    if none {
        return Ok((Vec::new(), Vec::new()));
    }

    let mut selected = BTreeSet::new();
    if all {
        selected.extend(
            rows.iter()
                .enumerate()
                .filter_map(|(index, row)| row.selectable().then_some(index)),
        );
    }
    for value in picked {
        if matches!(value.as_str(), "[all]" | "[none]") {
            continue;
        }
        let Some((index, _)) = rows
            .iter()
            .enumerate()
            .find(|(_, row)| row.proposed_id() == Some(value.as_str()) || row.label == *value)
        else {
            return Err(CliError::Usage(format!(
                "import picker selection '{value}' is neither a proposed id nor a rendered label"
            )));
        };
        selected.insert(index);
    }
    let (selectable, dropped): (Vec<_>, Vec<_>) = selected
        .into_iter()
        .partition(|index| rows[*index].selectable());
    Ok((selectable, dropped))
}

fn prompt_id(
    prompts: &mut impl PromptSeam<Error = CliError>,
    row_index: usize,
    row: &mut PickerRow,
) -> Result<Option<String>, CliError> {
    let base_id = row
        .detected
        .metadata
        .base_id
        .as_deref()
        .ok_or_else(|| CliError::Usage("importable row omitted its base id".to_string()))?;
    loop {
        if row.prompt_opens >= slice2_contract::ID_PROMPT_OPEN_LIMIT_PER_ROW {
            return Err(CliError::Usage(format!(
                "id prompt exhausted for {base_id} after {} opens",
                slice2_contract::ID_PROMPT_OPEN_LIMIT_PER_ROW
            )));
        }
        row.prompt_opens += 1;
        let initial = row
            .final_id
            .clone()
            .or_else(|| row.proposed_id().map(str::to_string))
            .ok_or_else(|| CliError::Usage("importable row omitted its proposed id".to_string()))?;
        match prompts.prompt(PromptRequest::EditId {
            row: row_index,
            initial,
        })? {
            PromptResponse::Id(id) if login_id_is_valid(base_id, &id) => return Ok(Some(id)),
            PromptResponse::Id(_) => {
                eprintln!(
                    "invalid credential id; keep the fixed '{base_id}' prefix and optionally append one label"
                );
            }
            PromptResponse::Cancel => return Ok(None),
            _ => {
                return Err(CliError::Usage(
                    "import prompt returned a non-id response for an id prompt".to_string(),
                ))
            }
        }
    }
}

fn edit_ids(
    prompts: &mut impl PromptSeam<Error = CliError>,
    rows: &mut [PickerRow],
    selected: &[usize],
) -> Result<bool, CliError> {
    for &index in selected {
        let Some(id) = prompt_id(prompts, index, &mut rows[index])? else {
            return Ok(false);
        };
        rows[index].final_id = Some(id);
    }

    loop {
        let mut by_id: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        for &index in selected {
            by_id
                .entry(
                    rows[index]
                        .final_id
                        .clone()
                        .expect("selected row has final id"),
                )
                .or_default()
                .push(index);
        }
        let collisions: Vec<_> = by_id
            .into_iter()
            .filter(|(_, indices)| indices.len() > 1)
            .collect();
        if collisions.is_empty() {
            return Ok(true);
        }
        for (id, indices) in collisions {
            let names = indices
                .iter()
                .map(|index| rows[*index].label.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            eprintln!("duplicate final id '{id}' for rows: {names}");
            for index in indices {
                let Some(new_id) = prompt_id(prompts, index, &mut rows[index])? else {
                    return Ok(false);
                };
                rows[index].final_id = Some(new_id);
            }
        }
    }
}

fn print_dropped(rows: &[PickerRow], dropped: &[usize]) {
    for &index in dropped {
        println!("{}: not importable", rows[index].label);
    }
}

fn drive<P, C>(
    global: &GlobalArgs,
    inventory: &[InventoryTuple],
    mut rows: Vec<PickerRow>,
    prompts: &mut P,
    commits: &mut C,
) -> Result<(), CliError>
where
    P: PromptSeam<Error = CliError>,
    C: CommitSeam<Error = CliError>,
{
    let (selected, dropped) = loop {
        let response = prompts.prompt(PromptRequest::PickRows)?;
        let picked = match response {
            PromptResponse::Picked(picked) => picked,
            PromptResponse::Cancel => return Ok(()),
            _ => {
                return Err(CliError::Usage(
                    "import prompt returned a non-selection response for the picker".to_string(),
                ))
            }
        };
        match resolve_selection(&rows, &picked) {
            Ok(selection) => break selection,
            Err(CliError::Usage(message)) if message.starts_with("[all]") => {
                eprintln!("{message}");
            }
            Err(error) => return Err(error),
        }
    };

    if selected.is_empty() {
        if dropped.is_empty() {
            return Ok(());
        }
        print_dropped(&rows, &dropped);
        return Err(CliError::Usage(
            "no selected account was importable".to_string(),
        ));
    }
    if !edit_ids(prompts, &mut rows, &selected)? {
        return Ok(());
    }

    println!("Import summary:");
    for &index in &selected {
        let id = rows[index].final_id.as_deref().expect("final id");
        println!(
            "  {id}: {}",
            action_text(classify_inventory_row(inventory, id))
        );
    }
    match prompts.prompt(PromptRequest::ConfirmSummary)? {
        PromptResponse::Confirm(true) => {}
        PromptResponse::Confirm(false) | PromptResponse::Cancel => return Ok(()),
        _ => {
            return Err(CliError::Usage(
                "import prompt returned a non-confirmation response for the summary".to_string(),
            ))
        }
    }

    let mut refused = !dropped.is_empty();
    print_dropped(&rows, &dropped);
    for &index in &selected {
        let row = &rows[index];
        let final_id = row.final_id.as_deref().expect("final id");
        let action = classify_inventory_row(inventory, final_id);
        let provider_selection = match &row.detected.metadata.entry_selection {
            EntrySelection::ProviderKey(provider) => Some(provider.as_str()),
            EntrySelection::AntigravityAccount(_) | EntrySelection::None => None,
        };
        let adapter = row.detected.metadata.refresh_adapter.clone();
        let source = row.detected.metadata.source.token();
        let payload = row
            .detected
            .payload()
            .expect("selected row payload")
            .as_bytes();
        let outcome = build_import_record(source, payload, final_id, provider_selection, adapter)
            .map(|(record, imported_email)| {
                attach_import_identity(record, IdentityFlags::default(), imported_email)
            })
            .and_then(|record| {
                commits.commit(
                    final_id,
                    record,
                    match action {
                        ImportAction::Create => CommitAction::Create,
                        ImportAction::Replace { .. } => CommitAction::Replace,
                    },
                )
            });
        match outcome {
            Ok(_) => match action {
                ImportAction::Create => {
                    println!("{final_id}: stored");
                    if !created_id_is_already_reachable(global, final_id) {
                        eprintln!(
                            "(not reachable by any consumer yet: no capability handle and no covering grant. When a consumer needs it, mint a handle with `ck auth mint-handle --id {final_id}` and place it where that consumer reads handles — the vault cannot write that file. A handle is bearer material, so it is worth minting when there is a reader rather than ahead of one.)"
                        );
                    }
                }
                ImportAction::Replace { record_version } => {
                    println!("{final_id}: replaced v{}", record_version + 1);
                }
            },
            Err(_) => {
                refused = true;
                println!("{final_id}: refused");
            }
        }
    }
    if refused {
        Err(CliError::Usage(
            "one or more selected accounts were not imported".to_string(),
        ))
    } else {
        Ok(())
    }
}

fn inventory(global: &GlobalArgs) -> Result<Vec<InventoryTuple>, CliError> {
    let path = super::store_path(global);
    if !path.exists() {
        return Ok(Vec::new());
    }
    if global.subc_conn.is_some() {
        let result = super::request_admin_status(global)?;
        return import_detect::parse_inventory(&result)
            .map_err(|message| CliError::RouteRefused(message.to_string()));
    }
    credentials_core::store::list_meta_read_only(&path)
        .map(|rows| {
            rows.into_iter()
                .map(|(id, meta)| {
                    (
                        format!("{:?}", meta.state).to_ascii_lowercase(),
                        meta.record_version,
                        id,
                    )
                })
                .collect()
        })
        .or_else(|error| match error {
            credentials_core::store::StoreOpError::NotFound => Ok(Vec::new()),
            error => Err(CliError::Store(error)),
        })
}

pub fn run(global: &GlobalArgs) -> Result<(), CliError> {
    #[cfg(feature = "import-prompt-seam")]
    let prompt_script_is_set = std::env::var_os(slice2_contract::PROMPT_SCRIPT_ENV).is_some();
    #[cfg(not(feature = "import-prompt-seam"))]
    let prompt_script_is_set = false;
    let prompt_source = slice2_contract::prompt_source(
        cfg!(feature = "import-prompt-seam"),
        prompt_script_is_set,
        std::io::stdin().is_terminal(),
        std::io::stdout().is_terminal(),
    );
    if prompt_source == PromptSource::RefuseNoTty {
        return Err(CliError::Usage(format!(
            "interactive import requires a terminal; use the flag form: {FLAG_FORM}"
        )));
    }

    let _resolved_key = resolve_store_key(global)?;
    let inventory = inventory(global)?;
    let detected = import_detect::enumerate(&import_detect::ImportPaths::from_process_env());
    let mut rows = Vec::with_capacity(detected.len());
    for detected in detected {
        let (label, initial_action) = render_row(&detected, &inventory);
        rows.push(PickerRow {
            detected,
            label,
            initial_action,
            final_id: None,
            prompt_opens: 0,
        });
    }
    if rows.is_empty() {
        return Err(CliError::Usage(format!(
            "no installed harness accounts were detected; use the flag form: {FLAG_FORM}"
        )));
    }

    let labels = std::iter::once("[all]".to_string())
        .chain(std::iter::once("[none]".to_string()))
        .chain(rows.iter().map(|row| row.label.clone()))
        .collect::<Vec<_>>();
    let defaults = [false, false]
        .into_iter()
        .chain(rows.iter().map(|row| {
            row.selectable() && matches!(row.initial_action, Some(ImportAction::Create))
        }))
        .collect::<Vec<_>>();

    #[cfg(feature = "import-prompt-seam")]
    if prompt_source == PromptSource::InjectedScript {
        let mut prompts = ScriptPrompts::from_env()?;
        if let Some(mut commits) = InjectedCommit::from_env(global)? {
            return drive(global, &inventory, rows, &mut prompts, &mut commits);
        }
        let mut commits = RealCommit { global };
        return drive(global, &inventory, rows, &mut prompts, &mut commits);
    }

    let mut prompts = TerminalPrompts { labels, defaults };
    let mut commits = RealCommit { global };
    drive(global, &inventory, rows, &mut prompts, &mut commits)
}
