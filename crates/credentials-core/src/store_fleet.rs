//! Fleet state transitions serialize authorization snapshots with key custody.
use super::*;
use crate::fleet::*;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use std::collections::{BTreeMap, BTreeSet};

struct EpochRow {
    epoch: u32,
    blob: Vec<u8>,
    minter: String,
    members: Vec<String>,
    mint_id: Option<String>,
    state: String,
}
redacted_debug!(EpochRow);

fn rows(conn: &rusqlite::Connection) -> Result<Vec<EpochRow>, FleetError> {
    let mut stmt = conn.prepare(
        "SELECT epoch, key, minter, members_json, mint_id, state FROM fleet_epochs ORDER BY epoch",
    )?;
    let raw = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, u32>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get(4)?,
                r.get(5)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    raw.into_iter()
        .map(|(epoch, blob, minter, members, mint_id, state)| {
            let members = serde_json::from_str::<Vec<String>>(&members)
                .map_err(|_| FleetError::Corrupt { epoch })?;
            if epoch == 0
                || !valid_members(&members)
                || !crate::federation::valid_member_id(&minter)
            {
                return Err(FleetError::Corrupt { epoch });
            }
            Ok(EpochRow {
                epoch,
                blob,
                minter,
                members,
                mint_id,
                state,
            })
        })
        .collect()
}

fn self_member(conn: &rusqlite::Connection) -> Result<String, FleetError> {
    conn.query_row(
        "SELECT value FROM settings WHERE name = ?1",
        [crate::federation::SELF_MEMBER_SETTING],
        |r| r.get::<_, String>(0),
    )
    .optional()?
    .filter(|id| crate::federation::valid_member_id(id))
    .ok_or(FleetError::EpochUnavailable)
}

fn removals(conn: &rusqlite::Connection) -> Result<BTreeSet<String>, FleetError> {
    let mut stmt =
        conn.prepare("SELECT DISTINCT member_id FROM fleet_removals ORDER BY member_id")?;
    let result = stmt
        .query_map([], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    Ok(result)
}

fn peers_map(peers: &[FleetPeer]) -> Result<BTreeMap<&str, &[u8; 32]>, FleetError> {
    let mut result = BTreeMap::new();
    for peer in peers {
        if result.insert(peer.member_id(), peer.public_key()).is_some() {
            return Err(FleetError::PeerKeysUnavailable);
        }
    }
    Ok(result)
}

fn binding_id(epoch: u32) -> String {
    format!("{STORE_DOMAIN}:{epoch}")
}
fn seal_epoch(key: &MasterKey, epoch: u32, secret: &[u8]) -> Result<Vec<u8>, FleetError> {
    envelope::seal(
        key,
        secret,
        &RecordBinding {
            credential_id: &binding_id(epoch),
            record_version: u64::from(epoch),
        },
    )
    .map_err(|_| FleetError::StoreError)
}
fn open_epoch(key: &MasterKey, row: &EpochRow) -> Result<Zeroizing<Vec<u8>>, FleetError> {
    #[cfg(test)]
    EPOCH_OPENS.with(|count| count.set(count.get() + 1));
    let bytes = envelope::open(
        key,
        &row.blob,
        &RecordBinding {
            credential_id: &binding_id(row.epoch),
            record_version: u64::from(row.epoch),
        },
    )
    .map_err(|_| FleetError::Corrupt { epoch: row.epoch })?;
    if bytes.len() != 32 {
        return Err(FleetError::Corrupt { epoch: row.epoch });
    }
    Ok(Zeroizing::new(bytes.to_vec()))
}

#[cfg(test)]
thread_local! {
    static EPOCH_OPENS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

fn open_record_key(
    master_key: &MasterKey,
    rows: &[EpochRow],
    epoch: u32,
) -> Result<Zeroizing<Vec<u8>>, FleetError> {
    let row = rows
        .iter()
        .find(|r| r.epoch == epoch && r.state != "pending")
        .ok_or(FleetError::EpochUnavailable)?;
    open_epoch(master_key, row)
}

fn open_record(key: &[u8], sealer: FleetSealer, item: &FleetOpenInput<'_>) -> FleetOpenResult {
    XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| FleetError::StoreError)?
        .decrypt(
            XNonce::from_slice(item.nonce),
            Payload {
                msg: item.ciphertext,
                aad: &record_aad(sealer, item.epoch, item.aad),
            },
        )
        .map(crate::secret::Secret::new)
        .map_err(|_| FleetError::EpochOpenFailed)
}

fn audit_fleet(
    tx: &rusqlite::Transaction<'_>,
    key: &[u8; 32],
    op: AuditOp,
) -> Result<(), FleetError> {
    append_audit_tx(
        tx,
        key,
        &AuditRecord {
            op,
            credential_id: None,
            payload_hash: None,
            actor: "reserved:entorhinal".into(),
            alarm: None,
        },
    )?;
    Ok(())
}

fn usable_current<'a>(
    rows: &'a [EpochRow],
    myself: &str,
    removed: &BTreeSet<String>,
) -> Result<&'a EpochRow, FleetError> {
    rows.iter()
        .find(|r| r.state == "current")
        .filter(|r| {
            r.members.iter().any(|id| id == myself)
                && !r.members.iter().any(|id| removed.contains(id))
        })
        .ok_or(FleetError::EpochUnavailable)
}

impl EncryptedStore {
    // Returning a typed refusal through a SQL error rolls back writes that preceded
    // it. An Ok(Err(...)) would commit those writes before reporting the refusal.
    fn fleet_write<T>(
        &self,
        f: impl FnOnce(&rusqlite::Transaction<'_>) -> Result<T, FleetError>,
    ) -> Result<T, FleetError> {
        let mut refusal = None;
        self.fenced_write(|tx| {
            f(tx).map_err(|error| {
                refusal = Some(error);
                rusqlite_err("fleet transaction refused")
            })
        })
        .map_err(|_| refusal.unwrap_or(FleetError::StoreError))
    }

    fn fleet_read<T>(
        &self,
        f: impl FnOnce(&rusqlite::Connection) -> Result<T, FleetError>,
    ) -> Result<T, FleetError> {
        self.store
            .with_conn(|conn| {
                let tx = conn.unchecked_transaction()?;
                let result = f(&tx);
                tx.commit()?;
                Ok(result)
            })
            .map_err(|_| FleetError::StoreError)?
    }

    /// Create missing purpose keys only; damaged or operator-rotated keys are never
    /// replaced by startup. Each created credential has its own birth audit row.
    pub fn ensure_fleet_keys(&self, now_ms: i64) -> Result<(), FleetError> {
        self.fleet_write(|tx| {
            for id in [RECORD_KEY_ID, WRAP_KEY_ID, BUS_KEY_ID]
                .into_iter()
                .chain(crate::signing::BUS_SIGNING_KEY_IDS)
            {
                let exists: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM credentials WHERE credential_id = ?1)", [id], |r| r.get(0))?;
                if exists { continue; }
                let (kind, pem) = if id.starts_with("signing:") {
                    (CredentialKind::SigningKey, generate_record_key()?)
                } else {
                    (CredentialKind::KemKey, crate::kem::generate_key().map_err(|_| FleetError::StoreError)?)
                };
                let record = VaultRecord::new_static(kind, "vault", pem.into_bytes(), None);
                let blob = self.seal_record(id, &record).map_err(|_| FleetError::StoreError)?;
                tx.execute("INSERT INTO credentials (credential_id, record_version, key_id, envelope, state, updated_at_ms, created_at_ms, created_by) VALUES (?1, 1, ?2, ?3, 'active', ?4, ?4, 'vault')",
                    rusqlite::params![id, self.key_id.to_hex(), blob, now_ms])?;
                append_audit_tx(tx, &self.audit_key, &AuditRecord { op: AuditOp::FleetKeyCreate,
                    credential_id: Some(id.into()), payload_hash: None, actor: "vault".into(), alarm: None })?;
            }
            Ok(())
        })
    }

    fn fleet_wrap_record(&self, conn: &rusqlite::Connection) -> Result<VaultRecord, FleetError> {
        let (state, version, blob): (String, u64, Vec<u8>) = conn.query_row(
            "SELECT state, record_version, envelope FROM credentials WHERE credential_id = ?1",
            [WRAP_KEY_ID],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        if state != "active" {
            return Err(FleetError::EpochUnavailable);
        }
        let bytes = envelope::open(
            &self.key,
            &blob,
            &RecordBinding {
                credential_id: WRAP_KEY_ID,
                record_version: version,
            },
        )
        .map_err(|_| FleetError::EpochUnavailable)?;
        let record = VaultRecord::decode(&bytes).map_err(|_| FleetError::EpochUnavailable)?;
        if record.kind != CredentialKind::KemKey {
            return Err(FleetError::EpochUnavailable);
        }
        Ok(record)
    }

    pub fn fleet_epoch_status(&self) -> Result<FleetStatus, FleetError> {
        self.fleet_read(|conn| {
            let rows = rows(conn)?;
            let removed = removals(conn)?;
            let current = rows.iter().find(|r| r.state == "current");
            Ok(FleetStatus {
                current: current.map(|r| r.epoch),
                held: rows
                    .iter()
                    .filter(|r| r.state != "pending")
                    .map(|r| r.epoch)
                    .collect(),
                pending: rows
                    .iter()
                    .find(|r| r.state == "pending")
                    .map(|r| FleetPending {
                        epoch: r.epoch,
                        mint_id: r.mint_id.clone().unwrap_or_default(),
                    }),
                sealing_blocked_by: current
                    .map(|r| {
                        r.members
                            .iter()
                            .filter(|id| removed.contains(*id))
                            .cloned()
                            .collect()
                    })
                    .unwrap_or_default(),
            })
        })
    }

    pub fn fleet_epoch_seal(
        &self,
        sealer: FleetSealer,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<FleetSealed, FleetError> {
        self.fleet_epoch_seal_batch(sealer, &[FleetSealInput { aad, plaintext }])?
            .pop()
            .ok_or(FleetError::StoreError)
    }

    /// One read snapshot fixes the current epoch and removal state for every item.
    /// No result escapes if any encryption or store operation refuses the batch.
    pub fn fleet_epoch_seal_batch(
        &self,
        sealer: FleetSealer,
        items: &[FleetSealInput<'_>],
    ) -> Result<Vec<FleetSealed>, FleetError> {
        validate_batch(items.len(), items.iter().map(FleetSealInput::validate))?;
        self.fleet_read(|conn| {
            let myself = self_member(conn)?;
            let removed = removals(conn)?;
            let rows = rows(conn)?;
            let row = usable_current(&rows, &myself, &removed)?;
            let key = open_epoch(&self.key, row)?;
            let cipher =
                XChaCha20Poly1305::new_from_slice(&key).map_err(|_| FleetError::StoreError)?;
            items
                .iter()
                .map(|item| {
                    let mut nonce = [0u8; 24];
                    getrandom::getrandom(&mut nonce).map_err(|_| FleetError::StoreError)?;
                    let ciphertext = cipher
                        .encrypt(
                            XNonce::from_slice(&nonce),
                            Payload {
                                msg: item.plaintext,
                                aad: &record_aad(sealer, row.epoch, item.aad),
                            },
                        )
                        .map_err(|_| FleetError::StoreError)?;
                    Ok(FleetSealed {
                        epoch: row.epoch,
                        nonce: encode(&nonce),
                        ciphertext: encode(&ciphertext),
                    })
                })
                .collect()
        })
    }

    pub fn fleet_epoch_open(
        &self,
        sealer: FleetSealer,
        epoch: u32,
        nonce: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<crate::secret::Secret<Vec<u8>>, FleetError> {
        let item = FleetOpenInput {
            epoch,
            nonce,
            ciphertext,
            aad,
        };
        item.validate()?;
        self.fleet_read(|conn| {
            self_member(conn)?;
            let rows = rows(conn)?;
            let key = open_record_key(&self.key, &rows, item.epoch)?;
            open_record(&key, sealer, &item)
        })
    }

    pub fn fleet_epoch_open_batch(
        &self,
        sealer: FleetSealer,
        items: &[FleetOpenInput<'_>],
    ) -> Result<Vec<FleetOpenResult>, FleetError> {
        validate_batch(items.len(), items.iter().map(FleetOpenInput::validate))?;
        self.fleet_read(|conn| {
            self_member(conn)?;
            let rows = rows(conn)?;
            let mut keys = BTreeMap::new();
            items
                .iter()
                .map(|item| {
                    let result = keys
                        .entry(item.epoch)
                        .or_insert_with(|| open_record_key(&self.key, &rows, item.epoch))
                        .as_ref()
                        .map_err(|error| *error)
                        .and_then(|key| open_record(key, sealer, item));
                    // A storage failure invalidates the shared read, not just one item.
                    if matches!(result, Err(FleetError::StoreError)) {
                        Err(FleetError::StoreError)
                    } else {
                        Ok(result)
                    }
                })
                .collect()
        })
    }

    pub fn fleet_epoch_mint(
        &self,
        members: &[String],
        peers: &[FleetPeer],
    ) -> Result<FleetMint, FleetError> {
        self.fleet_epoch_mint_with_exclusions(members, &[], peers)
    }

    pub fn fleet_epoch_mint_with_exclusions(
        &self,
        members: &[String],
        excluded: &[String],
        peers: &[FleetPeer],
    ) -> Result<FleetMint, FleetError> {
        let peers = peers_map(peers)?;
        let supplied: BTreeSet<_> = members.iter().cloned().collect();
        let omitted: BTreeSet<_> = excluded.iter().cloned().collect();
        if supplied.len() != members.len()
            || omitted.len() != excluded.len()
            || members
                .iter()
                .chain(excluded)
                .any(|id| !crate::federation::valid_member_id(id))
        {
            return Err(FleetError::InvalidParams);
        }
        if members.len() > MAX_HOLDERS || excluded.len() > MAX_HOLDERS {
            return Err(FleetError::EpochCapacity);
        }
        self.fleet_write(|tx| {
            let myself = self_member(tx)?;
            let removed = removals(tx)?;
            let rows = rows(tx)?;
            if rows.iter().any(|r| r.state == "pending") { return Err(FleetError::EpochPending); }
            let mut live: BTreeSet<String> = peers.keys().copied().chain(std::iter::once(myself.as_str()))
                .filter(|id| !removed.contains(*id)).map(str::to_owned).collect();
            if live.len() > MAX_HOLDERS || rows.len() >= MAX_EPOCHS { return Err(FleetError::EpochCapacity); }
            if omitted.contains(&myself) || !omitted.is_subset(&live) {
                return Err(FleetError::MembersMismatch);
            }
            live.retain(|id| !omitted.contains(id));
            if supplied != live || !supplied.contains(&myself) { return Err(FleetError::MembersMismatch); }
            let epoch = rows.last().map_or(Some(1), |r| r.epoch.checked_add(1)).ok_or(FleetError::EpochCapacity)?;
            let members: Vec<String> = supplied.into_iter().collect();
            let mut key = Zeroizing::new([0u8; 32]);
            let mut mint_id = [0u8; 16];
            getrandom::getrandom(key.as_mut()).map_err(|_| FleetError::StoreError)?;
            getrandom::getrandom(&mut mint_id).map_err(|_| FleetError::StoreError)?;
            let mint_id = encode(&mint_id);
            let plaintext = WrapPlaintext { keys: vec![WrapKey { epoch, key: encode(key.as_ref()),
                members: members.clone(), minter: myself.clone() }], kind: "rotation".into(), v: WRAP_DOMAIN.into() };
            let record = self.fleet_wrap_record(tx)?;
            let mut wraps = Vec::new();
            for member_id in members.iter().filter(|id| **id != myself) {
                let public = peers.get(member_id.as_str()).ok_or(FleetError::MembersMismatch)?;
                wraps.push(FleetMemberWrap { member_id: member_id.clone(),
                    wrap: make_wrap(&record, &myself, member_id, public.as_slice(), &plaintext)? });
            }
            let blob = seal_epoch(&self.key, epoch, key.as_ref())?;
            tx.execute("INSERT INTO fleet_epochs (epoch, key, minter, members_json, mint_id, state, created_at_ms) VALUES (?1, ?2, ?3, ?4, ?5, 'pending', ?6)",
                rusqlite::params![epoch, blob, myself, serde_json::to_string(&members).map_err(|_| FleetError::StoreError)?, mint_id, now_ms()])?;
            audit_fleet(tx, &self.audit_key, AuditOp::FleetEpochMint)?;
            Ok(FleetMint { epoch, mint_id, wraps })
        })
    }

    pub fn fleet_epoch_commit(
        &self,
        epoch: u32,
        mint_id: &str,
    ) -> Result<FleetTransition, FleetError> {
        check_mint_id(epoch, mint_id)?;
        self.fleet_write(|tx| {
            let myself = self_member(tx)?;
            let removed = removals(tx)?;
            let rows = rows(tx)?;
            let row = rows
                .iter()
                .find(|r| r.epoch == epoch && r.mint_id.as_deref() == Some(mint_id))
                .ok_or(FleetError::EpochNotPending)?;
            let result = FleetTransition {
                epoch,
                state: "current",
            };
            // A committed mint stays an idempotent success even after it retires.
            if row.state != "pending" {
                return Ok(result);
            }
            if !row.members.contains(&myself) || row.members.iter().any(|id| removed.contains(id)) {
                return Err(FleetError::MembersMismatch);
            }
            open_epoch(&self.key, row)?;
            tx.execute(
                "UPDATE fleet_epochs SET state = 'retired' WHERE state = 'current'",
                [],
            )?;
            tx.execute(
                "UPDATE fleet_epochs SET state = 'current' WHERE epoch = ?1",
                [epoch],
            )?;
            audit_fleet(tx, &self.audit_key, AuditOp::FleetEpochCommit)?;
            Ok(result)
        })
    }

    pub fn fleet_epoch_discard(
        &self,
        epoch: u32,
        mint_id: &str,
    ) -> Result<FleetTransition, FleetError> {
        check_mint_id(epoch, mint_id)?;
        self.fleet_write(|tx| {
            self_member(tx)?;
            removals(tx)?;
            let result = FleetTransition {
                epoch,
                state: "discarded",
            };
            let discarded: Option<u32> = tx
                .query_row(
                    "SELECT epoch FROM fleet_discards WHERE mint_id = ?1",
                    [mint_id],
                    |r| r.get(0),
                )
                .optional()?;
            if discarded == Some(epoch) {
                return Ok(result);
            }
            let changed = tx.execute(
                "DELETE FROM fleet_epochs WHERE epoch = ?1 AND mint_id = ?2 AND state = 'pending'",
                rusqlite::params![epoch, mint_id],
            )?;
            if changed == 0 {
                return Err(FleetError::EpochNotPending);
            }
            tx.execute(
                "INSERT INTO fleet_discards (mint_id, epoch) VALUES (?1, ?2)",
                rusqlite::params![mint_id, epoch],
            )?;
            audit_fleet(tx, &self.audit_key, AuditOp::FleetEpochDiscard)?;
            Ok(result)
        })
    }

    /// Removal observations are append-only. Each newly observed pair is one
    /// durable state change with its own audit row; an exact replay writes nothing.
    pub fn fleet_record_removals(
        &self,
        observations: &[FleetRemoval],
        observed_at_ms: i64,
    ) -> Result<usize, FleetError> {
        if observations.iter().any(|item| {
            !crate::federation::valid_member_id(&item.member_id) || item.removal_id.is_empty()
        }) {
            return Err(FleetError::InvalidParams);
        }
        self.fleet_write(|tx| {
            removals(tx)?;
            let mut count = 0;
            for item in observations {
                let changed = tx.execute("INSERT OR IGNORE INTO fleet_removals (member_id, removal_id, observed_at_ms) VALUES (?1, ?2, ?3)", rusqlite::params![item.member_id, item.removal_id, observed_at_ms])?;
                if changed != 0 {
                    append_audit_tx(tx, &self.audit_key, &AuditRecord { op: AuditOp::FleetRemoval,
                        credential_id: None, payload_hash: None, actor: "vault".into(), alarm: None })?;
                    count += 1;
                }
            }
            Ok(count)
        })
    }

    pub fn fleet_epoch_wrap_for(
        &self,
        member_id: &str,
        peers: &[FleetPeer],
    ) -> Result<FleetWrap, FleetError> {
        let peers = peers_map(peers)?;
        self.fleet_write(|tx| {
            let myself = self_member(tx)?;
            let removed = removals(tx)?;
            if member_id == myself || removed.contains(member_id) {
                return Err(FleetError::MembersMismatch);
            }
            let public = peers.get(member_id).ok_or(FleetError::MembersMismatch)?;
            let rows = rows(tx)?;
            usable_current(&rows, &myself, &removed)?;
            let held: Vec<_> = rows.iter().filter(|r| r.state != "pending").collect();
            let mut keys = Vec::new();
            for row in &held {
                let mut members: BTreeSet<_> = row.members.iter().cloned().collect();
                members.insert(member_id.to_owned());
                if members.len() > MAX_HOLDERS {
                    return Err(FleetError::EpochCapacity);
                }
                keys.push(WrapKey {
                    epoch: row.epoch,
                    key: encode(&open_epoch(&self.key, row)?),
                    members: members.into_iter().collect(),
                    minter: row.minter.clone(),
                });
            }
            let plaintext = WrapPlaintext {
                keys,
                kind: "join".into(),
                v: WRAP_DOMAIN.into(),
            };
            let record = self.fleet_wrap_record(tx)?;
            let wrap = make_wrap(&record, &myself, member_id, public.as_slice(), &plaintext)?;
            for key in &plaintext.keys {
                tx.execute(
                    "UPDATE fleet_epochs SET members_json = ?2 WHERE epoch = ?1",
                    rusqlite::params![
                        key.epoch,
                        serde_json::to_string(&key.members).map_err(|_| FleetError::StoreError)?
                    ],
                )?;
            }
            audit_fleet(tx, &self.audit_key, AuditOp::FleetEpochWrapFor)?;
            Ok(wrap)
        })
    }

    pub fn fleet_epoch_import(
        &self,
        wrap: &FleetWrap,
        peers: &[FleetPeer],
    ) -> Result<FleetImport, FleetError> {
        let peers = peers_map(peers)?;
        let enc = decode(&wrap.enc, 32)?;
        let ct = decode(&wrap.ct, MAX_BYTES + 16)?;
        if enc.len() != 32 {
            return Err(FleetError::InvalidParams);
        }
        self.fleet_write(|tx| {
            let myself = self_member(tx)?;
            let removed = removals(tx)?;
            let rows = rows(tx)?;
            if rows.iter().any(|r| r.state == "pending") { return Err(FleetError::EpochPending); }
            if wrap.to != myself || removed.contains(&wrap.from) || wrap.v != WRAP_DOMAIN
                || !crate::federation::valid_member_id(&wrap.from) {
                return Err(FleetError::WrapRefused);
            }
            let public = peers.get(wrap.from.as_str()).ok_or(FleetError::WrapRefused)?;
            let record = self.fleet_wrap_record(tx)?;
            let pem = std::str::from_utf8(record.payload.expose()).map_err(|_| FleetError::EpochUnavailable)?;
            let plaintext = Zeroizing::new(crate::kem::open_auth(pem, public.as_slice(), &enc, &ct,
                &wrap_info(&wrap.from, &wrap.to), b"").map_err(|_| FleetError::WrapRefused)?);
            if plaintext.len() > MAX_BYTES { return Err(FleetError::WrapRefused); }
            let body: WrapPlaintext = serde_json::from_slice(&plaintext).map_err(|_| FleetError::WrapRefused)?;
            validate_wrap(&body, &wrap.from, &myself)?;
            let highest = body.keys.last().ok_or(FleetError::WrapRefused)?.epoch;
            if body.keys.last().expect("validated nonempty").members.iter().any(|id| removed.contains(id)) {
                return Err(FleetError::WrapRefused);
            }
            let previous_highest = rows.last().map_or(0, |r| r.epoch);
            if body.kind == "rotation" && highest <= previous_highest && !rows.iter().any(|r| r.epoch == highest) {
                return Err(FleetError::WrapRefused);
            }
            let mut new_epochs = Vec::new();
            let mut updates = Vec::new();
            for key in &body.keys {
                let secret = decode(&key.key, 32).map_err(|_| FleetError::WrapRefused)?;
                if let Some(row) = rows.iter().find(|r| r.epoch == key.epoch) {
                    use subtle::ConstantTimeEq;
                    if !bool::from(open_epoch(&self.key, row)?.as_slice().ct_eq(secret.as_slice())) {
                        return Err(FleetError::WrapRefused);
                    }
                    let members: BTreeSet<_> = row.members.iter().chain(key.members.iter()).cloned().collect();
                    if members.len() > MAX_HOLDERS { return Err(FleetError::WrapRefused); }
                    let members: Vec<_> = members.into_iter().collect();
                    if members != row.members { updates.push((key.epoch, members)); }
                } else {
                    new_epochs.push(key.epoch);
                }
            }
            if rows.len() + new_epochs.len() > MAX_EPOCHS { return Err(FleetError::WrapRefused); }
            if new_epochs.is_empty() && updates.is_empty() {
                return Ok(FleetImport { epochs: new_epochs, already_held: true });
            }
            for key in &body.keys {
                if new_epochs.contains(&key.epoch) {
                    let secret = decode(&key.key, 32).map_err(|_| FleetError::WrapRefused)?;
                    let blob = seal_epoch(&self.key, key.epoch, &secret)?;
                    tx.execute("INSERT INTO fleet_epochs (epoch, key, minter, members_json, mint_id, state, created_at_ms) VALUES (?1, ?2, ?3, ?4, NULL, 'retired', ?5)",
                        rusqlite::params![key.epoch, blob, key.minter, serde_json::to_string(&key.members).map_err(|_| FleetError::StoreError)?, now_ms()])?;
                }
            }
            for (epoch, members) in updates {
                tx.execute("UPDATE fleet_epochs SET members_json = ?2 WHERE epoch = ?1", rusqlite::params![epoch,
                    serde_json::to_string(&members).map_err(|_| FleetError::StoreError)?])?;
            }
            if highest > previous_highest {
                tx.execute("UPDATE fleet_epochs SET state = 'retired' WHERE state = 'current'", [])?;
                tx.execute("UPDATE fleet_epochs SET state = 'current' WHERE epoch = ?1", [highest])?;
            }
            audit_fleet(tx, &self.audit_key, AuditOp::FleetEpochImport)?;
            Ok(FleetImport { already_held: new_epochs.is_empty(), epochs: new_epochs })
        })
    }
}

fn check_mint_id(epoch: u32, mint_id: &str) -> Result<(), FleetError> {
    if epoch == 0 || decode(mint_id, 16)?.len() != 16 {
        return Err(FleetError::InvalidParams);
    }
    Ok(())
}

fn generate_record_key() -> Result<String, FleetError> {
    use base64::Engine;
    let der = ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
        .map_err(|_| FleetError::StoreError)?;
    let encoded = Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(der.as_ref()));
    Ok(format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----",
        encoded.as_str()
    ))
}

fn make_wrap(
    record: &VaultRecord,
    from: &str,
    to: &str,
    public: &[u8],
    body: &WrapPlaintext,
) -> Result<FleetWrap, FleetError> {
    let pem =
        std::str::from_utf8(record.payload.expose()).map_err(|_| FleetError::EpochUnavailable)?;
    let plaintext = Zeroizing::new(serde_json::to_vec(body).map_err(|_| FleetError::StoreError)?);
    let (enc, ct) = crate::kem::seal_fleet_auth(pem, public, &plaintext, &wrap_info(from, to))
        .map_err(|_| FleetError::StoreError)?;
    Ok(FleetWrap {
        ct: encode(&ct),
        enc: encode(&enc),
        from: from.into(),
        to: to.into(),
        v: WRAP_DOMAIN.into(),
    })
}

fn validate_wrap(body: &WrapPlaintext, from: &str, myself: &str) -> Result<(), FleetError> {
    if body.v != WRAP_DOMAIN
        || !matches!(body.kind.as_str(), "rotation" | "join")
        || body.keys.is_empty()
        || body.keys.len() > MAX_EPOCHS
        || body
            .keys
            .windows(2)
            .any(|pair| pair[0].epoch >= pair[1].epoch)
        || (body.kind == "rotation"
            && (body.keys.len() != 1
                || body.keys[0].minter != from
                || !body.keys[0].members.contains(&body.keys[0].minter)))
    {
        return Err(FleetError::WrapRefused);
    }
    for key in &body.keys {
        if key.epoch == 0
            || !valid_members(&key.members)
            || !key.members.iter().any(|id| id == myself)
            || !crate::federation::valid_member_id(&key.minter)
            || decode(&key.key, 32)
                .map_err(|_| FleetError::WrapRefused)?
                .len()
                != 32
        {
            return Err(FleetError::WrapRefused);
        }
    }
    Ok(())
}

pub(super) fn rotate_fleet_epochs_tx(
    tx: &rusqlite::Transaction<'_>,
    old_key: &MasterKey,
    new_key: &MasterKey,
) -> rusqlite::Result<()> {
    // Holders are historical facts. Re-sealing neither checks nor adds the vault's
    // current member id.
    for row in rows(tx).map_err(|e| rusqlite_err(&format!("fleet row metadata: {e:?}")))? {
        let secret = open_epoch(old_key, &row)
            .map_err(|_| rusqlite_err(&format!("corrupt fleet epoch {}", row.epoch)))?;
        let blob = seal_epoch(new_key, row.epoch, &secret)
            .map_err(|_| rusqlite_err("fleet re-seal failed"))?;
        tx.execute(
            "UPDATE fleet_epochs SET key = ?2 WHERE epoch = ?1",
            rusqlite::params![row.epoch, blob],
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TestTempDir;

    fn id(n: usize) -> String {
        format!("fed-computer:{n:032x}")
    }
    fn set_self(store: &EncryptedStore, n: usize) {
        store
            .set_federation_self_member_audited(&id(n), AuditCtx::admin(AuditOp::FederationSelfSet))
            .unwrap();
    }
    fn rig(label: &str, n: u8) -> (TestTempDir, EncryptedStore) {
        let (root, store) = taxonomy_tests::rig(label, n);
        set_self(&store, usize::from(n));
        store.ensure_fleet_keys(1).unwrap();
        (root, store)
    }
    fn peer(store: &EncryptedStore, n: usize) -> FleetPeer {
        let record = store
            .fleet_read(|conn| store.fleet_wrap_record(conn))
            .unwrap();
        let (public, _) =
            crate::kem::public_half(std::str::from_utf8(record.payload.expose()).unwrap()).unwrap();
        FleetPeer::new(id(n), public.try_into().unwrap()).unwrap()
    }
    fn commit(store: &EncryptedStore, members: &[String], peers: &[FleetPeer]) -> FleetMint {
        let mint = store.fleet_epoch_mint(members, peers).unwrap();
        store.fleet_epoch_commit(mint.epoch, &mint.mint_id).unwrap();
        mint
    }
    fn opened(
        store: &EncryptedStore,
        sealed: &FleetSealed,
    ) -> Result<crate::secret::Secret<Vec<u8>>, FleetError> {
        store.fleet_epoch_open(
            FleetSealer::Entorhinal,
            sealed.epoch,
            &decode(&sealed.nonce, 24).unwrap(),
            &decode(&sealed.ciphertext, MAX_BYTES + 16).unwrap(),
            b"context",
        )
    }
    fn audit_len(store: &EncryptedStore) -> usize {
        store.read_audit(None).unwrap().len()
    }
    fn blobs(store: &EncryptedStore) -> Vec<(u32, Vec<u8>, Vec<String>)> {
        store
            .fleet_read(|conn| {
                Ok(rows(conn)?
                    .into_iter()
                    .map(|r| (r.epoch, r.blob, r.members))
                    .collect())
            })
            .unwrap()
    }
    fn seed(store: &EncryptedStore, epochs: usize, members: &[String]) {
        store.fleet_write(|tx| {
            for epoch in 1..=epochs as u32 {
                tx.execute("INSERT INTO fleet_epochs (epoch, key, minter, members_json, state, created_at_ms) VALUES (?1, ?2, ?3, ?4, ?5, 1)",
                    rusqlite::params![epoch, seal_epoch(&store.key, epoch, &[42; 32])?, id(1),
                        serde_json::to_string(members).unwrap(), if epoch == epochs as u32 { "current" } else { "retired" }])?;
            }
            Ok(())
        }).unwrap();
    }

    #[test]
    fn fleet_startup_is_create_only_and_audited_once_per_key() {
        let (_root, store) = rig("fleet-startup", 1);
        let before = store.list_meta().unwrap();
        let bus_before: Vec<_> = crate::signing::BUS_SIGNING_KEY_IDS
            .into_iter()
            .map(|id| {
                let record = store.get(id).unwrap();
                assert_eq!(record.kind, CredentialKind::SigningKey);
                assert!(!record.audit_each_signature);
                assert!(!record.operator_sign);
                crate::signing::public_key_ed25519(
                    std::str::from_utf8(record.payload.expose()).unwrap(),
                )
                .unwrap()
            })
            .collect();
        let count = audit_len(&store);
        store.ensure_fleet_keys(2).unwrap();
        assert_eq!(store.list_meta().unwrap(), before);
        assert_eq!(audit_len(&store), count);
        let audit = store.read_audit(None).unwrap();
        assert_eq!(
            audit.iter().filter(|a| a.op == "fleet_key_create").count(),
            8
        );
        for (id, public) in crate::signing::BUS_SIGNING_KEY_IDS
            .into_iter()
            .zip(bus_before)
        {
            let record = store.get(id).unwrap();
            assert_eq!(
                crate::signing::public_key_ed25519(
                    std::str::from_utf8(record.payload.expose()).unwrap()
                )
                .unwrap(),
                public
            );
            assert_eq!(audit.iter().filter(|a| a.op == "fleet_key_create" && a.credential_id.as_deref() == Some(id)).count(), 1);
        }
        assert!(audit
            .iter()
            .filter(|a| a.op == "fleet_key_create")
            .all(|a| a.actor == "vault" && a.payload_hash.is_none()));
        assert_eq!(store.verify_audit_chain().unwrap(), None);
    }

    #[test]
    fn fleet_removal_without_self_is_durable_and_still_blocks_later_use() {
        let (_root, store) = taxonomy_tests::rig("fleet-removal-no-self", 1);
        store.ensure_fleet_keys(1).unwrap();
        let observations = [FleetRemoval {
            member_id: id(2),
            removal_id: "opaque-removal".into(),
        }];
        let before = audit_len(&store);
        assert_eq!(store.fleet_record_removals(&observations, 1).unwrap(), 1);
        assert_eq!(store.fleet_record_removals(&observations, 2).unwrap(), 0);
        assert_eq!(audit_len(&store), before + 1);
        assert_eq!(
            store
                .fleet_epoch_seal(FleetSealer::Entorhinal, b"", b"x")
                .unwrap_err(),
            FleetError::EpochUnavailable
        );
        assert_eq!(
            store.fleet_epoch_mint(&[id(1)], &[]).unwrap_err(),
            FleetError::EpochUnavailable
        );
        set_self(&store, 1);
        seed(&store, 1, &[id(1), id(2)]);
        assert_eq!(
            store.fleet_epoch_status().unwrap().sealing_blocked_by,
            vec![id(2)]
        );
        assert_eq!(
            store
                .fleet_epoch_seal(FleetSealer::Entorhinal, b"", b"x")
                .unwrap_err(),
            FleetError::EpochUnavailable
        );
        let (_other_root, other) = rig("fleet-removal-no-self-peer", 2);
        assert_eq!(
            store
                .fleet_epoch_mint(&[id(1), id(2)], &[peer(&other, 2)])
                .unwrap_err(),
            FleetError::MembersMismatch
        );
        assert_eq!(store.verify_audit_chain().unwrap(), None);
    }

    #[test]
    fn fleet_epoch_binding_and_partial_indexes_refuse_copied_rows() {
        let (_root, store) = rig("fleet-binding", 1);
        let mint = commit(&store, &[id(1)], &[]);
        store.fleet_write(|tx| {
            tx.execute("INSERT INTO fleet_epochs SELECT 2, key, minter, members_json, NULL, 'retired', created_at_ms FROM fleet_epochs WHERE epoch = 1", [])?;
            Ok(())
        }).unwrap();
        assert_eq!(
            store
                .fleet_epoch_open(FleetSealer::Entorhinal, 2, &[0; 24], &[0; 16], b"")
                .unwrap_err(),
            FleetError::Corrupt { epoch: 2 }
        );
        assert!(store
            .fenced_write(|tx| tx.execute(
                "UPDATE fleet_epochs SET state = 'current' WHERE epoch = 2",
                []
            ))
            .is_err());
        store.fleet_epoch_mint(&[id(1)], &[]).unwrap();
        assert!(store.fenced_write(|tx| tx.execute("INSERT INTO fleet_epochs SELECT 4, key, minter, members_json, mint_id, 'pending', created_at_ms FROM fleet_epochs WHERE epoch = ?1", [mint.epoch])).is_err());
        assert!(store
            .fenced_write(|tx| tx.execute("UPDATE fleet_epochs SET state = 'held'", []))
            .is_err());
    }

    #[test]
    fn fleet_open_distinguishes_an_absent_epoch_from_a_bad_tag() {
        let (_root, store) = rig("fleet-open-absent", 1);
        let mint = commit(&store, &[id(1)], &[]);
        let sealed = store
            .fleet_epoch_seal(FleetSealer::Entorhinal, b"context", b"record")
            .unwrap();
        let nonce = decode(&sealed.nonce, 24).unwrap();
        let ciphertext = decode(&sealed.ciphertext, MAX_BYTES + 16).unwrap();
        let mut bad_tag = ciphertext.clone();
        *bad_tag.last_mut().unwrap() ^= 1;
        assert_eq!(
            store
                .fleet_epoch_open(
                    FleetSealer::Entorhinal,
                    mint.epoch,
                    &nonce,
                    &bad_tag,
                    b"context"
                )
                .unwrap_err(),
            FleetError::EpochOpenFailed
        );
        assert_eq!(
            store
                .fleet_epoch_open(
                    FleetSealer::Entorhinal,
                    mint.epoch + 1,
                    &nonce,
                    &ciphertext,
                    b"context"
                )
                .unwrap_err(),
            FleetError::EpochUnavailable
        );
    }

    #[test]
    fn fleet_open_batch_unwraps_each_requested_epoch_once() {
        let (_root, store) = rig("fleet-open-batch-unwraps", 1);
        let mut records = Vec::new();
        for plaintext in [b"first", b"later"] {
            let epoch = commit(&store, &[id(1)], &[]).epoch;
            let record = store
                .fleet_epoch_seal(FleetSealer::Entorhinal, b"", plaintext)
                .unwrap();
            records.push((
                epoch,
                decode(&record.nonce, 24).unwrap(),
                decode(&record.ciphertext, MAX_BYTES + 16).unwrap(),
            ));
        }
        let mut bad_tag = records[0].2.clone();
        *bad_tag.last_mut().unwrap() ^= 1;
        let item = |index: usize, bad| {
            let (epoch, nonce, ciphertext) = &records[index];
            FleetOpenInput {
                epoch: *epoch,
                nonce,
                ciphertext: if bad { &bad_tag } else { ciphertext },
                aad: b"",
            }
        };
        let before = EPOCH_OPENS.with(|count| count.get());
        let results = store
            .fleet_epoch_open_batch(
                FleetSealer::Entorhinal,
                &[
                    item(0, true),
                    item(1, false),
                    item(0, false),
                    item(1, false),
                ],
            )
            .unwrap();
        assert_eq!(EPOCH_OPENS.with(|count| count.get()) - before, 2);
        assert_eq!(
            results[0].as_ref().unwrap_err(),
            &FleetError::EpochOpenFailed
        );
        assert_eq!(results[1].as_ref().unwrap().expose(), b"later");
        assert_eq!(results[2].as_ref().unwrap().expose(), b"first");
        assert_eq!(results[3].as_ref().unwrap().expose(), b"later");
    }

    #[test]
    fn fleet_open_batch_reports_absent_and_pending_epochs_per_item() {
        let (_root, store) = rig("fleet-open-batch-mixed", 1);
        let held = commit(&store, &[id(1)], &[]);
        let pending = store.fleet_epoch_mint(&[id(1)], &[]).unwrap();
        let sealed = store
            .fleet_epoch_seal(FleetSealer::Entorhinal, b"context", b"record")
            .unwrap();
        let nonce = decode(&sealed.nonce, 24).unwrap();
        let ciphertext = decode(&sealed.ciphertext, MAX_BYTES + 16).unwrap();
        let mut bad_tag = ciphertext.clone();
        *bad_tag.last_mut().unwrap() ^= 1;
        let item = |epoch, ciphertext| FleetOpenInput {
            epoch,
            nonce: &nonce,
            ciphertext,
            aad: b"context",
        };
        let results = store
            .fleet_epoch_open_batch(
                FleetSealer::Entorhinal,
                &[
                    item(held.epoch, &bad_tag),
                    item(pending.epoch + 1, &ciphertext),
                    item(pending.epoch, &ciphertext),
                    item(held.epoch, &ciphertext),
                ],
            )
            .unwrap();
        assert_eq!(results.len(), 4);
        assert_eq!(results[3].as_ref().unwrap().expose(), b"record");
        let errors: Vec<_> = results[..3]
            .iter()
            .map(|result| *result.as_ref().unwrap_err())
            .collect();
        assert_eq!(
            errors,
            [
                FleetError::EpochOpenFailed,
                FleetError::EpochUnavailable,
                FleetError::EpochUnavailable
            ]
        );
    }

    #[test]
    fn fleet_open_batch_on_empty_epoch_table_refuses_each_item_once_self_is_set() {
        let (_root, store) = taxonomy_tests::rig("fleet-open-batch-empty", 1);
        let item = |epoch| FleetOpenInput {
            epoch,
            nonce: &[0; 24],
            ciphertext: &[0; 16],
            aad: b"",
        };
        let open = || store.fleet_epoch_open_batch(FleetSealer::Entorhinal, &[item(1), item(2)]);
        assert_eq!(open().unwrap_err(), FleetError::EpochUnavailable);
        set_self(&store, 1);
        assert_eq!(
            open()
                .unwrap()
                .into_iter()
                .map(Result::unwrap_err)
                .collect::<Vec<_>>(),
            [FleetError::EpochUnavailable; 2]
        );
    }

    #[test]
    fn fleet_mint_receipts_survive_restart_and_delayed_retries() {
        let (root, store) = rig("fleet-receipts", 1);
        let mint = store.fleet_epoch_mint(&[id(1)], &[]).unwrap();
        assert_eq!(
            store
                .fleet_epoch_seal(FleetSealer::Entorhinal, b"", b"pending")
                .unwrap_err(),
            FleetError::EpochUnavailable
        );
        assert_eq!(
            store
                .fleet_epoch_open(FleetSealer::Entorhinal, 1, &[0; 24], &[0; 16], b"")
                .unwrap_err(),
            FleetError::EpochUnavailable
        );
        let count = audit_len(&store);
        drop(store);
        let descriptor = cortexkit_store::StorageDescriptor {
            module_id: "claustrum".into(),
            storage_namespace: "taxonomy-fleet-receipts".into(),
            isolation: cortexkit_store::Isolation::Module,
            backend: cortexkit_store::StorageBackend::Sqlite {
                path: root.join("store.db").to_string_lossy().into_owned(),
            },
        };
        let store = EncryptedStore::open(
            cortexkit_store::open_sqlite(&descriptor).unwrap(),
            MasterKey::from_bytes([1; 32]),
        )
        .unwrap();
        assert_eq!(
            store.fleet_epoch_status().unwrap().pending.unwrap().mint_id,
            mint.mint_id
        );
        store.fleet_epoch_discard(1, &mint.mint_id).unwrap();
        store.fleet_epoch_discard(1, &mint.mint_id).unwrap();
        assert_eq!(audit_len(&store), count + 1);
        let later = store.fleet_epoch_mint(&[id(1)], &[]).unwrap();
        assert_eq!(later.epoch, 1);
        assert_ne!(later.mint_id, mint.mint_id);
        store.fleet_epoch_discard(1, &mint.mint_id).unwrap();
        assert_eq!(
            store.fleet_epoch_commit(1, &mint.mint_id).unwrap_err(),
            FleetError::EpochNotPending
        );
        store.fleet_epoch_commit(1, &later.mint_id).unwrap();
        let count = audit_len(&store);
        store.fleet_epoch_commit(1, &later.mint_id).unwrap();
        assert_eq!(audit_len(&store), count);
        commit(&store, &[id(1)], &[]);
        let count = audit_len(&store);
        store.fleet_epoch_commit(1, &later.mint_id).unwrap();
        assert_eq!(audit_len(&store), count);
        assert_eq!(store.fleet_epoch_status().unwrap().current, Some(2));
    }

    #[test]
    fn fleet_two_vault_authentication_and_idempotent_import() {
        let (_a, a) = rig("fleet-auth-a", 1);
        let (_b, b) = rig("fleet-auth-b", 2);
        let peers_a = [peer(&b, 2)];
        let peers_b = [peer(&a, 1)];
        let mint = commit(&a, &[id(1), id(2)], &peers_a);
        let wrap = &mint.wraps[0].wrap;
        assert_eq!(b.fleet_epoch_import(wrap, &peers_b).unwrap().epochs, [1]);
        let count = audit_len(&b);
        assert!(b.fleet_epoch_import(wrap, &peers_b).unwrap().already_held);
        assert_eq!(audit_len(&b), count);
        let from_a = a
            .fleet_epoch_seal(FleetSealer::Entorhinal, b"context", b"alpha")
            .unwrap();
        let from_b = b
            .fleet_epoch_seal(FleetSealer::Entorhinal, b"context", b"beta")
            .unwrap();
        assert_eq!(opened(&a, &from_b).unwrap().expose(), b"beta");
        assert_eq!(opened(&b, &from_a).unwrap().expose(), b"alpha");
        let bad_sender = crate::kem::generate_key().unwrap();
        let (public, _) = crate::kem::public_half(&bad_sender).unwrap();
        let impostor = [FleetPeer::new(id(1), public.try_into().unwrap()).unwrap()];
        assert_eq!(
            b.fleet_epoch_import(wrap, &impostor).unwrap_err(),
            FleetError::WrapRefused
        );
        let mut forged = wrap.clone();
        let b_public = peer(&b, 2);
        let (enc, ct) = crate::kem::seal_base(
            b_public.public_key(),
            b"forgery",
            &wrap_info(&id(1), &id(2)),
            b"",
        )
        .unwrap();
        forged.enc = encode(&enc);
        forged.ct = encode(&ct);
        assert_eq!(
            b.fleet_epoch_import(&forged, &peers_b).unwrap_err(),
            FleetError::WrapRefused
        );
        assert_eq!(audit_len(&b), count);
        assert_eq!(
            a.fleet_epoch_mint(&[id(1), id(2)], &[peers_a[0].clone(), peers_a[0].clone()])
                .unwrap_err(),
            FleetError::PeerKeysUnavailable
        );
    }

    #[test]
    fn fleet_removal_rotate_join_preserves_open_only_history() {
        let (_a, a) = rig("fleet-remove-a", 1);
        let (_b, b) = rig("fleet-remove-b", 2);
        let (_d, d) = rig("fleet-remove-d", 4);
        commit(&a, &[id(1), id(2)], &[peer(&b, 2)]);
        let old = a
            .fleet_epoch_seal(FleetSealer::Entorhinal, b"context", b"history")
            .unwrap();
        let count = audit_len(&a);
        assert_eq!(
            a.fleet_record_removals(
                &[FleetRemoval {
                    member_id: id(2),
                    removal_id: "opaque:removal".into()
                }],
                10
            )
            .unwrap(),
            1
        );
        assert_eq!(
            a.fleet_record_removals(
                &[FleetRemoval {
                    member_id: id(2),
                    removal_id: "opaque:removal".into()
                }],
                11
            )
            .unwrap(),
            0
        );
        assert_eq!(audit_len(&a), count + 1);
        assert_eq!(
            a.fleet_epoch_seal(FleetSealer::Entorhinal, b"", b"no")
                .unwrap_err(),
            FleetError::EpochUnavailable
        );
        assert_eq!(a.fleet_epoch_status().unwrap().sealing_blocked_by, [id(2)]);
        commit(&a, &[id(1), id(4)], &[peer(&b, 2), peer(&d, 4)]);
        let wrap = a.fleet_epoch_wrap_for(&id(4), &[peer(&d, 4)]).unwrap();
        d.fleet_record_removals(
            &[FleetRemoval {
                member_id: id(2),
                removal_id: "opaque:removal".into(),
            }],
            10,
        )
        .unwrap();
        assert_eq!(
            d.fleet_epoch_import(&wrap, &[peer(&a, 1)]).unwrap().epochs,
            [1, 2]
        );
        assert_eq!(opened(&d, &old).unwrap().expose(), b"history");
        assert_eq!(
            d.fleet_epoch_seal(FleetSealer::Entorhinal, b"context", b"new")
                .unwrap()
                .epoch,
            2
        );
        let count = audit_len(&a);
        a.fleet_epoch_wrap_for(&id(4), &[peer(&d, 4)]).unwrap();
        assert_eq!(audit_len(&a), count + 1, "even a repeated export audits");
        assert_eq!(
            a.fleet_epoch_wrap_for(&id(2), &[peer(&b, 2)]).unwrap_err(),
            FleetError::MembersMismatch
        );
    }

    #[test]
    fn fleet_holder_merges_propagate_a_join_then_removal() {
        let (_a, a) = rig("fleet-merge-a", 1);
        let (_b, b) = rig("fleet-merge-b", 2);
        let (_d, d) = rig("fleet-merge-d", 4);
        let mint = commit(&a, &[id(1), id(2)], &[peer(&b, 2)]);
        b.fleet_epoch_import(&mint.wraps[0].wrap, &[peer(&a, 1)])
            .unwrap();
        a.fleet_epoch_wrap_for(&id(4), &[peer(&d, 4)]).unwrap();
        let later = a.fleet_epoch_wrap_for(&id(2), &[peer(&b, 2)]).unwrap();
        let count = audit_len(&b);
        let result = b.fleet_epoch_import(&later, &[peer(&a, 1)]).unwrap();
        assert!(result.already_held);
        assert_eq!(
            audit_len(&b),
            count + 1,
            "holder union is an audited state change"
        );
        b.fleet_record_removals(
            &[FleetRemoval {
                member_id: id(4),
                removal_id: "removed".into(),
            }],
            20,
        )
        .unwrap();
        assert_eq!(
            b.fleet_epoch_seal(FleetSealer::Entorhinal, b"", b"no")
                .unwrap_err(),
            FleetError::EpochUnavailable
        );
        assert!(a
            .fleet_epoch_seal(FleetSealer::Entorhinal, b"", b"still unobserved")
            .is_ok());
    }

    #[test]
    fn fleet_self_change_is_scoped_to_new_or_current_rows() {
        let (root, a) = rig("fleet-self", 1);
        let (_d, d) = rig("fleet-self-d", 4);
        let pending = a.fleet_epoch_mint(&[id(1)], &[]).unwrap();
        set_self(&a, 3);
        assert_eq!(
            a.fleet_epoch_commit(1, &pending.mint_id).unwrap_err(),
            FleetError::MembersMismatch
        );
        a.fleet_epoch_discard(1, &pending.mint_id).unwrap();
        set_self(&a, 1);
        commit(&a, &[id(1)], &[]);
        let old = a
            .fleet_epoch_seal(FleetSealer::Entorhinal, b"context", b"former self")
            .unwrap();
        commit(&a, &[id(1)], &[]);
        let held_before = blobs(&a);
        set_self(&a, 3);
        drop(a);
        let descriptor = cortexkit_store::StorageDescriptor {
            module_id: "claustrum".into(),
            storage_namespace: "taxonomy-fleet-self".into(),
            isolation: cortexkit_store::Isolation::Module,
            backend: cortexkit_store::StorageBackend::Sqlite {
                path: root.join("store.db").to_string_lossy().into_owned(),
            },
        };
        let a = EncryptedStore::open(
            cortexkit_store::open_sqlite(&descriptor).unwrap(),
            MasterKey::from_bytes([1; 32]),
        )
        .unwrap();
        assert_eq!(
            a.fleet_epoch_seal(FleetSealer::Entorhinal, b"", b"no")
                .unwrap_err(),
            FleetError::EpochUnavailable
        );
        assert_eq!(
            a.fleet_epoch_wrap_for(&id(4), &[peer(&d, 4)]).unwrap_err(),
            FleetError::EpochUnavailable
        );
        assert_eq!(opened(&a, &old).unwrap().expose(), b"former self");
        commit(&a, &[id(3)], &[]);
        assert_eq!(
            &blobs(&a)[..2],
            held_before,
            "retiring an old current never grows holders"
        );
        let wrap = a.fleet_epoch_wrap_for(&id(4), &[peer(&d, 4)]).unwrap();
        d.fleet_epoch_import(&wrap, &[peer(&a, 3)]).unwrap();
        assert_eq!(opened(&d, &old).unwrap().expose(), b"former self");
        assert_eq!(blobs(&a)[0].2, [id(1), id(4)]);
        assert_eq!(blobs(&a)[1].2, [id(1), id(4)]);
        assert_eq!(blobs(&a)[2].2, [id(3), id(4)]);
    }

    #[test]
    fn fleet_master_rotation_reseals_all_states_without_growing_holders() {
        let (_root, mut store) = rig("fleet-rotation", 1);
        commit(&store, &[id(1)], &[]);
        let old = store
            .fleet_epoch_seal(FleetSealer::Entorhinal, b"context", b"retired history")
            .unwrap();
        commit(&store, &[id(1)], &[]);
        let pending = store.fleet_epoch_mint(&[id(1)], &[]).unwrap();
        let before = blobs(&store);
        set_self(&store, 7);
        let count = audit_len(&store);
        assert!(store
            .rotate_master_key(MasterKey::from_bytes([99; 32]))
            .unwrap()
            .is_empty());
        assert_eq!(audit_len(&store), count + 1);
        for (old, new) in before.iter().zip(blobs(&store)) {
            assert_eq!(old.0, new.0);
            assert_ne!(old.1, new.1);
            assert_eq!(old.2, new.2);
        }
        assert_eq!(opened(&store, &old).unwrap().expose(), b"retired history");
        set_self(&store, 1);
        let current = store
            .fleet_epoch_seal(FleetSealer::Entorhinal, b"context", b"current")
            .unwrap();
        assert_eq!(opened(&store, &current).unwrap().expose(), b"current");
        store
            .fleet_epoch_commit(pending.epoch, &pending.mint_id)
            .unwrap();
        let after = store
            .fleet_epoch_seal(
                FleetSealer::Entorhinal,
                b"context",
                b"pending became current",
            )
            .unwrap();
        assert_eq!(after.epoch, 3);
        assert_eq!(
            opened(&store, &after).unwrap().expose(),
            b"pending became current"
        );
        assert_eq!(store.verify_audit_chain().unwrap(), None);
    }

    fn envelope_snapshot(store: &EncryptedStore) -> Vec<(String, String, Vec<u8>)> {
        store.store.with_conn(|conn| {
            let mut stmt = conn.prepare("SELECT credential_id, key_id, envelope FROM credentials UNION ALL SELECT name, key_id, envelope FROM vault_secrets ORDER BY 1")?;
            let result = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect();
            result
        }).unwrap()
    }

    #[test]
    fn fleet_corrupt_retired_epoch_aborts_master_rotation_atomically() {
        let (_root, mut store) = rig("fleet-corrupt-rotate", 1);
        store
            .create("apikey:rotation-control", &taxonomy_tests::api_record())
            .unwrap();
        commit(&store, &[id(1)], &[]);
        commit(&store, &[id(1)], &[]);
        store.fleet_epoch_mint(&[id(1)], &[]).unwrap();
        let current = store
            .fleet_epoch_seal(FleetSealer::Entorhinal, b"context", b"healthy current")
            .unwrap();
        store
            .fenced_write(|tx| {
                tx.execute("UPDATE fleet_epochs SET key = x'00' WHERE epoch = 1", [])
            })
            .unwrap();
        let before = blobs(&store);
        let envelopes = envelope_snapshot(&store);
        let fingerprint = store.key_id.to_hex();
        let audit = store.read_audit(None).unwrap();
        let error = store
            .rotate_master_key(MasterKey::from_bytes([99; 32]))
            .unwrap_err();
        assert!(
            error.to_string().contains("corrupt fleet epoch 1"),
            "{error}"
        );
        assert_eq!(blobs(&store), before);
        assert_eq!(envelope_snapshot(&store), envelopes);
        assert_eq!(store.key_id.to_hex(), fingerprint);
        assert_eq!(
            store.key.key_id().to_hex(),
            fingerprint,
            "in-memory key never swaps on rollback"
        );
        assert_eq!(store.read_audit(None).unwrap(), audit);
        assert_eq!(
            opened(&store, &current).unwrap().expose(),
            b"healthy current"
        );
        assert_eq!(store.verify_audit_chain().unwrap(), None);
    }

    #[test]
    fn fleet_holder_cap_checks_unions_and_wraps_before_writing() {
        let (_a, a) = rig("fleet-cap-a", 1);
        let (_b, b) = rig("fleet-cap-b", 2);
        let (_d, d) = rig("fleet-cap-d", 100);
        let members: Vec<_> = (1..=63).map(id).collect();
        seed(&a, 1, &members);
        let wrap = a.fleet_epoch_wrap_for(&id(100), &[peer(&d, 100)]).unwrap();
        assert_eq!(blobs(&a)[0].2.len(), 64);
        d.fleet_epoch_import(&wrap, &[peer(&a, 1)]).unwrap();
        let before = blobs(&a);
        let count = audit_len(&a);
        let (_new, new) = rig("fleet-cap-new", 101);
        assert_eq!(
            a.fleet_epoch_wrap_for(&id(101), &[peer(&new, 101)])
                .unwrap_err(),
            FleetError::EpochCapacity
        );
        assert_eq!(blobs(&a), before);
        assert_eq!(audit_len(&a), count);
        let mut b_members = members;
        b_members.push(id(101));
        seed(&b, 1, &b_members);
        let join = a.fleet_epoch_wrap_for(&id(2), &[peer(&b, 2)]).unwrap();
        let before = blobs(&b);
        let count = audit_len(&b);
        assert_eq!(
            b.fleet_epoch_import(&join, &[peer(&a, 1)]).unwrap_err(),
            FleetError::WrapRefused
        );
        assert_eq!(blobs(&b), before);
        assert_eq!(audit_len(&b), count);
    }

    #[test]
    fn fleet_history_cap_and_full_join_round_trip() {
        let (_a, a) = rig("fleet-history-a", 1);
        let (_b, b) = rig("fleet-history-b", 64);
        seed(&a, 255, &(1..=63).map(id).collect::<Vec<_>>());
        // With 255 held epochs a mint is allowed; after commit there is no room
        // for another key even though the live fleet is just this vault.
        commit(&a, &[id(1)], &[]);
        let before = blobs(&a);
        let count = audit_len(&a);
        assert_eq!(
            a.fleet_epoch_mint(&[id(1)], &[]).unwrap_err(),
            FleetError::EpochCapacity
        );
        assert_eq!(blobs(&a), before);
        assert_eq!(audit_len(&a), count);
        // Give the final row the same 63 holders, so all 256 exported keys
        // carry exactly 64 holders after the recipient is added.
        a.fenced_write(|tx| {
            tx.execute(
                "UPDATE fleet_epochs SET members_json = ?1 WHERE epoch = 256",
                [serde_json::to_string(&(1..=63).map(id).collect::<Vec<_>>()).unwrap()],
            )
        })
        .unwrap();
        let wrap = a.fleet_epoch_wrap_for(&id(64), &[peer(&b, 64)]).unwrap();
        assert!(decode(&wrap.ct, MAX_BYTES + 16).unwrap().len() > crate::kem::MAX_SEAL_PLAINTEXT);
        assert_eq!(
            b.fleet_epoch_import(&wrap, &[peer(&a, 1)])
                .unwrap()
                .epochs
                .len(),
            256
        );
        assert!(blobs(&b).iter().all(|r| r.2.len() == 64));
        let sealed = a
            .fleet_epoch_seal(FleetSealer::Entorhinal, b"context", b"full join")
            .unwrap();
        assert_eq!(opened(&b, &sealed).unwrap().expose(), b"full join");
        let record = a.fleet_read(|conn| a.fleet_wrap_record(conn)).unwrap();
        let pem = std::str::from_utf8(record.payload.expose()).unwrap();
        let public = peer(&b, 64);
        let body = Zeroizing::new(
            crate::kem::open_auth(
                std::str::from_utf8(
                    b.fleet_read(|conn| b.fleet_wrap_record(conn))
                        .unwrap()
                        .payload
                        .expose(),
                )
                .unwrap(),
                peer(&a, 1).public_key(),
                &decode(&wrap.enc, 32).unwrap(),
                &decode(&wrap.ct, MAX_BYTES + 16).unwrap(),
                &wrap_info(&id(1), &id(64)),
                b"",
            )
            .unwrap(),
        );
        assert_eq!(
            crate::kem::seal_auth(pem, public.public_key(), &body, b"", b"").unwrap_err(),
            crate::kem::SealError::TooLarge
        );
        let overflow = WrapPlaintext {
            keys: vec![WrapKey {
                epoch: 257,
                key: encode(&[42; 32]),
                members: vec![id(1), id(64)],
                minter: id(1),
            }],
            kind: "rotation".into(),
            v: WRAP_DOMAIN.into(),
        };
        let overflow = make_wrap(&record, &id(1), &id(64), public.public_key(), &overflow).unwrap();
        let before = blobs(&b);
        let count = audit_len(&b);
        assert_eq!(
            b.fleet_epoch_import(&overflow, &[peer(&a, 1)]).unwrap_err(),
            FleetError::WrapRefused
        );
        assert_eq!(blobs(&b), before);
        assert_eq!(audit_len(&b), count);
    }

    #[test]
    fn fleet_byte_caps_and_auth_join_boundaries() {
        let (_root, store) = rig("fleet-bytes", 1);
        commit(&store, &[id(1)], &[]);
        let at = vec![5; MAX_BYTES];
        let over = vec![5; MAX_BYTES + 1];
        let sealed = store
            .fleet_epoch_seal(FleetSealer::Entorhinal, &at, &at)
            .unwrap();
        let nonce = decode(&sealed.nonce, 24).unwrap();
        let ct = decode(&sealed.ciphertext, MAX_BYTES + 16).unwrap();
        assert_eq!(
            store
                .fleet_epoch_open(FleetSealer::Entorhinal, 1, &nonce, &ct, &at)
                .unwrap()
                .expose(),
            at.as_slice()
        );
        assert_eq!(
            store
                .fleet_epoch_seal(FleetSealer::Entorhinal, b"", &over)
                .unwrap_err(),
            FleetError::InvalidParams
        );
        assert_eq!(
            store
                .fleet_epoch_seal(FleetSealer::Entorhinal, &over, b"")
                .unwrap_err(),
            FleetError::InvalidParams
        );
        assert_eq!(
            store
                .fleet_epoch_open(
                    FleetSealer::Entorhinal,
                    1,
                    &nonce,
                    &vec![0; MAX_BYTES + 17],
                    b""
                )
                .unwrap_err(),
            FleetError::InvalidParams
        );
        let sender = crate::kem::generate_key().unwrap();
        let recipient = crate::kem::generate_key().unwrap();
        let (public, _) = crate::kem::public_half(&recipient).unwrap();
        let (sender_public, _) = crate::kem::public_half(&sender).unwrap();
        let (enc, ct) = crate::kem::seal_fleet_auth(&sender, &public, &at, b"info").unwrap();
        assert_eq!(
            crate::kem::open_auth(&recipient, &sender_public, &enc, &ct, b"info", b"").unwrap(),
            at
        );
        assert_eq!(
            crate::kem::seal_fleet_auth(&sender, &public, &over, b"info").unwrap_err(),
            crate::kem::SealError::TooLarge
        );
    }

    #[test]
    fn fleet_mint_live_members_and_holder_boundaries() {
        let (_a, a) = rig("fleet-live", 1);
        let key = *peer(&a, 1).public_key();
        let peers: Vec<_> = (2..=64)
            .map(|n| FleetPeer::new(id(n), key).unwrap())
            .collect();
        let members: Vec<_> = (1..=64).map(id).collect();
        let mint = a.fleet_epoch_mint(&members, &peers).unwrap();
        assert_eq!(mint.wraps.len(), 63);
        a.fleet_epoch_discard(1, &mint.mint_id).unwrap();
        let count = audit_len(&a);
        let mut oversized = members.clone();
        oversized.push(id(65));
        assert_eq!(
            a.fleet_epoch_mint(&oversized, &peers).unwrap_err(),
            FleetError::EpochCapacity
        );
        let mut duplicates = members.clone();
        duplicates.push(id(1));
        assert_eq!(
            a.fleet_epoch_mint(&duplicates, &peers).unwrap_err(),
            FleetError::InvalidParams
        );
        let mut larger_peers = peers;
        larger_peers.push(FleetPeer::new(id(65), key).unwrap());
        assert_eq!(
            a.fleet_epoch_mint(&members, &larger_peers).unwrap_err(),
            FleetError::EpochCapacity
        );
        assert_eq!(
            a.fleet_epoch_mint(&[id(1)], &larger_peers[..1])
                .unwrap_err(),
            FleetError::MembersMismatch
        );
        assert_eq!(audit_len(&a), count);
    }

    #[test]
    fn fleet_peer_constructor_refuses_low_order_encodings() {
        for hex in [
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
            "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        ] {
            let bytes: Vec<_> = hex
                .as_bytes()
                .chunks(2)
                .map(|chunk| u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap())
                .collect();
            assert_eq!(
                FleetPeer::new(id(1), bytes.try_into().unwrap()).unwrap_err(),
                FleetError::PeerKeysUnavailable
            );
        }
        assert_eq!(
            FleetPeer::new("invalid".into(), [9; 32]).unwrap_err(),
            FleetError::PeerKeysUnavailable
        );
    }

    #[test]
    fn bus_grants_are_exact_ckbus_only_and_handles_are_reserved() {
        let (_root, store) = rig("bus-grant-store", 1);
        for base in crate::signing::BUS_SIGNING_KEY_IDS {
            for generation in ["1", "2", "future"] {
                let key = format!("{}:{generation}", base.rsplit_once(':').unwrap().0);
                for (kind, principal) in [
                    ("reserved", "ckbus"),
                    ("reserved", "callosum"),
                    ("reserved", "entorhinal"),
                    ("reserved", "other"),
                    ("enrolled", "ckbus"),
                    ("direct", "ckbus"),
                ] {
                    for operation in [
                        GrantOperation::Read,
                        GrantOperation::Sign,
                        GrantOperation::Open,
                        GrantOperation::Seal,
                        GrantOperation::List,
                        GrantOperation::Deposit,
                        GrantOperation::AccountToken,
                    ] {
                        let before = audit_len(&store);
                        let result = store.create_read_grant_audited(
                            kind,
                            principal,
                            SelectorKind::Exact,
                            &key,
                            operation,
                            AuditCtx::admin(AuditOp::GrantCreate),
                        );
                        let allowed = kind == "reserved"
                            && principal == "ckbus"
                            && matches!(operation, GrantOperation::Read | GrantOperation::Sign);
                        assert_eq!(
                            result.is_ok(),
                            allowed,
                            "{key} {kind}:{principal} {operation:?}"
                        );
                        if !allowed {
                            assert_eq!(result.unwrap_err().wire_code(), Some("bus_key_reserved"));
                            assert_eq!(audit_len(&store), before);
                        }
                    }
                }
                for selector in [SelectorKind::Category, SelectorKind::Audience] {
                    assert_eq!(
                        store
                            .create_read_grant_audited(
                                "reserved",
                                "ckbus",
                                selector,
                                &key,
                                GrantOperation::Read,
                                AuditCtx::admin(AuditOp::GrantCreate)
                            )
                            .unwrap_err()
                            .wire_code(),
                        Some("bus_key_reserved")
                    );
                }
                assert_eq!(
                    store
                        .put_handle_hash("canary", &key, AuditCtx::admin(AuditOp::MintHandle))
                        .unwrap_err()
                        .wire_code(),
                    Some("bus_key_reserved")
                );
            }
        }
    }

    #[test]
    fn bus_category_grants_cannot_authorize_a_key() {
        use crate::store::{DeclaredGrantSet, SetCategoryMode};
        let (_root, store) = rig("bus-category-store", 1);
        for key in crate::signing::BUS_SIGNING_KEY_IDS {
            store
                .set_categories_audited(
                    key,
                    SetCategoryMode::Add,
                    &["bus-test".into()],
                    AuditCtx::admin(AuditOp::SetCategory),
                )
                .unwrap();
        }
        for op in [GrantOperation::Read, GrantOperation::Sign] {
            store
                .create_read_grant_audited(
                    "reserved",
                    "ckbus",
                    SelectorKind::Category,
                    "bus-test",
                    op,
                    AuditCtx::admin(AuditOp::GrantCreate),
                )
                .unwrap();
            for key in crate::signing::BUS_SIGNING_KEY_IDS {
                assert!(!store
                    .read_grant_covers("reserved", "ckbus", key, op, &DeclaredGrantSet::default())
                    .unwrap());
                store
                    .create_read_grant_audited(
                        "reserved",
                        "ckbus",
                        SelectorKind::Exact,
                        key,
                        op,
                        AuditCtx::admin(AuditOp::GrantCreate),
                    )
                    .unwrap();
                assert!(store
                    .read_grant_covers("reserved", "ckbus", key, op, &DeclaredGrantSet::default())
                    .unwrap());
            }
        }
    }

    #[test]
    fn fleet_grants_and_handles_use_the_typed_reserved_refusal() {
        let (_root, store) = rig("fleet-grant-store", 1);
        let count = audit_len(&store);
        for key in [WRAP_KEY_ID, RECORD_KEY_ID] {
            for operation in [
                GrantOperation::Open,
                GrantOperation::Seal,
                GrantOperation::List,
            ] {
                let error = store
                    .create_read_grant_audited(
                        "reserved",
                        "callosum",
                        SelectorKind::Exact,
                        key,
                        operation,
                        AuditCtx::admin(AuditOp::GrantCreate),
                    )
                    .unwrap_err();
                assert_eq!(error.wire_code(), Some("fleet_key_reserved"));
            }
            let error = store
                .put_handle_hash("canary", key, AuditCtx::admin(AuditOp::MintHandle))
                .unwrap_err();
            assert_eq!(error.wire_code(), Some("fleet_key_reserved"));
        }
        assert_eq!(audit_len(&store), count);
        store
            .create_read_grant_audited(
                "reserved",
                "callosum",
                SelectorKind::Exact,
                WRAP_KEY_ID,
                GrantOperation::Read,
                AuditCtx::admin(AuditOp::GrantCreate),
            )
            .unwrap();
        store
            .create_read_grant_audited(
                "reserved",
                "entorhinal",
                SelectorKind::Exact,
                RECORD_KEY_ID,
                GrantOperation::Sign,
                AuditCtx::admin(AuditOp::GrantCreate),
            )
            .unwrap();
    }

    #[test]
    fn bus_seal_grants_and_handles_use_the_fleet_fence() {
        let (_root, store) = rig("bus-seal-grant-store", 1);
        for key in [BUS_KEY_ID, "kem:bus-seal:2"] {
            let grant = |kind, principal, operation| {
                store.create_read_grant_audited(
                    kind,
                    principal,
                    SelectorKind::Exact,
                    key,
                    operation,
                    AuditCtx::admin(AuditOp::GrantCreate),
                )
            };
            for (principal, operation) in [
                ("callosum", GrantOperation::Read),
                ("ckbus", GrantOperation::Open),
                ("engram", GrantOperation::Open),
            ] {
                assert!(grant("reserved", principal, operation).is_ok());
            }
            for (kind, principal) in [
                ("reserved", "other"),
                ("enrolled", "ckbus"),
                ("enrolled", "engram"),
                ("enrolled", "callosum"),
                ("reserved", "callosum"),
                ("reserved", "ckbus"),
                ("reserved", "engram"),
            ] {
                for operation in [
                    GrantOperation::Open,
                    GrantOperation::Read,
                    GrantOperation::Sign,
                    GrantOperation::Seal,
                    GrantOperation::List,
                    GrantOperation::Deposit,
                    GrantOperation::AccountToken,
                ] {
                    if matches!(
                        (kind, principal, operation),
                        ("reserved", "callosum", GrantOperation::Read)
                            | ("reserved", "ckbus" | "engram", GrantOperation::Open)
                    ) {
                        continue;
                    }
                    let result = grant(kind, principal, operation);
                    assert_eq!(
                        result.as_ref().err().and_then(|error| error.wire_code()),
                        Some("fleet_key_reserved"),
                        "{key} admitted or misclassified {kind}:{principal} {operation:?}: {result:?}"
                    );
                }
            }
            let error = store
                .put_handle_hash("canary", key, AuditCtx::admin(AuditOp::MintHandle))
                .unwrap_err();
            assert_eq!(error.wire_code(), Some("fleet_key_reserved"));
        }
    }

    #[test]
    fn fleet_epoch_row_debug_is_redacted() {
        let row = EpochRow {
            epoch: 1,
            blob: b"sealed-secret".to_vec(),
            minter: id(1),
            members: vec![id(1)],
            mint_id: None,
            state: "current".into(),
        };
        assert_eq!(format!("{row:?}"), "EpochRow([REDACTED])");
    }

    fn audit_fault(store: &EncryptedStore, enabled: bool) {
        store.fenced_write(|tx| tx.execute_batch(if enabled {
            "CREATE TRIGGER fleet_fail_audit BEFORE INSERT ON audit_log WHEN NEW.op LIKE 'fleet_%' BEGIN SELECT RAISE(ABORT, 'fleet audit fault'); END;"
        } else { "DROP TRIGGER fleet_fail_audit;" })).unwrap();
    }
    fn fails_atomically<T: std::fmt::Debug>(
        store: &EncryptedStore,
        action: impl FnOnce() -> Result<T, FleetError>,
    ) {
        let before = blobs(store);
        let status = store.fleet_epoch_status().unwrap();
        let audit = store.read_audit(None).unwrap();
        let counters = || {
            store
                .store
                .with_conn(|conn| {
                    Ok((
                        conn.query_row("SELECT count(*) FROM fleet_discards", [], |r| {
                            r.get::<_, i64>(0)
                        })?,
                        conn.query_row("SELECT count(*) FROM fleet_removals", [], |r| {
                            r.get::<_, i64>(0)
                        })?,
                    ))
                })
                .unwrap()
        };
        let counts = counters();
        audit_fault(store, true);
        assert_eq!(action().unwrap_err(), FleetError::StoreError);
        audit_fault(store, false);
        assert_eq!(blobs(store), before);
        assert_eq!(store.fleet_epoch_status().unwrap(), status);
        assert_eq!(store.read_audit(None).unwrap(), audit);
        assert_eq!(counters(), counts);
    }

    #[test]
    fn fleet_mutations_roll_back_when_their_single_audit_row_fails() {
        let (_a, a) = rig("fleet-atomic-a", 1);
        let (_b, b) = rig("fleet-atomic-b", 2);
        let (_d, d) = rig("fleet-atomic-d", 4);
        let ap = [peer(&b, 2)];
        let bp = [peer(&a, 1)];
        fails_atomically(&a, || a.fleet_epoch_mint(&[id(1), id(2)], &ap));
        let mint = a.fleet_epoch_mint(&[id(1), id(2)], &ap).unwrap();
        fails_atomically(&a, || a.fleet_epoch_commit(1, &mint.mint_id));
        fails_atomically(&a, || a.fleet_epoch_discard(1, &mint.mint_id));
        a.fleet_epoch_commit(1, &mint.mint_id).unwrap();
        fails_atomically(&b, || b.fleet_epoch_import(&mint.wraps[0].wrap, &bp));
        b.fleet_epoch_import(&mint.wraps[0].wrap, &bp).unwrap();
        fails_atomically(&a, || a.fleet_epoch_wrap_for(&id(4), &[peer(&d, 4)]));
        let removal = [FleetRemoval {
            member_id: id(2),
            removal_id: "opaque".into(),
        }];
        fails_atomically(&a, || a.fleet_record_removals(&removal, 1));
        let before = audit_len(&a);
        let pending = a.fleet_epoch_mint(&[id(1), id(2)], &ap).unwrap();
        assert_eq!(audit_len(&a), before + 1);
        a.fleet_record_removals(&removal, 1).unwrap();
        assert_eq!(
            a.fleet_epoch_commit(pending.epoch, &pending.mint_id)
                .unwrap_err(),
            FleetError::MembersMismatch
        );
        a.fleet_epoch_discard(pending.epoch, &pending.mint_id)
            .unwrap();
        assert_eq!(audit_len(&a), before + 3);
        assert_eq!(a.verify_audit_chain().unwrap(), None);
    }

    #[test]
    fn fleet_import_refuses_conflicts_and_never_moves_current_backwards() {
        let (_a, a) = rig("fleet-order-a", 1);
        let (_b, b) = rig("fleet-order-b", 2);
        seed(&a, 1, &[id(1), id(2)]);
        seed(&b, 3, &[id(1), id(2)]);
        b.fenced_write(|tx| tx.execute("DELETE FROM fleet_epochs WHERE epoch < 3", []))
            .unwrap();
        let wrap = a.fleet_epoch_wrap_for(&id(2), &[peer(&b, 2)]).unwrap();
        assert_eq!(
            b.fleet_epoch_import(&wrap, &[peer(&a, 1)]).unwrap().epochs,
            [1]
        );
        assert_eq!(b.fleet_epoch_status().unwrap().current, Some(3));
        let bad = seal_epoch(&b.key, 1, &[99; 32]).unwrap();
        b.fenced_write(|tx| tx.execute("UPDATE fleet_epochs SET key = ?1 WHERE epoch = 1", [&bad]))
            .unwrap();
        let before = blobs(&b);
        let count = audit_len(&b);
        assert_eq!(
            b.fleet_epoch_import(&wrap, &[peer(&a, 1)]).unwrap_err(),
            FleetError::WrapRefused
        );
        assert_eq!(blobs(&b), before);
        assert_eq!(audit_len(&b), count);
        let pending = b.fleet_epoch_mint(&[id(1), id(2)], &[peer(&a, 1)]).unwrap();
        assert_eq!(
            b.fleet_epoch_import(&wrap, &[peer(&a, 1)]).unwrap_err(),
            FleetError::EpochPending
        );
        b.fleet_epoch_discard(pending.epoch, &pending.mint_id)
            .unwrap();
    }

    #[test]
    fn fleet_unset_self_and_wrap_plaintext_validation_fail_closed() {
        let (_root, store) = taxonomy_tests::rig("fleet-unset", 1);
        assert_eq!(store.fleet_epoch_status().unwrap().current, None);
        assert_eq!(
            store.fleet_epoch_mint(&[id(1)], &[]).unwrap_err(),
            FleetError::EpochUnavailable
        );
        assert_eq!(
            store
                .fleet_epoch_open(FleetSealer::Entorhinal, 1, &[0; 24], &[0; 16], b"")
                .unwrap_err(),
            FleetError::EpochUnavailable
        );
        let good = || WrapPlaintext {
            keys: vec![WrapKey {
                epoch: 1,
                key: encode(&[7; 32]),
                members: vec![id(1), id(2)],
                minter: id(1),
            }],
            kind: "rotation".into(),
            v: WRAP_DOMAIN.into(),
        };
        assert!(validate_wrap(&good(), &id(1), &id(2)).is_ok());
        for variation in 0..7 {
            let mut body = good();
            match variation {
                0 => body.keys[0].epoch = 0,
                1 => body.keys[0].members = vec![id(1)],
                2 => body.keys[0].members.reverse(),
                3 => body.keys[0].minter = id(3),
                4 => body.keys[0].key = "invalid=".into(),
                5 => body.keys.push(WrapKey {
                    epoch: 1,
                    key: encode(&[7; 32]),
                    members: vec![id(1), id(2)],
                    minter: id(1),
                }),
                6 => body.kind = "unknown".into(),
                _ => unreachable!(),
            }
            assert_eq!(
                validate_wrap(&body, &id(1), &id(2)).unwrap_err(),
                FleetError::WrapRefused
            );
        }
        let mut json = serde_json::to_value(good()).unwrap();
        json["unknown"] = serde_json::json!(true);
        assert!(serde_json::from_value::<WrapPlaintext>(json).is_err());
        let mut json = serde_json::to_value(good()).unwrap();
        json["keys"][0]["unknown"] = serde_json::json!(true);
        assert!(serde_json::from_value::<WrapPlaintext>(json).is_err());
    }

    #[test]
    fn fleet_removed_sender_is_refused_for_rotation_and_join_without_writing() {
        let (_a, a) = rig("fleet-removed-sender-a", 1);
        let (_b, b) = rig("fleet-removed-sender-b", 2);
        let peers = [peer(&a, 1)];
        let record = a.fleet_read(|conn| a.fleet_wrap_record(conn)).unwrap();
        let public = peer(&b, 2);
        let mut body = WrapPlaintext {
            keys: vec![WrapKey {
                epoch: 1,
                key: encode(&[7; 32]),
                members: vec![id(2)],
                minter: id(1),
            }],
            kind: "join".into(),
            v: WRAP_DOMAIN.into(),
        };
        let join = make_wrap(&record, &id(1), &id(2), public.public_key(), &body).unwrap();
        // A join may carry history whose holders omit the sender. Prove the same
        // authenticated wrap is usable before its sender's removal is observed.
        assert_eq!(b.fleet_epoch_import(&join, &peers).unwrap().epochs, [1]);
        b.fleet_record_removals(
            &[FleetRemoval {
                member_id: id(1),
                removal_id: "removed-sender".into(),
            }],
            10,
        )
        .unwrap();
        body.keys[0].epoch = 2;
        let before = blobs(&b);
        let status = b.fleet_epoch_status().unwrap();
        let envelopes = envelope_snapshot(&b);
        let audit = b.read_audit(None).unwrap();
        for kind in ["rotation", "join"] {
            body.kind = kind.into();
            let wrap = make_wrap(&record, &id(1), &id(2), public.public_key(), &body).unwrap();
            assert_eq!(
                b.fleet_epoch_import(&wrap, &peers).unwrap_err(),
                FleetError::WrapRefused,
                "removed sender still in peer snapshot: {kind}"
            );
            assert_eq!(blobs(&b), before);
            assert_eq!(b.fleet_epoch_status().unwrap(), status);
            assert_eq!(envelope_snapshot(&b), envelopes);
            assert_eq!(b.read_audit(None).unwrap(), audit);
        }
    }

    #[test]
    fn fleet_rotation_omitting_its_minter_is_refused_before_writing() {
        let (_a, a) = rig("fleet-missing-minter-a", 1);
        let (_b, b) = rig("fleet-missing-minter-b", 2);
        let peers = [peer(&a, 1)];
        let record = a.fleet_read(|conn| a.fleet_wrap_record(conn)).unwrap();
        let public = peer(&b, 2);
        let mut body = WrapPlaintext {
            keys: vec![WrapKey {
                epoch: 1,
                key: encode(&[7; 32]),
                members: vec![id(2)],
                minter: id(1),
            }],
            kind: "rotation".into(),
            v: WRAP_DOMAIN.into(),
        };
        let wrap = make_wrap(&record, &id(1), &id(2), public.public_key(), &body).unwrap();
        let before = blobs(&b);
        let status = b.fleet_epoch_status().unwrap();
        let envelopes = envelope_snapshot(&b);
        let audit = b.read_audit(None).unwrap();
        assert_eq!(
            b.fleet_epoch_import(&wrap, &peers).unwrap_err(),
            FleetError::WrapRefused
        );
        assert_eq!(blobs(&b), before);
        assert_eq!(b.fleet_epoch_status().unwrap(), status);
        assert_eq!(envelope_snapshot(&b), envelopes);
        assert_eq!(b.read_audit(None).unwrap(), audit);
        body.keys[0].members.insert(0, id(1));
        let wrap = make_wrap(&record, &id(1), &id(2), public.public_key(), &body).unwrap();
        assert_eq!(b.fleet_epoch_import(&wrap, &peers).unwrap().epochs, [1]);
        assert_eq!(audit_len(&b), audit.len() + 1);
    }
}
