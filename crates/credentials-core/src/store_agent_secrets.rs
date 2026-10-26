use super::*;
use crate::agent_secret::{self, DEPOSIT_KEY_ID};

#[path = "store_secret_phone.rs"]
mod phone;
pub use phone::{secret_phone_gate_status_read_only, PhoneDeposit, PhoneOperation};
#[path = "store_secret_use.rs"]
mod use_secret;
pub use use_secret::SecretUseOutcome;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretDepositPublicKey {
    pub key_id: String,
    pub public_key: Vec<u8>,
}

impl EncryptedStore {
    /// Daemon-only bootstrap. Existing unusable keys are never replaced automatically.
    /// Store and audit failures still abort startup; unusable material disables deposits.
    pub fn ensure_secret_deposit_key(&self) -> Result<(), StoreOpError> {
        let audit_key = self.audit_key.clone();
        self.fenced_write(|tx| {
            let exists: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM credentials WHERE credential_id = ?1)",
                [DEPOSIT_KEY_ID], |row| row.get(0),
            )?;
            if exists { return Ok(()); }
            let pem = crate::kem::generate_key().map_err(|_| rusqlite_err("deposit key generation failed"))?;
            let (_, key_id) = crate::kem::public_half(&pem).map_err(|_| rusqlite_err("deposit public key failed"))?;
            let record = VaultRecord::new_static(CredentialKind::KemKey, "vault", pem.into_bytes(), None);
            let blob = self.seal_record(DEPOSIT_KEY_ID, &record).map_err(|_| rusqlite_err("deposit key seal failed"))?;
            tx.execute(
                "INSERT INTO credentials (credential_id, record_version, key_id, envelope, state, updated_at_ms, created_at_ms, created_by) VALUES (?1, 1, ?2, ?3, 'active', ?4, ?4, 'vault')",
                rusqlite::params![DEPOSIT_KEY_ID, self.key_id.to_hex(), blob, now_ms()],
            )?;
            append_audit_tx(tx, &audit_key, &AuditRecord {
                op: AuditOp::SecretDepositKeyCreate,
                credential_id: Some(DEPOSIT_KEY_ID.to_owned()),
                payload_hash: Some(deposit_key_creation_hash(&key_id)),
                actor: "vault".to_owned(), alarm: None,
            })?;
            Ok(())
        }).map_err(StoreOpError::from)
    }

    fn secret_deposit_record(&self) -> Result<VaultRecord, StoreOpError> {
        self.store
            .with_conn(|conn| Ok(self.secret_deposit_record_conn(conn)))
            .map_err(StoreOpError::from)?
    }

    fn secret_deposit_record_conn(
        &self,
        conn: &rusqlite::Connection,
    ) -> Result<VaultRecord, StoreOpError> {
        let stored = conn
            .query_row(
                "SELECT state, record_version, envelope FROM credentials WHERE credential_id = ?1",
                [DEPOSIT_KEY_ID],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, u64>(1)?,
                        r.get::<_, Vec<u8>>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(|e| StoreOpError::Store(e.to_string()))?;
        let Some((state, version, blob)) = stored else {
            return Err(StoreOpError::SecretSetupIncomplete);
        };
        if state != RecordState::Active.as_str() {
            return Err(StoreOpError::SecretSetupIncomplete);
        }
        let bytes = envelope::open(
            &self.key,
            &blob,
            &RecordBinding {
                credential_id: DEPOSIT_KEY_ID,
                record_version: version,
            },
        )
        .map_err(|_| StoreOpError::SecretSetupIncomplete)?;
        let record =
            VaultRecord::decode(&bytes).map_err(|_| StoreOpError::SecretSetupIncomplete)?;
        if record.kind != CredentialKind::KemKey {
            return Err(StoreOpError::SecretSetupIncomplete);
        }
        Ok(record)
    }

    pub fn secret_deposit_public_key(&self) -> Result<SecretDepositPublicKey, StoreOpError> {
        let record = self.secret_deposit_record()?;
        let pem = std::str::from_utf8(record.payload.expose())
            .map_err(|_| StoreOpError::SecretSetupIncomplete)?;
        let (public_key, key_id) =
            crate::kem::public_half(pem).map_err(|_| StoreOpError::SecretSetupIncomplete)?;
        Ok(SecretDepositPublicKey { key_id, public_key })
    }

    /// The deposit receiver is the only consumer of the reserved private key.
    pub fn open_secret_deposit(
        &self,
        sender_public: &[u8],
        enc: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<crate::secret::Secret<Vec<u8>>, StoreOpError> {
        let record = self.secret_deposit_record()?;
        let pem = std::str::from_utf8(record.payload.expose())
            .map_err(|_| StoreOpError::SecretSetupIncomplete)?;
        // Validate the stored key separately so malformed incoming HPKE data stays not_found.
        crate::kem::parse_pkcs8_pem(pem).map_err(|_| StoreOpError::SecretSetupIncomplete)?;
        crate::kem::open_auth(
            pem,
            sender_public,
            enc,
            ciphertext,
            agent_secret::DEPOSIT_INFO,
            aad,
        )
        .map(crate::secret::Secret::new)
        .map_err(|_| StoreOpError::NotFound)
    }
}

pub(super) fn rotate_agent_secrets_tx(
    tx: &rusqlite::Transaction<'_>,
    old_key: &MasterKey,
    new_key: &MasterKey,
) -> rusqlite::Result<Vec<String>> {
    let rows = {
        let mut stmt = tx.prepare(
            "SELECT name, kind, incarnation, record_version, envelope FROM agent_secrets",
        )?;
        let mapped = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, u64>(3)?,
                r.get::<_, Vec<u8>>(4)?,
            ))
        })?;
        mapped.collect::<rusqlite::Result<Vec<_>>>()?
    };
    let mut quarantined = Vec::new();
    for (name, kind, incarnation, version, blob) in rows {
        let id = agent_secret::record_binding(&kind, &incarnation, &name);
        let plaintext = id.as_ref().ok().and_then(|id| {
            envelope::open(
                old_key,
                &blob,
                &RecordBinding {
                    credential_id: id,
                    record_version: version,
                },
            )
            .ok()
        });
        match plaintext {
            Some(body) => {
                let id = id.expect("an opened row has a valid binding");
                let new_blob = envelope::seal(
                    new_key,
                    &body,
                    &RecordBinding {
                        credential_id: &id,
                        record_version: version,
                    },
                )
                .map_err(|_| rusqlite_err("secret re-seal failed"))?;
                tx.execute(
                    "UPDATE agent_secrets SET envelope = ?2, key_id = ?3 WHERE name = ?1",
                    rusqlite::params![name, new_blob, new_key.key_id().to_hex()],
                )?;
            }
            None => {
                tx.execute(
                    "UPDATE agent_secrets SET state = 'corrupt' WHERE name = ?1",
                    [&name],
                )?;
                quarantined.push(format!("secret|{name}"));
            }
        }
    }
    Ok(quarantined)
}

pub(super) fn deposit_key_write_protected(
    conn: &rusqlite::Connection,
    id: &str,
) -> rusqlite::Result<bool> {
    if !agent_secret::is_deposit_key(id) {
        return Ok(false);
    }
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM credentials WHERE credential_id = ?1 AND state = 'active')",
        [id],
        |r| r.get(0),
    )
}

fn deposit_key_creation_hash(key_id: &str) -> String {
    let mut payload = Vec::new();
    agent_secret::push_field(&mut payload, key_id.as_bytes());
    sha256_hex_of_bytes(&payload)
}

#[cfg(test)]
#[path = "store_agent_secret_tests.rs"]
mod tests;
