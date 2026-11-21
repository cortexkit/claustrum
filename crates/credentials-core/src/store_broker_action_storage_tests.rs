use rusqlite::{params, Connection};

use super::taxonomy_tests::rig;

const STATEMENT: &[u8] = br#"{"context":"minted bytes"}"#;
const LEGS: &str = r#"[
    {"kind":"first","method":"POST","resource":"owner/repo","request_sha256":"a"},
    {"kind":"second","method":"PATCH","resource":"owner/repo","request_sha256":"b"}
]"#;
const INSERT: &str = "INSERT INTO broker_action_requests (
        request_id, principal, agent_id, scope_json, statement_bytes, statement_sha256,
        policy_version, identity, legs_json, created_at_ms, expires_at_ms
    ) VALUES (?1, 'reserved:aft', 'agent', '{\"owner\":\"reserved:prefrontal-core\",\"kind\":\"head\",\"ref\":\"H\",\"epoch\":7}',
        ?2, 'digest', 1, 'github_app:sample', ?3, ?4, ?5)";

fn mint(conn: &Connection, id: &str, created: i64, expires: i64) -> rusqlite::Result<()> {
    conn.execute(INSERT, params![id, STATEMENT, LEGS, created, expires])?;
    Ok(())
}

fn approve(conn: &Connection, id: &str) -> rusqlite::Result<()> {
    assert_eq!(
        conn.execute(
            "UPDATE broker_action_requests SET approved_at_ms = created_at_ms + 1,
             device_fingerprint = 'phone', envelope_sha256 = 'envelope' WHERE request_id = ?1",
            [id],
        )?,
        1,
    );
    Ok(())
}

fn assert_refused(conn: &Connection, sql: &str, message: &str) {
    match conn.execute(sql, []) {
        Err(rusqlite::Error::SqliteFailure(_, Some(actual))) => {
            assert_eq!(actual, message, "{sql}")
        }
        other => panic!("expected refusal for {sql}, got {other:?}"),
    }
}

#[test]
fn broker_action_storage_preserves_every_minted_column_and_refuses_replacement() {
    let (_root, store) = rig("broker-action-immutable", 140);
    store
        .with_raw_conn(|conn| {
            conn.execute_batch("PRAGMA recursive_triggers = OFF")?;
            mint(conn, "request", 1, 600_001)?;
            for change in [
                "request_id = 'another'",
                "principal = 'reserved:plexus'",
                "agent_id = 'another'",
                "scope_json = '{}'",
                "statement_bytes = X'0001'",
                "statement_sha256 = 'another'",
                "policy_version = 2",
                "identity = 'github_app:another'",
                "legs_json = '[]'",
                "created_at_ms = 2",
                "expires_at_ms = 600002",
            ] {
                assert_refused(
                    conn,
                    &format!("UPDATE broker_action_requests SET {change}"),
                    "broker action request is immutable",
                );
            }
            let replace = INSERT.replacen("INSERT", "INSERT OR REPLACE", 1);
            let error = conn
                .execute(
                    &replace,
                    params!["request", b"replacement".as_slice(), LEGS, 2, 600_002],
                )
                .expect_err("a duplicate ID cannot overwrite the minted request");
            assert!(
                matches!(error, rusqlite::Error::SqliteFailure(_, Some(message))
            if message == "broker action request already exists")
            );
            let bytes: Vec<u8> = conn.query_row(
                "SELECT statement_bytes FROM broker_action_requests",
                [],
                |row| row.get(0),
            )?;
            assert_eq!(bytes, STATEMENT);
            Ok(())
        })
        .unwrap();
}

#[test]
fn broker_action_storage_records_approval_once_and_issues_one_leg_at_a_time() {
    let (_root, store) = rig("broker-action-progress", 140);
    store
        .with_raw_conn(|conn| {
            mint(conn, "request", 1, 600_001)?;
            type Progress = (Option<i64>, Option<String>, Option<String>, i64);
            let progress = || -> rusqlite::Result<Progress> {
                conn.query_row(
                    "SELECT approved_at_ms, device_fingerprint, envelope_sha256, issued_legs
                            FROM broker_action_requests",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
            };
            assert_eq!(progress()?, (None, None, None, 0));
            for change in [
                "issued_legs = 1",
                "approved_at_ms = 2",
                "approved_at_ms = 2, device_fingerprint = 'phone'",
                "device_fingerprint = 'phone', envelope_sha256 = 'envelope'",
            ] {
                let error = conn
                    .execute(&format!("UPDATE broker_action_requests SET {change}"), [])
                    .expect_err("a partial approval or an unapproved issue is refused");
                assert_eq!(
                    error.sqlite_error_code(),
                    Some(rusqlite::ErrorCode::ConstraintViolation),
                    "{change}"
                );
            }
            assert_eq!(progress()?, (None, None, None, 0));
            approve(conn, "request")?;
            for change in [
                "approved_at_ms = NULL",
                "approved_at_ms = 3",
                "device_fingerprint = NULL",
                "device_fingerprint = 'another'",
                "envelope_sha256 = NULL",
                "envelope_sha256 = 'another'",
            ] {
                assert_refused(
                    conn,
                    &format!("UPDATE broker_action_requests SET {change}"),
                    "broker action approval is write-once",
                );
            }
            assert_refused(
                conn,
                "UPDATE broker_action_requests SET issued_legs = 2",
                "broker action issuance must advance one leg",
            );
            let set_issued = |count: i64| {
                conn.execute(
                    "UPDATE broker_action_requests SET issued_legs = ?1",
                    [count],
                )
            };
            assert_eq!(set_issued(1)?, 1);
            assert_refused(
                conn,
                "UPDATE broker_action_requests SET issued_legs = 0",
                "broker action issuance must advance one leg",
            );
            assert_eq!(set_issued(2)?, 1);
            let error = set_issued(3).expect_err("cannot issue past the end of a two-leg request");
            assert_eq!(
                error.sqlite_error_code(),
                Some(rusqlite::ErrorCode::ConstraintViolation)
            );
            assert_eq!(
                progress()?,
                (Some(2), Some("phone".into()), Some("envelope".into()), 2)
            );
            Ok(())
        })
        .unwrap();
}

#[test]
fn broker_action_storage_prunes_only_after_the_retention_boundary_in_the_mint_write() {
    const NOW: i64 = 170_000_000_000;
    let (_root, store) = rig("broker-action-retention", 140);
    let audit = store.read_audit(None).unwrap();
    store
        .with_raw_conn(|conn| {
            fn ids(conn: &Connection) -> rusqlite::Result<Vec<String>> {
                let mut stmt = conn
                    .prepare("SELECT request_id FROM broker_action_requests ORDER BY request_id")?;
                let rows = stmt.query_map([], |row| row.get(0))?.collect();
                rows
            }

            for (id, expiry) in [
                ("older", NOW - 86_400_002),
                ("just-too-old", NOW - 86_400_001),
                ("exactly-24h", NOW - 86_400_000),
                ("just-within", NOW - 86_399_999),
                ("approved-live", NOW + 1),
            ] {
                mint(conn, id, expiry - 600_000, expiry)?;
            }
            approve(conn, "approved-live")?;
            let before = [
                "approved-live",
                "exactly-24h",
                "just-too-old",
                "just-within",
                "older",
            ];
            let after = ["approved-live", "exactly-24h", "just-within", "new"];
            assert_eq!(ids(conn)?, before);

            let tx = conn.unchecked_transaction()?;
            mint(&tx, "new", NOW, NOW + 600_000)?;
            assert_eq!(ids(&tx)?, after);
            tx.rollback()?;
            assert_eq!(
                ids(conn)?,
                before,
                "rolling back the mint restores the deleted rows"
            );

            let tx = conn.unchecked_transaction()?;
            mint(&tx, "new", NOW, NOW + 600_000)?;
            tx.commit()?;
            assert_eq!(ids(conn)?, after);
            let approved_unissued: bool = conn.query_row(
                "SELECT approved_at_ms IS NOT NULL AND issued_legs = 0
             FROM broker_action_requests WHERE request_id = 'approved-live'",
                [],
                |row| row.get(0),
            )?;
            assert!(approved_unissued);
            Ok(())
        })
        .unwrap();
    assert_eq!(store.read_audit(None).unwrap(), audit);
}
