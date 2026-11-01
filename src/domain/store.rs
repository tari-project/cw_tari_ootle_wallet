// Copyright 2026 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! Per-wallet state, persisted as one JSON file.
//!
//! Holds no key material: keys are re-derived from the seed words on every open, and Cake keeps the
//! seed in its own encrypted `.keys` file. What lives here is the scan cursor, the outputs the scan
//! found, the transactions this wallet made, burn claims, and the trusted validator set.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use ootle_rs::provider::SavedValidatorSet;
use serde::{Deserialize, Serialize};
use tari_ootle_common_types::{shard::Shard, StateVersion};

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum OutputStatus {
    Unspent,
    /// Spent by a transaction this wallet submitted that has not settled yet.
    Locked,
    Spent,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub(crate) struct OwnedOutput {
    pub value: u64,
    pub status: OutputStatus,
    pub locked_by: Option<String>,
    pub memo: Option<String>,
    pub found_at_ms: i64,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum TxKind {
    Received,
    Sent,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum TxState {
    Pending,
    Completed,
    Failed,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub(crate) struct TxRecord {
    pub id: String,
    pub kind: TxKind,
    pub amount: u64,
    pub fee: u64,
    pub state: TxState,
    pub counterparty: Option<String>,
    pub memo: Option<String>,
    pub error: Option<String>,
    pub max_epoch: Option<u64>,
    pub created_at_ms: i64,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum ClaimState {
    /// Proof stored, claim not yet accepted by the network (too early, or a failed attempt).
    Pending,
    Submitted,
    Claimed,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub(crate) struct ClaimRecord {
    /// Commitment of the L1 burn output, hex.
    pub id: String,
    pub value: u64,
    pub mined_in_epoch: u64,
    /// The proof file exactly as the L1 wallet produced it.
    pub proof_json: String,
    pub state: ClaimState,
    pub tx_id: Option<String>,
    pub last_error: Option<String>,
    pub created_at_ms: i64,
}

#[derive(Serialize, Deserialize, Default)]
pub(crate) struct Store {
    pub birthday_epoch: u64,
    /// Per-shard scan cursor; empty until the first scan.
    pub cursor: Vec<(Shard, StateVersion)>,
    /// Keyed by UTXO id (the commitment, hex).
    pub outputs: BTreeMap<String, OwnedOutput>,
    pub revealed: u64,
    pub transactions: Vec<TxRecord>,
    pub claims: Vec<ClaimRecord>,
    /// Outputs our own transactions created (change, claims, faucet), so the scan does not list
    /// them as income when it finds them.
    pub own_outputs: BTreeSet<String>,
    pub validator_set: Option<SavedValidatorSet>,
}

pub(crate) struct Balance {
    pub available: u64,
    pub locked: u64,
}

impl Store {
    pub fn load(path: &Path) -> anyhow::Result<Option<Self>> {
        match fs::read(path) {
            Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Write-then-rename so a crash or a killed app never leaves a half-written file.
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        let tmp = PathBuf::from(format!("{}.tmp", path.display()));
        let mut f = fs::File::create(&tmp)?;
        f.write_all(&serde_json::to_vec(self)?)?;
        f.sync_all()?;
        fs::rename(&tmp, path)?;
        Ok(())
    }

    pub fn balance(&self) -> Balance {
        let sum = |s: OutputStatus| {
            self.outputs
                .values()
                .filter(|o| o.status == s)
                .map(|o| o.value)
                .fold(0u64, u64::saturating_add)
        };
        Balance {
            available: sum(OutputStatus::Unspent),
            locked: sum(OutputStatus::Locked),
        }
    }

    /// Atomically verifies that all `inputs` are still `Unspent` and locks them to `tx_id`.
    /// Prevents a concurrent send from overwriting `locked_by` on in-flight inputs and later
    /// unlocking them when the second send fails.
    pub fn lock_inputs(&mut self, inputs: &[String], tx_id: &str) -> anyhow::Result<()> {
        for id in inputs {
            let Some(output) = self.outputs.get(id) else {
                anyhow::bail!("input output {id} is missing from wallet store");
            };
            if output.status != OutputStatus::Unspent || output.locked_by.is_some() {
                anyhow::bail!("input output {id} is no longer unspent");
            }
        }
        for id in inputs {
            if let Some(o) = self.outputs.get_mut(id) {
                o.status = OutputStatus::Locked;
                o.locked_by = Some(tx_id.to_string());
            }
        }
        Ok(())
    }

    pub fn has_live_outputs(&self) -> bool {
        self.outputs
            .values()
            .any(|o| o.status != OutputStatus::Spent)
    }

    pub fn tx_mut(&mut self, id: &str) -> Option<&mut TxRecord> {
        self.transactions.iter_mut().find(|t| t.id == id)
    }

    /// Settle a submitted transaction: its locked inputs become spent (or unspent again on failure).
    pub fn settle(&mut self, tx_id: &str, ok: bool, fee: u64, error: Option<String>) {
        for o in self
            .outputs
            .values_mut()
            .filter(|o| o.locked_by.as_deref() == Some(tx_id))
        {
            o.status = if ok {
                OutputStatus::Spent
            } else {
                OutputStatus::Unspent
            };
            o.locked_by = None;
        }
        if let Some(tx) = self.tx_mut(tx_id) {
            tx.state = if ok {
                TxState::Completed
            } else {
                TxState::Failed
            };
            tx.fee = fee;
            tx.error = error;
        }
    }
}

pub(crate) fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn output(value: u64, status: OutputStatus, locked_by: Option<&str>) -> OwnedOutput {
        OwnedOutput {
            value,
            status,
            locked_by: locked_by.map(str::to_string),
            memo: None,
            found_at_ms: 0,
        }
    }

    fn tx(id: &str) -> TxRecord {
        TxRecord {
            id: id.into(),
            kind: TxKind::Sent,
            amount: 5,
            fee: 0,
            state: TxState::Pending,
            counterparty: None,
            memo: None,
            error: None,
            max_epoch: None,
            created_at_ms: 0,
        }
    }

    #[test]
    fn settle_moves_locked_inputs_and_balance() {
        let mut s = Store::default();
        s.outputs
            .insert("a".into(), output(10, OutputStatus::Locked, Some("t1")));
        s.outputs
            .insert("b".into(), output(7, OutputStatus::Unspent, None));
        s.outputs
            .insert("c".into(), output(3, OutputStatus::Locked, Some("t2")));
        s.transactions.push(tx("t1"));
        s.transactions.push(tx("t2"));
        assert_eq!((s.balance().available, s.balance().locked), (7, 13));

        s.settle("t1", true, 42, None);
        s.settle("t2", false, 0, Some("rejected".into()));
        assert_eq!(s.outputs["a"].status, OutputStatus::Spent);
        assert_eq!(s.outputs["c"].status, OutputStatus::Unspent);
        assert_eq!((s.balance().available, s.balance().locked), (10, 0));
        assert_eq!(s.transactions[0].state, TxState::Completed);
        assert_eq!(s.transactions[0].fee, 42);
        assert_eq!(s.transactions[1].state, TxState::Failed);
    }

    #[test]
    fn save_load_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("w.json");
        assert!(Store::load(&path).unwrap().is_none());
        let mut s = Store {
            birthday_epoch: 9,
            ..Store::default()
        };
        s.outputs
            .insert("a".into(), output(1, OutputStatus::Unspent, None));
        s.save(&path).unwrap();
        let back = Store::load(&path).unwrap().unwrap();
        assert_eq!(back.birthday_epoch, 9);
        assert_eq!(back.outputs.len(), 1);
    }

    #[test]
    fn lock_inputs_rejects_already_locked_utxo_without_stealing_lock() {
        let mut s = Store::default();
        s.outputs
            .insert("a".into(), output(10, OutputStatus::Unspent, None));
        s.outputs
            .insert("b".into(), output(20, OutputStatus::Unspent, None));

        s.lock_inputs(&["a".into()], "tx1").unwrap();
        assert_eq!(s.outputs["a"].status, OutputStatus::Locked);
        assert_eq!(s.outputs["a"].locked_by.as_deref(), Some("tx1"));

        // A concurrent second send attempting to lock ["b", "a"] must fail atomically without
        // locking "b" or overwriting "a"'s locked_by.
        let err = s
            .lock_inputs(&["b".into(), "a".into()], "tx2")
            .unwrap_err()
            .to_string();
        assert!(err.contains("no longer unspent"), "{err}");
        assert_eq!(s.outputs["a"].locked_by.as_deref(), Some("tx1"));
        assert_eq!(s.outputs["b"].status, OutputStatus::Unspent);

        // If tx2 fails and settles, tx1's locked input remains locked.
        s.settle("tx2", false, 0, Some("failed".into()));
        assert_eq!(s.outputs["a"].status, OutputStatus::Locked);
        assert_eq!(s.outputs["a"].locked_by.as_deref(), Some("tx1"));
    }

    #[test]
    fn balance_saturates_on_overflow() {
        let mut s = Store::default();
        s.outputs.insert(
            "a".into(),
            output(u64::MAX - 5, OutputStatus::Unspent, None),
        );
        s.outputs
            .insert("b".into(), output(100, OutputStatus::Unspent, None));
        assert_eq!(s.balance().available, u64::MAX);
    }
}
