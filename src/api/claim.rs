// Copyright 2026 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! Claiming L1 (Minotari) burns into this wallet.

use crate::{
    api::send::SendEvent,
    domain::{
        burn_proof::BurnProof,
        send::{self, ClaimOutcome},
        store::{now_ms, ClaimRecord, ClaimState, Store},
        wallet::Wallet,
    },
    frb_generated::StreamSink,
};

pub enum ClaimStatus {
    /// Waiting for the network to accept it (the burn must be a few epochs old), or the last attempt failed.
    Pending,
    Submitted,
    Claimed,
}

pub struct ClaimDto {
    /// The burn output's commitment, hex.
    pub id: String,
    pub amount: u64,
    pub status: ClaimStatus,
    pub tx_id: Option<String>,
    pub last_error: Option<String>,
    /// The L2 accepts the claim once its epoch is past this.
    pub mined_in_epoch: u64,
    pub created_at_ms: i64,
}

fn dto(c: &ClaimRecord) -> ClaimDto {
    ClaimDto {
        id: c.id.clone(),
        amount: c.value,
        status: match c.state {
            ClaimState::Pending => ClaimStatus::Pending,
            ClaimState::Submitted => ClaimStatus::Submitted,
            ClaimState::Claimed => ClaimStatus::Claimed,
        },
        tx_id: c.tx_id.clone(),
        last_error: c.last_error.clone(),
        mined_in_epoch: c.mined_in_epoch,
        created_at_ms: c.created_at_ms,
    }
}

/// Stores a burn proof from the L1 wallet (the `proof_json` of `cw_tari_wallet::get_burn_proofs`).
/// Adding the same proof twice is a no-op.
pub fn add_burn_proof(name: String, proof_json: String) -> anyhow::Result<ClaimDto> {
    let proof = BurnProof::from_json(&proof_json)?;
    let id = proof.claim_proof.commitment.to_string();
    Wallet::get(&name)?.write(|s| {
        if let Some(existing) = s.claims.iter().find(|c| c.id == id) {
            return dto(existing);
        }
        let record = ClaimRecord {
            id,
            value: proof.claim_proof.value,
            mined_in_epoch: proof.mined_in_epoch,
            proof_json,
            state: ClaimState::Pending,
            tx_id: None,
            last_error: None,
            created_at_ms: now_ms(),
        };
        let out = dto(&record);
        s.claims.push(record);
        out
    })
}

pub fn get_claims(name: String) -> anyhow::Result<Vec<ClaimDto>> {
    Ok(Wallet::get(&name)?.read(|s| s.claims.iter().map(dto).collect()))
}

fn playable_claim_proof_json(store: &Store, claim_id: &str) -> anyhow::Result<String> {
    let c = store
        .claims
        .iter()
        .find(|c| c.id == claim_id)
        .ok_or_else(|| anyhow::anyhow!("no claim {claim_id}"))?;
    match c.state {
        ClaimState::Claimed => anyhow::bail!("claim {claim_id} has already been claimed"),
        ClaimState::Submitted => {
            anyhow::bail!(
                "claim {claim_id} has already been submitted and is awaiting confirmation"
            )
        }
        ClaimState::Pending => Ok(c.proof_json.clone()),
    }
}

fn apply_claim_result(
    store: &mut Store,
    claim_id: &str,
    result: Result<ClaimOutcome, String>,
) -> SendEvent {
    match result {
        Ok(ClaimOutcome::Committed { tx_id }) => {
            if let Some(c) = store.claims.iter_mut().find(|c| c.id == claim_id) {
                c.state = ClaimState::Claimed;
                c.tx_id = Some(tx_id.clone());
                c.last_error = None;
            }
            SendEvent::Completed { tx_id }
        }
        Ok(ClaimOutcome::WatchFailed { tx_id, error }) => {
            if let Some(c) = store.claims.iter_mut().find(|c| c.id == claim_id) {
                c.state = ClaimState::Submitted;
                c.tx_id = Some(tx_id);
                c.last_error = Some(error.clone());
            }
            SendEvent::Failed { message: error }
        }
        Err(message) => {
            if let Some(c) = store.claims.iter_mut().find(|c| c.id == claim_id) {
                c.state = ClaimState::Pending;
                c.tx_id = None;
                c.last_error = Some(message.clone());
            }
            SendEvent::Failed { message }
        }
    }
}

/// Submits the claim and streams until it lands. A pre-broadcast or on-chain rejection leaves the
/// claim pending to retry; a post-broadcast watch disconnect keeps it in `Submitted`.
pub async fn claim_burn(
    sink: StreamSink<SendEvent>,
    name: String,
    claim_id: String,
) -> anyhow::Result<()> {
    let wallet = Wallet::get(&name)?;
    let proof_json = wallet.read(|s| playable_claim_proof_json(s, &claim_id))?;
    let proof = BurnProof::from_json(&proof_json)?;
    let set = |state: ClaimState, tx_id: Option<String>, error: Option<String>| {
        wallet.write(|s| {
            if let Some(c) = s.claims.iter_mut().find(|c| c.id == claim_id) {
                c.state = state;
                c.tx_id = tx_id.or(c.tx_id.take());
                c.last_error = error;
            }
        })
    };
    let result = send::claim(&wallet, proof, |p| match p {
        send::Progress::Submitted { tx_id } => {
            let _ = set(ClaimState::Submitted, Some(tx_id.clone()), None);
            let _ = sink.add(SendEvent::Submitted { tx_id });
        }
    })
    .await
    .map_err(|e| format!("{e:#}"));
    let event = wallet.write(|s| apply_claim_result(s, &claim_id, result))?;
    let _ = sink.add(event);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_claim(state: ClaimState) -> ClaimRecord {
        ClaimRecord {
            id: "c1".into(),
            value: 1_000,
            mined_in_epoch: 5,
            proof_json: "{}".into(),
            state,
            tx_id: None,
            last_error: None,
            created_at_ms: 0,
        }
    }

    #[test]
    fn duplicate_claim_is_rejected_when_submitted_or_claimed() {
        let mut store = Store::default();
        store.claims.push(sample_claim(ClaimState::Submitted));
        assert!(playable_claim_proof_json(&store, "c1").is_err());

        store.claims[0].state = ClaimState::Claimed;
        assert!(playable_claim_proof_json(&store, "c1").is_err());

        store.claims[0].state = ClaimState::Pending;
        assert_eq!(playable_claim_proof_json(&store, "c1").unwrap(), "{}");
    }

    #[test]
    fn post_broadcast_watch_failure_preserves_submitted_state_and_tx_id() {
        let mut store = Store::default();
        store.claims.push(sample_claim(ClaimState::Submitted));

        let event = apply_claim_result(
            &mut store,
            "c1",
            Ok(ClaimOutcome::WatchFailed {
                tx_id: "tx_abc".into(),
                error: "watch timed out".into(),
            }),
        );
        assert!(matches!(event, SendEvent::Failed { .. }));
        assert_eq!(store.claims[0].state, ClaimState::Submitted);
        assert_eq!(store.claims[0].tx_id.as_deref(), Some("tx_abc"));
        assert_eq!(
            store.claims[0].last_error.as_deref(),
            Some("watch timed out")
        );
    }
}
