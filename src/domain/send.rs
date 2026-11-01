// Copyright 2026 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! Spending: stealth sends, burn claims and the Esmeralda faucet.
//!
//! Fees settle the way Universe and walletd do it: the engine never refunds an overpaid fee, so
//! dry-run at a placeholder fee, raise it to what the run says is required, and repeat until a
//! build at that fee covers what it is charged.

use std::{future::Future, num::NonZeroU64};

use anyhow::{anyhow, bail};
use ootle_rs::{
    builtin_templates::{faucet::IFaucet, UnsignedTransactionBuilder},
    claim_burn::ClaimBurn,
    provider::{Provider as _, WalletProvider as _},
    stealth::{Output, StealthTransfer},
    template_types::{
        constants::{TARI, TARI_TOKEN},
        UtxoAddress, UtxoId,
    },
    wallet::NetworkWallet,
    Epoch, TransactionOutcome, TransactionRequest,
};
use tari_ootle_address::OotleAddress;
use tari_ootle_transaction::{Transaction, UnsignedTransaction};

use super::{
    burn_proof::BurnProof,
    store::{now_ms, OutputStatus, TxKind, TxRecord, TxState},
    wallet::{Provider, Wallet},
};

/// Refuse any fee above 0.1 TARI, the same ceiling Universe applies.
pub(crate) const MAX_FEE: u64 = TARI / 10;
const MAX_FEE_ROUNDS: usize = 5;
/// How many epochs a transaction stays valid for.
const VALIDITY_EPOCHS: u64 = 10;

/// Dry-runs `build(fee)` until the fee settles, returning it.
async fn settle_fee<W, F, Fut>(provider: &Provider, mut build: F) -> anyhow::Result<u64>
where
    W: NetworkWallet + Send + Sync,
    F: FnMut(u64) -> Fut,
    Fut: Future<Output = anyhow::Result<(UnsignedTransaction, W)>>,
{
    let mut fee = 1;
    for _ in 0..MAX_FEE_ROUNDS {
        let (unsigned, authorizer) = build(fee).await?;
        let run = provider
            .sign_and_send_dry_run_with(&authorizer, unsigned)
            .await?;
        if let Some(reason) = run.finalize.any_reject() {
            if run.finalize.required_fees() <= fee {
                bail!("Transaction dry run was rejected: {reason}");
            }
        } else if run.finalize.charged_fees() <= fee {
            return Ok(fee);
        }
        fee = run.finalize.required_fees().max(fee.saturating_add(1));
        if fee > MAX_FEE {
            bail!("The network asked for a fee of {fee} µT, over the {MAX_FEE} µT limit");
        }
    }
    bail!("The fee estimate did not settle after {MAX_FEE_ROUNDS} dry runs")
}

fn checked_target(amount: NonZeroU64, fee: u64) -> anyhow::Result<u64> {
    amount.get().checked_add(fee).ok_or_else(|| {
        anyhow!(
            "send amount {} µT plus fee {fee} µT overflows u64",
            amount.get()
        )
    })
}

fn checked_change(total: u64, amount: NonZeroU64, fee: u64) -> anyhow::Result<u64> {
    let target = checked_target(amount, fee)?;
    total
        .checked_sub(target)
        .ok_or_else(|| anyhow!("selected inputs total {total} µT is below required {target} µT"))
}

/// Largest outputs first, so the merged fee+transfer statement stays as small as it can.
fn select_inputs(wallet: &Wallet, target: u64) -> anyhow::Result<(Vec<UtxoId>, u64)> {
    let mut unspent: Vec<(String, u64)> = wallet.read(|s| {
        s.outputs
            .iter()
            .filter(|(_, o)| o.status == OutputStatus::Unspent)
            .map(|(id, o)| (id.clone(), o.value))
            .collect()
    });
    unspent.sort_by_key(|o| std::cmp::Reverse(o.1));
    let mut picked = Vec::new();
    let mut total = 0u64;
    for (id, value) in unspent {
        if total >= target {
            break;
        }
        picked.push(UtxoId::from_hex(&id).map_err(|e| anyhow!("bad stored utxo id {id}: {e:?}"))?);
        total = total.saturating_add(value);
    }
    if total < target {
        bail!("Insufficient funds: need {target} µT, have {total} µT available");
    }
    Ok((picked, total))
}

/// One stealth transfer that pays the recipient, returns change, and reveals `fee` into the bucket
/// the fee is paid from, all inside the fee intent (walletd's merged shape).
///
/// ponytail: merged shape only; a send that needs many inputs can exceed the fee-intent compute
/// credit and fail its dry run. walletd then falls back to a separate fee statement; add that if
/// fragmented wallets hit it.
async fn build_send<'p>(
    wallet: &Wallet,
    provider: &'p Provider,
    to: &OotleAddress,
    amount: NonZeroU64,
    fee: u64,
    memo: Option<&str>,
) -> anyhow::Result<(
    UnsignedTransaction,
    ootle_rs::wallet::WalletStealthAuthorizer<'p, ootle_rs::wallet::OotleWallet>,
    Vec<UtxoId>,
    Vec<String>,
)> {
    let target = checked_target(amount, fee)?;
    let (inputs, total) = select_inputs(wallet, target)?;
    let change = checked_change(total, amount, fee)?;
    let mut recipient = Output::new(to.clone(), TARI_TOKEN, amount);
    if let Some(memo) = memo {
        recipient = recipient.with_memo_message(memo);
    }
    let mut transfer = StealthTransfer::new(TARI_TOKEN, provider);
    for id in &inputs {
        transfer = transfer.spend_stealth_input(wallet.address.clone(), id.into_commitment_bytes());
    }
    transfer = transfer.to_stealth_output(recipient);
    if let Some(change) = NonZeroU64::new(change) {
        transfer =
            transfer.to_stealth_output(Output::new(wallet.address.clone(), TARI_TOKEN, change));
    }
    let (statement, signers) = transfer.to_revealed_output(fee).prepare().await?;
    // Output 0 is the recipient's; anything after it is our change.
    let change_ids = statement
        .outputs_statement
        .outputs
        .iter()
        .skip(1)
        .map(|o| UtxoId::from(o.output.commitment).to_string())
        .collect();

    let max_epoch = Epoch(provider.get_epoch().await?.as_u64() + VALIDITY_EPOCHS);
    let mut builder = Transaction::builder(provider.network(), max_epoch)
        .with_fee_instructions_builder(|b| {
            b.stealth_transfer(TARI_TOKEN, statement)
                .put_last_instruction_output_on_workspace("revealed_bucket")
                .pay_fee_from_bucket("revealed_bucket")
        });
    builder = builder.add_input(TARI_TOKEN);
    for id in &inputs {
        builder = builder.add_input(UtxoAddress::new(TARI_TOKEN, *id));
    }
    let authorizer = provider.wallet().stealth_authorizer(signers);
    Ok((builder.build_unsigned(), authorizer, inputs, change_ids))
}

pub(crate) async fn estimate_fee(
    wallet: &Wallet,
    to: &OotleAddress,
    amount: NonZeroU64,
) -> anyhow::Result<u64> {
    let provider = wallet.provider().await?;
    settle_fee(&provider, |fee| {
        let provider = &provider;
        async move {
            let (unsigned, authorizer, _, _) =
                build_send(wallet, provider, to, amount, fee, None).await?;
            Ok((unsigned, authorizer))
        }
    })
    .await
}

pub(crate) enum Progress {
    Submitted { tx_id: String },
}

/// Builds at the approved `fee`, locks the inputs, submits, and waits for finalization.
/// Returns the transaction id.
pub(crate) async fn send(
    wallet: &Wallet,
    to: &OotleAddress,
    amount: NonZeroU64,
    fee: u64,
    memo: Option<String>,
    on_progress: impl Fn(Progress),
) -> anyhow::Result<String> {
    if fee > MAX_FEE {
        bail!("Fee {fee} µT is over the {MAX_FEE} µT limit");
    }
    let mut provider = wallet.provider().await?;
    let (unsigned, authorizer, inputs, change_ids) =
        build_send(wallet, &provider, to, amount, fee, memo.as_deref()).await?;
    let max_epoch = Some(unsigned.max_epoch().as_u64());
    let tx = TransactionRequest::default()
        .with_transaction(unsigned)
        .build(&authorizer)
        .await?;
    drop(authorizer);
    let tx_id = tx.calculate_id().to_string();

    // Lock before submitting: if the app dies after submit, the scan still knows these were ours to
    // settle, and expire_stale_sends releases them if the send never lands.
    let input_ids: Vec<String> = inputs.iter().map(UtxoId::to_string).collect();
    wallet.write(|s| -> anyhow::Result<()> {
        s.lock_inputs(&input_ids, &tx_id)?;
        s.own_outputs.extend(change_ids);
        s.transactions.push(TxRecord {
            id: tx_id.clone(),
            kind: TxKind::Sent,
            amount: amount.get(),
            fee,
            state: TxState::Pending,
            counterparty: Some(to.to_string()),
            memo,
            error: None,
            max_epoch,
            created_at_ms: now_ms(),
        });
        Ok(())
    })??;

    let pending = match provider.send_transaction(tx).await {
        Ok(p) => p,
        Err(e) => {
            wallet.write(|s| s.settle(&tx_id, false, 0, Some(e.to_string())))?;
            return Err(e.into());
        }
    };
    on_progress(Progress::Submitted {
        tx_id: tx_id.clone(),
    });
    finish(
        wallet,
        &tx_id,
        pending.watch().await.map_err(|e| anyhow!(e.to_string())),
        fee,
    )?;
    wallet.remember_validator_set(&provider).await?;
    Ok(tx_id)
}

/// Records how a submitted send ended. A watch error (timeout, lost connection) leaves it
/// pending for the next scan to settle.
fn finish(
    wallet: &Wallet,
    tx_id: &str,
    outcome: anyhow::Result<TransactionOutcome>,
    fee: u64,
) -> anyhow::Result<()> {
    match outcome {
        Ok(TransactionOutcome::Commit) => wallet.write(|s| s.settle(tx_id, true, fee, None)),
        // Everything sits in the fee intent, so a fee-only commit spent the inputs as well.
        Ok(TransactionOutcome::OnlyFeeCommit(reason)) => {
            wallet.write(|s| s.settle(tx_id, true, fee, Some(reason.to_string())))?;
            bail!("Transaction {tx_id} failed after paying its fee: {reason}")
        }
        Ok(TransactionOutcome::Reject(reason)) => {
            wallet.write(|s| s.settle(tx_id, false, 0, Some(reason.to_string())))?;
            bail!("Transaction {tx_id} was rejected: {reason}")
        }
        Err(e) => {
            log::warn!("Lost track of {tx_id}: {e}. The next scan settles it.");
            Ok(())
        }
    }
}

/// Waits for a claim or faucet transaction. Their outputs reach history through the scan.
async fn await_commit(pending: ootle_rs::provider::PendingTransaction) -> anyhow::Result<()> {
    match pending.watch().await.map_err(|e| anyhow!(e.to_string()))? {
        TransactionOutcome::Commit => Ok(()),
        TransactionOutcome::OnlyFeeCommit(reason) | TransactionOutcome::Reject(reason) => {
            bail!("Transaction {} failed: {reason}", pending.tx_id())
        }
    }
}

/// Claims an L1 burn into this account as a stealth output. Returns the transaction id.
pub(crate) async fn claim(
    wallet: &Wallet,
    proof: BurnProof,
    on_progress: impl Fn(Progress),
) -> anyhow::Result<String> {
    let mut provider = wallet.provider().await?;
    let build = |fee: u64| {
        let provider = &provider;
        let proof = (proof.claim_proof.clone(), proof.encrypted_data.clone());
        async move {
            let max_epoch = Epoch(provider.get_epoch().await?.as_u64() + VALIDITY_EPOCHS);
            Ok(ClaimBurn::new(provider, proof.0, proof.1, max_epoch)
                .with_max_fee(fee)
                .prepare()
                .await?)
        }
    };
    let fee = settle_fee(&provider, build).await?;
    let (unsigned, sealer) = build(fee).await?;
    let tx = TransactionRequest::default()
        .with_transaction(unsigned)
        .build(&sealer)
        .await?;
    let tx_id = tx.calculate_id().to_string();
    let pending = provider.send_transaction(tx).await?;
    on_progress(Progress::Submitted {
        tx_id: tx_id.clone(),
    });
    await_commit(pending).await?;
    Ok(tx_id)
}

/// Esmeralda only: takes the faucet's TARI into the account and moves 500 of it into a stealth
/// output we own. The faucet bucket arrives a little under its nominal 1,000, so the rest stays
/// revealed in the account.
pub(crate) async fn faucet(wallet: &Wallet) -> anyhow::Result<String> {
    if wallet.keys.network == ootle_rs::Network::MainNet {
        bail!("There is no faucet on mainnet");
    }
    const FAUCET_AMOUNT: u64 = 500 * TARI;
    let mut provider = wallet.provider().await?;
    let build = |fee: u64| {
        let provider = &provider;
        async move {
            let keep = NonZeroU64::new(FAUCET_AMOUNT - fee)
                .ok_or_else(|| anyhow!("fee exceeds faucet amount"))?;
            let (statement, signers) = StealthTransfer::new(TARI_TOKEN, provider)
                .spend_revealed_input(FAUCET_AMOUNT)
                .to_revealed_output(fee)
                .to_stealth_output(Output::new(wallet.address.clone(), TARI_TOKEN, keep))
                .prepare()
                .await?;
            let max_epoch = Epoch(provider.get_epoch().await?.as_u64() + VALIDITY_EPOCHS);
            let unsigned = IFaucet::new(provider, max_epoch)
                .take_faucet_funds()
                .into_stealth_transfer(statement)
                .and_pay_fee_from_revealed_output()
                .prepare()
                .await?;
            Ok((unsigned, provider.wallet().stealth_authorizer(signers)))
        }
    };
    let fee = settle_fee(&provider, build).await?;
    let (unsigned, authorizer) = build(fee).await?;
    let tx = TransactionRequest::default()
        .with_transaction(unsigned)
        .build(&authorizer)
        .await?;
    drop(authorizer);
    let tx_id = tx.calculate_id().to_string();
    await_commit(provider.send_transaction(tx).await?).await?;
    Ok(tx_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_target_and_change_reject_overflow_and_underflow() {
        let max_amount = NonZeroU64::new(u64::MAX).unwrap();
        assert!(checked_target(max_amount, 1).is_err());
        assert!(checked_change(u64::MAX, max_amount, 1).is_err());

        let amount = NonZeroU64::new(1_000).unwrap();
        assert_eq!(checked_target(amount, 250).unwrap(), 1_250);
        assert_eq!(checked_change(2_000, amount, 250).unwrap(), 750);
        assert!(checked_change(1_200, amount, 250).is_err());
    }
}
