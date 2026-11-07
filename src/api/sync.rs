// Copyright 2026 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! Scanning, balance and history.

use std::{
    collections::HashMap,
    sync::{LazyLock, Mutex},
};

use futures::FutureExt;
use std::panic::AssertUnwindSafe;
use tokio::task::AbortHandle;

use crate::{
    domain::{
        scan,
        store::{TxKind, TxState},
        wallet::Wallet,
    },
    frb_generated::StreamSink,
};

pub enum ScanEvent {
    /// A pass was saved; `has_more` while the backlog is still draining.
    Progress {
        has_more: bool,
    },
    Completed,
    Failed {
        message: String,
    },
}

static SCANS: LazyLock<Mutex<HashMap<String, AbortHandle>>> = LazyLock::new(Default::default);

/// Scans the wallet until it is up to date. A new scan of the same wallet replaces a running one.
/// Each pass is saved before its event fires, so stopping mid-scan loses nothing.
pub async fn start_scan(sink: StreamSink<ScanEvent>, name: String) -> anyhow::Result<()> {
    let wallet = Wallet::get(&name)?;
    let scan_name = name.clone();
    let task = tokio::spawn(async move {
        // A panic in a spawned task would otherwise just close the stream with no event.
        let result = AssertUnwindSafe(scan::scan(&wallet, |has_more| {
            let _ = sink.add(ScanEvent::Progress { has_more });
        }))
        .catch_unwind()
        .await;
        let _ = sink.add(match result {
            Ok(Ok(())) => ScanEvent::Completed,
            Ok(Err(e)) => ScanEvent::Failed {
                message: format!("{e:#}"),
            },
            Err(panic) => ScanEvent::Failed {
                message: format!("scan panicked: {}", panic_message(&*panic)),
            },
        });
        let mut scans = SCANS.lock().unwrap_or_else(|e| e.into_inner());
        if scans.get(&scan_name).is_some_and(AbortHandle::is_finished) {
            scans.remove(&scan_name);
        }
    });
    if let Some(old) = SCANS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(name, task.abort_handle())
    {
        old.abort();
    }
    Ok(())
}

fn panic_message(panic: &(dyn std::any::Any + Send)) -> &str {
    panic
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| panic.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("unknown panic")
}

pub fn stop_scan(name: String) {
    if let Some(task) = SCANS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&name)
    {
        task.abort();
    }
}

/// Amounts in micro-TARI.
pub struct BalanceDto {
    /// Spendable stealth outputs.
    pub available: u64,
    /// Outputs held by sends that have not settled.
    pub pending_outgoing: u64,
    /// TARI in the account's public vault (shown, not spent by v1).
    pub revealed: u64,
}

pub fn get_balance(name: String) -> anyhow::Result<BalanceDto> {
    let wallet = Wallet::get(&name)?;
    Ok(wallet.read(|s| {
        let b = s.balance();
        BalanceDto {
            available: b.available,
            pending_outgoing: b.locked,
            revealed: s.revealed,
        }
    }))
}

pub enum TxDirection {
    Incoming,
    Outgoing,
}

pub enum TxStatus {
    Pending,
    Completed,
    Failed,
}

pub struct TransactionDto {
    pub id: String,
    pub direction: TxDirection,
    pub amount: u64,
    pub fee: u64,
    pub status: TxStatus,
    pub counterparty: Option<String>,
    pub memo: Option<String>,
    pub error: Option<String>,
    pub timestamp_ms: i64,
}

/// Newest first.
pub fn get_transactions(name: String) -> anyhow::Result<Vec<TransactionDto>> {
    let wallet = Wallet::get(&name)?;
    Ok(wallet.read(|s| {
        s.transactions
            .iter()
            .rev()
            .map(|t| TransactionDto {
                id: t.id.clone(),
                direction: match t.kind {
                    TxKind::Received => TxDirection::Incoming,
                    TxKind::Sent => TxDirection::Outgoing,
                },
                amount: t.amount,
                fee: t.fee,
                status: match t.state {
                    TxState::Pending => TxStatus::Pending,
                    TxState::Completed => TxStatus::Completed,
                    TxState::Failed => TxStatus::Failed,
                },
                counterparty: t.counterparty.clone(),
                memo: t.memo.clone(),
                error: t.error.clone(),
                timestamp_ms: t.created_at_ms,
            })
            .collect()
    }))
}
