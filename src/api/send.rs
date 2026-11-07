// Copyright 2026 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! Fees, sending, and the Esmeralda faucet.

use std::{num::NonZeroU64, str::FromStr};

use anyhow::anyhow;
use ootle_rs::Network;
use tari_ootle_address::OotleAddress;

use crate::{
    domain::{send, wallet::Wallet},
    frb_generated::StreamSink,
};

pub enum SendEvent {
    Submitted { tx_id: String },
    Completed { tx_id: String },
    Failed { message: String },
}

fn parse(
    wallet_network: Network,
    to: &str,
    amount: u64,
) -> anyhow::Result<(OotleAddress, NonZeroU64)> {
    let to = OotleAddress::from_str(to)?;
    to.validate()?;
    if to.network() != wallet_network {
        return Err(anyhow!(
            "recipient address network ({}) does not match wallet network ({})",
            to.network(),
            wallet_network
        ));
    }
    Ok((
        to,
        NonZeroU64::new(amount).ok_or_else(|| anyhow!("amount must be above zero"))?,
    ))
}

/// The fee (µT) a send of `amount` to `to` settles at. Show it to the user and pass it unchanged
/// to `send_transaction`.
pub async fn estimate_fee(name: String, to: String, amount: u64) -> anyhow::Result<u64> {
    let wallet = Wallet::get(&name)?;
    let (to, amount) = parse(wallet.keys.network, &to, amount)?;
    send::estimate_fee(&wallet, &to, amount).await
}

/// Sends at the approved `fee` and streams until the transaction finalizes or fails.
pub async fn send_transaction(
    sink: StreamSink<SendEvent>,
    name: String,
    to: String,
    amount: u64,
    fee: u64,
    memo: Option<String>,
) -> anyhow::Result<()> {
    let wallet = Wallet::get(&name)?;
    let result = async {
        let (to, amount) = parse(wallet.keys.network, &to, amount)?;
        send::send(&wallet, &to, amount, fee, memo, |p| match p {
            send::Progress::Submitted { tx_id } => {
                let _ = sink.add(SendEvent::Submitted { tx_id });
            }
        })
        .await
    }
    .await;
    let _ = sink.add(match result {
        Ok(tx_id) => SendEvent::Completed { tx_id },
        Err(e) => SendEvent::Failed {
            message: format!("{e:#}"),
        },
    });
    Ok(())
}

/// Esmeralda only: 1,000 test TARI into this wallet. Returns the transaction id.
pub async fn request_faucet_funds(name: String) -> anyhow::Result<String> {
    send::faucet(&*Wallet::get(&name)?).await
}

#[cfg(test)]
mod tests {
    use tari_common_types::seeds::cipher_seed::CipherSeed;

    use super::*;
    use crate::domain::keys::AccountKeys;

    #[test]
    fn parse_rejects_mismatched_recipient_network_and_zero_amount() {
        let esm_addr = AccountKeys::from_seed(&CipherSeed::random(), Network::Esmeralda, 0)
            .address()
            .to_string();
        let main_addr = AccountKeys::from_seed(&CipherSeed::random(), Network::MainNet, 0)
            .address()
            .to_string();

        assert!(parse(Network::Esmeralda, &esm_addr, 100).is_ok());
        assert!(parse(Network::MainNet, &main_addr, 100).is_ok());

        let err = parse(Network::MainNet, &esm_addr, 100).unwrap_err();
        assert!(err.to_string().contains("network"), "{err}");

        let err = parse(Network::Esmeralda, &esm_addr, 0).unwrap_err();
        assert!(err.to_string().contains("above zero"), "{err}");
    }
}
