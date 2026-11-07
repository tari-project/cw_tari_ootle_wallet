// Copyright 2026 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! Keys, addresses and opening a wallet.

use std::str::FromStr;

use ootle_rs::{provider::ProviderBuilder, Network};
use tari_common_types::seeds::{
    cipher_seed::CipherSeed,
    mnemonic::{Mnemonic, MnemonicLanguage},
};
use tari_crypto::tari_utilities::hex::Hex;
use tari_ootle_address::OotleAddress;

use crate::domain::{keys::AccountKeys, wallet::Wallet};

pub enum TariOotleNetwork {
    MainNet,
    Esmeralda,
}

impl From<TariOotleNetwork> for Network {
    fn from(n: TariOotleNetwork) -> Self {
        match n {
            TariOotleNetwork::MainNet => Network::MainNet,
            TariOotleNetwork::Esmeralda => Network::Esmeralda,
        }
    }
}

pub struct WalletCreated {
    pub seed_words: String,
    pub address: String,
}

/// New seed words (the same CipherSeed format the L1 wallet uses) and the account 0 address.
pub fn create_wallet(network: TariOotleNetwork) -> anyhow::Result<WalletCreated> {
    let seed = CipherSeed::random();
    let words = seed.to_mnemonic(MnemonicLanguage::English, None)?;
    Ok(WalletCreated {
        seed_words: words.join(" ").reveal().clone(),
        address: AccountKeys::from_seed(&seed, network.into(), 0)
            .address()
            .to_string(),
    })
}

/// Address of account 0 for these seed words. Same words as the L1 (Minotari) wallet.
pub fn address_from_seed(seed_words: String, network: TariOotleNetwork) -> anyhow::Result<String> {
    Ok(AccountKeys::from_words(&seed_words, network.into())?
        .address()
        .to_string())
}

#[flutter_rust_bridge::frb(sync)]
pub fn validate_address(address: String, network: TariOotleNetwork) -> bool {
    let network: Network = network.into();
    OotleAddress::from_str(&address).is_ok_and(|a| a.validate().is_ok() && a.network() == network)
}

/// The claim public key (hex) an L1 burn must target so the owner of this L2 address can claim it.
/// An Ootle address carries its account public key, which is that key.
pub fn claim_public_key_from_address(address: String) -> anyhow::Result<String> {
    let address = OotleAddress::from_str(&address)?;
    address.validate()?;
    Ok(address.account_public_key().to_hex())
}

/// The current epoch, to use as a new wallet's birthday so its first scan skips older history.
pub async fn get_current_epoch(indexer_url: String) -> anyhow::Result<u64> {
    let provider = ProviderBuilder::new().connect(&indexer_url).await?;
    Ok(provider.get_epoch().await?.as_u64())
}

pub struct OpenWalletRequest {
    /// Cake's wallet name; every other call refers to the wallet by it.
    pub name: String,
    /// Directory the wallet's state file lives in.
    pub data_dir: String,
    pub seed_words: String,
    pub network: TariOotleNetwork,
    pub indexer_url: String,
    /// Epoch to start scanning from on first open. 0 scans the whole chain (restores).
    pub birthday_epoch: u64,
}

pub struct WalletInfo {
    pub address: String,
    /// Hex Ristretto public key an L1 burn targets so this wallet can claim it.
    pub claim_public_key: String,
}

pub fn open_wallet(req: OpenWalletRequest) -> anyhow::Result<WalletInfo> {
    if req.name.trim().is_empty() {
        anyhow::bail!("wallet name cannot be empty");
    }
    if req.data_dir.trim().is_empty() {
        anyhow::bail!("data_dir cannot be empty");
    }
    if req.indexer_url.trim().is_empty() {
        anyhow::bail!("indexer_url cannot be empty");
    }
    let keys = AccountKeys::from_words(&req.seed_words, req.network.into())?;
    let claim_public_key = keys.account_public_key().to_hex();
    let wallet = Wallet::open(
        req.name.trim(),
        req.data_dir.trim(),
        keys,
        req.indexer_url.trim().to_string(),
        req.birthday_epoch,
    )?;
    Ok(WalletInfo {
        address: wallet.address.to_string(),
        claim_public_key,
    })
}

pub fn close_wallet(name: String) {
    crate::api::sync::stop_scan(name.clone());
    Wallet::close(&name);
}

pub fn set_indexer_url(name: String, indexer_url: String) -> anyhow::Result<()> {
    let trimmed = indexer_url.trim();
    if trimmed.is_empty() {
        anyhow::bail!("indexer_url cannot be empty");
    }
    Wallet::get(&name)?.set_indexer_url(trimmed.to_string());
    Ok(())
}
