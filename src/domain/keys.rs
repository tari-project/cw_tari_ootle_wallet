// Copyright 2026 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

use std::str::FromStr;

use ootle_rs::{crypto::derive_ristretto_key, keys::OotleSecretKey, Network};
use tari_common_types::seeds::{
    cipher_seed::CipherSeed, mnemonic::Mnemonic, seed_words::SeedWords,
};
use tari_crypto::{
    keys::PublicKey,
    ristretto::{RistrettoPublicKey, RistrettoSecretKey},
};
use tari_ootle_address::OotleAddress;

// Same branch labels walletd's KeyManager uses (KeyBranch::Account / ViewOnlyKey), so a seed
// restored here lands on the same account as walletd and Universe.
const ACCOUNT_BRANCH: &[u8] = b"account";
const VIEW_BRANCH: &[u8] = b"view_only_key";

pub(crate) struct AccountKeys {
    pub network: Network,
    pub account_secret: RistrettoSecretKey,
    pub view_secret: RistrettoSecretKey,
}

impl AccountKeys {
    pub fn from_seed(seed: &CipherSeed, network: Network, index: u64) -> Self {
        Self {
            network,
            account_secret: derive_ristretto_key(seed.entropy(), ACCOUNT_BRANCH, index),
            view_secret: derive_ristretto_key(seed.entropy(), VIEW_BRANCH, index),
        }
    }

    pub fn from_words(seed_words: &str, network: Network) -> anyhow::Result<Self> {
        Ok(Self::from_seed(&parse_seed(seed_words)?, network, 0))
    }

    pub fn secret(&self) -> OotleSecretKey {
        OotleSecretKey::new(
            self.network,
            self.account_secret.clone(),
            self.view_secret.clone(),
        )
    }

    pub fn address(&self) -> OotleAddress {
        self.secret().to_address()
    }

    /// The key an L1 burn targets so this account can claim it.
    pub fn account_public_key(&self) -> RistrettoPublicKey {
        RistrettoPublicKey::from_secret_key(&self.account_secret)
    }
}

pub(crate) fn parse_seed(seed_words: &str) -> anyhow::Result<CipherSeed> {
    let normalized = seed_words.split_whitespace().collect::<Vec<_>>().join(" ");
    let words =
        SeedWords::from_str(&normalized).map_err(|e| anyhow::anyhow!("invalid seed words: {e}"))?;
    Ok(CipherSeed::from_mnemonic(&words, None)?)
}

#[cfg(test)]
mod tests {
    use tari_crypto::tari_utilities::hex::Hex;

    use super::*;
    use crate::api::wallet::claim_public_key_from_address;

    #[test]
    fn address_carries_the_burn_claim_key() {
        let keys = AccountKeys::from_seed(&CipherSeed::random(), Network::Esmeralda, 0);
        let from_address = claim_public_key_from_address(keys.address().to_string()).unwrap();
        assert_eq!(from_address, keys.account_public_key().to_hex());
    }

    #[test]
    fn restore_reproduces_the_address() {
        let created =
            crate::api::wallet::create_wallet(crate::api::wallet::TariOotleNetwork::Esmeralda)
                .unwrap();
        assert_eq!(created.seed_words.split(' ').count(), 24);
        assert!(
            created.address.starts_with("otl_esm_"),
            "{}",
            created.address
        );
        let restored = AccountKeys::from_words(&created.seed_words, Network::Esmeralda)
            .unwrap()
            .address();
        assert_eq!(restored.to_string(), created.address);
    }
}
