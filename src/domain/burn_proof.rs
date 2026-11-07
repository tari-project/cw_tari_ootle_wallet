// Copyright 2026 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! The L1 wallet's burn proof file, converted into the claim the L2 takes.
//!
//! `claim_proof_from_l1` is tari-ootle v0.47.0's `tari_ootle_app_utilities::burn_claim_proof`
//! (BSD-3-Clause, The Tari Project), which is unpublished and pulls in node-side crates; keep it in
//! step with upstream when bumping Ootle.

use ootle_byte_type::ToByteType;
use ootle_rs::template_types::EncryptedData;
use tari_common_types::burn_proof::{BurnOutputProof, MmrInclusionProof};
use tari_engine_types::confidential::{
    BurnOutput, BurnOutputFeatures, BurnOutputInclusionProof, BurnSidechainId,
    MinotariBurnClaimProof, MmrInclusionProof as ClaimMmrInclusionProof,
};
use tari_sidechain::{BurnClaimProof, CompleteClaimBurnProof};
use tari_template_lib::types::Hash32;
use tari_transaction_components::transaction_components::{
    OutputFeatures, OutputType, SideChainFeatureData,
};

pub(crate) struct BurnProof {
    pub claim_proof: MinotariBurnClaimProof,
    pub encrypted_data: EncryptedData,
    /// The L1 epoch the burn was mined in. The L2 rejects a claim until it is past it.
    pub mined_in_epoch: u64,
}

impl BurnProof {
    /// Parses the JSON `cw_tari_wallet::get_burn_proofs` (and minotari's proof worker) writes.
    pub fn from_json(json: &str) -> anyhow::Result<Self> {
        let file: CompleteClaimBurnProof = serde_json::from_str(json)?;
        let len = file.encrypted_data.len();
        Ok(Self {
            claim_proof: claim_proof_from_l1(&file.claim_proof)
                .map_err(|e| anyhow::anyhow!("Invalid burn proof: {e}"))?,
            encrypted_data: EncryptedData::try_from(file.encrypted_data).map_err(|_| {
                anyhow::anyhow!("The burn proof's encrypted data is {len} bytes, out of range")
            })?,
            mined_in_epoch: file.mined_in_epoch,
        })
    }
}

fn claim_proof_from_l1(proof: &BurnClaimProof) -> Result<MinotariBurnClaimProof, String> {
    if proof.value == 0 {
        return Err("burn proof value must be greater than zero".to_string());
    }
    let BurnOutputProof {
        block_hash,
        output,
        normal_output_proof,
        normal_output_mr,
        block_output_proof,
        ..
    } = &proof.output_proof;
    let features: OutputFeatures = borsh::from_slice(&output.features)
        .map_err(|e| format!("invalid burn output features: {e}"))?;
    if features.output_type != OutputType::Burn {
        return Err(format!(
            "the output is a {} output, not a burn",
            features.output_type
        ));
    }
    let sidechain_feature = features
        .sidechain_feature
        .as_ref()
        .ok_or("the burn output has no sidechain feature, so it names no claimant")?;
    let SideChainFeatureData::ConfidentialOutput(confidential_output) = &sidechain_feature.data
    else {
        return Err("the burn output's sidechain feature is not a confidential output".to_string());
    };
    if confidential_output.claim_public_key != proof.burn_public_key {
        return Err(
            "the burn proof's burn_public_key does not match the output's claim_public_key"
                .to_string(),
        );
    }
    Ok(MinotariBurnClaimProof {
        commitment: output.commitment.to_byte_type(),
        ownership_proof: proof.ownership_proof.to_byte_type(),
        value: proof.value,
        output: BurnOutput {
            version: output.version,
            features: BurnOutputFeatures {
                version: features.version.as_u8(),
                maturity: features.maturity,
                claim_public_key: confidential_output.claim_public_key.to_byte_type(),
                sidechain_id: sidechain_feature.sidechain_id().map(|id| BurnSidechainId {
                    public_key: id.public_key().to_byte_type(),
                    knowledge_proof: id.knowledge_proof().to_byte_type(),
                }),
                range_proof_type: features.range_proof_type.as_byte(),
            },
            rangeproof_hash: Hash32::from_array(output.rangeproof_hash.into_array()),
            script: bytes("script", output.script.clone())?,
            sender_offset_public_key: output.sender_offset_public_key.to_byte_type(),
            metadata_signature: bytes(
                "metadata signature",
                borsh::to_vec(&output.metadata_signature).map_err(|e| e.to_string())?,
            )?,
            covenant: bytes("covenant", output.covenant.clone())?,
            encrypted_data: bytes("encrypted data", output.encrypted_data.clone())?,
            minimum_value_promise: output.minimum_value_promise,
        },
        inclusion_proof: BurnOutputInclusionProof {
            block_hash: Hash32::from_array(block_hash.into_array()),
            normal_output_proof: mmr_proof(normal_output_proof),
            normal_output_mr: Hash32::from_array(normal_output_mr.into_array()),
            block_output_proof: mmr_proof(block_output_proof),
        },
    })
}

fn bytes<const N: usize>(
    field: &str,
    bytes: Vec<u8>,
) -> Result<bounded_vec::BoundedVec<u8, 1, N>, String> {
    let len = bytes.len();
    bounded_vec::BoundedVec::<u8, 1, N>::from_vec(bytes)
        .map_err(|_| format!("burn output {field} length {len} is out of range"))
}

fn mmr_proof(proof: &MmrInclusionProof) -> ClaimMmrInclusionProof {
    let hashes = |hashes: &[tari_common_types::types::FixedHash]| {
        hashes
            .iter()
            .map(|hash| Hash32::from_array(hash.into_array()))
            .collect()
    };
    ClaimMmrInclusionProof {
        leaf_index: proof.leaf_index,
        mmr_size: proof.mmr_size,
        path: hashes(&proof.path),
        peaks: hashes(&proof.peaks),
    }
}

#[cfg(test)]
mod tests {
    use tari_common_types::{
        burn_proof::{BurnOutputProof, MmrInclusionProof, OutputHashPreimage},
        types::{CompressedPublicKey, FixedHash},
    };
    use tari_crypto::{
        keys::{PublicKey as _, SecretKey as _},
        ristretto::{RistrettoPublicKey, RistrettoSecretKey},
    };
    use tari_transaction_components::transaction_components::{
        ConfidentialOutputData, SideChainFeature,
    };

    use super::*;

    fn public_key(seed: u8) -> CompressedPublicKey {
        let secret = RistrettoSecretKey::from_uniform_bytes(&[seed; 64]).unwrap();
        CompressedPublicKey::new_from_pk(RistrettoPublicKey::from_secret_key(&secret))
    }

    fn l1_mmr_proof(leaf_index: u64) -> MmrInclusionProof {
        MmrInclusionProof {
            leaf_index,
            mmr_size: 4,
            path: vec![FixedHash::from([1u8; 32]), FixedHash::from([2u8; 32])],
            peaks: vec![FixedHash::from([3u8; 32])],
        }
    }

    /// A Minotari burn proof file, as JSON, for an output with `features` (from upstream's tests).
    fn proof_file(features: &OutputFeatures) -> String {
        let burn_public_key = features
            .sidechain_feature
            .as_ref()
            .and_then(|sf| match &sf.data {
                SideChainFeatureData::ConfidentialOutput(co) => Some(co.claim_public_key.clone()),
                _ => None,
            })
            .unwrap_or_else(|| public_key(1));
        serde_json::to_string(&CompleteClaimBurnProof {
            claim_proof: BurnClaimProof {
                burn_public_key,
                ownership_proof: Default::default(),
                output_proof: BurnOutputProof {
                    block_hash: FixedHash::from([4u8; 32]),
                    block_height: 100,
                    output: OutputHashPreimage {
                        version: 1,
                        features: borsh::to_vec(features).unwrap(),
                        commitment: Default::default(),
                        rangeproof_hash: FixedHash::from([5u8; 32]),
                        script: vec![1, 0x73],
                        sender_offset_public_key: public_key(2),
                        metadata_signature: Default::default(),
                        covenant: vec![0],
                        encrypted_data: vec![0; 84],
                        minimum_value_promise: 0,
                    },
                    normal_output_proof: l1_mmr_proof(2),
                    normal_output_mr: FixedHash::from([6u8; 32]),
                    block_output_proof: l1_mmr_proof(1),
                },
                value: 12_345,
            },
            encrypted_data: vec![9; 80],
            mined_in_epoch: 3,
        })
        .unwrap()
    }

    fn burn_to(claim_public_key: Option<CompressedPublicKey>) -> OutputFeatures {
        OutputFeatures {
            output_type: OutputType::Burn,
            sidechain_feature: claim_public_key.map(|claim_public_key| SideChainFeature {
                data: SideChainFeatureData::ConfidentialOutput(ConfidentialOutputData {
                    claim_public_key,
                }),
                sidechain_id: None,
            }),
            ..Default::default()
        }
    }

    #[test]
    fn converts_a_minotari_proof_file() {
        let proof = BurnProof::from_json(&proof_file(&burn_to(Some(public_key(3))))).unwrap();
        assert_eq!(
            proof.claim_proof.output.features.claim_public_key,
            public_key(3).to_byte_type()
        );
        assert_eq!(proof.claim_proof.value, 12_345);
        assert_eq!(proof.claim_proof.output.script.as_slice(), &[1, 0x73]);
        assert_eq!(
            proof
                .claim_proof
                .inclusion_proof
                .normal_output_proof
                .leaf_index,
            2
        );
        assert_eq!(
            proof.claim_proof.inclusion_proof.block_hash,
            Hash32::from_array([4u8; 32])
        );
        assert_eq!(proof.mined_in_epoch, 3);
        assert_eq!(proof.encrypted_data.as_ref(), &[9; 80]);
    }

    #[test]
    fn refuses_outputs_ootle_cannot_claim() {
        let not_a_burn = OutputFeatures {
            sidechain_feature: burn_to(Some(public_key(3))).sidechain_feature,
            ..Default::default()
        };
        for (features, reason) in [
            (not_a_burn, "not a burn"),
            (burn_to(None), "no sidechain feature"),
        ] {
            let err = BurnProof::from_json(&proof_file(&features))
                .err()
                .unwrap()
                .to_string();
            assert!(err.contains(reason), "expected '{reason}', got '{err}'");
        }
        // cw_tari_wallet's fixture is a well-formed file around a placeholder (non-burn) output.
        let err = BurnProof::from_json(include_str!("testdata/l1_burn_proof.json"))
            .err()
            .unwrap()
            .to_string();
        assert!(err.starts_with("Invalid burn proof"), "{err}");
    }
}
