//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::common::constants::*;
use curve25519_dalek::scalar::Scalar;
use crate::common::sho::Sho;

pub type AesKeyBytes = [u8; AES_KEY_LEN];
pub type GroupMasterKeyBytes = [u8; GROUP_MASTER_KEY_LEN];
pub type UidBytes = [u8; UUID_LEN];
pub type RandomnessBytes = [u8; RANDOMNESS_LEN];
pub type ReservedBytes = [u8; RESERVED_LEN];
pub type SignatureBytes = [u8; SIGNATURE_LEN];
pub type NotarySignatureBytes = [u8; SIGNATURE_LEN];
pub type GroupIdentifierBytes = [u8; GROUP_IDENTIFIER_LEN];

pub type VoteTopicIDBytes = [u8; VOTE_TOPIC_ID_LEN];
pub type VoteStakeWeightBytes = [u8; VOTE_STAKE_WEIGHT_LEN];
pub type VoteTypeBytes = [u8; VOTE_TYPE_LEN];
pub type VoteUniqIDBytes = [u8; VOTE_UNIQ_ID_LEN];




// pub fn encode_redemption_time(redemption_time: u32) -> Scalar {
//     let mut scalar_bytes: [u8; 32] = Default::default();
//     scalar_bytes[0..4].copy_from_slice(&redemption_time.to_be_bytes());
//     Scalar::from_bytes_mod_order(scalar_bytes)
// }

pub fn encode_timestamp(timestamp: u64) -> Scalar {
    let mut sho = Sho::new(
        b"LibVote_zkvote_20230306_Timestamp_Calc_m",
        &timestamp.to_be_bytes(),
    );
    sho.get_scalar()
}

pub fn encode_vote_bytes(vote_bytes: VoteTypeBytes) -> Scalar {
    assert_eq!(vote_bytes.len(), 1); // should be less than eq 32
    let mut scalar_bytes: [u8; 32] = Default::default();
    scalar_bytes[0..1].copy_from_slice(&vote_bytes[..]);
    Scalar::from_bytes_mod_order(scalar_bytes)
}

pub fn encode_vote_id(vote_id: VoteUniqIDBytes) -> Scalar {
    assert_eq!(vote_id.len(), 32); // should be less than eq 32
    let mut scalar_bytes: [u8; 32] = Default::default();
    scalar_bytes[0..VOTE_UNIQ_ID_LEN].copy_from_slice(&vote_id[..]);
    Scalar::from_bytes_mod_order(scalar_bytes)
}

pub fn encode_vote_stake_weight(stake_weight: VoteStakeWeightBytes) -> Scalar {
    assert_eq!(stake_weight.len(), 32); // should be less than eq 32
    let mut scalar_bytes: [u8; 32] = Default::default();
    scalar_bytes[0..VOTE_STAKE_WEIGHT_LEN].copy_from_slice(&stake_weight[..]);
    Scalar::from_bytes_mod_order(scalar_bytes)
}

pub fn encode_vote_topic_id(topic_id: VoteTopicIDBytes) -> Scalar {
    assert_eq!(topic_id.len(), 16); // should be less than eq 32
    let mut scalar_bytes: [u8; 32] = Default::default();
    scalar_bytes[0..VOTE_TOPIC_ID_LEN].copy_from_slice(&topic_id[..]);
    Scalar::from_bytes_mod_order(scalar_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_scalar() {
        let s_bytes = [0xFF; 32];
        match bincode::deserialize::<Scalar>(&s_bytes) {
            Err(_) => (),
            Ok(_) => unreachable!(),
        }
    }
}
