use crate::common::simple_types::*;
use serde::{Deserialize, Serialize};

use crate::crypto::proofs::VoteCredentialPresentationProof;

#[derive(Serialize, Deserialize)]
pub struct VoteCredentialPresentation {
    pub(crate) proof: VoteCredentialPresentationProof,
    pub(crate) vote_type: VoteTypeBytes,
    pub(crate) vote_id: VoteUniqIDBytes,
    pub(crate) stake_weight: VoteStakeWeightBytes,
    pub(crate) topic_id: VoteTopicIDBytes,
}