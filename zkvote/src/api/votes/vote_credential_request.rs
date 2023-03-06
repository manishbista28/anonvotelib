
use crate::common::simple_types::*;
use crate::{crypto, api};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct VoteCredentialRequest {
    pub(crate) reserved: ReservedBytes,
    pub(crate) public_key: crypto::vote_credential_request::PublicKey,
    pub(crate) stake_weight: VoteStakeWeightBytes,
    pub(crate) topic_id: VoteTopicIDBytes,
    pub(crate) ciphertext: crypto::vote_credential_request::Ciphertext,
    pub(crate) auth_presentation: api::auth::AuthCredentialPresentation,
}
