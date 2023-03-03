
use crate::common::simple_types::*;
use crate::crypto;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct VoteCredentialRequest {
    pub(crate) reserved: ReservedBytes,
    pub(crate) public_key: crypto::vote_credential_request::PublicKey,
    pub(crate) ciphertext: crypto::vote_credential_request::Ciphertext,
    pub(crate) proof: crypto::proofs::VoteCredentialRequestProof,
}
