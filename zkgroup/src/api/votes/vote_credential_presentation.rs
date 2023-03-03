// use crate::common::constants::*;
// use crate::common::errors::*;
use crate::common::simple_types::*;
use crate::{ crypto};
use serde::{Deserialize, Serialize};
//TODO
#[derive(Serialize, Deserialize)]
pub struct VoteCredentialPresentation {
    pub(crate) version: ReservedBytes,
    //pub(crate) proof: crypto::proofs::VoteCredentialPresentationProof,
    pub(crate) uid_enc_ciphertext: crypto::uid_encryption::Ciphertext,
    pub(crate) vote_enc_ciphertext: crypto::vote_encryption::Ciphertext,
}