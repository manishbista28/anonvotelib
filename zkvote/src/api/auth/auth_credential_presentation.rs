use crate::crypto;
use serde::{Deserialize, Serialize};


#[derive(Serialize, Deserialize)]
pub struct AuthCredentialPresentation {
    pub(crate) proof: crypto::proofs::AuthCredentialPresentationProof,
    pub(crate) uid_enc_ciphertext: crypto::uid_encryption::Ciphertext,
    pub(crate) expiration_time: u64,
}
