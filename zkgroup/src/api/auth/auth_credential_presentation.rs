use crate::{crypto, CoarseRedemptionTime};
use serde::{Deserialize, Serialize};


#[derive(Serialize, Deserialize)]
pub struct AuthCredentialPresentation {
    pub(crate) proof: crypto::proofs::AuthCredentialPresentationProof,
    pub(crate) uid_enc_ciphertext: crypto::uid_encryption::Ciphertext,
    pub(crate) redemption_time: CoarseRedemptionTime,
}

// TODO
// expose uid_commitment just like redemption_time
// check how uid_commitment is being computed, is j3 secure
//