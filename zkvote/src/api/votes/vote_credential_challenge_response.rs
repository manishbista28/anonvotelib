
use crate::crypto::{
    vote_credential_challenge::ChallengeCommitments,
    proofs::VoteCredentialChallengeProof,
};
use curve25519_dalek::ristretto::RistrettoPoint;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct VoteCredentialChallengeResponse {
    pub(crate) private_commitments: ChallengeCommitments,
    pub(crate) public_commitments: ChallengeCommitments,
    pub(crate) public_W: RistrettoPoint,
    pub(crate) proof: VoteCredentialChallengeProof,
}
