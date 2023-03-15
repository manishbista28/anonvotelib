
use crate::crypto::vote_credential_challenge::ChallengeCommitments;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct VoteCredentialChallengeRequest {
    pub(crate) commitments: ChallengeCommitments,
}

