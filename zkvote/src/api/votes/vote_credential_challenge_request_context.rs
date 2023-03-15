
use crate::crypto::vote_credential_challenge::ChallengeCommitmentsWithNonce;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct VoteCredentialChallengeRequestContext {
    pub(crate) commitments: ChallengeCommitmentsWithNonce,
}

