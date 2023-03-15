#![allow(non_snake_case)]

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use serde::{Deserialize, Serialize};
use crate::common::simple_types::*;

use super::credentials;

#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeCommitmentsWithNonce {
    CX0: RistrettoPoint,
    CX1: RistrettoPoint,
    CY1: RistrettoPoint,
    CY2: RistrettoPoint,
    CY3: RistrettoPoint,
    CY4: RistrettoPoint,
    z: Scalar,
    C_V: RistrettoPoint,
}

#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeCommitments {
    pub(crate) CX0: RistrettoPoint,
    pub(crate) CX1: RistrettoPoint,
    pub(crate) CY1: RistrettoPoint,
    pub(crate) CY2: RistrettoPoint,
    pub(crate) CY3: RistrettoPoint,
    pub(crate) CY4: RistrettoPoint,
}

pub fn from_slice(req: [RistrettoPoint; 6]) -> ChallengeCommitments {
    ChallengeCommitments { CX0: req[0], CX1: req[1], CY1: req[2], CY2: req[3], CY3: req[4], CY4: req[5] } 
}
    
impl ChallengeCommitments {
    pub fn to_slice(&self) -> [RistrettoPoint; 6] {
        let ret = [
            self.CX0,
            self.CX1,
            self.CY1,
            self.CY2,
            self.CY3,
            self.CY4,
        ];
        ret
    }

    pub fn create_user_commitment_with_nonce(
        vote_credential: credentials::VoteCredential,
        vote_type: VoteTypeBytes,
        vote_id: VoteUniqIDBytes,
        stake_weight: VoteStakeWeightBytes,
        topic_id: VoteTopicIDBytes,
        z: Scalar,
    ) -> ChallengeCommitmentsWithNonce {
        let credentials_system = credentials::SystemParams::get_hardcoded();

        let M1 = credentials::convert_to_point_vote_stake_weight(stake_weight);
        let M2 = credentials::convert_to_point_vote_topic_id(topic_id);
        let M3 = credentials::convert_to_point_vote_type(vote_type);
        let M4 = credentials::convert_to_point_vote_id(vote_id);


        let CX0 = z * credentials_system.G_x0 + vote_credential.U;
        let CX1 = z * credentials_system.G_x1 + vote_credential.t * vote_credential.U;
        let CY1 = z * credentials_system.G_y[1] + M1;
        let CY2 = z * credentials_system.G_y[2] + M2;
        let CY3 = z * credentials_system.G_y[3] + M3;
        let CY4 = z * credentials_system.G_y[4] + M4;
        let C_V = z * credentials_system.G_V + vote_credential.V;

        ChallengeCommitmentsWithNonce { CX0, CX1, CY1, CY2, CY3, CY4,z, C_V }

    }
}

impl ChallengeCommitmentsWithNonce {
    pub fn get_commitment(&self) -> ChallengeCommitments {
        ChallengeCommitments { 
            CX0: self.CX0.clone(),
            CX1: self.CX1.clone(), 
            CY1: self.CY1.clone(), 
            CY2: self.CY2.clone(), 
            CY3: self.CY3.clone(), 
            CY4: self.CY4.clone(), 
        }
    }

    pub fn get_nonce(&self) -> Scalar {
        self.z.clone()
    }

    pub fn get_cv(&self) -> RistrettoPoint {
        self.C_V.clone()
    }
}