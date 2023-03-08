//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::common::simple_types::*;
use crate::crypto;
use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, Serialize, Deserialize)]
pub struct AuthCredentialCommitment {
    pub(crate) reserved: ReservedBytes,
    pub(crate) commitment: crypto::auth_credential_commitment::Commitment,
}

impl AuthCredentialCommitment {
    pub fn new(commitment: crypto::auth_credential_commitment::Commitment)-> Self {
        AuthCredentialCommitment { 
            reserved: Default::default(), 
            commitment: commitment, 
        }
    }
}