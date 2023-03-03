//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::common::simple_types::*;
use crate::{api, crypto};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct VoteCredentialRequestContext {
    pub(crate) reserved: ReservedBytes,
    pub(crate) uid_bytes: UidBytes,
    pub(crate) division_bytes: ProfileKeyBytes,
    pub(crate) type_bytes: ProfileKeyBytes,
    pub(crate) identifier_bytes: ProfileKeyBytes,
    pub(crate) key_pair: crypto::vote_credential_request::KeyPair,
    pub(crate) ciphertext_with_secret_nonce:
        crypto::vote_credential_request::CiphertextWithSecretNonce,
    pub(crate) proof: crypto::proofs::VoteCredentialRequestProof, // TODO
}

impl VoteCredentialRequestContext {
    pub fn get_request(&self) -> api::votes::VoteCredentialRequest {
        let ciphertext = self.ciphertext_with_secret_nonce.get_ciphertext();
        let public_key = self.key_pair.get_public_key();
        api::votes::VoteCredentialRequest {
            reserved: Default::default(),
            public_key,
            ciphertext,
            proof: self.proof.clone(),
        }
    }
}
