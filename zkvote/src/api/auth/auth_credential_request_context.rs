//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::common::simple_types::*;
use crate::{api, crypto};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct AuthCredentialRequestContext {
    pub(crate) reserved: ReservedBytes,
    pub(crate) uid_bytes: UidBytes,
    pub(crate) key_pair: crypto::auth_credential_request::KeyPair,
    pub(crate) ciphertext_with_secret_nonce:
        crypto::auth_credential_request::CiphertextWithSecretNonce,
    pub(crate) proof: crypto::proofs::AuthCredentialRequestProof,
}

impl AuthCredentialRequestContext {
    pub fn get_request(&self) -> api::auth::AuthCredentialRequest {
        let ciphertext = self.ciphertext_with_secret_nonce.get_ciphertext();
        let public_key = self.key_pair.get_public_key();
        api::auth::AuthCredentialRequest {
            reserved: Default::default(),
            public_key,
            ciphertext,
            proof: self.proof.clone(),
        }
    }
}
