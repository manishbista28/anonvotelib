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
    pub(crate) stake_weight: VoteStakeWeightBytes,
    pub(crate) topic_id: VoteTopicIDBytes,
    pub(crate) key_pair: crypto::vote_credential_request::KeyPair,
    pub(crate) ciphertext_with_secret_nonce:
        crypto::vote_credential_request::CiphertextWithSecretNonce, 
    pub(crate) auth_presentation: api::auth::AuthCredentialPresentation,
}

impl VoteCredentialRequestContext {

    pub fn get_request(&self) -> api::votes::VoteCredentialRequest {
    
        let ciphertext = self.ciphertext_with_secret_nonce.get_ciphertext();
        let public_key = self.key_pair.get_public_key();
        let presentation_clone  = api::auth::AuthCredentialPresentation {
            proof: self.auth_presentation.proof.clone(),
            uid_enc_ciphertext: self.auth_presentation.uid_enc_ciphertext.clone(),
            redemption_time: self.auth_presentation.redemption_time.clone()
        }; // TODO: why clone ?
        api::votes::VoteCredentialRequest {
            reserved: Default::default(),
            public_key,
            ciphertext: ciphertext,
            auth_presentation: presentation_clone,
            stake_weight: self.stake_weight.clone(),
            topic_id: self.topic_id.clone(),
        }
    }
}
