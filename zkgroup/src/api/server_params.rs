//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use serde::{Deserialize, Serialize};

use crate::common::constants::*;
use crate::common::errors::*;
use crate::common::sho::*;
use crate::common::simple_types::*;
use crate::{api, crypto};

#[derive(Copy, Clone, Serialize, Deserialize)]
pub struct ServerSecretParams {
    pub(crate) reserved: ReservedBytes,
    pub(crate) auth_credentials_key_pair:
        crypto::credentials::KeyPair<crypto::credentials::AuthCredential>,
    sig_key_pair: crypto::signature::KeyPair,
}

#[derive(Copy, Clone, Serialize, Deserialize)]
pub struct ServerPublicParams {
    pub(crate) reserved: ReservedBytes,
    pub(crate) auth_credentials_public_key: crypto::credentials::PublicKey,
    sig_public_key: crypto::signature::PublicKey,
}

impl ServerSecretParams {
    pub fn generate(randomness: RandomnessBytes) -> Self {
        let mut sho = Sho::new(
            b"Signal_ZKGroup_20200424_Random_ServerSecretParams_Generate",
            &randomness,
        );

        let auth_credentials_key_pair = crypto::credentials::KeyPair::generate(&mut sho);
        let sig_key_pair = crypto::signature::KeyPair::generate(&mut sho);

        Self {
            reserved: Default::default(),
            auth_credentials_key_pair,
            sig_key_pair,
        }
    }

    pub fn get_public_params(&self) -> ServerPublicParams {
        ServerPublicParams {
            reserved: Default::default(),
            auth_credentials_public_key: self.auth_credentials_key_pair.get_public_key(),
            sig_public_key: self.sig_key_pair.get_public_key(),
        }
    }

    pub fn sign(&self, randomness: RandomnessBytes, message: &[u8]) -> NotarySignatureBytes {
        let mut sho = Sho::new(
            b"Signal_ZKGroup_20200424_Random_ServerSecretParams_Sign",
            &randomness,
        );
        self.sig_key_pair.sign(message, &mut sho)
    }

    pub fn issue_auth_credential(
        &self,
        randomness: RandomnessBytes,
        uid_bytes: UidBytes,
        redemption_time: CoarseRedemptionTime,
    ) -> api::auth::AuthCredentialResponse {
        let mut sho = Sho::new(
            b"Signal_ZKGroup_20200424_Random_ServerSecretParams_IssueAuthCredential",
            &randomness,
        );

        let uid = crypto::uid_struct::UidStruct::new(uid_bytes);
        let credential =
            self.auth_credentials_key_pair
                .create_auth_credential(uid, redemption_time, &mut sho);
        let proof = crypto::proofs::AuthCredentialIssuanceProof::new(
            self.auth_credentials_key_pair,
            credential,
            uid,
            redemption_time,
            &mut sho,
        );
        api::auth::AuthCredentialResponse {
            reserved: Default::default(),
            credential,
            proof,
        }
    }

    /// Checks that `current_time_in_seconds` is within the validity window defined by
    /// `redemption_time_in_seconds`.
    ///
    /// All times are relative to SystemTime::UNIX_EPOCH,
    /// but we don't actually use SystemTime because it's too small on 32-bit Linux.
    fn check_auth_credential_redemption_time(
        redemption_time_in_seconds: Timestamp,
        current_time_in_seconds: Timestamp,
    ) -> Result<(), ZkGroupVerificationFailure> {
        let acceptable_start_time = redemption_time_in_seconds - SECONDS_PER_DAY;
        let acceptable_end_time = redemption_time_in_seconds + 2 * SECONDS_PER_DAY;

        if !(acceptable_start_time..=acceptable_end_time).contains(&current_time_in_seconds) {
            return Err(ZkGroupVerificationFailure);
        }

        Ok(())
    }

    pub fn verify_auth_credential_presentation(
        &self,
        group_public_params: api::groups::GroupPublicParams,
        presentation: &api::auth::AnyAuthCredentialPresentation,
        current_time_in_seconds: Timestamp,
    ) -> Result<(), ZkGroupVerificationFailure> {
        Self::check_auth_credential_redemption_time(
            presentation.get_redemption_time(),
            current_time_in_seconds,
        )?;

        match presentation {
            api::auth::AnyAuthCredentialPresentation::V2(presentation) => {
                presentation.proof.verify(
                    self.auth_credentials_key_pair,
                    group_public_params.uid_enc_public_key,
                    presentation.ciphertext,
                    presentation.redemption_time,
                )
            }
        }
    }

    pub fn verify_auth_credential_presentation_v2(
        &self,
        group_public_params: api::groups::GroupPublicParams,
        presentation: &api::auth::AuthCredentialPresentationV2,
        current_time_in_days: CoarseRedemptionTime,
    ) -> Result<(), ZkGroupVerificationFailure> {
        Self::check_auth_credential_redemption_time(
            u64::from(presentation.get_redemption_time()) * SECONDS_PER_DAY,
            u64::from(current_time_in_days) * SECONDS_PER_DAY,
        )?;
        presentation.proof.verify(
            self.auth_credentials_key_pair,
            group_public_params.uid_enc_public_key,
            presentation.ciphertext,
            presentation.redemption_time,
        )
    }
}

impl ServerPublicParams {
    pub fn verify_signature(
        &self,
        message: &[u8],
        signature: NotarySignatureBytes,
    ) -> Result<(), ZkGroupVerificationFailure> {
        self.sig_public_key.verify(message, signature)
    }

    pub fn receive_auth_credential(
        &self,
        uid_bytes: UidBytes,
        redemption_time: CoarseRedemptionTime,
        response: &api::auth::AuthCredentialResponse,
    ) -> Result<api::auth::AuthCredential, ZkGroupVerificationFailure> {
        let uid = crypto::uid_struct::UidStruct::new(uid_bytes);
        response.proof.verify(
            self.auth_credentials_public_key,
            response.credential,
            uid,
            redemption_time,
        )?;

        Ok(api::auth::AuthCredential {
            reserved: Default::default(),
            credential: response.credential,
            uid,
            redemption_time,
        })
    }
    pub fn create_auth_credential_presentation(
        &self,
        randomness: RandomnessBytes,
        group_secret_params: api::groups::GroupSecretParams,
        auth_credential: api::auth::AuthCredential,
    ) -> api::auth::AnyAuthCredentialPresentation {
        let presentation_v2 = self.create_auth_credential_presentation_v2(
            randomness,
            group_secret_params,
            auth_credential,
        );
        api::auth::AnyAuthCredentialPresentation::V2(presentation_v2)
    }

    pub fn create_auth_credential_presentation_v2(
        &self,
        randomness: RandomnessBytes,
        group_secret_params: api::groups::GroupSecretParams,
        auth_credential: api::auth::AuthCredential,
    ) -> api::auth::AuthCredentialPresentationV2 {
        let mut sho = Sho::new(
            b"Signal_ZKGroup_20220120_Random_ServerPublicParams_CreateAuthCredentialPresentationV2",
            &randomness,
        );

        let uuid_ciphertext = group_secret_params.encrypt_uid_struct(auth_credential.uid);

        let proof = crypto::proofs::AuthCredentialPresentationProofV2::new(
            self.auth_credentials_public_key,
            group_secret_params.uid_enc_key_pair,
            auth_credential.credential,
            auth_credential.uid,
            uuid_ciphertext.ciphertext,
            auth_credential.redemption_time,
            &mut sho,
        );

        api::auth::AuthCredentialPresentationV2 {
            version: [PRESENTATION_VERSION_2],
            proof,
            ciphertext: uuid_ciphertext.ciphertext,
            redemption_time: auth_credential.redemption_time,
        }
    }
}
