//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use serde::{Deserialize, Serialize};

// use crate::common::constants::*;
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
        request: &api::auth::AuthCredentialRequest,
        commitment: api::auth::AuthCredentialCommitment,
    ) -> Result<api::auth::AuthCredentialResponse, ZkGroupVerificationFailure> {
        let mut sho = Sho::new(
            b"Signal_ZKGroup_20200424_Random_ServerSecretParams_IssueAuthCredential",
            &randomness,
        );

        request.proof.verify(
            request.public_key,
            request.ciphertext,
            commitment.commitment,
        )?;

        let blinded_credential_with_secret_nonce = self
            .auth_credentials_key_pair
            .create_blinded_auth_credential(
                request.public_key,
                request.ciphertext,
                &mut sho,
            );

        let proof = crypto::proofs::AuthCredentialIssuanceProof::new(
            self.auth_credentials_key_pair,
            request.public_key,
            request.ciphertext,
            blinded_credential_with_secret_nonce,
            &mut sho,
        );

        Ok(api::auth::AuthCredentialResponse {
            reserved: Default::default(),
            blinded_credential: blinded_credential_with_secret_nonce
                .get_blinded_auth_credential(),
            proof,
        })
    }

    pub fn verify_auth_credential_presentation(
        &self,
        group_public_params: api::groups::GroupPublicParams,
        presentation: &api::auth::AuthCredentialPresentation,
    ) -> Result<(), ZkGroupVerificationFailure> {
        presentation.proof.verify(
            self.auth_credentials_key_pair,
            group_public_params.uid_enc_public_key,
            presentation.uid_enc_ciphertext,
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

    pub fn create_auth_credential_request_context(
        &self,
        randomness: RandomnessBytes,
        uid_bytes: UidBytes,
    ) -> api::auth::AuthCredentialRequestContext {
        let mut sho = Sho::new(
            b"Signal_ZKGroup_20200424_Random_ServerPublicParams_CreateAuthCredentialRequestContext",
            &randomness,
        );
        let uid_struct =
            crypto::uid_struct::UidStruct::new(uid_bytes);

        let commitment_with_secret_nonce =
            crypto::auth_credential_commitment::CommitmentWithSecretNonce::new(
                uid_struct,
            );

        let key_pair = crypto::auth_credential_request::KeyPair::generate(&mut sho);
        let ciphertext_with_secret_nonce = key_pair.encrypt(uid_struct, &mut sho);

        let proof = crypto::proofs::AuthCredentialRequestProof::new(
            key_pair,
            ciphertext_with_secret_nonce,
            commitment_with_secret_nonce,
            &mut sho,
        );

        api::auth::AuthCredentialRequestContext {
            reserved: Default::default(),
            uid_bytes,
            key_pair,
            ciphertext_with_secret_nonce,
            proof,
        }
    }

    pub fn receive_auth_credential(
        &self,
        context: &api::auth::AuthCredentialRequestContext,
        response: &api::auth::AuthCredentialResponse,
    ) -> Result<api::auth::AuthCredential, ZkGroupVerificationFailure> {
        response.proof.verify(
            self.auth_credentials_public_key,
            context.key_pair.get_public_key(),
            context.ciphertext_with_secret_nonce.get_ciphertext(),
            response.blinded_credential,
        )?;

        let credential = context
            .key_pair
            .decrypt_blinded_auth_credential(response.blinded_credential);

        Ok(api::auth::AuthCredential {
            reserved: Default::default(),
            credential,
            uid_bytes: context.uid_bytes,
        })
    }

    pub fn create_auth_credential_presentation(
        &self,
        randomness: RandomnessBytes,
        group_secret_params: api::groups::GroupSecretParams,
        auth_credential: api::auth::AuthCredential,
    ) -> api::auth::AuthCredentialPresentation {
        let mut sho = Sho::new(
            b"Signal_ZKGroup_20220120_Random_ServerPublicParams_CreateAuthCredentialPresentationV2",
            &randomness,
        );
        let uid = crypto::uid_struct::UidStruct::new(auth_credential.uid_bytes);
        let uuid_ciphertext = group_secret_params.encrypt_uid_struct(uid);
        
        let proof = crypto::proofs::AuthCredentialPresentationProof::new(
            self.auth_credentials_public_key,
            group_secret_params.uid_enc_key_pair,
            auth_credential.credential,
            uid,
            uuid_ciphertext.ciphertext,
            &mut sho,
        );

        api::auth::AuthCredentialPresentation {
            proof,
            uid_enc_ciphertext: uuid_ciphertext.ciphertext,
        }
    }

}
