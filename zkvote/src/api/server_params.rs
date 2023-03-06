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
    pub(crate) vote_credentials_key_pair:
        crypto::credentials::KeyPair<crypto::credentials::VoteCredential>,
    sig_key_pair: crypto::signature::KeyPair,
}

#[derive(Copy, Clone, Serialize, Deserialize)]
pub struct ServerPublicParams {
    pub(crate) reserved: ReservedBytes,
    pub(crate) auth_credentials_public_key: crypto::credentials::PublicKey,
    pub(crate) vote_credentials_public_key: crypto::credentials::PublicKey,
    sig_public_key: crypto::signature::PublicKey,
}

impl ServerSecretParams {
    pub fn generate(randomness: RandomnessBytes) -> Self {
        let mut sho = Sho::new(
            b"Signal_ZKGroup_20200424_Random_ServerSecretParams_Generate",
            &randomness,
        );

        let auth_credentials_key_pair = crypto::credentials::KeyPair::<crypto::credentials::AuthCredential>::generate(&mut sho);
        let vote_credentials_key_pair = crypto::credentials::KeyPair::<crypto::credentials::VoteCredential>::generate(&mut sho);
        let sig_key_pair = crypto::signature::KeyPair::generate(&mut sho);

        Self {
            reserved: Default::default(),
            auth_credentials_key_pair,
            vote_credentials_key_pair,
            sig_key_pair,
        }
    }

    pub fn get_public_params(&self) -> ServerPublicParams {
        ServerPublicParams {
            reserved: Default::default(),
            auth_credentials_public_key: self.auth_credentials_key_pair.get_public_key(),
            vote_credentials_public_key: self.vote_credentials_key_pair.get_public_key(),
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
    
    pub fn verify_auth_credential_presentation(
        &self,
        group_public_params: api::groups::GroupPublicParams,
        presentation: &api::auth::AuthCredentialPresentation,
        current_time_in_seconds: u64,
    ) -> Result<(), ZkGroupVerificationFailure> {

        if current_time_in_seconds > presentation.expiration_time {
            return Err(ZkGroupVerificationFailure);
        }

        presentation.proof.verify(
            self.auth_credentials_key_pair,
            group_public_params.uid_enc_public_key,
            presentation.uid_enc_ciphertext,
            presentation.expiration_time,
        )
    }

    pub fn verify_vote_credential_presentation(
        &self,
        presentation: &api::votes::VoteCredentialPresentation,
    ) -> Result<(), ZkGroupVerificationFailure> {

        // TODO: ensure presentation params are consistent with server params and current operation
        presentation.proof.verify(self.vote_credentials_key_pair,
             presentation.vote_type, 
             presentation.vote_id, 
             presentation.stake_weight, 
             presentation.topic_id
        )
    }

    pub fn issue_auth_credential(
        &self,
        randomness: RandomnessBytes,
        request: &api::auth::AuthCredentialRequest,
        commitment: api::auth::AuthCredentialCommitment,
        credential_expiration_time: u64,
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
                credential_expiration_time,
                &mut sho,
            );

        let proof = crypto::proofs::AuthCredentialIssuanceProof::new(
            self.auth_credentials_key_pair,
            request.public_key,
            request.ciphertext,
            blinded_credential_with_secret_nonce,
            credential_expiration_time,
            &mut sho,
        );

        Ok(api::auth::AuthCredentialResponse {
            reserved: Default::default(),
            blinded_credential: blinded_credential_with_secret_nonce
                .get_blinded_auth_credential(),
            proof,
            expiration_time: credential_expiration_time,
        })
    }

    pub fn issue_vote_credential(
        &self,
        randomness: RandomnessBytes,
        request: &api::votes::VoteCredentialRequest,
        vote_topic: VoteTopicIDBytes,
        group_public_params: api::groups::GroupPublicParams,
    ) -> Result<api::votes::VoteCredentialResponse, ZkGroupVerificationFailure> {
        let mut sho = Sho::new(
            b"Signal_ZKGroup_20200424_Random_ServerSecretParams_IssueAuthCredential",
            &randomness,
        );

        assert_eq!(vote_topic, request.topic_id);
        // TODO: verify request.vote_stake_weight is permissible

        self.verify_auth_credential_presentation(
            group_public_params, 
            &request.auth_presentation, 
            10 * SECONDS_PER_DAY).unwrap(); // TOOD: 0 and unwrap_err 
        

        let blinded_credential_with_secret_nonce = self
            .vote_credentials_key_pair
            .create_blinded_vote_credential(
                request.public_key, 
                request.ciphertext, 
                &mut sho, 
                request.stake_weight, 
                request.topic_id, 
            );

        let proof = crypto::proofs::VoteCredentialIssuanceProof::new(
            self.vote_credentials_key_pair,
            request.public_key,
            request.ciphertext,
            blinded_credential_with_secret_nonce,
            request.stake_weight,
            request.topic_id,
            & mut sho
        );
        Ok(api::votes::VoteCredentialResponse {
            reserved: Default::default(),
            blinded_credential: blinded_credential_with_secret_nonce
                .get_blinded_vote_credential(),
            proof,
        })
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
        client_request: &api::auth::AuthCredentialRequestContext,
        response: &api::auth::AuthCredentialResponse,
        expiration_time: u64,
    ) -> Result<api::auth::AuthCredential, ZkGroupVerificationFailure> {
        response.proof.verify(
            self.auth_credentials_public_key,
            client_request.key_pair.get_public_key(),
            client_request.ciphertext_with_secret_nonce.get_ciphertext(),
            response.blinded_credential,
            response.expiration_time,
        )?;

        let credential = client_request
            .key_pair
            .decrypt_blinded_auth_credential(response.blinded_credential);

        Ok(api::auth::AuthCredential {
            reserved: Default::default(),
            credential,
            uid_bytes: client_request.uid_bytes,
            expiration_time,
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
            expiration_time: auth_credential.expiration_time,
        }
    }

    pub fn create_vote_credential_request_context(
        &self,
        randomness: RandomnessBytes,
        vote_type: VoteTypeBytes,
        topic_id: VoteTopicIDBytes, 
        stake_weight: VoteStakeWeightBytes,
        auth_presentation: api::auth::AuthCredentialPresentation,
    ) -> api::votes::VoteCredentialRequestContext {
        let mut sho = Sho::new(
            b"Signal_ZKGroup_20200424_Random_ServerPublicParams_CreateAuthCredentialRequestContext",
            &randomness,
        );
        let mut vote_id = [0u8; VOTE_UNIQ_ID_LEN];
        vote_id.copy_from_slice(&sho.squeeze(VOTE_UNIQ_ID_LEN));
        let key_pair = crypto::vote_credential_request::KeyPair::generate(&mut sho);
        let ciphertext_with_secret_nonce = key_pair.encrypt_vote_type_id(vote_type, vote_id, &mut sho);

        api::votes::VoteCredentialRequestContext {
            reserved: Default::default(),
            vote_type,
            vote_id,
            stake_weight,
            topic_id,
            key_pair,
            ciphertext_with_secret_nonce,
            auth_presentation: auth_presentation,
        }
    }

    pub fn receive_vote_credential(
        &self,
        request: &api::votes::VoteCredentialRequestContext,
        response: &api::votes::VoteCredentialResponse,
    ) -> Result<api::votes::VoteCredential, ZkGroupVerificationFailure> {
        response.proof.verify(
            self.auth_credentials_public_key,
            request.key_pair.get_public_key(),
            request.ciphertext_with_secret_nonce.get_ciphertext(),
            response.blinded_credential,
            request.stake_weight,
            request.topic_id,
        )?;

        let credential = request
            .key_pair
            .decrypt_blinded_vote_credential(response.blinded_credential);
        let vote_type = request.vote_type.clone();
        let vote_id = request.vote_id.clone();
        let stake_weight = request.stake_weight.clone();
        let topic_id = request.topic_id.clone();

        Ok(api::votes::VoteCredential{
            reserved: Default::default(),
            credential,
            vote_type,
            vote_id,
            stake_weight,
            topic_id,
        })
    }


    pub fn create_vote_credential_presentation(
        &self,
        randomness: RandomnessBytes,
        response: api::votes::VoteCredential,
    ) -> api::votes::VoteCredentialPresentation {
        let mut sho = Sho::new(
            b"Signal_ZKGroup_20220120_Random_ServerPublicParams_CreateAuthCredentialPresentationV2",
            &randomness,
        );
        
        let proof = crypto::proofs::VoteCredentialPresentationProof::new(
            self.vote_credentials_public_key,
            response.credential,
            &mut sho,
        );
        let vtype = response.vote_type.clone();
        let vid = response.vote_id.clone();
        let vwt = response.stake_weight.clone();
        let vtid = response.topic_id.clone();
        api::votes::VoteCredentialPresentation {
            proof,
            vote_type: vtype,
            vote_id: vid,
            stake_weight: vwt,
            topic_id: vtid,
        }
    }

}
