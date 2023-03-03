//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![allow(non_snake_case)]

// use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
// use curve25519_dalek::traits::Identity;

use serde::{Deserialize, Serialize};

use crate::common::array_utils::OneBased;
use crate::common::constants::*;
use crate::common::errors::*;
use crate::common::sho::*;
use crate::common::simple_types::*;
// use crate::crypto::timestamp_struct::TimestampStruct;
use crate::crypto::{
    credentials, uid_encryption, uid_struct,
    auth_credential_commitment, auth_credential_request,
};

#[derive(Serialize, Deserialize, Clone)]
pub struct AuthCredentialIssuanceProof {
    poksho_proof: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AuthCredentialRequestProof {
    poksho_proof: Vec<u8>,
}


impl AuthCredentialIssuanceProof {
    pub fn get_poksho_statement() -> poksho::Statement {
        let mut st = poksho::Statement::new();
        st.add("C_W", &[("w", "G_w"), ("wprime", "G_wprime")]);
        st.add(
            "G_V-I",
            &[
                ("x0", "G_x0"),
                ("x1", "G_x1"),
                ("y1", "G_y1"),
                ("y2", "G_y2"),
                ("y3", "G_y3"),
                ("y4", "G_y4"),
            ],
        );
        st.add("S1", &[("y3", "D1"), ("y4", "E1"), ("rprime", "G")]);
        st.add(
            "S2",
            &[
                ("y3", "D2"),
                ("y4", "E2"),
                ("rprime", "Y"),
                ("w", "G_w"),
                ("x0", "U"),
                ("x1", "tU"),
                ("y1", "M1"),
                ("y2", "M2"),
            ],
        );
        st
    }

    pub fn new(
        key_pair: credentials::KeyPair<credentials::AuthCredential>,
        request_public_key: auth_credential_request::PublicKey,
        request: auth_credential_request::Ciphertext,
        blinded_credential: credentials::BlindedAuthCredentialWithSecretNonce,
        uid: uid_struct::UidStruct,
        sho: &mut Sho,
    ) -> Self {
        let credentials_system = credentials::SystemParams::get_hardcoded();

        let mut scalar_args = poksho::ScalarArgs::new();
        scalar_args.add("w", key_pair.w);
        scalar_args.add("wprime", key_pair.wprime);
        scalar_args.add("x0", key_pair.x0);
        scalar_args.add("x1", key_pair.x1);
        scalar_args.add("y1", key_pair.y[1]);
        scalar_args.add("y2", key_pair.y[2]);
        scalar_args.add("y3", key_pair.y[3]);
        scalar_args.add("y4", key_pair.y[4]);
        scalar_args.add("rprime", blinded_credential.rprime);

        let mut point_args = poksho::PointArgs::new();
        point_args.add("C_W", key_pair.C_W);
        point_args.add("G_w", credentials_system.G_w);
        point_args.add("G_wprime", credentials_system.G_wprime);
        point_args.add("G_V-I", credentials_system.G_V - key_pair.I);
        point_args.add("G_x0", credentials_system.G_x0);
        point_args.add("G_x1", credentials_system.G_x1);
        point_args.add("G_y1", credentials_system.G_y[1]);
        point_args.add("G_y2", credentials_system.G_y[2]);
        point_args.add("G_y3", credentials_system.G_y[3]);
        point_args.add("G_y4", credentials_system.G_y[4]);
        point_args.add("S1", blinded_credential.S1);
        point_args.add("D1", request.D1);
        point_args.add("E1", request.E1);
        point_args.add("S2", blinded_credential.S2);
        point_args.add("D2", request.D2);
        point_args.add("E2", request.E2);
        point_args.add("Y", request_public_key.Y);
        point_args.add("U", blinded_credential.U);
        point_args.add("tU", blinded_credential.t * blinded_credential.U);
        point_args.add("M1", uid.M1);
        point_args.add("M2", uid.M2);

        let poksho_proof = Self::get_poksho_statement()
            .prove(
                &scalar_args,
                &point_args,
                &[],
                &sho.squeeze(RANDOMNESS_LEN)[..],
            )
            .unwrap();
        AuthCredentialIssuanceProof { poksho_proof }
    }

    pub fn verify(
        &self,
        credentials_public_key: credentials::PublicKey,
        request_public_key: auth_credential_request::PublicKey,
        uid_bytes: UidBytes,
        request: auth_credential_request::Ciphertext,
        blinded_credential: credentials::BlindedAuthCredential,
    ) -> Result<(), ZkGroupVerificationFailure> {
        let credentials_system = credentials::SystemParams::get_hardcoded();
        let uid = uid_struct::UidStruct::new(uid_bytes);

        let mut point_args = poksho::PointArgs::new();
        point_args.add("C_W", credentials_public_key.C_W);
        point_args.add("G_w", credentials_system.G_w);
        point_args.add("G_wprime", credentials_system.G_wprime);
        point_args.add("G_V-I", credentials_system.G_V - credentials_public_key.I);
        point_args.add("G_x0", credentials_system.G_x0);
        point_args.add("G_x1", credentials_system.G_x1);
        point_args.add("G_y1", credentials_system.G_y[1]);
        point_args.add("G_y2", credentials_system.G_y[2]);
        point_args.add("G_y3", credentials_system.G_y[3]);
        point_args.add("G_y4", credentials_system.G_y[4]);
        point_args.add("S1", blinded_credential.S1);
        point_args.add("D1", request.D1);
        point_args.add("E1", request.E1);
        point_args.add("S2", blinded_credential.S2);
        point_args.add("D2", request.D2);
        point_args.add("E2", request.E2);
        point_args.add("Y", request_public_key.Y);
        point_args.add("U", blinded_credential.U);
        point_args.add("tU", blinded_credential.t * blinded_credential.U);
        point_args.add("M1", uid.M1);
        point_args.add("M2", uid.M2);

        match Self::get_poksho_statement().verify_proof(&self.poksho_proof, &point_args, &[]) {
            Err(_) => Err(ZkGroupVerificationFailure),
            Ok(_) => Ok(()),
        }
    }
}


impl AuthCredentialRequestProof {
    pub fn get_poksho_statement() -> poksho::Statement {
        let mut st = poksho::Statement::new();
        st.add("Y", &[("y", "G")]);
        st.add("D1", &[("r1", "G")]);
        st.add("E1", &[("r2", "G")]);
        st.add("J3", &[("j3", "G_j3")]);
        st.add("D2-J1", &[("r1", "Y"), ("j3", "-G_j1")]);
        st.add("E2-J2", &[("r2", "Y"), ("j3", "-G_j2")]);
        st
    }

    pub fn new(
        key_pair: auth_credential_request::KeyPair,
        ciphertext: auth_credential_request::CiphertextWithSecretNonce,
        commitment: auth_credential_commitment::CommitmentWithSecretNonce,
        sho: &mut Sho,
    ) -> AuthCredentialRequestProof {
        let commitment_system = auth_credential_commitment::SystemParams::get_hardcoded();

        let mut scalar_args = poksho::ScalarArgs::new();
        scalar_args.add("y", key_pair.y);
        scalar_args.add("r1", ciphertext.r1);
        scalar_args.add("r2", ciphertext.r2);
        scalar_args.add("j3", commitment.j3);

        let mut point_args = poksho::PointArgs::new();
        point_args.add("Y", key_pair.Y);
        point_args.add("D1", ciphertext.D1);
        point_args.add("E1", ciphertext.E1);
        point_args.add("J3", commitment.J3);
        point_args.add("G_j3", commitment_system.G_j3);
        point_args.add("D2-J1", ciphertext.D2 - commitment.J1);
        point_args.add("-G_j1", -commitment_system.G_j1);
        point_args.add("E2-J2", ciphertext.E2 - commitment.J2);
        point_args.add("-G_j2", -commitment_system.G_j2);

        let poksho_proof = Self::get_poksho_statement()
            .prove(
                &scalar_args,
                &point_args,
                &[],
                &sho.squeeze(RANDOMNESS_LEN)[..],
            )
            .unwrap();
        AuthCredentialRequestProof { poksho_proof }
    }

    pub fn verify(
        &self,
        public_key: auth_credential_request::PublicKey,
        ciphertext: auth_credential_request::Ciphertext,
        commitment: auth_credential_commitment::Commitment,
    ) -> Result<(), ZkGroupVerificationFailure> {
        let commitment_system = auth_credential_commitment::SystemParams::get_hardcoded();

        let mut point_args = poksho::PointArgs::new();
        point_args.add("Y", public_key.Y);
        point_args.add("D1", ciphertext.D1);
        point_args.add("E1", ciphertext.E1);
        point_args.add("J3", commitment.J3);
        point_args.add("G_j3", commitment_system.G_j3);
        point_args.add("D2-J1", ciphertext.D2 - commitment.J1);
        point_args.add("-G_j1", -commitment_system.G_j1);
        point_args.add("E2-J2", ciphertext.E2 - commitment.J2);
        point_args.add("-G_j2", -commitment_system.G_j2);

        match Self::get_poksho_statement().verify_proof(&self.poksho_proof, &point_args, &[]) {
            Err(_) => Err(ZkGroupVerificationFailure),
            Ok(_) => Ok(()),
        }
    }
}