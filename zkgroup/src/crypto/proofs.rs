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
    vote_credential_request,
};

#[derive(Serialize, Deserialize, Clone)]
pub struct AuthCredentialIssuanceProof {
    poksho_proof: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct VoteCredentialIssuanceProof {
    poksho_proof: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AuthCredentialRequestProof {
    poksho_proof: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AuthCredentialPresentationProof {
    C_x0: RistrettoPoint,
    C_x1: RistrettoPoint,
    C_y1: RistrettoPoint,
    C_y2: RistrettoPoint,
    C_y3: RistrettoPoint,
    C_V: RistrettoPoint,
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
            ],
        );
        st.add("S1", &[("y1", "D1"), ("y2", "E1"), ("rprime", "G")]);
        st.add(
            "S2",
            &[
                ("y1", "D2"),
                ("y2", "E2"),
                ("rprime", "Y"),
                ("w", "G_w"),
                ("x0", "U"),
                ("x1", "tU"),
                ("y3", "M3"),
            ],
        );
        st
    }

    pub fn new(
        key_pair: credentials::KeyPair<credentials::AuthCredential>,
        request_public_key: auth_credential_request::PublicKey,
        request: auth_credential_request::Ciphertext,
        blinded_credential: credentials::BlindedAuthCredentialWithSecretNonce,
        redemption_time: CoarseRedemptionTime,
        sho: &mut Sho,
    ) -> Self {
        let credentials_system = credentials::SystemParams::get_hardcoded();
        let redemption_time_scalar = encode_redemption_time(redemption_time);

        let mut scalar_args = poksho::ScalarArgs::new();
        scalar_args.add("w", key_pair.w);
        scalar_args.add("wprime", key_pair.wprime);
        scalar_args.add("x0", key_pair.x0);
        scalar_args.add("x1", key_pair.x1);
        scalar_args.add("y1", key_pair.y[1]);
        scalar_args.add("y2", key_pair.y[2]);
        scalar_args.add("y3", key_pair.y[3]);
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
        point_args.add("S1", blinded_credential.S1);
        point_args.add("D1", request.D1);
        point_args.add("E1", request.E1);
        point_args.add("S2", blinded_credential.S2);
        point_args.add("D2", request.D2);
        point_args.add("E2", request.E2);
        point_args.add("Y", request_public_key.Y);
        point_args.add("U", blinded_credential.U);
        point_args.add("tU", blinded_credential.t * blinded_credential.U);
        point_args.add("M3", redemption_time_scalar * credentials_system.G_m2);


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
        request: auth_credential_request::Ciphertext,
        blinded_credential: credentials::BlindedAuthCredential,
        redemption_time: CoarseRedemptionTime,
    ) -> Result<(), ZkGroupVerificationFailure> {
        let credentials_system = credentials::SystemParams::get_hardcoded();
        let redemption_time_scalar = encode_redemption_time(redemption_time);

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
        point_args.add("S1", blinded_credential.S1);
        point_args.add("D1", request.D1);
        point_args.add("E1", request.E1);
        point_args.add("S2", blinded_credential.S2);
        point_args.add("D2", request.D2);
        point_args.add("E2", request.E2);
        point_args.add("Y", request_public_key.Y);
        point_args.add("U", blinded_credential.U);
        point_args.add("tU", blinded_credential.t * blinded_credential.U);
        point_args.add("M3", redemption_time_scalar * credentials_system.G_m2);


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


impl AuthCredentialPresentationProof {
    pub fn get_poksho_statement() -> poksho::Statement {
        let mut st = poksho::Statement::new();

        st.add("Z", &[("z", "I")]);
        st.add("C_x1", &[("t", "C_x0"), ("z0", "G_x0"), ("z", "G_x1")]);
        st.add("A", &[("a1", "G_a1"), ("a2", "G_a2")]);
        st.add("C_y2-E_A2", &[("z", "G_y2"), ("a2", "-E_A1")]);
        st
    }

    pub fn new(
        credentials_public_key: credentials::PublicKey,
        uid_enc_key_pair: uid_encryption::KeyPair,
        credential: credentials::AuthCredential,
        uid: uid_struct::UidStruct,
        uid_ciphertext: uid_encryption::Ciphertext,
        redemption_time: CoarseRedemptionTime,
        sho: &mut Sho,
    ) -> Self {
        let credentials_system = credentials::SystemParams::get_hardcoded();
        let uid_system = uid_encryption::SystemParams::get_hardcoded();
        let M = credentials::convert_to_points_uid_struct(uid, redemption_time);

        let z = sho.get_scalar();

        let C_y1 = z * credentials_system.G_y[1] + M[0];
        let C_y2 = z * credentials_system.G_y[2] + M[1];
        let C_y3 = z * credentials_system.G_y[3];

        let C_x0 = z * credentials_system.G_x0 + credential.U;
        let C_V = z * credentials_system.G_V + credential.V;
        let C_x1 = z * credentials_system.G_x1 + credential.t * credential.U;

        let z0 = -z * credential.t;
        //let z1 = -z * uid_enc_key_pair.a1;

        let I = credentials_public_key.I;
        let Z = z * I;

        // Scalars listed in order of stmts for debugging
        let mut scalar_args = poksho::ScalarArgs::new();
        scalar_args.add("z", z);
        scalar_args.add("t", credential.t);
        scalar_args.add("z0", z0);
        scalar_args.add("a1", uid_enc_key_pair.a1);
        scalar_args.add("a2", uid_enc_key_pair.a2);
        //scalar_args.add("z1", z1);

        // Points listed in order of stmts for debugging
        let mut point_args = poksho::PointArgs::new();
        point_args.add("Z", Z);
        point_args.add("I", I);
        point_args.add("C_x1", C_x1);
        point_args.add("C_x0", C_x0);
        point_args.add("G_x0", credentials_system.G_x0);
        point_args.add("G_x1", credentials_system.G_x1);
        point_args.add("A", uid_enc_key_pair.A);
        point_args.add("G_a1", uid_system.G_a1);
        point_args.add("G_a2", uid_system.G_a2);
        point_args.add("C_y2-E_A2", C_y2 - uid_ciphertext.E_A2);
        point_args.add("G_y2", credentials_system.G_y[2]);
        point_args.add("-E_A1", -uid_ciphertext.E_A1);
        point_args.add("C_y3", C_y3);
        point_args.add("G_y3", credentials_system.G_y[3]);

        let poksho_proof = Self::get_poksho_statement()
            .prove(
                &scalar_args,
                &point_args,
                &[],
                &sho.squeeze(RANDOMNESS_LEN)[..],
            )
            .unwrap();

        Self {
            C_x0,
            C_x1,
            C_y1,
            C_y2,
            C_y3,
            C_V,
            poksho_proof,
        }
    }

    pub fn verify(
        &self,
        credentials_key_pair: credentials::KeyPair<credentials::AuthCredential>,
        uid_enc_public_key: uid_encryption::PublicKey,
        uid_ciphertext: uid_encryption::Ciphertext,
        redemption_time: CoarseRedemptionTime,
    ) -> Result<(), ZkGroupVerificationFailure> {
        let enc_system = uid_encryption::SystemParams::get_hardcoded();
        let credentials_system = credentials::SystemParams::get_hardcoded();

        let Self {
            C_x0,
            C_x1,
            C_y1,
            C_y2,
            C_y3,
            C_V,
            poksho_proof,
        } = self;

        let (C_x0, C_x1, C_y1, C_y2, C_y3, C_V) = (*C_x0, *C_x1, *C_y1, *C_y2, *C_y3, *C_V);

        let credentials::KeyPair {
            W,
            x0,
            x1,
            y: OneBased([y1, y2, y3, ..]),
            I,
            ..
        } = credentials_key_pair;

        let m3 = encode_redemption_time(redemption_time);
        let M3 = m3 * credentials_system.G_m3;
        let Z = C_V - W - x0 * C_x0 - x1 * C_x1 - y1 * C_y1 - y2 * C_y2- y3 * (C_y3 + M3);

        // Points listed in order of stmts for debugging
        let mut point_args = poksho::PointArgs::new();
        point_args.add("Z", Z);
        point_args.add("I", I);
        point_args.add("C_x1", C_x1);
        point_args.add("C_x0", C_x0);
        point_args.add("G_x0", credentials_system.G_x0);
        point_args.add("G_x1", credentials_system.G_x1);
        point_args.add("A", uid_enc_public_key.A);
        point_args.add("G_a1", enc_system.G_a1);
        point_args.add("G_a2", enc_system.G_a2);
        point_args.add("C_y2-E_A2", C_y2 - uid_ciphertext.E_A2);
        point_args.add("G_y2", credentials_system.G_y[2]);
        point_args.add("-E_A1", -uid_ciphertext.E_A1);
        //point_args.add("E_A1", uid_ciphertext.E_A1);
        //point_args.add("C_y1", C_y1);
        //point_args.add("G_y1", credentials_system.G_y[1]);
        point_args.add("C_y3", C_y3);
        point_args.add("G_y3", credentials_system.G_y[3]);
        //point_args.add("0", RistrettoPoint::identity());

        match Self::get_poksho_statement().verify_proof(poksho_proof, &point_args, &[]) {
            Err(_) => Err(ZkGroupVerificationFailure),
            Ok(_) => Ok(()),
        }
    }
}


impl VoteCredentialIssuanceProof {
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
            ],
        );
        st.add("S1", &[("y1", "D1"), ("y2", "E1"), ("rprime", "G")]);
        st.add(
            "S2",
            &[
                ("y1", "D2"),
                ("y2", "E2"),
                ("rprime", "Y"),
                ("w", "G_w"),
                ("x0", "U"),
                ("x1", "tU"),
                ("y3", "M3"),
            ],
        );
        st
    }

    pub fn new(
        key_pair: credentials::KeyPair<credentials::VoteCredential>,
        request_public_key: vote_credential_request::PublicKey,
        ciphertext: vote_credential_request::Ciphertext,
        blinded_credential: credentials::BlindedVoteCredentialWithSecretNonce,
        sho: &mut Sho,
    ) -> Self {
        // let credentials_system = credentials::SystemParams::get_hardcoded();
        // let redemption_time_scalar = encode_redemption_time(redemption_time);

        let mut scalar_args = poksho::ScalarArgs::new();
        scalar_args.add("w", key_pair.w);
        scalar_args.add("wprime", key_pair.wprime);
        scalar_args.add("x0", key_pair.x0);
        scalar_args.add("x1", key_pair.x1);
        scalar_args.add("y1", key_pair.y[1]);
        scalar_args.add("y2", key_pair.y[2]);
        scalar_args.add("y3", key_pair.y[3]);
        scalar_args.add("rprime", blinded_credential.rprime);

        let mut point_args = poksho::PointArgs::new();
        // point_args.add("C_W", key_pair.C_W);
        // point_args.add("G_w", credentials_system.G_w);
        // point_args.add("G_wprime", credentials_system.G_wprime);
        // point_args.add("G_V-I", credentials_system.G_V - key_pair.I);
        // point_args.add("G_x0", credentials_system.G_x0);
        // point_args.add("G_x1", credentials_system.G_x1);
        // point_args.add("G_y1", credentials_system.G_y[1]);
        // point_args.add("G_y2", credentials_system.G_y[2]);
        // point_args.add("G_y3", credentials_system.G_y[3]);
        // point_args.add("S1", blinded_credential.S1);
        // point_args.add("D1", request.D1);
        // point_args.add("E1", request.E1);
        // point_args.add("S2", blinded_credential.S2);
        // point_args.add("D2", request.D2);
        // point_args.add("E2", request.E2);
        // point_args.add("Y", request_public_key.Y);
        // point_args.add("U", blinded_credential.U);
        // point_args.add("tU", blinded_credential.t * blinded_credential.U);
        // point_args.add("M3", redemption_time_scalar * credentials_system.G_m2);


        let poksho_proof = Self::get_poksho_statement()
            .prove(
                &scalar_args,
                &point_args,
                &[],
                &sho.squeeze(RANDOMNESS_LEN)[..],
            )
            .unwrap();
        VoteCredentialIssuanceProof { poksho_proof }
    }

    pub fn verify(
        &self,
        // credentials_public_key: credentials::PublicKey,
        // request_public_key: auth_credential_request::PublicKey,
        // request: auth_credential_request::Ciphertext,
        // blinded_credential: credentials::BlindedAuthCredential,
        // redemption_time: CoarseRedemptionTime,
    ) -> Result<(), ZkGroupVerificationFailure> {
        // let credentials_system = credentials::SystemParams::get_hardcoded();
        // let redemption_time_scalar = encode_redemption_time(redemption_time);

        let mut point_args = poksho::PointArgs::new();
        // point_args.add("C_W", credentials_public_key.C_W);
        // point_args.add("G_w", credentials_system.G_w);
        // point_args.add("G_wprime", credentials_system.G_wprime);
        // point_args.add("G_V-I", credentials_system.G_V - credentials_public_key.I);
        // point_args.add("G_x0", credentials_system.G_x0);
        // point_args.add("G_x1", credentials_system.G_x1);
        // point_args.add("G_y1", credentials_system.G_y[1]);
        // point_args.add("G_y2", credentials_system.G_y[2]);
        // point_args.add("G_y3", credentials_system.G_y[3]);
        // point_args.add("S1", blinded_credential.S1);
        // point_args.add("D1", request.D1);
        // point_args.add("E1", request.E1);
        // point_args.add("S2", blinded_credential.S2);
        // point_args.add("D2", request.D2);
        // point_args.add("E2", request.E2);
        // point_args.add("Y", request_public_key.Y);
        // point_args.add("U", blinded_credential.U);
        // point_args.add("tU", blinded_credential.t * blinded_credential.U);
        // point_args.add("M3", redemption_time_scalar * credentials_system.G_m2);


        match Self::get_poksho_statement().verify_proof(&self.poksho_proof, &point_args, &[]) {
            Err(_) => Err(ZkGroupVerificationFailure),
            Ok(_) => Ok(()),
        }
    }
}
