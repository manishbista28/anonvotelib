#![allow(non_snake_case)]

use curve25519_dalek::ristretto::RistrettoPoint;

use curve25519_dalek::scalar::Scalar;
use serde::{Deserialize, Serialize};

use crate::common::array_utils::OneBased;
use crate::common::constants::*;
use crate::common::errors::*;
use crate::common::sho::*;
use crate::common::simple_types::*;
use crate::crypto::credentials::convert_to_point_vote_stake_weight;
use crate::crypto::credentials::convert_to_point_vote_topic_id;
use crate::crypto::credentials::convert_to_point_vote_type;
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

#[derive(Serialize, Deserialize, Clone)]
pub struct VoteCredentialPresentationProof {
    C_x0: RistrettoPoint,
    C_x1: RistrettoPoint,
    C_y1: RistrettoPoint,
    C_y2: RistrettoPoint,
    C_y3: RistrettoPoint,
    C_y4: RistrettoPoint,
    C_V: RistrettoPoint,
    poksho_proof: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct VoteCredentialPresentationProofV2 {
    C_x0: RistrettoPoint,
    C_x1: RistrettoPoint,
    C_y1: RistrettoPoint,
    C_y2: RistrettoPoint,
    C_y3: RistrettoPoint,
    C_y4: RistrettoPoint,
    C_V: RistrettoPoint,
    C_z: RistrettoPoint,
    E: Vec<RistrettoPoint>,
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
        st.add("SX", &[("y2", "DX"), ("y3", "EX"), ("rprime", "G")]);
        st.add(
            "SY",
            &[
                ("y2", "DY"),
                ("y3", "EY"),
                ("rprime", "Y"),
                ("w", "G_w"),
                ("x0", "U"),
                ("x1", "tU"),
                ("y1", "M1"),
            ],
        );
        st
    }

    pub fn new(
        key_pair: credentials::KeyPair<credentials::AuthCredential>,
        request_public_key: auth_credential_request::PublicKey,
        ciphertext: auth_credential_request::Ciphertext,
        blinded_credential: credentials::BlindedAuthCredentialWithSecretNonce,
        expiration_time: u64,
        sho: &mut Sho,
    ) -> Self {
        let credentials_system = credentials::SystemParams::get_hardcoded();
        let expiration_time_scalar = encode_timestamp(expiration_time);

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
        point_args.add("SX", blinded_credential.SX);
        point_args.add("DX", ciphertext.DX);
        point_args.add("EX", ciphertext.EX);
        point_args.add("SY", blinded_credential.SY);
        point_args.add("DY", ciphertext.DY);
        point_args.add("EY", ciphertext.EY);
        point_args.add("Y", request_public_key.Y);
        point_args.add("U", blinded_credential.U);
        point_args.add("tU", blinded_credential.t * blinded_credential.U);
        point_args.add("M1", expiration_time_scalar * credentials_system.G_m1);


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
        ciphertext: auth_credential_request::Ciphertext,
        blinded_credential: credentials::BlindedAuthCredential,
        expiration_time: u64,
    ) -> Result<(), ZkVerificationFailure> {
        let credentials_system = credentials::SystemParams::get_hardcoded();
        let expiration_time_scalar = encode_timestamp(expiration_time);

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
        point_args.add("SX", blinded_credential.SX);
        point_args.add("DX", ciphertext.DX);
        point_args.add("EX", ciphertext.EX);
        point_args.add("SY", blinded_credential.SY);
        point_args.add("DY", ciphertext.DY);
        point_args.add("EY", ciphertext.EY);
        point_args.add("Y", request_public_key.Y);
        point_args.add("U", blinded_credential.U);
        point_args.add("tU", blinded_credential.t * blinded_credential.U);
        point_args.add("M1", expiration_time_scalar * credentials_system.G_m1);


        match Self::get_poksho_statement().verify_proof(&self.poksho_proof, &point_args, &[]) {
            Err(_) => Err(ZkVerificationFailure),
            Ok(_) => Ok(()),
        }
    }
}


impl AuthCredentialRequestProof {
    pub fn get_poksho_statement() -> poksho::Statement {
        let mut st = poksho::Statement::new();
        st.add("Y", &[("y", "G")]);
        st.add("DX", &[("rX", "G")]);
        st.add("EX", &[("rY", "G")]);
        st.add("J3", &[("j3", "G_j3")]);
        st.add("DY-J1", &[("rX", "Y"), ("j3", "-G_j1")]);
        st.add("EY-J2", &[("rY", "Y"), ("j3", "-G_j2")]);
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
        scalar_args.add("rX", ciphertext.rX);
        scalar_args.add("rY", ciphertext.rY);
        scalar_args.add("j3", commitment.j3);

        let mut point_args = poksho::PointArgs::new();
        point_args.add("Y", key_pair.Y);
        point_args.add("DX", ciphertext.DX);
        point_args.add("EX", ciphertext.EX);
        point_args.add("J3", commitment.J3);
        point_args.add("G_j3", commitment_system.G_j3);
        point_args.add("DY-J1", ciphertext.DY - commitment.J1);
        point_args.add("-G_j1", -commitment_system.G_j1);
        point_args.add("EY-J2", ciphertext.EY - commitment.J2);
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
    ) -> Result<(), ZkVerificationFailure> {
        let commitment_system = auth_credential_commitment::SystemParams::get_hardcoded();

        let mut point_args = poksho::PointArgs::new();
        point_args.add("Y", public_key.Y);
        point_args.add("DX", ciphertext.DX);
        point_args.add("EX", ciphertext.EX);
        point_args.add("J3", commitment.J3);
        point_args.add("G_j3", commitment_system.G_j3);
        point_args.add("DY-J1", ciphertext.DY - commitment.J1);
        point_args.add("-G_j1", -commitment_system.G_j1);
        point_args.add("EY-J2", ciphertext.EY - commitment.J2);
        point_args.add("-G_j2", -commitment_system.G_j2);

        match Self::get_poksho_statement().verify_proof(&self.poksho_proof, &point_args, &[]) {
            Err(_) => Err(ZkVerificationFailure),
            Ok(_) => Ok(()),
        }
    }
}


impl AuthCredentialPresentationProof {
    pub fn get_poksho_statement() -> poksho::Statement {
        let mut st = poksho::Statement::new();

        st.add("Z", &[("z", "I")]);
        st.add("C_x1", &[("t", "C_x0"), ("z0", "G_x0"), ("z", "G_x1")]);
        st.add("A", &[("a2", "G_a2"), ("a3", "G_a3")]);
        st.add("C_y3-E_A3", &[("z", "G_y3"), ("a3", "-E_A2")]);
        st.add("E_A2", &[("a2", "C_y2"), ("z1", "G_y2")]);
        st.add("C_y1", &[("z", "G_y1")]);
        st
    }

    pub fn new(
        credentials_public_key: credentials::PublicKey,
        uid_enc_key_pair: uid_encryption::KeyPair,
        credential: credentials::AuthCredential,
        uid: uid_struct::UidStruct,
        uid_ciphertext: uid_encryption::Ciphertext,
    ) -> Self {
        let mut sho =     Sho::new(
            b"LibVote_zkvote_20230306_Random_ServerSecretParams_Generate",
            b"",
        );
        let credentials_system = credentials::SystemParams::get_hardcoded();
        let uid_system = uid_encryption::SystemParams::get_hardcoded();
        //let M = credentials::convert_to_points_uid_struct(uid, expiration_time);

        let z = sho.get_scalar();

        let C_y1 = z * credentials_system.G_y[1];
        let C_y2 = z * credentials_system.G_y[2] + uid.M2;
        let C_y3 = z * credentials_system.G_y[3] + uid.M3;

        let C_x0 = z * credentials_system.G_x0 + credential.U;
        let C_V = z * credentials_system.G_V + credential.V;
        let C_x1 = z * credentials_system.G_x1 + credential.t * credential.U;

        let z0 = -z * credential.t;
        let z1 = -z * uid_enc_key_pair.a2;

        let I = credentials_public_key.I;
        let Z = z * I;

        let mut scalar_args = poksho::ScalarArgs::new();
        scalar_args.add("z", z);
        scalar_args.add("t", credential.t);
        scalar_args.add("z0", z0);
        scalar_args.add("z1", z1);
        scalar_args.add("a2", uid_enc_key_pair.a2);
        scalar_args.add("a3", uid_enc_key_pair.a3);

        let mut point_args = poksho::PointArgs::new();
        point_args.add("Z", Z);
        point_args.add("I", I);
        point_args.add("C_x1", C_x1);
        point_args.add("C_x0", C_x0);
        point_args.add("G_x0", credentials_system.G_x0);
        point_args.add("G_x1", credentials_system.G_x1);
        point_args.add("A", uid_enc_key_pair.A);
        point_args.add("G_a2", uid_system.G_a2);
        point_args.add("G_a3", uid_system.G_a3);
        
        point_args.add("C_y3-E_A3", C_y3 - uid_ciphertext.E_A3);
        point_args.add("G_y2", credentials_system.G_y[2]);
        point_args.add("G_y1", credentials_system.G_y[1]);
        point_args.add("-E_A2", -uid_ciphertext.E_A2);
        point_args.add("E_A2", uid_ciphertext.E_A2);
        point_args.add("C_y2", C_y2);
        point_args.add("C_y1", C_y1);
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
        expiration_time: u64,
    ) -> Result<(), ZkVerificationFailure> {
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

        let m1 = encode_timestamp(expiration_time);
        let M1 = m1 * credentials_system.G_m1;
        let Z = C_V - W - x0 * C_x0 - x1 * C_x1 - y1 * (C_y1 + M1) - y2 * C_y2 - y3 * C_y3;

        let mut point_args = poksho::PointArgs::new();
        point_args.add("Z", Z);
        point_args.add("I", I);
        point_args.add("C_x1", C_x1);
        point_args.add("C_x0", C_x0);
        point_args.add("G_x0", credentials_system.G_x0);
        point_args.add("G_x1", credentials_system.G_x1);
        point_args.add("A", uid_enc_public_key.A);
        point_args.add("G_a2", enc_system.G_a2);
        point_args.add("G_a3", enc_system.G_a3);
        
        point_args.add("C_y3-E_A3", C_y3 - uid_ciphertext.E_A3);
        point_args.add("G_y2", credentials_system.G_y[2]);
        point_args.add("G_y1", credentials_system.G_y[1]);
        point_args.add("-E_A2", -uid_ciphertext.E_A2);
        point_args.add("E_A2", uid_ciphertext.E_A2);
        point_args.add("C_y2", C_y2);
        point_args.add("C_y1", C_y1);
        point_args.add("G_y3", credentials_system.G_y[3]);

        match Self::get_poksho_statement().verify_proof(poksho_proof, &point_args, &[]) {
            Err(_) => Err(ZkVerificationFailure),
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
                ("y4", "G_y4"),
            ],
        );
        st.add("SX", &[("y3", "DX"), ("y4", "EX"), ("rprime", "G")]);
        st.add(
            "SY",
            &[
                ("y3", "DY"),
                ("y4", "EY"),
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
        key_pair: credentials::KeyPair<credentials::VoteCredential>,
        request_public_key: vote_credential_request::PublicKey,
        ciphertext: vote_credential_request::Ciphertext,
        blinded_credential: credentials::BlindedVoteCredentialWithSecretNonce,
        stake_weight: VoteStakeWeightBytes,
        topic_id: VoteTopicIDBytes,
        sho: &mut Sho,
        isv2: bool,
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

        let M1 = credentials::convert_to_point_vote_stake_weight(stake_weight, isv2);
        let M2 = credentials::convert_to_point_vote_topic_id(topic_id, isv2);

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
        point_args.add("SX", blinded_credential.SX);
        point_args.add("DX", ciphertext.DX);
        point_args.add("EX", ciphertext.EX);
        point_args.add("SY", blinded_credential.SY);
        point_args.add("DY", ciphertext.DY);
        point_args.add("EY", ciphertext.EY);
        point_args.add("Y", request_public_key.Y);
        point_args.add("U", blinded_credential.U);
        point_args.add("tU", blinded_credential.t * blinded_credential.U);
        point_args.add("M1", M1);
        point_args.add("M2", M2);


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
        credentials_public_key: credentials::PublicKey,
        request_public_key: vote_credential_request::PublicKey,
        ciphertext: vote_credential_request::Ciphertext,
        blinded_credential: credentials::BlindedVoteCredential,
        stake_weight: VoteStakeWeightBytes,
        topic_id: VoteTopicIDBytes,
        isv2: bool,
    ) -> Result<(), ZkVerificationFailure> {
        let credentials_system = credentials::SystemParams::get_hardcoded();
        let M1 = credentials::convert_to_point_vote_stake_weight(stake_weight, isv2);
        let M2 = credentials::convert_to_point_vote_topic_id(topic_id, isv2);

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
        point_args.add("SX", blinded_credential.SX);
        point_args.add("DX", ciphertext.DX);
        point_args.add("EX", ciphertext.EX);
        point_args.add("SY", blinded_credential.SY);
        point_args.add("DY", ciphertext.DY);
        point_args.add("EY", ciphertext.EY);
        point_args.add("Y", request_public_key.Y);
        point_args.add("U", blinded_credential.U);
        point_args.add("tU", blinded_credential.t * blinded_credential.U);
        point_args.add("M1", M1);
        point_args.add("M2", M2);

        match Self::get_poksho_statement().verify_proof(&self.poksho_proof, &point_args, &[]) {
            Err(_) => Err(ZkVerificationFailure),
            Ok(_) => Ok(()),
        }
    }
}

impl VoteCredentialPresentationProof {
    pub fn get_poksho_statement() -> poksho::Statement {
        let mut st = poksho::Statement::new();

        st.add("Z", &[("z", "I")]);
        st.add("C_x1", &[("t", "C_x0"), ("z0", "G_x0"), ("z", "G_x1")]);
        st.add("C_y1", &[("z", "G_y1")]);
        st.add("C_y2", &[("z", "G_y2")]);
        st.add("C_y3", &[("z", "G_y3")]);
        st.add("C_y4", &[("z", "G_y4")]);
        st
    }

    pub fn new(
        credentials_public_key: credentials::PublicKey,
        credential: credentials::VoteCredential,
        sho: &mut Sho,
    ) -> Self {
        let credentials_system = credentials::SystemParams::get_hardcoded();

        let z = sho.get_scalar();

        let C_y1 = z * credentials_system.G_y[1];
        let C_y2 = z * credentials_system.G_y[2];
        let C_y3 = z * credentials_system.G_y[3];
        let C_y4 = z * credentials_system.G_y[4];

        let C_x0 = z * credentials_system.G_x0 + credential.U;
        let C_V = z * credentials_system.G_V + credential.V;
        let C_x1 = z * credentials_system.G_x1 + credential.t * credential.U;

        let z0 = -z * credential.t;

        let I = credentials_public_key.I;
        let Z = z * I;

        // Scalars listed in order of stmts for debugging
        let mut scalar_args = poksho::ScalarArgs::new();
        scalar_args.add("z", z);
        scalar_args.add("t", credential.t);
        scalar_args.add("z0", z0);

        // Points listed in order of stmts for debugging
        let mut point_args = poksho::PointArgs::new();
        point_args.add("Z", Z);
        point_args.add("I", I);
        point_args.add("C_x0", C_x0);
        point_args.add("C_x1", C_x1);
        point_args.add("C_y1", C_y1);
        point_args.add("C_y2", C_y2);
        point_args.add("C_y3", C_y3);
        point_args.add("C_y4", C_y4);
        point_args.add("G_x0", credentials_system.G_x0);
        point_args.add("G_x1", credentials_system.G_x1);
        point_args.add("G_y1", credentials_system.G_y[1]);
        point_args.add("G_y2", credentials_system.G_y[2]);
        point_args.add("G_y3", credentials_system.G_y[3]);
        point_args.add("G_y4", credentials_system.G_y[4]);

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
            C_y4,
            C_V,
            poksho_proof,
        }
    }

    pub fn verify(
        &self,
        credentials_key_pair: credentials::KeyPair<credentials::VoteCredential>,
        vote_type: VoteTypeBytes,
        vote_id: VoteUniqIDBytes,
        stake_weight: VoteStakeWeightBytes,
        topic_id: VoteTopicIDBytes,
    ) -> Result<(), ZkVerificationFailure> {
        let credentials_system = credentials::SystemParams::get_hardcoded();

        let Self {
            C_x0,
            C_x1,
            C_y1,
            C_y2,
            C_y3,
            C_y4,
            C_V,
            poksho_proof,
        } = self;

        let (C_x0, C_x1, C_y1, C_y2, C_y3, C_y4, C_V) = (*C_x0, *C_x1, *C_y1, *C_y2, *C_y3, *C_y4, *C_V);

        let credentials::KeyPair {
            W,
            x0,
            x1,
            y: OneBased([y1, y2, y3, y4, ..]),
            I,
            ..
        } = credentials_key_pair;

        let isv2 = false;
        let M1 = credentials::convert_to_point_vote_stake_weight(stake_weight, isv2);
        let M2 = credentials::convert_to_point_vote_topic_id(topic_id, isv2);
        let M3 = credentials::convert_to_point_vote_type(vote_type, isv2);
        let M4 = credentials::convert_to_point_vote_id(vote_id, isv2);

        
        let Z = C_V - W - x0 * C_x0 - x1 * C_x1 - (y1 * (C_y1 + M1)) - (y2 * (C_y2 + M2))- (y3 * (C_y3 + M3)) - (y4 * (C_y4 + M4));

        let mut point_args = poksho::PointArgs::new();
        point_args.add("Z", Z);
        point_args.add("I", I);
        point_args.add("C_x0", C_x0);
        point_args.add("C_x1", C_x1);
        point_args.add("C_y1", C_y1);
        point_args.add("C_y2", C_y2);
        point_args.add("C_y3", C_y3);
        point_args.add("C_y4", C_y4);
        point_args.add("G_x0", credentials_system.G_x0);
        point_args.add("G_x1", credentials_system.G_x1);
        point_args.add("G_y1", credentials_system.G_y[1]);
        point_args.add("G_y2", credentials_system.G_y[2]);
        point_args.add("G_y3", credentials_system.G_y[3]);
        point_args.add("G_y4", credentials_system.G_y[4]);

        match Self::get_poksho_statement().verify_proof(poksho_proof, &point_args, &[]) {
            Err(_) => Err(ZkVerificationFailure),
            Ok(_) => Ok(()),
        }
    }
}

impl VoteCredentialPresentationProofV2 {
    pub fn get_poksho_statement() -> poksho::Statement {
        let mut st = poksho::Statement::new();

        st.add("C_z", &[("z", "G_z")]);
        st.add("Z", &[("z", "I")]);
        st.add("C_x1", &[("t", "C_x0"), ("z0", "G_x0"), ("z", "G_x1")]);
        st.add("C_y1-E1_Y", &[("z", "G_y1"), ("r1s", "-G_m1")]);
        st.add("E1_X", &[("r1", "G_m1")]);
        st.add("C_y2-E2_Y", &[("z", "G_y2"), ("r2s", "-G_m2")]);
        st.add("E2_X", &[("r2", "G_m2")]);
        st.add("C_y3-E3_Y", &[("z", "G_y3"), ("r3s", "-G_m3")]);
        st.add("E3_X", &[("r3", "G_m3")]);
        st.add("C_y4", &[("z", "G_y4")]);
        st
    }

    pub fn new(
        credentials_public_key: credentials::PublicKey,
        credential: credentials::VoteCredential,
        stake_weight: VoteStakeWeightBytes,
        topic_id: VoteTopicIDBytes,
        vote_type: VoteTypeBytes,
        sho: &mut Sho,
        secret: Scalar,
    ) -> Self {
        let credentials_system = credentials::SystemParams::get_hardcoded();

        let r1 = sho.get_scalar();
        let r2 = sho.get_scalar();
        let r3 = sho.get_scalar();
        let r1s = r1 * secret;
        let r2s = r2 * secret;
        let r3s = r3 * secret;
        let M1 = convert_to_point_vote_stake_weight(stake_weight, true);
        let M2 = convert_to_point_vote_topic_id(topic_id, true);
        let M3 = convert_to_point_vote_type(vote_type, true);
        let E1_X = r1 * credentials_system.G_m1;
        let E2_X = r2 * credentials_system.G_m2;
        let E3_X = r3 * credentials_system.G_m3;
        let E1_Y = r1s * credentials_system.G_m1 + M1;
        let E2_Y = r2s * credentials_system.G_m2 + M2;
        let E3_Y = r3s * credentials_system.G_m3 + M3;

        let z = sho.get_scalar();

        let C_y1 = z * credentials_system.G_y[1] + M1;
        let C_y2 = z * credentials_system.G_y[2] + M2;
        let C_y3 = z * credentials_system.G_y[3] + M3;
        let C_y4 = z * credentials_system.G_y[4];

        let C_x0 = z * credentials_system.G_x0 + credential.U;
        let C_V = z * credentials_system.G_V + credential.V;
        let C_x1 = z * credentials_system.G_x1 + credential.t * credential.U;
        let C_z = z * credentials_system.G_z;

        let z0 = -z * credential.t;

        let I = credentials_public_key.I;
        let Z = z * I;

        // Scalars listed in order of stmts for debugging
        let mut scalar_args = poksho::ScalarArgs::new();
        scalar_args.add("z", z);
        scalar_args.add("t", credential.t);
        scalar_args.add("z0", z0);
        scalar_args.add("r1", r1);
        scalar_args.add("r2", r2);
        scalar_args.add("r3", r3);
        scalar_args.add("r1s", r1s);
        scalar_args.add("r2s", r2s);
        scalar_args.add("r3s", r3s);

        // Points listed in order of stmts for debugging
        let mut point_args = poksho::PointArgs::new();
        point_args.add("C_z", C_z);
        point_args.add("G_z", credentials_system.G_z);
        point_args.add("Z", Z);
        point_args.add("I", I);
        point_args.add("C_x0", C_x0);
        point_args.add("C_x1", C_x1);
        point_args.add("C_y1-E1_Y", C_y1-E1_Y);
        point_args.add("C_y2-E2_Y", C_y2-E2_Y);
        point_args.add("C_y3-E3_Y", C_y3-E3_Y);
        point_args.add("E1_X", E1_X);
        point_args.add("E2_X", E2_X);
        point_args.add("E3_X", E3_X);
        point_args.add("C_y4", C_y4);
        point_args.add("G_x0", credentials_system.G_x0);
        point_args.add("G_x1", credentials_system.G_x1);
        point_args.add("G_y1", credentials_system.G_y[1]);
        point_args.add("G_y2", credentials_system.G_y[2]);
        point_args.add("G_y3", credentials_system.G_y[3]);
        point_args.add("G_y4", credentials_system.G_y[4]);
        point_args.add("-G_m1", -credentials_system.G_m1);
        point_args.add("-G_m2", -credentials_system.G_m2);
        point_args.add("-G_m3", -credentials_system.G_m3);
        point_args.add("G_m1", credentials_system.G_m1);
        point_args.add("G_m2", credentials_system.G_m2);
        point_args.add("G_m3", credentials_system.G_m3);


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
            C_y4,
            C_V,
            C_z,
            E: [E1_Y, E2_Y, E3_Y, E1_X, E2_X, E3_X].to_vec(),
            poksho_proof,
        }
    }

    pub fn verify(
        &self,
        credentials_key_pair: credentials::KeyPair<credentials::VoteCredential>,
        vote_id: VoteUniqIDBytes,
    ) -> Result<(), ZkVerificationFailure> {
        let credentials_system = credentials::SystemParams::get_hardcoded();

        let Self {
            C_x0,
            C_x1,
            C_y1,
            C_y2,
            C_y3,
            C_y4,
            C_V,
            C_z,
            E,
            poksho_proof,
        } = self;

        let (C_x0, C_x1, C_y1, C_y2, C_y3, C_y4, C_V, C_z) = (*C_x0, *C_x1, *C_y1, *C_y2, *C_y3, *C_y4, *C_V, *C_z);

        let credentials::KeyPair {
            W,
            x0,
            x1,
            y: OneBased([y1, y2, y3, y4, ..]),
            I,
            ..
        } = credentials_key_pair;


        let M4 = credentials::convert_to_point_vote_id(vote_id, true);

        
        let Z = C_V - W - x0 * C_x0 - x1 * C_x1 - (y1 * C_y1) - (y2 * C_y2)- (y3 * C_y3) - (y4 * (C_y4 + M4));
        let Es = E.clone();

        assert_eq!(Es.len(), 6);

        // Points listed in order of stmts for debugging
        let mut point_args = poksho::PointArgs::new();
        point_args.add("C_z", C_z);
        point_args.add("G_z", credentials_system.G_z);
        point_args.add("Z", Z);
        point_args.add("I", I);
        point_args.add("C_x0", C_x0);
        point_args.add("C_x1", C_x1);
        point_args.add("C_y1-E1_Y", C_y1-Es[0]);
        point_args.add("C_y2-E2_Y", C_y2-Es[1]);
        point_args.add("C_y3-E3_Y", C_y3-Es[2]);
        point_args.add("E1_X", Es[3]);
        point_args.add("E2_X", Es[4]);
        point_args.add("E3_X", Es[5]);
        point_args.add("C_y4", C_y4);
        point_args.add("G_x0", credentials_system.G_x0);
        point_args.add("G_x1", credentials_system.G_x1);
        point_args.add("G_y1", credentials_system.G_y[1]);
        point_args.add("G_y2", credentials_system.G_y[2]);
        point_args.add("G_y3", credentials_system.G_y[3]);
        point_args.add("G_y4", credentials_system.G_y[4]);
        point_args.add("-G_m1", -credentials_system.G_m1);
        point_args.add("-G_m2", -credentials_system.G_m2);
        point_args.add("-G_m3", -credentials_system.G_m3);
        point_args.add("G_m1", credentials_system.G_m1);
        point_args.add("G_m2", credentials_system.G_m2);
        point_args.add("G_m3", credentials_system.G_m3);

        match Self::get_poksho_statement().verify_proof(poksho_proof, &point_args, &[]) {
            Err(_) => Err(ZkVerificationFailure),
            Ok(_) => Ok(()),
        }
    }
}
