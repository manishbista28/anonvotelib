#![allow(non_snake_case)]

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use serde::{Deserialize, Serialize};

use crate::common::array_utils::{ArrayLike, OneBased};
use crate::common::sho::*;
use crate::common::simple_types::*;
use crate::crypto::uid_struct;
use crate::crypto::{
    auth_credential_request, vote_credential_request,
};

use crate::{
    NUM_AUTH_CRED_ATTRIBUTES, NUM_VOTES_ATTRIBUTES, 
};

use lazy_static::lazy_static;

lazy_static! {
    static ref SYSTEM_PARAMS: SystemParams =
        bincode::deserialize::<SystemParams>(SystemParams::SYSTEM_HARDCODED).unwrap();
}

const NUM_SUPPORTED_ATTRS: usize = 6;
#[derive(Copy, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemParams {
    pub(crate) G_w: RistrettoPoint,
    pub(crate) G_wprime: RistrettoPoint,
    pub(crate) G_x0: RistrettoPoint,
    pub(crate) G_x1: RistrettoPoint,
    pub(crate) G_y: OneBased<[RistrettoPoint; NUM_SUPPORTED_ATTRS]>,
    pub(crate) G_m1: RistrettoPoint,
    pub(crate) G_m2: RistrettoPoint,
    pub(crate) G_m3: RistrettoPoint,
    pub(crate) G_m4: RistrettoPoint,
    pub(crate) G_m5: RistrettoPoint,
    pub(crate) G_V: RistrettoPoint,
    pub(crate) G_z: RistrettoPoint,
}

/// Used to specialize a [`KeyPair<S>`] to support a certain number of attributes.
///
/// The only required member is `Storage`, which should be a fixed-size array of [`Scalar`], one for
/// each attribute. However, for backwards compatibility some systems support fewer attributes than
/// are actually stored, and in this case the `NUM_ATTRS` member can be set to a custom value. Note
/// that `NUM_ATTRS` must always be less than or equal to the number of elements in `Storage`.
pub trait AttrScalars {
    /// The storage (should be a fixed-size array of Scalar).
    type Storage: ArrayLike<Scalar> + Copy + Eq + Serialize + for<'a> Deserialize<'a>;

    /// The number of attributes supported in this system.
    ///
    /// Defaults to the full set stored in `Self::Storage`.
    const NUM_ATTRS: usize = Self::Storage::LEN;
}

impl AttrScalars for AuthCredential {
    // Store four scalars for backwards compatibility.
    type Storage = [Scalar; 3];
    const NUM_ATTRS: usize = NUM_AUTH_CRED_ATTRIBUTES;
}

impl AttrScalars for VoteCredential { //TODO
    // Store four scalars for backwards compatibility.
    type Storage = [Scalar; 4];
    const NUM_ATTRS: usize = NUM_VOTES_ATTRIBUTES;
}

#[derive(Serialize, Deserialize)]
pub struct KeyPair<S: AttrScalars> {
    // private
    pub(crate) w: Scalar,
    pub(crate) wprime: Scalar,
    pub(crate) W: RistrettoPoint,
    pub(crate) x0: Scalar,
    pub(crate) x1: Scalar,
    pub(crate) y: OneBased<S::Storage>,

    // public
    pub(crate) C_W: RistrettoPoint,
    pub(crate) I: RistrettoPoint,
}

impl<S: AttrScalars> Clone for KeyPair<S> {
    fn clone(&self) -> Self {
        // Rely on Copy
        *self
    }
}

impl<S: AttrScalars> Copy for KeyPair<S> {}

impl<S: AttrScalars> PartialEq for KeyPair<S> {
    fn eq(&self, other: &Self) -> bool {
        self.w == other.w
            && self.wprime == other.wprime
            && self.W == other.W
            && self.x0 == other.x0
            && self.x1 == other.x1
            && self.y == other.y
            && self.C_W == other.C_W
            && self.I == other.I
    }
}
impl<S: AttrScalars> Eq for KeyPair<S> {}

#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKey {
    pub(crate) C_W: RistrettoPoint,
    pub(crate) I: RistrettoPoint,
}

#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthCredential {
    pub(crate) t: Scalar,
    pub(crate) U: RistrettoPoint,
    pub(crate) V: RistrettoPoint,
}

#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlindedAuthCredentialWithSecretNonce {
    pub(crate) rprime: Scalar,
    pub(crate) t: Scalar,
    pub(crate) U: RistrettoPoint,
    pub(crate) S1: RistrettoPoint,
    pub(crate) S2: RistrettoPoint,
}

#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlindedAuthCredential {
    pub(crate) t: Scalar,
    pub(crate) U: RistrettoPoint,
    pub(crate) S1: RistrettoPoint,
    pub(crate) S2: RistrettoPoint,
}


#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VoteCredential {
    pub(crate) t: Scalar,
    pub(crate) U: RistrettoPoint,
    pub(crate) V: RistrettoPoint,
}

#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlindedVoteCredentialWithSecretNonce {
    pub(crate) rprime: Scalar,
    pub(crate) t: Scalar,
    pub(crate) U: RistrettoPoint,
    pub(crate) S1: RistrettoPoint,
    pub(crate) S2: RistrettoPoint,
}

#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlindedVoteCredential {
    pub(crate) t: Scalar,
    pub(crate) U: RistrettoPoint,
    pub(crate) S1: RistrettoPoint,
    pub(crate) S2: RistrettoPoint,
}

pub(crate) fn convert_to_points_uid_struct(
    uid: uid_struct::UidStruct,
    expiration_time: u64,
) -> Vec<RistrettoPoint> {
    let system = SystemParams::get_hardcoded();
    let expiration_time_scalar = encode_timestamp(expiration_time);
    vec![uid.M1, uid.M2, expiration_time_scalar * system.G_m1]
}

pub(crate) fn convert_to_point_vote_type(
    vote_type: VoteTypeBytes,
) -> RistrettoPoint {
    let system = SystemParams::get_hardcoded();
    let vote_scalar = encode_vote_bytes(vote_type);
    vote_scalar * system.G_m1
}

pub(crate) fn convert_to_point_vote_id(
    vote_id: VoteUniqIDBytes,
) -> RistrettoPoint {
    let system = SystemParams::get_hardcoded();
    let vote_scalar = encode_vote_id(vote_id);
    vote_scalar * system.G_m2
}

pub(crate) fn convert_to_point_vote_stake_weight(
    stake_weight: VoteStakeWeightBytes,
) -> RistrettoPoint {
    let system = SystemParams::get_hardcoded();
    let vote_scalar = encode_vote_id(stake_weight);
    vote_scalar * system.G_m3
}

pub(crate) fn convert_to_point_vote_topic_id(
    topic_id: VoteTopicIDBytes,
) -> RistrettoPoint {
    let system = SystemParams::get_hardcoded();
    let vote_scalar = encode_vote_topic_id(topic_id);
    vote_scalar * system.G_m4
}
/*
pub(crate) fn convert_to_point_auth_commitment(
    auth_commitment: auth_credential_commitment::Commitment,
) -> RistrettoPoint {
    let mut combined_vec = Vec::<u8>::with_capacity(160*3);
    let mut enc_j1 = bincode::serialize(&auth_commitment.J1).unwrap();
    let mut enc_j2 = bincode::serialize(&auth_commitment.J2).unwrap();
    let mut enc_j3 = bincode::serialize(&auth_commitment.J3).unwrap();
    combined_vec.append(&mut enc_j1);
    combined_vec.append(&mut enc_j2);
    combined_vec.append(&mut enc_j3);
    let mut sho = Sho::new(
        b"Signal_ZKGroup_20200424_Random_Commitment_Generate",
        &combined_vec,
    );
    let mut point_bytes = [0u8; 32];
    point_bytes.copy_from_slice(&sho.squeeze(32)[..]);
    let vote_scalar =  Scalar::from_bytes_mod_order(point_bytes);
    let system = SystemParams::get_hardcoded();
    vote_scalar * system.G_m5
}
 */

impl SystemParams {
    #[cfg(test)]
    fn generate() -> Self {
        let mut sho = Sho::new(
            b"LibVote_zkvote_20230306_Constant_Credentials_SystemParams_Generate",
            b"",
        );
        let G_w = sho.get_point();
        let G_wprime = sho.get_point();

        let G_x0 = sho.get_point();
        let G_x1 = sho.get_point();

        let G_y1 = sho.get_point();
        let G_y2 = sho.get_point();
        let G_y3 = sho.get_point();
        let G_y4 = sho.get_point();

        let G_m1 = sho.get_point();
        let G_m2 = sho.get_point();
        let G_m3 = sho.get_point();
        let G_m4 = sho.get_point();

        let G_V = sho.get_point();
        let G_z = sho.get_point();

        // We don't ever want to use existing generator points in new ways,
        // so new points have to be added at the end.
        let G_y5 = sho.get_point();
        let G_y6 = sho.get_point();

        let G_m5 = sho.get_point();

        SystemParams {
            G_w,
            G_wprime,
            G_x0,
            G_x1,
            G_y: OneBased([G_y1, G_y2, G_y3, G_y4, G_y5, G_y6]),
            G_m1,
            G_m2,
            G_m3,
            G_m4,
            G_m5,
            G_V,
            G_z,
        }
    }

    pub fn get_hardcoded() -> SystemParams {
        *SYSTEM_PARAMS
    }

    const SYSTEM_HARDCODED: &'static [u8] = &[
        0x1e,  0x4b,  0xcc,  0x31,  0xdc,  0x4f,  0x1b,  0x62,  0xa9,  0x3b,  0xcd,  0xa3,  0x51,  0x86,  0x6a,  0xbf,  0x46,  0xbe,  0x81,  0xad,  0x2a,  0x23,  0xae,  0x66,  0x8f,  0xee,  0x5e,  0xcb,  0xe4,  0x27,  0xbc,  0x3b,  0x1a,  0x80,  0xe9,  0x61,  0x44,  0x3,  0xe4,  0xe4,  0x9f,  0xce,  0xee,  0x97,  0x5c,  0x31,  0x8,  0xd3,  0x80,  0xb2,  0x6e,  0x38,  0x4e,  0xfd,  0x90,  0x48,  0xe1,  0xc5,  0xe5,  0x50,  0x45,  0x15,  0x5c,  0x3d,  0x94,  0xcb,  0xae,  0xfd,  0x7,  0xc9,  0xb1,  0x78,  0x35,  0xc8,  0xe7,  0xc0,  0xbc,  0x59,  0xca,  0xcb,  0x52,  0x7,  0x52,  0x8,  0xd3,  0x5f,  0xaf,  0xd7,  0xe,  0x66,  0xb0,  0xb6,  0x9d,  0xa4,  0xe1,  0x1a,  0x18,  0xe5,  0x5b,  0x4a,  0x8d,  0x61,  0xa1,  0xc,  0xa0,  0x2f,  0x73,  0x87,  0xd5,  0x82,  0x29,  0x14,  0xa,  0x22,  0x5d,  0x9a,  0x22,  0x2c,  0x3c,  0xb,  0x77,  0x58,  0xc8,  0xdc,  0x8c,  0xe0,  0x4a,  0x4,  0x94,  0x94,  0x2,  0xe7,  0xf9,  0x10,  0x9,  0xc6,  0x22,  0xe7,  0xcc,  0x16,  0xf0,  0xea,  0x19,  0x7d,  0xf2,  0x80,  0xdb,  0x2f,  0x9d,  0xa,  0xb0,  0xe,  0xed,  0x17,  0x35,  0x81,  0xca,  0x91,  0x23,  0x3c,  0x80,  0x7e,  0xaf,  0xc6,  0x9d,  0xf7,  0x45,  0x65,  0xda,  0xc7,  0x36,  0xb,  0x98,  0xf9,  0xfd,  0x87,  0xe3,  0xce,  0xf0,  0xa6,  0x7,  0x8,  0x97,  0xcb,  0x59,  0x28,  0xa4,  0x50,  0x84,  0x4f,  0x36,  0x61,  0xd0,  0xf3,  0x61,  0x4e,  0x12,  0x17,  0x8,  0xd7,  0xe7,  0xea,  0xd0,  0x29,  0x0,  0xa,  0x22,  0xc9,  0xd1,  0x51,  0x6d,  0x5f,  0xa8,  0x13,  0x8d,  0x43,  0xb5,  0x47,  0xdf,  0x30,  0x4d,  0x86,  0xd4,  0x1,  0xca,  0xd5,  0x2d,  0xa7,  0xe9,  0x4d,  0xd0,  0x6b,  0x98,  0xf,  0x5a,  0x30,  0xee,  0xea,  0x46,  0xa3,  0x81,  0xc9,  0x1e,  0x7e,  0x65,  0x9a,  0x71,  0xf7,  0x35,  0xb2,  0xab,  0x50,  0xf8,  0x32,  0xd,  0x6d,  0x90,  0xb9,  0x5b,  0xfa,  0x7d,  0xec,  0xa9,  0x68,  0xb7,  0x65,  0x24,  0xe4,  0xee,  0x4e,  0x45,  0x16,  0x2b,  0xa6,  0xf9,  0x6a,  0x8f,  0xde,  0x5b,  0x86,  0xaf,  0x26,  0x16,  0x5f,  0x95,  0xd7,  0xe9,  0x78,  0xa0,  0x8d,  0x3c,  0x71,  0x9b,  0x39,  0x4e,  0xc4,  0x1e,  0x37,  0x29,  0xa9,  0xfb,  0x6,  0xed,  0xd0,  0xd4,  0xa3,  0xb0,  0x66,  0x7d,  0x87,  0xae,  0xe,  0x36,  0x90,  0xde,  0xf6,  0xba,  0x63,  0x0,  0x50,  0xec,  0x9c,  0x6e,  0x2a,  0x50,  0xf8,  0xb6,  0x72,  0x30,  0x16,  0x4c,  0xcf,  0xfa,  0xc2,  0xff,  0x53,  0xee,  0xfb,  0xeb,  0x5c,  0x5f,  0xfd,  0x76,  0x32,  0xa9,  0x9,  0xcc,  0x73,  0xd6,  0x4f,  0x56,  0xf,  0xa4,  0x57,  0xe7,  0x1,  0x75,  0x96,  0x61,  0x30,  0x16,  0x61,  0x1d,  0x59,  0x2d,  0x62,  0xf6,  0xe3,  0x26,  0x12,  0xc8,  0x45,  0xd8,  0xdb,  0xb5,  0x45,  0xf3,  0x8d,  0x4d,  0xb2,  0x19,  0x21,  0xca,  0x3b,  0xe,  0x67,  0x9c,  0x86,  0x7,  0xb6,  0x90,  0x9f,  0x7c,  0x80,  0xd7,  0xa,  0xe9,  0xc7,  0x92,  0x59,  0xc0,  0xaa,  0x28,  0x99,  0x8f,  0xd9,  0x7,  0xde,  0xb5,  0x9a,  0x13,  0xed,  0x64,  0x2d,  0x53,  0x2b,  0xf0,  0x1e,  0x6c,  0x4c,  0x6b,  0x44,  0xf,  0x81,  0xee,  0x9f,  0x4e,  0xdf,  0x1,  0xd4,  0xd0,  0xe,  0x57,  0x4f,  0x5,  0x43,  0xd6,  0x8,  0xd0,  0x9c,  0xf,  0x4c,  0x24,  0x4c,  0x5d,  0xcf,  0x30,  0x6a,  0x74,  0xd5,  0x1c,  0xa9,  0xbc,  0x61,  0xb9,  0x33,  0xac,  0xe1,  0xc0,  0x43,  0xb6,  0xb,  0x91,  0x7d,  0xea,  0x40,  0xc,  0xf3,  0xeb,  0x5a,  0xc6,  0x95,  0x84,  0xae,  0x8c,  0x16,  0xec,  0x3e,  0xe1,  0x37,  0x28,  0xf3,  0x7d,  0x1,  0xa6,  0xdf,  0xb4,  0x85,  0xff,  0xca,  0xe,  0xc3,  0x86,  0x20,  0xf0,  0x3c,  0x3c,  0x11,  0x62,  0xaa,  0x72,  0xe8,  0x54,  0xe5,  0x97,  0x12,  0x93,  0x19,  0xe2,  0xbf,  0x33,  0x36,  0xd6,  0xc8,  0x30,  0xed,  0xa5,  0x37,  0x14,  0xa,  0xaf,  0x4,  0x7d,  0x7e,  0xc6,  0x7,  0xbd,  0xb2,  0xd,  0xff,  0xd0,  0x78,  0x75,  0xf2,  0xa5,  0xc7,  0x7a,  0x7e,  0xe9,  0xf7,  0x63,  0x22,  0x4e,  0x18,
    ];
}

impl<S: AttrScalars> KeyPair<S> {
    pub fn generate(sho: &mut Sho) -> Self {
        assert!(S::NUM_ATTRS >= 1, "at least one attribute required");
        assert!(
            S::NUM_ATTRS <= NUM_SUPPORTED_ATTRS,
            "more than {} attributes not supported",
            NUM_SUPPORTED_ATTRS
        );
        assert!(
            S::NUM_ATTRS <= S::Storage::LEN,
            "more attributes than storage",
        );

        let system = SystemParams::get_hardcoded();
        let w = sho.get_scalar();
        let W = w * system.G_w;
        let wprime = sho.get_scalar();
        let x0 = sho.get_scalar();
        let x1 = sho.get_scalar();

        let y = OneBased::<S::Storage>::create(|| sho.get_scalar());

        let C_W = (w * system.G_w) + (wprime * system.G_wprime);
        let mut I = system.G_V - (x0 * system.G_x0) - (x1 * system.G_x1);

        for (yn, G_yn) in y.iter().zip(system.G_y.iter()).take(S::NUM_ATTRS) {
            I -= yn * G_yn;
        }

        KeyPair {
            w,
            wprime,
            W,
            x0,
            x1,
            y,
            C_W,
            I,
        }
    }

    pub fn get_public_key(&self) -> PublicKey {
        PublicKey {
            C_W: self.C_W,
            I: self.I,
        }
    }

    fn credential_core(
        &self,
        M: &[RistrettoPoint],
        sho: &mut Sho,
    ) -> (Scalar, RistrettoPoint, RistrettoPoint) {
        assert!(
            M.len() <= S::NUM_ATTRS,
            "more than {} attributes not supported",
            S::NUM_ATTRS
        );
        let t = sho.get_scalar();
        let U = sho.get_point();

        let mut V = self.W + (self.x0 + self.x1 * t) * U;
        for (yn, Mn) in self.y.iter().zip(M) {
            V += yn * Mn;
        }
        (t, U, V)
    }
}

impl KeyPair<AuthCredential> {
    pub fn create_blinded_auth_credential(
        &self,
        public_key: auth_credential_request::PublicKey,
        ciphertext: auth_credential_request::Ciphertext,
        expiration_time: u64,
        sho: &mut Sho,
    ) -> BlindedAuthCredentialWithSecretNonce {
        let system = SystemParams::get_hardcoded();
        let expiration_time_scalar = encode_timestamp(expiration_time);
        let M = [expiration_time_scalar * system.G_m3];

        let (t, U, Vprime) = self.credential_core(&M, sho);
        let rprime = sho.get_scalar();
        let R1 = rprime * RISTRETTO_BASEPOINT_POINT;
        let R2 = rprime * public_key.Y + Vprime;
        let S1 = R1 + (self.y[2] * ciphertext.D1) + (self.y[3] * ciphertext.E1);
        let S2 = R2 + (self.y[2] * ciphertext.D2) + (self.y[3] * ciphertext.E2);
        BlindedAuthCredentialWithSecretNonce {
            rprime,
            t,
            U,
            S1,
            S2,
        }
    }
}

impl KeyPair<VoteCredential> {
    pub fn create_blinded_vote_credential(
        &self,
        public_key: vote_credential_request::PublicKey,
        ciphertext: vote_credential_request::Ciphertext,
        sho: &mut Sho,
        stake_weight: VoteStakeWeightBytes,
        topic_id: VoteTopicIDBytes,
    ) -> BlindedVoteCredentialWithSecretNonce {

        let M = [
            convert_to_point_vote_stake_weight(stake_weight),
            convert_to_point_vote_topic_id(topic_id),
        ];

        let (t, U, Vprime) = self.credential_core(&M, sho);
        let rprime = sho.get_scalar();
        let R1 = rprime * RISTRETTO_BASEPOINT_POINT;
        let R2 = rprime * public_key.Y + Vprime;
        let S1 = R1 + (self.y[3] * ciphertext.D1) + (self.y[4] * ciphertext.E1);
        let S2 = R2 + (self.y[3] * ciphertext.D2) + (self.y[4] * ciphertext.E2);
        BlindedVoteCredentialWithSecretNonce {
            rprime,
            t,
            U,
            S1,
            S2,
        }
    }
}


impl BlindedAuthCredentialWithSecretNonce {
    pub fn get_blinded_auth_credential(&self) -> BlindedAuthCredential {
        BlindedAuthCredential {
            t: self.t,
            U: self.U,
            S1: self.S1,
            S2: self.S2,
        }
    }
}

impl BlindedVoteCredentialWithSecretNonce {
    pub fn get_blinded_vote_credential(&self) -> BlindedVoteCredential {
        BlindedVoteCredential {
            t: self.t,
            U: self.U,
            S1: self.S1,
            S2: self.S2,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::common::constants::*;
    use crate::crypto::proofs;

    use super::*;

    #[test]
    fn test_system() {
        let params = SystemParams::generate();
        println!("PARAMS = {:#x?}", bincode::serialize(&params));
        assert!(SystemParams::generate() == SystemParams::get_hardcoded());
    }

    #[test]
    fn test_mac() {
        let mut sho = Sho::new(b"Test_Credentials", b"");
        let serverKeypair = KeyPair::<AuthCredential>::generate(&mut sho);
        let clientEncryptionKeyPair = auth_credential_request::KeyPair::generate(&mut sho);
        let clientPubKey = clientEncryptionKeyPair.get_public_key();

        let uid_bytes = TEST_ARRAY_16;
        let expiration_time = 1678102259;
        let uid = uid_struct::UidStruct::new(uid_bytes);

        let encryptedUID = clientEncryptionKeyPair.encrypt(uid, &mut sho);
        let ciphertext = encryptedUID.get_ciphertext();
        let blinded_auth_credential= serverKeypair.create_blinded_auth_credential(clientPubKey, ciphertext, expiration_time, &mut sho);
        


        let proof = proofs::AuthCredentialIssuanceProof::new(
            serverKeypair,
            clientPubKey,
            ciphertext,
            blinded_auth_credential,
            expiration_time,
            &mut sho,
        );

        proof.verify(
            serverKeypair.get_public_key(), 
            clientPubKey, 
            ciphertext, 
            blinded_auth_credential.get_blinded_auth_credential(),
            expiration_time)
            .unwrap();



        let mac_bytes = bincode::serialize(&blinded_auth_credential.get_blinded_auth_credential()).unwrap();

        println!("mac_bytes= {:#x?}", mac_bytes);
        assert!(
            mac_bytes
                == vec![
                    0x2e,  0xf3,  0x98,  0xf1,  0x86,  0x77,  0xc7,  0xf7,  0x24,  0x40,  0x51,  0xaf,  0xe3,  0x9,  0x9b,  0xc3,  0x6b,  0xda,  0xfc,  0x98,  0xe9,  0x33,  0xbc,  0xe4,  0x22,  0xb8,  0xf1,  0x68,  0xb8,  0x1a,  0x9b,  0xd,  0xac,  0xf0,  0xeb,  0xca,  0xeb,  0xa4,  0xf1,  0xe9,  0x67,  0x31,  0xbc,  0xa,  0xc1,  0x3b,  0xbd,  0xfa,  0x82,  0x25,  0x17,  0xb,  0x18,  0xb9,  0x14,  0xf8,  0xcd,  0x93,  0x26,  0xa3,  0x42,  0xb1,  0xd,  0x5a,  0x46,  0x3b,  0x2,  0xa3,  0xaf,  0xff,  0x13,  0xb4,  0x2b,  0x5,  0x3c,  0xe6,  0xbb,  0x92,  0x4,  0x45,  0x4,  0xe4,  0x5b,  0xb9,  0xc5,  0x23,  0xab,  0xf,  0x82,  0x4,  0xcc,  0x9d,  0xf3,  0xc1,  0x77,  0x68,  0xe0,  0x7a,  0x15,  0xcf,  0x4f,  0x50,  0x4,  0xcf,  0x73,  0xb6,  0x87,  0x5c,  0xf2,  0xeb,  0xc4,  0x5d,  0x8b,  0xcb,  0xf0,  0xc9,  0x45,  0xd6,  0x39,  0xf9,  0x5f,  0x81,  0x71,  0x7c,  0x6a,  0x9e,  0xfe,  0x28,
                ]
        );
    }

}
