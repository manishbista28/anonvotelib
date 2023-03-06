#![allow(non_snake_case)]

use crate::common::errors::*;
use crate::common::sho::*;
use crate::common::simple_types::*;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use crate::crypto::vote_struct;

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use serde::{Deserialize, Serialize};

use curve25519_dalek::subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

use lazy_static::lazy_static;

lazy_static! {
    static ref SYSTEM_PARAMS: SystemParams =
        bincode::deserialize::<SystemParams>(&SystemParams::SYSTEM_HARDCODED).unwrap();
}

#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemParams {
    pub(crate) G_b1: RistrettoPoint,
    pub(crate) G_b2: RistrettoPoint,
}

#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyPair {
    pub(crate) b1: Scalar,
    pub(crate) b2: Scalar,
    pub(crate) B: RistrettoPoint,
}

#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKey {
    pub(crate) B: RistrettoPoint,
}

#[derive(Copy, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ciphertext {
    pub(crate) E_B1: RistrettoPoint,
    pub(crate) E_B2: RistrettoPoint,
}

impl SystemParams {
    pub fn generate() -> Self {
        let mut sho = Sho::new(
            b"Signal_ZKGroup_20200424_Constant_ProfileKeyEncryption_SystemParams_Generate",
            b"",
        );
        let G_b1 = sho.get_point();
        let G_b2 = sho.get_point();
        SystemParams { G_b1, G_b2 }
    }

    pub fn get_hardcoded() -> SystemParams {
        *SYSTEM_PARAMS
    }

    const SYSTEM_HARDCODED: [u8; 64] = [
        0xf6, 0xba, 0xa3, 0x17, 0xce, 0x18, 0x39, 0xc9, 0x3d, 0x61, 0x7e, 0xc, 0xd8, 0x37, 0xd1,
        0x9d, 0xa9, 0xc8, 0xa4, 0xc5, 0x20, 0xbf, 0x7c, 0x51, 0xb1, 0xe6, 0xc2, 0xcb, 0x2a, 0x4,
        0x9c, 0x61, 0x2e, 0x1, 0x75, 0x89, 0x4c, 0x87, 0x30, 0xb2, 0x3, 0xab, 0x3b, 0xd9, 0x8e,
        0xcb, 0x2d, 0x81, 0xab, 0xac, 0xb6, 0x5f, 0x8a, 0x61, 0x24, 0xf4, 0x97, 0x71, 0xd1, 0x4a,
        0x98, 0x52, 0x12, 0xc,
    ];
}

impl KeyPair {
    pub fn derive_from(sho: &mut Sho) -> Self {
        let system = SystemParams::get_hardcoded();

        let b1 = sho.get_scalar();
        let b2 = sho.get_scalar();

        let B = b1 * system.G_b1 + b2 * system.G_b2;
        KeyPair { b1, b2, B }
    }

    pub fn get_public_key(&self) -> PublicKey {
        PublicKey { B: self.B }
    }

    pub fn encrypt(&self, vote_struct: vote_struct::VoteStruct) -> Ciphertext {
        let E_B1 = self.b1 * vote_struct.M2;
        let E_B2 = (self.b2 * E_B1) + vote_struct.M1;
        Ciphertext { E_B1, E_B2}
    }

    #[allow(clippy::needless_range_loop)]
    pub fn decrypt(
        &self,
        ciphertext: Ciphertext,
        uid_bytes: UidBytes,
        division_bytes: ProfileKeyBytes, 
        identifier_bytes: ProfileKeyBytes,
    ) -> Result<vote_struct::VoteStruct, ZkGroupVerificationFailure> {
        if ciphertext.E_B1 == RISTRETTO_BASEPOINT_POINT {
            return Err(ZkGroupVerificationFailure);
        }
        let M1 = ciphertext.E_B2 - (self.b2 * ciphertext.E_B1);
        let (mask, candidates) = M1.decode_253_bits();

        let target_M2 = self.b1.invert() * ciphertext.E_B1;

        let mut retval: vote_struct::VoteStruct = Default::default();
        let mut n_found = 0;
        for i in 0..8 {
            let is_valid_fe = Choice::from((mask >> i) & 1);
            let profile_key_bytes: ProfileKeyBytes = candidates[i];
            for j in 0..8 {
                let mut pk = profile_key_bytes;
                if ((j >> 2) & 1) == 1 {
                    pk[0] |= 0x01;
                }
                if ((j >> 1) & 1) == 1 {
                    pk[31] |= 0x80;
                }
                if (j & 1) == 1 {
                    pk[31] |= 0x40;
                }
                let M2 = vote_struct::VoteStruct::calc_combined(pk, uid_bytes);
                let candidate_retval = vote_struct::VoteStruct::from_partial_data(division_bytes, pk, identifier_bytes, M1, M2);
                let found = M2.ct_eq(&target_M2) & is_valid_fe;
                retval.conditional_assign(&candidate_retval, found);
                n_found += found.unwrap_u8();
            }
        }
        if n_found == 1 {
            Ok(retval)
        } else {
            Err(ZkGroupVerificationFailure)
        }
    }

}