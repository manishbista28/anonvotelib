#![allow(non_snake_case)]

use crate::common::constants::*;
use crate::common::sho::*;
use crate::common::simple_types::*;
use crate::crypto::uid_struct;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use serde::{Deserialize, Serialize};

use lazy_static::lazy_static;

lazy_static! {
    static ref SYSTEM_PARAMS: SystemParams =
        bincode::deserialize::<SystemParams>(&SystemParams::SYSTEM_HARDCODED).unwrap();
}

#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemParams {
    pub(crate) G_j1: RistrettoPoint,
    pub(crate) G_j2: RistrettoPoint,
    pub(crate) G_j3: RistrettoPoint,
}

#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitmentWithSecretNonce {
    pub(crate) J1: RistrettoPoint,
    pub(crate) J2: RistrettoPoint,
    pub(crate) J3: RistrettoPoint,
    pub(crate) j3: Scalar,
}

#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Commitment {
    pub(crate) J1: RistrettoPoint,
    pub(crate) J2: RistrettoPoint,
    pub(crate) J3: RistrettoPoint,
}

impl SystemParams {
    pub fn generate() -> Self {
        let mut sho = Sho::new(
            b"LibVoting_zkvote_20230306_Constant_AuthCommitment_SystemParams_Generate",
            b"",
        );
        let G_j1 = sho.get_point();
        let G_j2 = sho.get_point();
        let G_j3 = sho.get_point();
        SystemParams { G_j1, G_j2, G_j3 }
    }

    pub fn get_hardcoded() -> SystemParams {
        *SYSTEM_PARAMS
    }

    const SYSTEM_HARDCODED: [u8; 96] = [
        0x6,  0xc1,  0x51,  0x47,  0xf2,  0xf2,  0x16,  0xe0,  0x89,  0x31,  0x5a,  0xce,  0x51,  0xa6,  0xc2,  0x82,  0x76,  
        0x19,  0xe1,  0xae,  0xa3,  0x6b,  0x9c,  0xbd,  0x5e,  0x87,  0xd2,  0x1d,  0x8c,  0xf9,  0x16,  0x76,  0x58,  0x71,  
        0x18,  0x77,  0xb9,  0x47,  0xb8,  0xbb,  0x7d,  0xfa,  0xf1,  0x3,  0x25,  0x9d,  0xc7,  0x11,  0x7f,  0x50,  0xd4, 
        0x2c,  0xa4,  0x8d,  0x51,  0xcd,  0x6d,  0xa2,  0x40,  0x47,  0x4a,  0x2b,  0xcf,  0x33,  0x94,  0x4c,  0xd3,  0x5,
        0x66,  0xf7,  0x31,  0x80,  0xa5,  0xef,  0x3b,  0xe7,  0x61,  0x3e,  0x3b,  0xe7,  0x2d,  0x6e,  0x5f,  0xb5,  0x88,  
        0x89,  0x86,  0x67,  0x77,  0x16,  0xd3,  0xd2,  0xd7,  0x96,  0xa0,  0x51,
    ];
}

impl CommitmentWithSecretNonce {
    pub fn new(
        uid_key: uid_struct::UidStruct,
    ) -> CommitmentWithSecretNonce {
        let commitment_system = SystemParams::get_hardcoded();

        let uid_struct::UidStruct { M1, M2, bytes } = uid_key;
        let j3 = Self::calc_j3(bytes);
        let J1 = (j3 * commitment_system.G_j1) + M1;
        let J2 = (j3 * commitment_system.G_j2) + M2;
        let J3 = j3 * commitment_system.G_j3;
        CommitmentWithSecretNonce { J1, J2, J3, j3 }
    }

    pub fn get_profile_key_commitment(&self) -> Commitment {
        Commitment {
            J1: self.J1,
            J2: self.J2,
            J3: self.J3,
        }
    }

    pub fn calc_j3(uid_bytes: UidBytes) -> Scalar {
        let mut combined_array = [0u8; UUID_LEN];
        combined_array[..UUID_LEN].copy_from_slice(&uid_bytes);
        Sho::new(
            b"LibVoting_zkvote_20230306_UidBytes_UIDCommitment_Calcj3",
            &combined_array,
        )
        .get_scalar()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_system() {
        let params = SystemParams::generate();
        println!("PARAMS = {:#x?}", bincode::serialize(&params));
        assert!(SystemParams::generate() == SystemParams::get_hardcoded());
    }

    #[test]
    fn test_commitment() {
        let uid = uid_struct::UidStruct::new(TEST_ARRAY_16);
        let c1 = CommitmentWithSecretNonce::new(uid);
        let c2 = CommitmentWithSecretNonce::new(uid);
        assert!(c1 == c2);
    }
}
