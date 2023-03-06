#![allow(non_snake_case)]

use crate::common::sho::*;
use crate::crypto::credentials::{
    BlindedAuthCredential, AuthCredential,
};
use crate::crypto::uid_struct;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyPair {
    // private
    pub(crate) y: Scalar,

    // public
    pub(crate) Y: RistrettoPoint,
}

#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKey {
    pub(crate) Y: RistrettoPoint,
}

#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CiphertextWithSecretNonce {
    pub(crate) r1: Scalar,
    pub(crate) r2: Scalar,
    pub(crate) D1: RistrettoPoint,
    pub(crate) D2: RistrettoPoint,
    pub(crate) E1: RistrettoPoint,
    pub(crate) E2: RistrettoPoint,
}

#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ciphertext {
    pub(crate) D1: RistrettoPoint,
    pub(crate) D2: RistrettoPoint,
    pub(crate) E1: RistrettoPoint,
    pub(crate) E2: RistrettoPoint,
}

impl KeyPair {
    pub fn generate(sho: &mut Sho) -> Self {
        let y = sho.get_scalar();
        let Y = y * RISTRETTO_BASEPOINT_POINT;
        KeyPair { y, Y }
    }

    pub fn get_public_key(&self) -> PublicKey {
        PublicKey { Y: self.Y }
    }

    pub fn encrypt(
        &self,
        uid_struct: uid_struct::UidStruct,
        sho: &mut Sho,
    ) -> CiphertextWithSecretNonce {
        let r1 = sho.get_scalar();
        let r2 = sho.get_scalar();
        let D1 = r1 * RISTRETTO_BASEPOINT_POINT;
        let E1 = r2 * RISTRETTO_BASEPOINT_POINT;

        let D2 = r1 * (self.Y) + uid_struct.M1;
        let E2 = r2 * (self.Y) + uid_struct.M2;

        CiphertextWithSecretNonce {
            r1,
            r2,
            D1,
            D2,
            E1,
            E2,
        }
    }

    pub fn decrypt_blinded_auth_credential(
        &self,
        blinded_auth_credential: BlindedAuthCredential,
    ) -> AuthCredential {
        let V = blinded_auth_credential.S2 - self.y * blinded_auth_credential.S1;
        AuthCredential {
            t: blinded_auth_credential.t,
            U: blinded_auth_credential.U,
            V,
        }
    }

}

impl CiphertextWithSecretNonce {
    pub fn get_ciphertext(&self) -> Ciphertext {
        Ciphertext {
            D1: self.D1,
            D2: self.D2,
            E1: self.E1,
            E2: self.E2,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::constants::*;

    #[test]
    fn test_key_pair_generation() {
        let mut sho = Sho::new(b"Test_Profile_Key_Credential_Request", b"");

        let blind_key_pair = KeyPair::generate(&mut sho);
        let calculated_base_point = blind_key_pair.y.invert() * blind_key_pair.Y;

        // Y = yG => G = y_inv * Y        
        assert_eq!(calculated_base_point, RISTRETTO_BASEPOINT_POINT);
    
        let mut sho = Sho::new(b"Test_Profile_Key_Credential_Request", b"new_randomness");
        let new_blind_key_pair = KeyPair::generate(&mut sho);
        // new randomness => new keypair
        assert_ne!(bincode::serialize(&blind_key_pair).unwrap(), bincode::serialize(&new_blind_key_pair).unwrap());
    }

    #[test]
    fn test_uid_encryption() {
        let mut sho = Sho::new(b"Test_Profile_Key_Credential_Request", b"");
        let blind_key_pair = KeyPair::generate(&mut sho);
        let uid_struct = uid_struct::UidStruct::new( TEST_ARRAY_16);

        let _ = blind_key_pair.encrypt(uid_struct, &mut sho);
        
    }
}
