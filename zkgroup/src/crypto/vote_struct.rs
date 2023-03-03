
#![allow(non_snake_case)]


use crate::common::constants::*;
use crate::common::sho::*;
use crate::common::simple_types::*;
use curve25519_dalek::ristretto::RistrettoPoint;
use serde::{Deserialize, Serialize};

use curve25519_dalek::subtle::{Choice, ConditionallySelectable};


#[derive(Copy, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VoteStruct {
    pub(crate) type_bytes: ProfileKeyBytes,     // encrypted form of vote (yes no pass)
    pub(crate) division_bytes: ProfileKeyBytes, // plain text: break down of total stakes into multiple credentials
    pub(crate) identifier_bytes: ProfileKeyBytes,  // plain text: voting identifier/topic/cycle
    pub(crate) M1: RistrettoPoint,
    pub(crate) M2: RistrettoPoint,
    pub(crate) M3: RistrettoPoint,
    pub(crate) M4: RistrettoPoint,
}

impl VoteStruct {
    pub fn new(uid_bytes: UidBytes, division_bytes: ProfileKeyBytes, type_bytes: ProfileKeyBytes, identifier_bytes: ProfileKeyBytes) -> Self {
        let mut encoded_type_bytes = type_bytes;
        encoded_type_bytes[0] &= 254;
        encoded_type_bytes[31] &= 63;
        let M1 = RistrettoPoint::from_uniform_bytes_single_elligator(&encoded_type_bytes);
        let M2 = Self::calc_combined(type_bytes, uid_bytes);

        let mut encoded_division_bytes = division_bytes;
        encoded_division_bytes[0] &= 254;
        encoded_division_bytes[31] &= 63;
        let M3 = RistrettoPoint::from_uniform_bytes_single_elligator(&encoded_division_bytes);

        let mut encoded_identifier_bytes = identifier_bytes;
        encoded_identifier_bytes[0] &= 254;
        encoded_identifier_bytes[31] &= 63;
        let M4 = RistrettoPoint::from_uniform_bytes_single_elligator(&encoded_identifier_bytes);

        VoteStruct {
            type_bytes,
            division_bytes,
            identifier_bytes,
            M1,
            M2,
            M3,
            M4
        }
    }

    pub fn from_partial_data(uid_bytes: UidBytes, division_bytes: ProfileKeyBytes, type_bytes: ProfileKeyBytes, identifier_bytes: ProfileKeyBytes, M1: RistrettoPoint, M2: RistrettoPoint) -> Self {
        let mut encoded_division_bytes = division_bytes;
        encoded_division_bytes[0] &= 254;
        encoded_division_bytes[31] &= 63;
        let M3 = RistrettoPoint::from_uniform_bytes_single_elligator(&encoded_division_bytes);

        let mut encoded_identifier_bytes = identifier_bytes;
        encoded_identifier_bytes[0] &= 254;
        encoded_identifier_bytes[31] &= 63;
        let M4 = RistrettoPoint::from_uniform_bytes_single_elligator(&encoded_identifier_bytes);

        VoteStruct {
            type_bytes,
            division_bytes,
            identifier_bytes,
            M1,
            M2,
            M3,
            M4
        }
    }

    pub fn calc_combined(src: ProfileKeyBytes, uid_bytes: UidBytes) -> RistrettoPoint {
        let mut combined_array = [0u8; PROFILE_KEY_LEN + UUID_LEN];
        combined_array[..PROFILE_KEY_LEN].copy_from_slice(&src);
        combined_array[PROFILE_KEY_LEN..].copy_from_slice(&uid_bytes);
        Sho::new(
            b"Signal_ZKGroup_20200424_ProfileKeyAndUid_ProfileKey_CalcM56",
            &combined_array,
        )
        .get_point_single_elligator()
    }
}


impl ConditionallySelectable for VoteStruct {
    #[allow(clippy::needless_range_loop)]
    fn conditional_select(
        a: &VoteStruct,
        b: &VoteStruct,
        choice: Choice,
    ) -> VoteStruct {
        let mut type_bytes: ProfileKeyBytes = [0u8; PROFILE_KEY_LEN];
        let mut division_bytes: ProfileKeyBytes = [0u8; PROFILE_KEY_LEN];
        let mut identifier_bytes: ProfileKeyBytes = [0u8; PROFILE_KEY_LEN];
        for i in 0..PROFILE_KEY_LEN {
            type_bytes[i] = u8::conditional_select(&a.type_bytes[i], &b.type_bytes[i], choice);
            division_bytes[i] = u8::conditional_select(&a.division_bytes[i], &b.division_bytes[i], choice);
            identifier_bytes[i] = u8::conditional_select(&a.identifier_bytes[i], &b.identifier_bytes[i], choice);
        }

        VoteStruct {
            type_bytes,
            division_bytes,
            identifier_bytes,
            M1: RistrettoPoint::conditional_select(&a.M1, &b.M1, choice),
            M2: RistrettoPoint::conditional_select(&a.M2, &b.M2, choice),
            M3: RistrettoPoint::conditional_select(&a.M3, &b.M3, choice),
            M4: RistrettoPoint::conditional_select(&a.M4, &b.M4, choice),
        }
    }
}
