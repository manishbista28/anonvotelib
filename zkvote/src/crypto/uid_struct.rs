//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![allow(non_snake_case)]

use crate::common::sho::*;
use crate::common::simple_types::*;
use curve25519_dalek::ristretto::RistrettoPoint;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UidStruct {
    pub(crate) bytes: UidBytes,
    pub(crate) M2: RistrettoPoint,
    pub(crate) M3: RistrettoPoint,
}

pub struct PointDecodeFailure;

impl UidStruct {
    pub fn new(uid_bytes: UidBytes) -> Self {
        let mut sho = Sho::new(b"LibVote_zkvote_20230306_UID_CalcM1", &uid_bytes);
        let M2 = sho.get_point();
        let M3 = RistrettoPoint::lizard_encode::<Sha256>(&uid_bytes);

        UidStruct {
            bytes: uid_bytes,
            M2,
            M3,
        }
    }

    pub fn from_M3(M3: RistrettoPoint) -> Result<Self, PointDecodeFailure> {
        match M3.lizard_decode::<Sha256>() {
            None => Err(PointDecodeFailure),
            Some(bytes) => Ok(Self::new(bytes)),
        }
    }

    pub fn to_bytes(&self) -> UidBytes {
        self.bytes
    }
}
