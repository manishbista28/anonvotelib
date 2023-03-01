//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::common::constants::*;
use crate::common::errors::*;
use crate::common::simple_types::*;
use crate::{crypto};
use serde::{Deserialize, Serialize, Serializer};

#[derive(Serialize, Deserialize)]
pub struct AuthCredentialPresentationV2 {
    pub(crate) version: ReservedBytes,
    pub(crate) proof: crypto::proofs::AuthCredentialPresentationProofV2,
    pub(crate) ciphertext: crypto::uid_encryption::Ciphertext,
    pub(crate) redemption_time: CoarseRedemptionTime,
}

impl AuthCredentialPresentationV2 {
    // pub fn get_uuid_ciphertext(&self) -> api::groups::UuidCiphertext {
    //     api::groups::UuidCiphertext {
    //         reserved: Default::default(),
    //         ciphertext: self.ciphertext,
    //     }
    // }

    pub fn get_redemption_time(&self) -> CoarseRedemptionTime {
        self.redemption_time
    }
}


#[allow(clippy::large_enum_variant)]
pub enum AnyAuthCredentialPresentation {
    V2(AuthCredentialPresentationV2),
}

impl AnyAuthCredentialPresentation {
    pub fn new(presentation_bytes: &[u8]) -> Result<Self, ZkGroupDeserializationFailure> {
        match presentation_bytes[0] {
            PRESENTATION_VERSION_2 => {
                match bincode::deserialize::<AuthCredentialPresentationV2>(presentation_bytes) {
                    Ok(presentation) => Ok(AnyAuthCredentialPresentation::V2(presentation)),
                    Err(_) => Err(ZkGroupDeserializationFailure),
                }
            }
            _ => Err(ZkGroupDeserializationFailure),
        }
    }

    // pub fn get_uuid_ciphertext(&self) -> api::groups::UuidCiphertext {
    //     match self {
    //         AnyAuthCredentialPresentation::V2(presentation) => presentation.get_uuid_ciphertext(),
    //         AnyAuthCredentialPresentation::V3(presentation) => presentation.get_aci_ciphertext(),
    //     }
    // }

    pub fn get_redemption_time(&self) -> Timestamp {
        match self {
            AnyAuthCredentialPresentation::V2(presentation) => {
                u64::from(presentation.get_redemption_time()) * SECONDS_PER_DAY
            }
        }
    }
}

impl Serialize for AnyAuthCredentialPresentation {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            AnyAuthCredentialPresentation::V2(presentation) => presentation.serialize(serializer),
        }
    }
}

impl From<AuthCredentialPresentationV2> for AnyAuthCredentialPresentation {
    fn from(presentation: AuthCredentialPresentationV2) -> Self {
        Self::V2(presentation)
    }
}
