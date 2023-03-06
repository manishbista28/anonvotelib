//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::common::simple_types::*;
use crate::crypto;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct AuthCredentialResponse {
    pub(crate) reserved: ReservedBytes,
    pub(crate) blinded_credential: crypto::credentials::BlindedAuthCredential,
    pub(crate) proof: crypto::proofs::AuthCredentialIssuanceProof,
    pub(crate) expiration_time: u64,
}
