//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::common::simple_types::*;
use crate::crypto;
use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, Serialize, Deserialize)]
pub struct VoteCredential {
    pub(crate) reserved: ReservedBytes,
    pub(crate) credential: crypto::credentials::VoteCredential,
    pub(crate) vote_type: VoteTypeBytes,
    pub(crate) vote_id: VoteUniqIDBytes,
    pub(crate) stake_weight: VoteStakeWeightBytes,
    pub(crate) topic_id: VoteTopicIDBytes,
}
