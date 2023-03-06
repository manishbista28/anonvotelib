//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#[derive(Debug, displaydoc::Display)]
/// Verification failure in zkvote
pub struct ZkGroupVerificationFailure;

#[derive(Debug, displaydoc::Display)]
/// Deserialization failure in zkvote
pub struct ZkGroupDeserializationFailure;
