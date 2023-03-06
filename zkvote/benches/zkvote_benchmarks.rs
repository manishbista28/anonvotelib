//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use criterion::{criterion_group, criterion_main, Criterion};

extern crate zkvote;

fn benchmark_integration_auth(c: &mut Criterion) {
    // let server_secret_params = zkvote::ServerSecretParams::generate(zkvote::TEST_ARRAY_32);
    // let server_public_params = server_secret_params.get_public_params();

    // let master_key = zkvote::groups::GroupMasterKey::new(zkvote::TEST_ARRAY_32_1);
    // let group_secret_params =
    //     zkvote::groups::GroupSecretParams::derive_from_master_key(master_key);
    // let group_public_params = group_secret_params.get_public_params();

    // let uid = zkvote::TEST_ARRAY_16;
    // let redemption_time = 123456u32;

    // let randomness = zkvote::TEST_ARRAY_32_2;
    // let auth_credential_response =
    //     server_secret_params.issue_auth_credential(randomness, uid, redemption_time);

    // c.bench_function("issue_auth_credential", |b| {
    //     b.iter(|| server_secret_params.issue_auth_credential(randomness, uid, redemption_time))
    // });

    // let auth_credential = server_public_params
    //     .receive_auth_credential(uid, redemption_time, &auth_credential_response)
    //     .unwrap();

    // c.bench_function("receive_auth_credential", |b| {
    //     b.iter(|| {
    //         server_public_params
    //             .receive_auth_credential(uid, redemption_time, &auth_credential_response)
    //             .unwrap()
    //     })
    // });

    // let uuid_ciphertext = group_secret_params.encrypt_uuid(uid);
    // let plaintext = group_secret_params.decrypt_uuid(uuid_ciphertext).unwrap();
    // assert!(plaintext == uid);

    // let randomness = zkvote::TEST_ARRAY_32_5;

    // let presentation_v2 = server_public_params.create_auth_credential_presentation_v2(
    //     randomness,
    //     group_secret_params,
    //     auth_credential,
    // );

    // c.bench_function("create_auth_credential_presentation_v2", |b| {
    //     b.iter(|| {
    //         server_public_params.create_auth_credential_presentation_v2(
    //             randomness,
    //             group_secret_params,
    //             auth_credential,
    //         )
    //     })
    // });

    // let _presentation_bytes = &bincode::serialize(&presentation_v2).unwrap();


    // c.bench_function("verify_auth_credential_presentation_v2", |b| {
    //     b.iter(|| {
    //         server_secret_params
    //             .verify_auth_credential_presentation_v2(
    //                 group_public_params,
    //                 &presentation_v2,
    //                 redemption_time,
    //             )
    //             .unwrap();
    //     })
    // });
}


criterion_group!(
    benches,
    benchmark_integration_auth
);
criterion_main!(benches);
