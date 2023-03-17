use rand::Rng;
use zkvote::{
    RandomnessBytes, 
    crypto::{uid_struct::UidStruct, auth_credential_commitment},
    api::{auth::AuthCredentialCommitment}, VoteTypeBytes, VoteTopicIDBytes, VoteStakeWeightBytes,
};
use zkvote::common::constants::*;


#[test]
fn test_integration_auth() {
    // Server: Generate secrets 
    let mut rng = rand::thread_rng();
    let mut srv_randomness: RandomnessBytes = [0u8; RANDOMNESS_LEN];
    rng.fill(&mut srv_randomness);

    let server_secret_params = zkvote::ServerSecretParams::generate(srv_randomness);
    let server_public_params = server_secret_params.get_public_params();


    // Client: Generate random UID (equivalent to a user's private key)
    let mut uid_bytes = [0u8; 16];
    rng.fill(&mut uid_bytes);
    let uid_struct = UidStruct::new(uid_bytes);
   

    // Client: calculates commitment to its UID and saves it on the server    
    let uid_commitment  = auth_credential_commitment::CommitmentWithSecretNonce::new(
        uid_struct,
    ).get_auth_commitment();
    let uid_commitment_saved_on_server = AuthCredentialCommitment::new(uid_commitment);

    // Client: Calculate auth credential request context
    let mut auth_req_context_randomness: RandomnessBytes = [0u8; RANDOMNESS_LEN]; 
    rng.fill(&mut auth_req_context_randomness);
    let auth_req_context = server_public_params.create_auth_credential_request_context(auth_req_context_randomness, uid_bytes);

    // Client: sends auth_req_obj to the server
    let auth_req_obj = auth_req_context.get_request();

    // Server: checks if the commitment present on the auth_req_obj is equal to the one saved on server
    let credential_expiration_time = 1678257735; // requested time_stamp + how_long_token_should_be valid
    let mut srv_auth_randomness: RandomnessBytes = [0u8; RANDOMNESS_LEN];
    rng.fill(& mut srv_auth_randomness);
    let auth_cred_response = server_secret_params.issue_auth_credential(srv_auth_randomness, &auth_req_obj, uid_commitment_saved_on_server, credential_expiration_time);

    // Client: verifies response of the auth credential request and extracts auth credential
    let auth_credential = server_public_params.receive_auth_credential(&auth_req_context, &auth_cred_response.unwrap()).unwrap();

            // Optional: when needed, client can present this auth credential to prove his authenticity. Following block shows how. can be skipped for current anonymous voting use case
            // Client: present auth_credential

            let mut client_randomness: RandomnessBytes = [0u8; RANDOMNESS_LEN];
            rng.fill(&mut client_randomness);

            let master_key = zkvote::groups::GroupMasterKey::new(client_randomness);
            let client_secret_params = zkvote::groups::GroupSecretParams::derive_from_master_key(master_key);
            let client_public_params = client_secret_params.get_public_params();
            
            let auth_presentation = server_public_params.create_auth_credential_presentation(client_secret_params, auth_credential);
            let current_time_in_seconds = credential_expiration_time - 100;
            
            // Server: verifies that the auth credential is okay
            server_secret_params.verify_auth_credential_presentation(
                client_public_params,
                &auth_presentation,
                current_time_in_seconds
            ).unwrap();
    
    // SO FAR, we have time limited auth credential
    // now we use this token to fetch a vote credential
    // Client: creates a request context
    let mut vote_req_context_randomness: RandomnessBytes = [0u8; RANDOMNESS_LEN]; 
    rng.fill(&mut vote_req_context_randomness);

    let vote_type: VoteTypeBytes = [1]; // 1 -> yes, 0 -> no, 2 -> sth_else, etc..
    let topic_id: VoteTopicIDBytes = *b"proposal___topic";
    let stake_weight: VoteStakeWeightBytes = *b"0x00000000000000000000001a2fced4"; // vote credential of how much stake (< total)
    let vote_req_context = server_public_params.create_vote_credential_request_context(vote_req_context_randomness, vote_type, topic_id, stake_weight, auth_presentation);


    // Client: sends auth_req_obj to the server
    let vote_req_obj = vote_req_context.get_request();


    // Server: issues vote credential for the request
    let mut srv_vote_randomness: RandomnessBytes = [0u8; RANDOMNESS_LEN];
    rng.fill(& mut srv_vote_randomness);
    let vote_credential_response = server_secret_params.issue_vote_credential(srv_vote_randomness, &vote_req_obj, topic_id, client_public_params);

    // Client: verifies response of the vote credential request and extracts vote credential
    let vote_credential = server_public_params.receive_vote_credential(&vote_req_context, &vote_credential_response.unwrap()).unwrap();

    
    // Client: presents the credential
    let mut srv_vote_present_randomness: RandomnessBytes = [0u8; RANDOMNESS_LEN];
    rng.fill(& mut srv_vote_present_randomness);
    let vote_presentation = server_public_params.create_vote_credential_presentation(
        srv_vote_randomness,
        vote_credential,
    );

    // // Sserver: verfies that the submitted credential is okay
    server_secret_params.verify_vote_credential_presentation(&vote_presentation).unwrap();


}

