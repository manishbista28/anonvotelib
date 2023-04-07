## Overview

anonvotelib implements core logic for anonymous voting and exposes a set of APIs that can be used by client and server applications to fully realize the use case.


The basic requirement of any anonymous voting application is to cast vote such that this process can not be traced back to identify the user later on. In certain applications, the voting power (or weight) can be different between users. For example, a user's voting power can be commensurate with how much a user has staked (or invested) on an investment. Anonymous voting, in such *staked-voting* case, also needs to determine ways to ensure this factor does not aid in revealing the user. 


To meet these requirements, and few other secondary ones, this library implements a protocol using [Keyed-Verification Anonymous Credentials](https://eprint.iacr.org/2013/516), whose integral assumption is that issuer and verifier of a credential (here, voting credential) is the same entity (or entities that share a common secret value). To elaborate, a user could prove his identity and show a proof of eligiblity to a server, which will then provide the user with a voting credential. This voting credential has no user-identifiable value but holds all information necessary to cast the vote. The user can later present this voting credential anonymously to cast the vote. 


The library's implementation is inspired from and makes use of Signal messaging app's [core library](https://github.com/signalapp/libsignal). Additionally, it uses Brave's [STAR protocol](https://github.com/brave/sta-rs) for threshold aggregation of cast votes. Thanks to the Signal and Brave team for making their project open-source.

## Protocol at a high level

The basic set of steps is as follows:

1. Server Requirements:

    Initially, the server holds a list of public keys (public identifiers) for each users and a value corresponding to their voting weight (proportional to stake). It is assumed a secure mutually authenticated channel for communication between a user and the server is present. This can be implemented either through mTLS or through messages encrypted with each others' public keys stored on a commonly accessible storage medium. 

2. User Requirements:

    Each of the users have a private key corresponding to the public key registered on the server. For a user to prove his identity to the server, he needs to provide or prove knowledge of secret identifier (e.g. passwords). So the user, at first, generates a 16 byte ephemeral secret key and provides its Pedersen commitment to the server. This can be done through mutually authenticated channels. With this, the server will now hold the tuple (Public Key, Pedersen Commitment of Ephemeral Key, Total Voting Weight) for its list of voters.

3. User generates Authentication Credential.
    
    An authentication credential is proof of identity alongside other relevant attributes (e.g. validity period of the credential). The credential can be used alongside any other use case to prove authenticity and the credential itself can be submitted such that user identifiable information is masked yet the credential can be verified by the verifier. Presenting authentication credential instead of repeatedly authenticating over every interaction has both performance benefits and is a better way because of modularization of credentials.

    To start, the user creates a request to obtain authentication credential. The request proves, using zero-knowledge proof, that the user has a secret value whose Pedersen commitment is registered on the set of users. Alongside the commitment, the user also submits an encrypted value of this ephemeral secret. 
    
    The server receives the client submitted secret and verifies that the ciphertext is indeed an encryption of a secret whose commitment is of a registered user. The server then encodes this cipher text along with a credential validity period (or any other necessary attribute) to form the authentication credential and then passes it to the client. 
    
    The client now processes the response to decrypt the ephemeral secret and will have in possession an authentication credential equivalent to the one he would have had if he had submitted ephemeral secret in plain text and server had issued him a credential without checking the ephemeral secret's value.

    As such, an authentication credential encodes values unique to the user and serves to prove: one who holds this credential is a registered user and only he who possesses the ephemeral secret for this user shall be able to use it. The user can just present this credential and the server will not have to do any identity lookups.


4. User generates Voting Credential

    A voting credential is equivalent to a token that can be submitted to cast a vote. So it should embed necessary attributes like the topic (or proposal) of the voting request for, the weight of staked-voting, preference (yes, no, abstain), credential identifer or vote-id to avoid double votes. 

    To start, the user creates a request to obtain voting credential. The request includes a presentation of authentication credential calculated above and the user's public identifier. The public identifier is used to fetch how much total voting weight the user possesses. The request includes claimed voting-weight and voting topic in plain text, while voting preference and voting identifier is present in encrypted form.

    The server verifies authentication credential and the validity of voting-weight and voting topic. If all is well, the server encodes all of these voting attributes to form a voting credential and then passes it to the client.

    The client decrypts attributes it had encrypted and obtains the necessary voting credential, which does not have any attribute that ties back to user identity. *Note* that the voting-weight should not be unique, as the server can trace identity through the uniqueness later on. Since the protocol supports multiple voting credentials of different weights, the user can choose a value that other users have chosen to mask the uniqueness. This is equivalent to a transaction mixer. An honest server can even suggest values for vote-weight that user's can use to obfuscate.

6. User presents Voting Credential(s) to cast vote

    As mentioned above, the user can possess multiple voting credentials each with different voting-weights, preference, etc. These credentials can be submitted anonymously (through different IPs and accounts). Additionally, the attributes themselves can be provided to the server in an encrypted form. These encrypted attributes can only be decrypted by the server when a certain pre-specified number of such unique submissions is received. This ensures that neither the server nor or other users will be susceptible to any bias based on attributes of votes already cast. After the threshold is met and decryption key can be extracted by the server, it can now decipher the attributes of credential, which it had verified before and publish the results. 


The protocol has the benefit of being flexible. Different attributes necessary for a credential can be added and removed if necessary. Attributes can be encrypted or submitted in plain text. Multiple credentials can be issued and verified separately making modular implementations possible and composed later efficiently to make more complex processes possible.

It is also generic in the sense that credential issuance and verification can be applied to other use cases e.g. Signal's private group system. As such the learnings here open up possibilities for a broader range of use cases.

## Limitations

For secret sharing scheme, which is used to encrypt attributes during credential presentation, to work, the users need to have knowledge of a *common secret string* that the server is not aware of. Additionally, this *common secret string* needs to be different between voting rounds. One way to do so, is to first establish a  group secret through any secure medium. Generating a hash of this group secret and vote subject identifier will yield a different *common secret string* every time. This approach requires a single group communication at the start and the server itself will not be able to determine the seed phrase used.

## Folder structure

poksho: Signal's [poksho](https://github.com/signalapp/libsignal/tree/main/rust/poksho) package that includes implementation of Sigma protocol for zero-knowledge proofs.

zkvote: Implements functionality specific to anonymous voting and exposes APIs.




## Building

Clone the repository, build and run tests. 

```sh
cd zkvote
cargo build
cargo test
```

[Integration-test](https://github.com/manishbista28/anonvotelib/blob/main/zkvote/tests/integration_tests.rs) includes a basic follow through of necessary APIs to issue and cast a vote.