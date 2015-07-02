Time Capsule Encryption Network
============================
Design Documentation and Protocol Specification
============================

## Introduction

This protocol provides for the generation of public encryption keys labeled with contracts that guarantee publication
of the corresponding private key at a later date. Using these keys, messages can be sent "into the future" so they
cannot be read until the contract date.

In particular, this protocol generates OpenPGP keys with contracts embedded in the user ID comment field, in the form:

    {
        "state_digest": <digest>, 
        "uuid": <uuid>, 
        "contract": {
            "release_date": "2015-06-25T21:12:33.652483+00:00", 
            "recovery_threshold": recovery_threshold, 
            "share_count": share_count
        }
    }

A valid key must be signed by `share_count` Trustees, who are known and trusted by the user of the key. Each signature indicates 
that a given Trustee has followed this protocol in generating and verifying the public key, and will release their share
of the private key on the `release_date`.

As long as at least `recovery_threshold` Trustees: (a) follow the protocol, (c) safeguard their private key material until the
`release_date`, and (c) publish their private key material on `release_date`, this protocol guarantees that the private 
key *will not* be available before `release_date` and *will* be available after.

## Definitions

### Parties

The `user` is a person who wishes to download a public key with a contract attached for later release of the private key.

The `Trustees` are independent keyholders, trusted by the user to enforce the contract.

The `Coordinator` coordinates key generation and provides user access to generated keys, but has no special access to 
key material and need not be trusted by the user.

### Magic numbers

The Trustees share a set of predefined, public constants:

- `p` is a 4096-bit "safe" prime.
- `q` is the prime equal to `(p-1)/2`.
- `g` is a generator in `p` of prime order `q`.

## Protocol

### Key Generation

#### Overview

Key generation proceeds in three rounds. Each round consists of a message sent from the Coordinator to each Trustee, 
and a response back from each Trustee to the Coordinator.

At the end of the three rounds the Coordinator will have a public OpenPGP key signed by all Trustees, along with a
*state object* that can be used to recover the private key. Parts of the state object will be encrypted, so the private
key can only be recovered when `t` Trustees turn over their corresponding private keys.

#### Round One: Generate Contract Keypair

In Round One, the Coordinator asks each Trustee to generate a new *contract keypair* for use with this contract.
Each Trustee saves its `contract_private_key` locally, and returns the `contract_public_key`.

**Round One Example:**

(assuming `share_count` of 3 and `recovery_threshold` of 2)

Message to each Trustee:

    {'uuid':uuid, 'action':'generate_keypair'}

Response from Trustee 1:

    {'uuid':uuid, 'contract_public_key':contract_public_key1}
    
Response from Trustee 2:

    {'uuid':uuid, 'contract_public_key':contract_public_key2}
    
Response from Trustee 3:

    {'uuid':uuid, 'contract_public_key':contract_public_key3}

#### Round Two: Generate Share

In Round Two, the Coordinator asks each Trustee to generate a share of an ElGamal keypair, as well as 
verified-threshold subshares of that share for each of the other Trustees.

Internally, each Trustee generates the following values:

- `x`: a private ElGamal key in the range `2 <= x <= q-1`
- `y`:  a public ElGamal key equal to `g^x % p`
- `recovery_polynomial`: a polynomial for Shamir secret sharing of `x`, in the form `x + randint(q-1) * i + ... + randint(q-1) * i ^ (recovery_threshold-1)`
- `subshares`: a share of `x` for each other Trustee, in the form `[recovery_polynomial(1), ..., recovery_polynomial(share_count)]`
- `commitments`: A list of commitments the other Trustees can use to verify that they have received valid subshares, 
    in the form `g^coefficient % p` for each random coefficient of the recovery_polynomial

The Trustee returns the `x`, `y`, `subshares`, and `commitments` values to the Coordinator. 
Any values that are not public are encrypted using the appropriate contract_public_key.

**Round Two Example:**

(assuming `share_count` of 3 and `recovery_threshold` of 2)

Message to each Trustee:

    {'uuid':uuid, 'action':'generate_share', 'contract_public_keys':[contract_public_key1, contract_public_key2, contract_public_key3]}

Response from Trustee 1:

    {
        'uuid':uuid, 
        'share':{
            'contract_public_key': contract_private_key1,
            'x':encrypt(contract_private_key1, contract_public_key1, x), 
            'y':y,
            'subshares':[encrypt(contract_private_key1, contract_public_key2, subshares1[0]), encrypt(contract_private_key1, contract_public_key2, subshares1[1])],
            'commitments':[commitments1[0]],
        }
    }

Response from Trustee 2:

    {
        'uuid':uuid, 
        'share':{
            'contract_public_key': contract_public_key2,
            'x':encrypt(contract_private_key2, contract_public_key2, x), 
            'y':y,
            'subshares':[encrypt(contract_private_key2, contract_public_key1, subshares2[0]), encrypt(contract_private_key2, contract_public_key3, subshares2[1])],
            'commitments':[commitments2[0]],
        }
    }
   
Response from Trustee 3:

    {
        'uuid':uuid, 
        'share':{
            'contract_public_key': contract_public_key3,
            'x':encrypt(contract_private_key3, contract_public_key3, x), 
            'y':y,
            'subshares':[encrypt(contract_private_key3, contract_public_key1, subshares3[0]), encrypt(contract_private_key3, contract_public_key2, subshares3[1])],
            'commitments':[commitments3[0]],
        }
    }
  
Importantly, `encrypt(private_key_1, public_key_2, message)` in these examples encrypts a message so it can only be read
by the owner of private_key_2, but also allows the decrypter to verify that the message was sent by the owner of 
private_key_1. 
    
#### Round Three: Verify GPG Key

In Round Three, the Coordinator assembles all the shares from Round Two into a `state_object`, representing the
`release_date`, `share_count`, `recovery_threshold`, and collected `shares`.

The Coordinator uses the state_object to generate an OpenPGP ElGamal public key, having a `y` value equal to the product
of the `y` value in each share, mod `p`.

The user ID comment for the generated OpenPGP key takes this form:
    
    {
        "state_digest": <digest>, 
        "uuid": <uuid>, 
        "contract": {
            "release_date": "2015-06-25T21:12:33.652483+00:00", 
            "recovery_threshold": recovery_threshold, 
            "share_count": share_count,
        }
    }
 
The Coordinator sends a message to each Trustee with the state object and the generated public key.

Each Trustee verifies that:

- The number of shares is `share_count`.
- For exactly one share:
    - The Trustee possesses the corresponding `contract_private_key`.
    - The Trustee can decrypt the `x` value, and therefore must have itself generated it in Round Two.
    - The y value is equal to `g ^ x % p`.
- For the remaining shares:
    - The number of commitments is `recovery_threshold - 1`.
    - The Trustee can decrypt one of the `subshare` values.
    - The decrypted `subshare` value represents a unique point on a polynomial of order `recovery_threshold - 1` with a
        y-intercept of `x`, as mathematically verified by the `y` and `commitments` values.
- The contract, state_digest, p, g, and y values attached to the OpenPGP key are correct

If all validations pass, the Trustee signs the OpenPGP key and returns its signature.

**Round Three Example:**

(assuming `share_count` of 3 and `recovery_threshold` of 2)

Message to each Trustee:

    {
        'uuid':uuid, 
        'action':'verify_key', 
        'combined_gpg_key':generate_elgamal_key(p, g, y, comment={uuid, state_digest, contract), 
        'state':'{
            'contract':{
                'release_date':release_date, 
                'share_count':share_count, 
                'recovery_threshold':recovery_threshold
            },
            'shares':[
                {
                    'contract_public_key': contract_private_key1,
                    'x':encrypt(contract_private_key1, contract_public_key1, x), 
                    'y':y,
                    'subshares':[encrypt(contract_private_key1, contract_public_key2, subshares1[0]), encrypt(contract_private_key1, contract_public_key2, subshares1[1])],
                    'commitments':[commitments1[0]],
                },
                {
                    'contract_public_key': contract_public_key2,
                    'x':encrypt(contract_private_key2, contract_public_key2, x), 
                    'y':y,
                    'subshares':[encrypt(contract_private_key2, contract_public_key1, subshares2[0]), encrypt(contract_private_key2, contract_public_key3, subshares2[1])],
                    'commitments':[commitments2[0]],
                },
                {
                    'contract_public_key': contract_public_key3,
                    'x':encrypt(contract_private_key3, contract_public_key3, x), 
                    'y':y,
                    'subshares':[encrypt(contract_private_key3, contract_public_key1, subshares3[0]), encrypt(contract_private_key3, contract_public_key2, subshares3[1])],
                    'commitments':[commitments3[0]],
                },
            ]
        }',
    }

Response from Trustee 1:

    {'uuid':uuid, 'certificate':certificate(trustee_1_signing_key, combined_gpg_key)}
    
Response from Trustee 2:

    {'uuid':uuid, 'certificate':certificate(trustee_2_signing_key, combined_gpg_key)}
    
Response from Trustee 3:

    {'uuid':uuid, 'certificate':certificate(trustee_3_signing_key, combined_gpg_key)}

### Key Use

The Coordinator publishes the ElGamal public key along with the certificates obtained from all Trustees. 
Any user can verify the key by independently obtaining the signing public keys of the Trustees, 
and verifying that the key is signed by `share_count` Trustees.

A user should not rely on a key with fewer than `share_count` trusted signatures, although the security properties are 
in principle retained with at least `recovery_threshold` trusted signatures.

### Key Recovery

The `state_object` is public, and should be backed up by the Coordinator, Trustees, and any other interested party.

Each Trustee should keep their `contract_private_key` on secure offline storage.

When the `release_date` arrives, each Trustee should publish their `contract_private_key`. As soon as `recovery_threshold` 
contract_private_keys are available, the ElGamal private key can be recovered, either by decrypting the `x` value for each
share, or by recovering it using the subshares.

## Security Guarantees and Assumptions

The core security assumptions of this system are:

- At least `recovery_threshold` Trustees (known as the *compliant Trustees*) can be trusted to follow the protocol; to 
    successfully protect their `contract_private_keys` and signing keys; and to publish their `contract_private_keys` 
    on the `release_date`.
- The adversary cannot decrypt encrypted portions of the `state_object` without the `contract_private_keys`.
- The adversary cannot decrypt messages encrypted with an ElGamal OpenPGP key whose `y` value is the product of the `y` 
    values in the `state_object`, without knowing the sum of the `x` values in the `state_object`.
- The `state_digest` is a valid cryptographic hash of the `state_object`.
    
Assuming those assumptions are true, the following guarantees must be true of any OpenPGP key having signatures from
`share_count` Trustees:

- Because the `state_digest` is a valid cryptographic hash of the `state_object`, the compliant Trustees must each have 
    verified the same `state_object`.
- Because the compliant Trustees followed the protocol, they must have verified that the `p`, `g`, and `y` values in the
    ElGamal OpenPGP key match the values in the `state_object`.
- Because messages encrypted with the ElGamal OpenPGP key use the product of the `y` values in the `state_object`, they
    cannot be decrypted until the `x` values in the `state_object` are decrypted.
- Because the adversary cannot decrypt encrypted portions of the `state_object` without the `contract_private_keys`, the
    `x` values belonging to the compliant Trustees will not be available until they published their `contract_private_keys`
    on `release_date`.
- Because the compliant Trustees followed the protocol, they must have mathematically verified that each `share` other than
    their own included a `subshare`, encrypted to their `contract_private_key`, that could be used in combination with
    any `recovery_threshold - 1` other `subshares` to recover the `x` value for that share.
    - Because there are at least `recovery_threshold` compliant Trustees, once the compliant Trustees publish their
    `contract_private_keys` it must be possible to decrypt at least `recovery_threshold` subshares for any `share` which
    lacks a compliant Trustee to decrypt the `x` value directly. Therefore, all `x` values must be recoverable as soon as
    `recovery_threshold` compliant Trustees publish their `contract_private_keys`.



## References

This system implements the cryptographic protocol described in 
[M. O. Rabin and C. Thorpe. Time-lapse cryptography. Technical Report TR-22-06, Harvard University School of Engineering and Computer Science, 2006.](http://www.eecs.harvard.edu/~cat/tlc.pdf) 

In short, the protocol uses Pedersen distributed key generation to generate and publish ElGamal keypairs according to a fixed schedule.
