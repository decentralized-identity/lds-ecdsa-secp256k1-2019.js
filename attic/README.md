# EcdsaSecp256k1Signature2019

[![Build Status](https://travis-ci.org/decentralized-identity/lds-ecdsa-secp256k1-2019.js.svg?branch=master)](https://travis-ci.org/decentralized-identity/lds-ecdsa-secp256k1-2019.js) [![codecov](https://codecov.io/gh/decentralized-identity/lds-ecdsa-secp256k1-2019.js/branch/master/graph/badge.svg)](https://codecov.io/gh/decentralized-identity/lds-ecdsa-secp256k1-2019.js) [![Coverage Status](https://coveralls.io/repos/github/decentralized-identity/lds-ecdsa-secp256k1-2019.js/badge.svg?branch=master)](https://coveralls.io/github/decentralized-identity/lds-ecdsa-secp256k1-2019.js?branch=master) [![MIT License](https://img.shields.io/badge/license-MIT_License-green.svg?style=flat-square)](https://github.com/decentralized-identity/lds-ecdsa-secp256k1-2019.js/blob/master/LICENSE) [![GitHub forks](https://img.shields.io/github/forks/decentralized-identity/lds-ecdsa-secp256k1-2019.js.svg?style=social&label=Fork&maxAge=2592000?style=flat-square)](https://github.com/decentralized-identity/lds-ecdsa-secp256k1-2019.js#fork-destination-box) [![GitHub stars](https://img.shields.io/github/stars/decentralized-identity/lds-ecdsa-secp256k1-2019.js.svg?style=social&label=Star&maxAge=2592000?style=flat-square)](https://github.com/decentralized-identity/lds-ecdsa-secp256k1-2019.js/stargazers)

## Motivation

Standards for JSON-LD Signatures provide clear guidance on required attributes for cryptographic suites, yet support for raw EC cryptography is poor, and many implementations are overly coupled to bitcoin or ethereum libraries. 

We set out to provide a reference implementation in JavaScript.

We also seek to remedy confusion over how JWT and JSON-LD Signatures are compatible, this implementation differs significantly from [Ed25519Signature2018](https://github.com/digitalbazaar/jsonld-signatures/blob/master/lib/suites/Ed25519Signature2018.js#L32). 

If the signature is a valid JWS, then its property name should be `jws`, this library's signatures are `base64Url(hex(leftpad(r),hex(leftpad(s)),hex(v))`. This means that no JWS header is validated when the signature is verified. 

It also means this signature suites internal signature method can be used to create a valid JWS for `ES256K-R`, but note that the JOSE algorithm registry does not contain these algorithms yet, and you may have trouble validating JWTs generated with these values such as [did-jwt](https://github.com/uport-project/did-jwt). When `ES256K-R` is added to JOSE, it would be best to use a JWS approach like the one used for Ed25519Signature2018. 

[JSON Web Token (JWT) with ES256K (secp256k1) signature](https://connect2id.com/products/nimbus-jose-jwt/examples/jwt-with-es256k-signature)

A linked data signature suite is for signing and verifying json-ld. JWS as used in JWTs are used for signing and verifying normal json objects, and in particular, there is no cannonization applied. This means that although lds-ecdsa-secp256k1-2019.js and did-jwt both have signatues of the form `base64Url(hex(leftpad(r),hex(leftpad(s)),hex(v))`, they are not doing the same thing. One is used to create and verify JWTs, the other is uses to sign and verify json-ld. Both use ecdsa over secp256k1, but lds-ecdsa-secp256k1-2019.js signs verifyData constructed from cannonized and hashing the document and its signatureOptions whereas did-jwt signs a `sha256(base64Url(JSON.stringify(header)).base64Url(JSON.stringify(payload)))`. Though the signature algorithm and encoding of signature is the same, the preprocessing of json and intentions are different.

The correct way to unify these is the way Ed25519Signature2018 is implemented, but this cannot be done until JOSE supports `ES256K-R`.

It is possible to alter the signature format used by lds-ecdsa-secp256k1-2019.js to be more like Ed25519Signature2018, in anticipation of JOSE support. Its unclear if that should be done or not.

### Linked Data Signature Suite Details

#### [canonicalization algorithm: URDNA2015](https://github.com/digitalbazaar/jsonld.js/#canonize-normalize)

#### [message digest algorithm: sha256](https://nodejs.org/api/crypto.html#crypto_crypto_createhash_algorithm_options)

#### [signature algorithm: secp256k1 ecdsa](https://github.com/indutny/elliptic#ecdsa)

`signatureValue` is base64urlencoded concatonation of hex encoded r, s, recoveryParam.

`createVerifyData` transforms a javascript objects similar to the approach used in `RsaSignature2017`, [used by mastodon](https://github.com/tootsuite/mastodon/blob/cabdbb7f9c1df8007749d07a2e186bb3ad35f62b/app/lib/activitypub/linked_data_signature.rb#L19). 

createVerifyData is described [here](https://w3c-dvcg.github.io/ld-signatures/#create-verify-hash-algorithm)

## Details

This signature suite follows the approach taken by:
- [Ed25519Signature2018](https://github.com/transmute-industries/Ed25519Signature2018)
- [RsaSignature2017](https://github.com/transmute-industries/RsaSignature2017)
- [EcdsaKoblitzSignature2016](https://github.com/transmute-industries/EcdsaKoblitzSignature2016)


Commercial Support
------------------

Commercial support for this library is available upon request from
Transmute: support@transmute.industries.

## W3C Links

#### [EcdsaSecp256k1Signature2019 Spec](https://github.com/w3c-dvcg/lds-ecdsa-secp256k1-2019)

#### [Linked Data Cryptographic Suite Registry](https://w3c-ccg.github.io/ld-cryptosuite-registry)

#### [Linked Data Signatures](https://w3c-dvcg.github.io/ld-signatures)

#### [Decentralized Identifiers](https://w3c-ccg.github.io/did-spec/)

