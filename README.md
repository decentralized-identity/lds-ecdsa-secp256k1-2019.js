# EcdsaSecp256k1Signature2019

[![Build Status](https://travis-ci.org/decentralized-identity/lds-ecdsa-secp256k1-2019.js.svg?branch=master)](https://travis-ci.org/decentralized-identity/lds-ecdsa-secp256k1-2019.js) [![codecov](https://codecov.io/gh/decentralized-identity/lds-ecdsa-secp256k1-2019.js/branch/master/graph/badge.svg)](https://codecov.io/gh/decentralized-identity/lds-ecdsa-secp256k1-2019.js)

🚧 This library is experimental / under development / not audited. Use at your own risk.

- [Demo](https://identity.foundation/lds-ecdsa-secp256k1-2019.js/demo)
- [W3C DVCG Spec](https://w3c-dvcg.github.io/lds-ecdsa-secp256k1-2019/)
- [EcdsaSecp256k1Signature2019 Library Documentation](https://identity.foundation/lds-ecdsa-secp256k1-2019.js/lds-ecdsa-secp256k1-2019/)
- [ES256K Library Documentation](https://identity.foundation/lds-ecdsa-secp256k1-2019.js/es256k-jws-ts/)

This project relies on:

- [secp256k1 typescript / wasm](https://github.com/bitauth/bitcoin-ts)
- [ES256K Draft](https://tools.ietf.org/html/draft-ietf-cose-webauthn-algorithms-01)

## Usage

### Install

_this package has not been published yet_

```
npm i @transmute/lds-ecdsa-secp256k1-2019 --save
```

### Sign

```ts
import { sign } from `@transmute/lds-ecdsa-secp256k1-2019`;
const doc = {
  '@context': {
    action: 'schema:action',
    schema: 'http://schema.org/',
  },
  action: 'AuthenticateMe',
};
const signatureOptions = {
  challenge: 'abc',
  created: '2019-01-16T20:13:10Z',
  domain: 'example.com',
  proofPurpose: 'authentication',
  verificationMethod: 'https://example.com/i/alice/keys/2',
};
const privateKey = {
  crv: 'secp256k1',
  d: 'rhYFsBPF9q3-uZThy7B3c4LDF_8wnozFUAEm5LLC4Zw',
  kid: 'JUvpllMEYUZ2joO59UNui_XYDqxVqiFLLAJ8klWuPBw',
  kty: 'EC',
  x: 'dWCvM4fTdeM0KmloF57zxtBPXTOythHPMm1HCLrdd3A',
  y: '36uMVGM7hnw-N6GnjFcihWE3SkrhMLzzLCdPMXPEXlA',
};
const signedDocument = await sign(doc, signatureOptions, privateKey);
// see verify for example.
```

### Verify

```ts
import { verify } from `@transmute/lds-ecdsa-secp256k1-2019`;
const signedDocument = {
  '@context': 'https://w3id.org/security/v2',
  'http://schema.org/action': 'AuthenticateMe',
  proof: {
    challenge: 'abc',
    created: '2019-01-16T20:13:10Z',
    domain: 'example.com',
    proofPurpose: 'authentication',
    verificationMethod: 'https://example.com/i/alice/keys/2',
    type: 'EcdsaSecp256k1Signature2019',
    jws:
      'eyJhbGciOiJFUzI1NksiLCJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdfQ..QgbRWT8w1LJet_KFofNfz_TVs27z4pwdPwUHhXYUaFlKicBQp6U1H5Kx-mST6uFvIyOqrYTJifDijZbtAfi0MA',
  },
};
const publicKey = {
  crv: 'secp256k1',
  kid: 'JUvpllMEYUZ2joO59UNui_XYDqxVqiFLLAJ8klWuPBw',
  kty: 'EC',
  x: 'dWCvM4fTdeM0KmloF57zxtBPXTOythHPMm1HCLrdd3A',
  y: '36uMVGM7hnw-N6GnjFcihWE3SkrhMLzzLCdPMXPEXlA',
};
const verified = await verify(signedDocument, publicKey);
// expect: verified === true
```

## Motivation

ES256K is currently a DRAFT, however, it has been implemented and is being used by companies. Node 12 supports ES256K out of the box, but browser support requires custom implementations. This library attempts to provide a Node/Web implementation of ES256K as well as a JSON-LD Signature Suite, EcdsaSecp256k1Signature2019, built on detached ES256K JWS according to [rfc7797](https://tools.ietf.org/html/rfc7797#section-6).

Our approach is based on [lds-ed25519-2018](https://w3c-dvcg.github.io/lds-ed25519-2018/) and [jsonld-signatures](https://github.com/digitalbazaar/jsonld-signatures).

## Development

This monorepo uses [lerna](https://github.com/lerna/lerna), most of the scripts in the root directory just call lerna.

```
npm i
npm run build
npm run test
npm run coverage
npm run docs
NPM_CONFIG_OTP="" npm run release
```

## Releases

1. Prepare the release

```
npm run version:prerelease
prep:release
git add

```
