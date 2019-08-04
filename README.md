# EcdsaSecp256k1Signature2019

[![Build Status](https://travis-ci.org/decentralized-identity/lds-ecdsa-secp256k1-2019.js.svg?branch=master)](https://travis-ci.org/decentralized-identity/lds-ecdsa-secp256k1-2019.js) [![codecov](https://codecov.io/gh/decentralized-identity/lds-ecdsa-secp256k1-2019.js/branch/master/graph/badge.svg)](https://codecov.io/gh/decentralized-identity/lds-ecdsa-secp256k1-2019.js)

- [Demo](https://identity.foundation/lds-ecdsa-secp256k1-2019.js/demo)
- [W3C Spec (WIP)](https://identity.foundation/lds-ecdsa-secp256k1-2019.js/spec)
- [EcdsaSecp256k1Signature2019 Documentation](https://identity.foundation/lds-ecdsa-secp256k1-2019.js/lds-ecdsa-secp256k1-2019/)
- [ES256K Documentation](https://identity.foundation/lds-ecdsa-secp256k1-2019.js/es256k-jws-ts/)

## Usage

### Install

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
import { sign } from `@transmute/lds-ecdsa-secp256k1-2019`;
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
const verified = await sign(signedDocument, publicKey);
// expect: verified === true
```

## Development

This monorepo uses [lerna](https://github.com/lerna/lerna)

```
npm i
npm run test
```
