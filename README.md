# EcdsaSecp256k1Signature2019

This library is no longer maintained, please use [JsonWebSignature2020](https://github.com/w3c-ccg/lds-jws2020) instead.


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

```
npm i @transmute/lds-ecdsa-secp256k1-2019 --save
```

### Issue and Verify with vc-js

````js

const {
  EcdsaSecp256k1KeyClass2019,
  EcdsaSecp256k1Signature2019,
  defaultDocumentLoader,
} = require('@transmute/lds-ecdsa-secp256k1-2019');

const vc = require('vc-js');

const key = new EcdsaSecp256k1KeyClass2019({
  id:
    'did:elem:EiChaglAoJaBq7bGWp6bA5PAQKaOTzVHVXIlJqyQbljfmg#qfknmVDhMi3Uc190IHBRfBRqMgbEEBRzWOj1E9EmzwM',
  controller: 'did:elem:EiChaglAoJaBq7bGWp6bA5PAQKaOTzVHVXIlJqyQbljfmg',
  privateKeyJwk: {
    kty: 'EC',
    crv: 'secp256k1',
    d: 'wNZx20zCHoOehqaBOFsdLELabfv8sX0612PnuAiyc-g',
    x: 'NbASvplLIO_XTzP9R69a3MuqOO0DQw2LGnhJjirpd4w',
    y: 'EiZOvo9JWPz1yGlNNW66IV8uA44EQP_Yv_E7OZl1NG0',
    kid: 'qfknmVDhMi3Uc190IHBRfBRqMgbEEBRzWOj1E9EmzwM',
  },
});

const suite = new EcdsaSecp256k1Signature2019({
  key,
});

// Sample unsigned credential
const credential = {
  '@context': [
    'https://www.w3.org/2018/credentials/v1',
    'https://www.w3.org/2018/credentials/examples/v1',
  ],
  id: 'https://example.com/credentials/1872',
  type: ['VerifiableCredential', 'AlumniCredential'],
  issuer: key.controller,
  issuanceDate: '2010-01-01T19:23:24Z',
  credentialSubject: {
    id: 'did:example:ebfeb1f712ebc6f1c276e12ec21',
    alumniOf: 'Example University',
  },
};

const signedVC = await vc.issue({ credential, suite });
const result = await vc.verify({
  credential: signedVC,
  suite,
  documentLoader: defaultDocumentLoader,
});
```

### Sign

```ts
const jsigs = require('jsonld-signatures');

const { AssertionProofPurpose } = jsigs.purposes;

const {
  EcdsaSecp256k1KeyClass2019,
  EcdsaSecp256k1Signature2019,
  defaultDocumentLoader,
} = require('@transmute/lds-ecdsa-secp256k1-2019');

const key = new EcdsaSecp256k1KeyClass2019({
  id:
    'did:elem:EiChaglAoJaBq7bGWp6bA5PAQKaOTzVHVXIlJqyQbljfmg#qfknmVDhMi3Uc190IHBRfBRqMgbEEBRzWOj1E9EmzwM',
  controller: 'did:elem:EiChaglAoJaBq7bGWp6bA5PAQKaOTzVHVXIlJqyQbljfmg',
  privateKeyJwk: {
    kty: 'EC',
    crv: 'secp256k1',
    d: 'wNZx20zCHoOehqaBOFsdLELabfv8sX0612PnuAiyc-g',
    x: 'NbASvplLIO_XTzP9R69a3MuqOO0DQw2LGnhJjirpd4w',
    y: 'EiZOvo9JWPz1yGlNNW66IV8uA44EQP_Yv_E7OZl1NG0',
    kid: 'qfknmVDhMi3Uc190IHBRfBRqMgbEEBRzWOj1E9EmzwM',
  },
});
const signed = await jsigs.sign(
  {
    '@context': [
      {
        schema: 'http://schema.org/',
        name: 'schema:name',
        homepage: 'schema:url',
        image: 'schema:image',
      },
    ],
    name: 'Manu Sporny',
    homepage: 'https://manu.sporny.org/',
    image: 'https://manu.sporny.org/images/manu.png',
  },
  {
    compactProof: false,
    documentLoader: defaultDocumentLoader,
    purpose: new AssertionProofPurpose(),
    suite: new EcdsaSecp256k1Signature2019({
      key,
    }),
  }
);
// see verify for example.
````

### Verify

```ts
const res = await jsigs.verify(signed, {
  suite: new EcdsaSecp256k1Signature2019({
    key,
  }),

  compactProof: false,
  documentLoader: defaultDocumentLoader,
  purpose: new AssertionProofPurpose(),
});
// Leave for development purposes
if (!res.verified) {
  // tslint:disable-next-line:no-console
  console.log(res);
}
expect(res.verified).toBe(true);
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
```

## Releases

```
npm run release
```
