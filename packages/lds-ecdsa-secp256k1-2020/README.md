# Linked Data Signatures for JOSE

[View On Github](https://github.com/transmute-industries/lds-jose2020)

## Supported JWS Algs

If an `alg` is not specified, this library will assume the following:

| kty | crvOrSize | alg    |
| --- | --------- | ------ |
| OKP | Ed25519   | EdDSA  |
| EC  | secp256k1 | ES256K |
| EC  | P-256     | ES256  |
| RSA | \*        | PS256  |

Other JWS are supported when `alg` is provided by the consuming library.

### About Linked Data Signatures

A JSON-LD Signature has a verification key type, and a signature/proof type for example:

- `JoseVerificationKey2020`
- `JoseLinkedDataSignature2020`

This library makes working with Linked Data Signatures trivial for developers familar with JOSE.

- [example keystore](./example/didDocJwks.json).

- [example did doc](./example/didDoc.json)

You must provide both a json-ld context, and human readable documentation for every property you create for your signature suite.

In this case, we define these verification key and proof formats, as well as the `publicKeyJwk` property.

You can read the documentation here:

[https://transmute-industries.github.io/lds-jose2020/](https://transmute-industries.github.io/lds-jose2020/)

And the context:

[https://transmute-industries.github.io/lds-jose2020/contexts/lds-jose2020-v0.0.jsonld](https://transmute-industries.github.io/lds-jose2020/contexts/lds-jose2020-v0.0.jsonld)

You MUST always version context files, and MUST ensure they remain resolvable at their published path once they are in use.

Failure to do so is similar to not maintaining an npm module, or unpublishing a module that may be used by others. If you are not sure if you can maintain a JSON-LD context, its best that you not create one, or rely on github / community structures to ensure that the context can easily be updated.

## Getting Started

```
npm i
npm run test
npm run coverage
npm run docs
```

Built on top of: [https://www.npmjs.com/package/jose](https://www.npmjs.com/package/jose)

Works with: [https://github.com/digitalbazaar/jsonld-signatures](https://github.com/digitalbazaar/jsonld-signatures)
