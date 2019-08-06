# ES256K

This library is experimental / under development / not audited. Use at your own risk.

- [secp256k1 wasm implementation](https://github.com/bitauth/bitcoin-ts)
- [ES256K Draft](https://tools.ietf.org/html/draft-ietf-cose-webauthn-algorithms-01)

## Install

```
npm i @transmute/es256k-jws-ts --save
```

## Development

See [package.json](./package.json) for complete list.

Node 12 Coverage Tests are ignored due to an issue babel.

```
npm i
npm run test
npm run build
npm run docs
```

For releases, see the root README.

### JWS - JSON-LD Signature Details

- `signDetached` relies on [rfc7797](https://tools.ietf.org/html/rfc7797), the signature is over the result of createVerify data, not an encoded payload! This makes more sense when you consider that JSON-LD Signatures have a signature property, it would be redunant for that signature to include a base64url encoded copy of the object.
