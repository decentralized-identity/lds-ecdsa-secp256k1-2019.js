# EcdsaSecp256k1Signature2019

This library is experimental / under development / not audited. Use at your own risk.

- [secp256k1 wasm implementation](https://github.com/bitauth/bitcoin-ts)
- [ES256K Draft](https://tools.ietf.org/html/draft-ietf-cose-webauthn-algorithms-01)

## Development

See [package.json](./package.json) for complete list.

```
npm i
npm run test
npm run build
npm run docs
```

For releases, see the root README.

### JWS Gotcha's

- Header relies on [rfc7797](https://tools.ietf.org/html/rfc7797), the signature is over the result of createVerify data, not an encoded payload! Its possible a non detached payload signature will be supported in the future.

### References

- [RsaSignature2017](https://github.com/transmute-industries/RsaSignature2017)
- [EcdsaKoblitzSignature2016](https://github.com/transmute-industries/EcdsaKoblitzSignature2016)
- [Ed25519Signature2018](https://github.com/transmute-industries/Ed25519Signature2018)
