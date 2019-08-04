### References

### JWS Gotcha's

- Header relies on [rfc7797](https://tools.ietf.org/html/rfc7797), the signature is over the result of createVerify data, not an encoded payload! Its possible a non detached payload signature will be supported in the future.

- [RsaSignature2017](https://github.com/transmute-industries/RsaSignature2017)
- [EcdsaKoblitzSignature2016](https://github.com/transmute-industries/EcdsaKoblitzSignature2016)
- [Ed25519Signature2018](https://github.com/transmute-industries/Ed25519Signature2018)
