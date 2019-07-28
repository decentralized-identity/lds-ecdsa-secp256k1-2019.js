# ES256K JWS

A TypeScript + WebAssembly Implementation of ES256K according to [draft-ietf-cose-webauthn-algorithms-01](https://tools.ietf.org/html/draft-ietf-cose-webauthn-algorithms-01).

Relies on [bitcoin-ts](https://github.com/bitauth/bitcoin-ts) for secp256k1 operations.

Users `crypto.createHash('sha256')` for Message Hashing.

Does not require node 12, and is tested against [@panva/jose](https://github.com/panva/jose).

Supports JWK / Hex / Pem key conversion using [@trust/keyto](https://github.com/EternalDeiwos/keyto) and [rfc7638](https://tools.ietf.org/html/rfc7638).

## Example Usage

### Key Conversion, Sign and Verify

```ts
import { JWS, keyUtils } from '@transmute/es256k-jws'

const privateKeyHex =
  'ae1605b013c5f6adfeb994e1cbb0777382c317ff309e8cc5500126e4b2c2e19c'
const publicKeyHex =
  '027560af3387d375e3342a6968179ef3c6d04f5d33b2b611cf326d4708badd7770'
const payload = {
  hello: 'world',
}
const privateKeyJWK = await keyUtils.privateJWKFromPrivateKeyHex(privateKeyHex)
const publicKeyJWK = await keyUtils.publicJWKFromPublicKeyHex(publicKeyHex)
const jws = await JWS.sign(payload, privateKeyJWK)
const verified = await JWS.verify(jws, publicKeyJWK)
expect(verified).toEqual(payload)
```

### BIP39 Support

```ts
import { keyUtils } from '@transmute/es256k-jws'

const mnemonic =
  'start fuel hybrid exit sell now gas salmon defense chest attend cycle'
const hdPath = "m/44'/60'/0'/0"
const seed = await bip39.mnemonicToSeed(mnemonic)
const root = hdkey.fromMasterSeed(seed)
const addrNode = root.derive(hdPath)
const privateKey = addrNode.privateKey.toString('hex')
expect(privateKey).toBe(
  '617e062ea82d0cc631bc6b315b444f2efb55319ea8e0b64f6f8a807ef7588e41'
)
const privateKeyJWK = await keyUtils.privateJWKFromPrivateKeyHex(privateKey)
expect(privateKeyJWK).toEqual({
  crv: 'secp256k1',
  kid: 'b0pjci0P8v5hgFGyEa5yCWTx5XqSFhSa4915yqtd7Xg',
  kty: 'EC',

  d: 'YX4GLqgtDMYxvGsxW0RPLvtVMZ6o4LZPb4qAfvdYjkE',
  x: 'I0vpvN8EH3Uwl5uLiLfcYt1QWnWIPIIR86glBTT5bcA',
  y: 'wJuz6QuuiiuKXUE21UgY-JLEAXb4KZRSApjkF3fZfg4',
})
```
