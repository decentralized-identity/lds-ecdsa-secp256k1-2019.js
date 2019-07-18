const EC = require('elliptic').ec;

const secp256k1 = new EC('secp256k1');

const didJWT = require('did-jwt');

const fixtures = require('./__fixtures__');

const {
  sha256,
  hexToSignature,
  decodeHexFromBase64Url,
} = require('../suite/encoding');

const { verify } = require('../suite');

const { publicKey, privateKey } = fixtures.keypair;

const signer = didJWT.SimpleSigner(privateKey);

describe('did-jwt', () => {
  describe('createJWT', () => {
    it('should create a JWT', async () => {
      const jwt = await didJWT.createJWT(
        {
          aud: 'did:example:123',
          exp: 1957463421,
          name: 'uPort Developer',
        },
        {
          issuer: 'did:example:123',
          alg: 'ES256K-R',
          signer,
        },
      );
      const { payload } = didJWT.decodeJWT(jwt);
      expect(payload.aud).toBe('did:example:123');
    });

    it('should verify a uport jwt signature', async () => {
      const { signature, data } = didJWT.decodeJWT(fixtures.uportJWT);
      const s = hexToSignature(decodeHexFromBase64Url(signature));
      const verifyData = data;
      const verifyDataHash = sha256(verifyData);
      const verifyDataHashBuffer = Buffer.from(verifyDataHash, 'hex');
      const recoveredKey = secp256k1
        .recoverPubKey(verifyDataHashBuffer, { ...s }, s.v)
        .encode('hex');
      expect(recoveredKey).toEqual(`${fixtures.keypair.publicKey}`);
    });

    it('can verify a JWT with lds-ecdsa-secp256k1-2019.js', async () => {
      const { signature, data } = didJWT.decodeJWT(fixtures.uportJWT);
      const verified = await verify({
        verifyData: data,
        signature,
        publicKey,
      });
      expect(verified).toBe(true);
    });
  });
});
