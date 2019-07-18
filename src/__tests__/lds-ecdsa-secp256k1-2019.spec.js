const fixtures = require('./__fixtures__');
const { sign, verify } = require('../index');

const { publicKey, privateKey } = fixtures.keypair;

describe('lds-ecdsa-secp256k1-2019.js', () => {
  it(
    'can sign and verify',
    async () => {
      const signed = await sign({
        data: fixtures.linkedData,
        signatureOptions: {
          created: '2019-01-16T20:13:10Z',
          challenge: 'abc',
          domain: 'example.com',
          proofPurpose: 'authentication',
          verificationMethod: 'https://example.com/i/alice/keys/2',
        },
        privateKey,
      });

      const verified = await verify({
        data: signed,
        publicKey,
      });

      expect(verified).toBe(true);
    },
    10 * 1000,
  );
});
