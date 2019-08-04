import jose from '@panva/jose';

import { JWS, keyUtils } from '../../../index';

const privateKeyHex =
  'ae1605b013c5f6adfeb994e1cbb0777382c317ff309e8cc5500126e4b2c2e19c';

const publicKeyHex =
  '027560af3387d375e3342a6968179ef3c6d04f5d33b2b611cf326d4708badd7770';

const payload = {
  hello: true,
};

describe('node 12 @panva/jose', () => {
  describe('keys interop', () => {
    it('privateKey', async () => {
      const privateKey = await keyUtils.privateJWKFromPrivateKeyHex(
        privateKeyHex
      );
      expect(jose.JWK.asKey(privateKey).toJWK(true)).toEqual(privateKey);
    });
    it('publicKey', async () => {
      const publicKey = await keyUtils.publicJWKFromPublicKeyHex(publicKeyHex);
      expect(jose.JWK.asKey(publicKey).toJWK()).toEqual(publicKey);
    });
  });

  describe('signature interop', () => {
    it('we sign, jose verify', async () => {
      const privateKey = await keyUtils.privateJWKFromPrivateKeyHex(
        privateKeyHex
      );
      const publicKey = await keyUtils.publicJWKFromPublicKeyHex(publicKeyHex);
      const jws = await JWS.sign(payload, privateKey);
      const verified = jose.JWS.verify(jws, jose.JWK.asKey(publicKey));
      expect(verified).toEqual(payload);
    });

    it('jose sign, we verify', async () => {
      const privateKey = await keyUtils.privateJWKFromPrivateKeyHex(
        privateKeyHex
      );
      const publicKey = await keyUtils.publicJWKFromPublicKeyHex(publicKeyHex);
      const jws = jose.JWS.sign(payload, jose.JWK.asKey(privateKey));
      const verified = await JWS.verify(jws, publicKey);
      expect(verified).toEqual(payload);
    });
  });

  describe('errors interop', () => {
    // TODO: add tests for tampered signatures
    describe('JWSVerificationFailed', () => {
      it('jose signature verify fail, wrong key', async () => {
        expect.assertions(2);
        const privateKey = await keyUtils.privateJWKFromPrivateKeyHex(
          privateKeyHex
        );
        const publicKey = jose.JWK.generateSync('EC', 'secp256k1').toJWK();
        const jws = jose.JWS.sign(payload, jose.JWK.asKey(privateKey));
        try {
          jose.JWS.verify(jws, jose.JWK.asKey(publicKey));
        } catch (e) {
          expect(e.name).toBe('JWSVerificationFailed');
          expect(e.message).toBe('signature verification failed');
        }
      });

      it('our signature verify fail, wrong key', async () => {
        expect.assertions(2);
        const privateKey = await keyUtils.privateJWKFromPrivateKeyHex(
          privateKeyHex
        );
        const publicKey = jose.JWK.generateSync('EC', 'secp256k1').toJWK();
        const jws = jose.JWS.sign(payload, jose.JWK.asKey(privateKey));
        try {
          await JWS.verify(jws, publicKey as any);
        } catch (e) {
          expect(e.name).toBe('JWSVerificationFailed');
          expect(e.message).toBe('signature verification failed');
        }
      });
    });
  });
});
