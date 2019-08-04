import { JWS, keyUtils } from '../../index';

describe('README Example', () => {
  it('convert keys, sign and verify', async () => {
    const privateKeyHex =
      'ae1605b013c5f6adfeb994e1cbb0777382c317ff309e8cc5500126e4b2c2e19c';
    const publicKeyHex =
      '027560af3387d375e3342a6968179ef3c6d04f5d33b2b611cf326d4708badd7770';
    const payload = {
      hello: 'world',
    };
    const privateKeyJWK = await keyUtils.privateJWKFromPrivateKeyHex(
      privateKeyHex
    );
    const publicKeyJWK = await keyUtils.publicJWKFromPublicKeyHex(publicKeyHex);
    const jws = await JWS.sign(payload, privateKeyJWK);
    const verified = await JWS.verify(jws, publicKeyJWK);
    expect(verified).toEqual(payload);
  });
});
