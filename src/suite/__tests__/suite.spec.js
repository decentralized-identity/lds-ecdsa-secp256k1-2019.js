const fixtures = require('../../__tests__/__fixtures__');

const { sign, verify } = require('../index');

describe('primitive', () => {
  it('sign and verify', async () => {
    const { publicKey, privateKey } = fixtures.keypair;
    const verifyData = fixtures.base64UrlEncoded;

    const signature = await sign({
      verifyData,
      privateKey,
    });

    const verified = await verify({
      verifyData,
      signature,
      publicKey,
    });
    expect(verified).toBe(true);
  });
});
