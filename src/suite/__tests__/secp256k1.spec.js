const EC = require('elliptic').ec;

const secp256k1 = new EC('secp256k1');
const fixtures = require('../../__tests__/__fixtures__');

const { sha256 } = require('../encoding');

describe('secp256k1', () => {
  it('sign and verify', () => {
    const { publicKey, privateKey } = fixtures.keypair;

    const verifyData = fixtures.base64UrlEncoded;
    const verifyDataHash = sha256(verifyData);
    const verifyDataHashBuffer = Buffer.from(verifyDataHash, 'hex');

    const signature = secp256k1.sign(
      verifyDataHashBuffer,
      secp256k1.keyFromPrivate(privateKey),
    );

    const s = {
      r: signature.r,
      s: signature.s,
      v: signature.recoveryParam,
    };

    const recoveredKey = secp256k1
      .recoverPubKey(verifyDataHashBuffer, { ...s }, s.v)
      .encode('hex');

    const verified = recoveredKey === `${publicKey}`;
    expect(verified).toBe(true);
  });
});
