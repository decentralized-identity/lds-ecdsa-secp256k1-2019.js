const EC = require('elliptic').ec;

const secp256k1 = new EC('secp256k1');
const fixtures = require('../../../__tests__/__fixtures__');

const {
  sha256,
  signatureToHex,
  hexToSignature,
  encodeHexAsBase64Url,
  decodeHexFromBase64Url,
} = require('../index');

describe('encoding', () => {
  it('signatureToHex and hexToSignature ', () => {
    const { publicKey, privateKey } = fixtures.keypair;

    const verifyData = `${fixtures.base64UrlEncoded}12321k3jh12g3g12g3j112%^$D%&$ASDA`;
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

    const signatureHexEncoded = signatureToHex(s);

    const signatureObject = hexToSignature(signatureHexEncoded);

    const recoveredKey = secp256k1
      .recoverPubKey(
        verifyDataHashBuffer,
        { ...signatureObject },
        signatureObject.v,
      )
      .encode('hex');

    const verified = recoveredKey === `${publicKey}`;
    expect(verified).toBe(true);
  });

  it('encodeHexAsBase64Url and decodeHexFromBase64Url ', () => {
    const b64Encoded = encodeHexAsBase64Url(fixtures.signatureHex);
    const b64Decoded = decodeHexFromBase64Url(b64Encoded);
    expect(b64Decoded).toEqual(fixtures.signatureHex);
  });
});
