const EC = require('elliptic').ec;

const secp256k1 = new EC('secp256k1');

const {
  sha256,
  hexToSignature,
  decodeHexFromBase64Url,
} = require('./encoding');

module.exports = async ({ verifyData, signature, publicKey }) => {
  const verifyDataHash = sha256(verifyData);

  const verifyDataHashBuffer = Buffer.from(verifyDataHash, 'hex');
  const signatureHex = decodeHexFromBase64Url(signature);

  const s = hexToSignature(signatureHex);

  const recoveredKey = secp256k1
    .recoverPubKey(verifyDataHashBuffer, { ...s }, s.v)
    .encode('hex');

  return recoveredKey === `${publicKey}`;
};
