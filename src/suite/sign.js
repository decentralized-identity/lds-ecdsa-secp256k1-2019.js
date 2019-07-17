const EC = require('elliptic').ec;

const secp256k1 = new EC('secp256k1');

const { sha256, signatureToHex, encodeHexAsBase64Url } = require('./encoding');

module.exports = async ({ verifyData, privateKey }) => {
  const verifyDataHash = sha256(verifyData);
  // console.log("sign verifyDataHash: ", verifyDataHash);
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


  const signatureHex = signatureToHex(s);

  const signatureBase64Url = encodeHexAsBase64Url(signatureHex);

  return signatureBase64Url;
};
