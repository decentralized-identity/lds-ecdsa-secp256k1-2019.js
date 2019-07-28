const base64url = require("base64url");
const ethUtil = require("ethereumjs-util");

const crypto = require("crypto");

const sha256 = data => {
  const h = crypto.createHash("sha256");
  h.update(data);
  return h.digest("hex");
};

const leftpad = data => {
  return "0".repeat(64 - data.length) + data;
};

const signatureToHex = ({ r, s, v }) => {
  const signatureHex = Buffer.alloc(65);
  Buffer.from(leftpad(r.toString("hex")), "hex").copy(signatureHex, 0);
  Buffer.from(leftpad(s.toString("hex")), "hex").copy(signatureHex, 32);
  signatureHex[64] = v;
  return signatureHex.toString("hex");
};

const hexToSignature = signature => {
  const signatureBuffer = Buffer.from(signature, "hex");
  const r = signatureBuffer.slice(0, 32).toString("hex");
  const s = signatureBuffer.slice(32, 64).toString("hex");
  const v = signatureBuffer[64];
  return { r, s, v };
};

const encodeHexAsBase64Url = data => {
  return base64url.encode(Buffer.from(data, "hex"));
};

const decodeHexFromBase64Url = data => {
  return base64url.toBuffer(data).toString("hex");
};

const publicKeyHexToEthereumAddress = publicKeyHex => {
  return ethUtil.toChecksumAddress(
    ethUtil.pubToAddress(publicKeyHex).toString("hex")
  );
};

module.exports = {
  sha256,
  signatureToHex,
  hexToSignature,
  encodeHexAsBase64Url,
  decodeHexFromBase64Url,
  publicKeyHexToEthereumAddress
};
