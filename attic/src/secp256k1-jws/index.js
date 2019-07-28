const { instantiateSecp256k1 } = require("bitcoin-ts");
const crypto = require("crypto");
const base64url = require("base64url");

function toHexString(byteArray) {
  return Array.prototype.map
    .call(byteArray, function(byte) {
      return ("0" + (byte & 0xff).toString(16)).slice(-2);
    })
    .join("");
}
function toByteArray(hexString) {
  var result = [];
  for (var i = 0; i < hexString.length; i += 2) {
    result.push(parseInt(hexString.substr(i, 2), 16));
  }
  return result;
}

const signWithHex = async (payload, privateKeyHex) => {
  const secp256k1 = await instantiateSecp256k1();
  const privateKeyUInt8Array = toByteArray(privateKeyHex);

  const header = { alg: "ES256K" };
  const encodedHeader = base64url.encode(JSON.stringify(header));
  const encodedPayload = base64url.encode(JSON.stringify(payload));

  const toBeSigned = encodedHeader + "." + encodedPayload;

  const message = Buffer.from(toBeSigned);
  const digest = crypto
    .createHash("sha256")
    .update(message)
    .digest()
    .toString("hex");

  const messageHashUInt8Array = toByteArray(digest);

  const signatureUInt8Array = secp256k1.signMessageHashCompact(
    privateKeyUInt8Array,
    messageHashUInt8Array
  );

  const signatureHex = toHexString(signatureUInt8Array);

  const encodedSignature = base64url.encode(Buffer.from(signatureHex, "hex"));
  return `${encodedHeader}.${encodedPayload}.${encodedSignature}`;
};

const verifyWithHex = async (signature, publicKeyHex) => {
  const secp256k1 = await instantiateSecp256k1();
  const publicKeyUInt8Array = toByteArray(publicKeyHex);
  const [encodedHeader, encodedPayload, encodedSignature] = signature.split(
    "."
  );
  const toBeSigned = encodedHeader + "." + encodedPayload;

  const message = Buffer.from(toBeSigned);
  const digest = crypto
    .createHash("sha256")
    .update(message)
    .digest()
    .toString("hex");

  const messageHashUInt8Array = toByteArray(digest);

  const signatureUInt8Array = toByteArray(
    base64url.toBuffer(encodedSignature).toString("hex")
  );

  const verified = secp256k1.verifySignatureCompact(
    signatureUInt8Array,
    publicKeyUInt8Array,
    messageHashUInt8Array
  );
  if (verified) {
    return JSON.parse(base64url.decode(encodedPayload));
  }
  return false;
};

module.exports = { signWithHex, verifyWithHex };
