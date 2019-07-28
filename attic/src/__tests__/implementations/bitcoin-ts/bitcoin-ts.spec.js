const { instantiateSecp256k1 } = require("bitcoin-ts");

const crypto = require("crypto");

const privateKeyHex =
  "ae1605b013c5f6adfeb994e1cbb0777382c317ff309e8cc5500126e4b2c2e19c";

const publicKeyHex =
  "027560af3387d375e3342a6968179ef3c6d04f5d33b2b611cf326d4708badd7770";

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

describe("bitcoin-ts", () => {
  it("raw bitcoin-ts", async () => {
    const privateKeyUInt8Array = toByteArray(privateKeyHex);

    const secp256k1 = await instantiateSecp256k1();

    const data = Buffer.from("");
    const digest = crypto
      .createHash("sha256")
      .update(data)
      .digest()
      .toString("hex");

    const messageHashUInt8Array = toByteArray(digest);

    const signatureUInt8Array = secp256k1.signMessageHashCompact(
      privateKeyUInt8Array,
      messageHashUInt8Array
    );

    const signatureHex = toHexString(signatureUInt8Array);

    // console.log(signatureHex.length);

    const publicKeyUInt8Array = secp256k1.derivePublicKeyCompressed(
      privateKeyUInt8Array
    );

    const verified = secp256k1.verifySignatureCompact(
      signatureUInt8Array,
      publicKeyUInt8Array,
      messageHashUInt8Array
    );

    expect(verified).toBe(true);
  });
});
