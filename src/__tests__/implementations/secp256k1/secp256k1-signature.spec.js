const secp256k1 = require("secp256k1");
const crypto = require("crypto");

const privateKeyHex =
  "ae1605b013c5f6adfeb994e1cbb0777382c317ff309e8cc5500126e4b2c2e19c";

const publicKeyHex =
  "027560af3387d375e3342a6968179ef3c6d04f5d33b2b611cf326d4708badd7770";

describe("secp256k1", () => {
  it("raw secp256k1 signatures", async () => {
    const data = Buffer.from("");
    const digest = crypto
      .createHash("sha256")
      .update(data)
      .digest();
    expect(
      secp256k1
        .publicKeyCreate(Buffer.from(privateKeyHex, "hex"))
        .toString("hex")
    ).toBe(publicKeyHex);
    const sigObj = secp256k1.sign(
      Buffer.from(digest, "hex"),
      Buffer.from(privateKeyHex, "hex")
    );
    expect(sigObj.recovery).toBe(0);
    expect(sigObj.signature.toString("hex")).toBe(
      "01dcf356a9d429b1139bf2960ff4b2537082b242b5a6fd0eb161cbfa413c7ed404dec526b53df3787c6ffa1af17e088a7720943b61d2e441956619f6b57cb813"
    );
    const verified = secp256k1.verify(
      Buffer.from(digest, "hex"),
      sigObj.signature,
      Buffer.from(publicKeyHex, "hex")
    );
    expect(verified).toBe(true);
  });
});
