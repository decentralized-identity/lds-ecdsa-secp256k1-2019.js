const privateKeyHex =
  "ae1605b013c5f6adfeb994e1cbb0777382c317ff309e8cc5500126e4b2c2e19c";

const didJWT = require("did-jwt");

const signer = didJWT.SimpleSigner(privateKeyHex);

describe("uport did-jwt key and signature sanity", () => {
  it("raw secp256k1 signatures", async () => {
    const data = Buffer.from("");
    const sig = await signer(data);
    expect(sig.r).toBe(
      "01dcf356a9d429b1139bf2960ff4b2537082b242b5a6fd0eb161cbfa413c7ed4"
    );
    expect(sig.s).toBe(
      "fb213ad94ac20c87839005e50e81f774438e48ab4d75bbfa2a6c44961ab9892e"
    );
    expect(sig.recoveryParam).toBe(1);
  });
});
