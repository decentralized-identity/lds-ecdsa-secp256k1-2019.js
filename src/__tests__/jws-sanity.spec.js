const jose = require("@panva/jose");
const keyto = require("@trust/keyto");
const secp256k1 = require("secp256k1");

const crypto = require("crypto");

const payload = {
  hello: true
};

const privateKeyHex =
  "ae1605b013c5f6adfeb994e1cbb0777382c317ff309e8cc5500126e4b2c2e19c";

const publicKeyHex =
  "027560af3387d375e3342a6968179ef3c6d04f5d33b2b611cf326d4708badd7770";

const privateKeyJWK = jose.JWK.asKey({
  ...keyto.from(privateKeyHex, "blk").toJwk("private"),
  crv: "secp256k1"
});

const didJWT = require("did-jwt");

describe("jose/jws", () => {
  it("raw node 12 crypto", async () => {
    const privateKey = crypto.createPrivateKey({
      key: `-----BEGIN PRIVATE KEY-----
MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgrhYFsBPF9q3+uZThy7B3
c4LDF/8wnozFUAEm5LLC4ZyhRANCAAR1YK8zh9N14zQqaWgXnvPG0E9dM7K2Ec8y
bUcIut13cN+rjFRjO4Z8Pjehp4xXIoVhN0pK4TC88ywnTzFzxF5Q
-----END PRIVATE KEY-----`
    });
    const publicKey = crypto.createPublicKey({
      key: `-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEdWCvM4fTdeM0KmloF57zxtBPXTOythHP
Mm1HCLrdd3Dfq4xUYzuGfD43oaeMVyKFYTdKSuEwvPMsJ08xc8ReUA==
-----END PUBLIC KEY-----`
    });
    const data = Buffer.from("");
    const signature = crypto.sign("sha256", data, privateKey);
    const verified = crypto.verify("sha256", data, publicKey, signature);
    expect(verified).toBe(true);
  });

  it("raw secp256k1 signatures", async () => {
    const data = Buffer.from("");
    const macKey = "test";
    const hash = crypto
      .createHmac("sha256", macKey)
      .update(data)
      .digest();

    expect(
      secp256k1
        .publicKeyCreate(Buffer.from(privateKeyHex, "hex"))
        .toString("hex")
    ).toBe(publicKeyHex);

    const sigObj = secp256k1.sign(hash, Buffer.from(privateKeyHex, "hex"));

    console.log(sigObj.signature.toString("base64"));
    const verified = secp256k1.verify(
      hash,
      sigObj.signature,
      Buffer.from(publicKeyHex, "hex")
    );
    expect(verified).toBe(true);
  });

  it("signature", async () => {
    // const privateKeyPem = keyto
    //   .from(Buffer.from(privateKeyHex, "hex"), "blk")
    //   .toString("pem", "private_pkcs8");
    // console.log(privateKeyPem);
    // // const signature = jose.JWS.sign(payload, privateKeyJWK);
    // // const decoded = jose.JWT.decode(signature, { complete: true });
    // // expect(decoded.header).toEqual({ alg: "ES256K" });
    // // expect(decoded.payload).toEqual({ hello: true });
    // // console.log(decoded);
    // // const signer = didJWT.SimpleSigner(privateKeyHex);
    // // const sigObj = await signer("asdf");
    // // console.log(sigObj);
    // const toBeSigned = "hello";
    // const digest = crypto
    //   .createHash("sha256")
    //   .update(Buffer.from(toBeSigned))
    //   .digest("base64");
    // console.log(
    //   crypto.sign(
    //     "ES256K",
    //     Buffer.from("Hello world"),
    //     Buffer.from(privateKeyPem)
    //   )
    // );
  });
});
