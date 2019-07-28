const crypto = require("crypto");
const jose = require("@panva/jose");
const secp256k1 = require("secp256k1");
const keyto = require("@trust/keyto");
const didJWT = require("did-jwt");

const help = require("./help");

const privateKeyHex =
  "ae1605b013c5f6adfeb994e1cbb0777382c317ff309e8cc5500126e4b2c2e19c";

const signer = didJWT.SimpleSigner(privateKeyHex);

let publicKeyHex;
let privateKeyPem;
let publicKeyPem;
describe("draft-compliance", () => {
  it("keys", async () => {
    publicKeyHex = secp256k1
      .publicKeyCreate(Buffer.from(privateKeyHex, "hex"))
      .toString("hex");
    const data = Buffer.from("");
    const digest = crypto
      .createHash("sha256")
      .update(data)
      .digest();
    const secp256k1SigObject = secp256k1.sign(
      digest,
      Buffer.from(privateKeyHex, "hex")
    );
    const verifiedSecp256k1SigObject = secp256k1.verify(
      digest,
      secp256k1SigObject.signature,
      Buffer.from(publicKeyHex, "hex")
    );

    const secp256k1SignatureHex = secp256k1SigObject.signature.toString("hex");
    expect(secp256k1SignatureHex).toBe(
      "01dcf356a9d429b1139bf2960ff4b2537082b242b5a6fd0eb161cbfa413c7ed404dec526b53df3787c6ffa1af17e088a7720943b61d2e441956619f6b57cb813"
    );

    privateKeyPem = keyto
      .from(Buffer.from(privateKeyHex, "hex"), "blk")
      .toString("pem", "private_pkcs8");

    const uncompressedPublicKeyHex = secp256k1
      .publicKeyConvert(Buffer.from(publicKeyHex, "hex"), false)
      .toString("hex");

    publicKeyPem = keyto
      .from(uncompressedPublicKeyHex, "blk")
      .toString("pem", "public_pkcs8");

    const signatureDER = crypto.sign(
      "sha256",
      data,
      crypto.createPrivateKey({
        key: privateKeyPem
      })
    );
    const verifiedDER = crypto.verify(
      "sha256",
      data,
      crypto.createPublicKey({
        key: publicKeyPem
      }),
      signatureDER
    );
    expect(verifiedDER).toBe(true);

    const DERFromSecp256k1SignatureHex = help.joseToDer(
      Buffer.from(secp256k1SignatureHex, "hex"),
      "ES256"
    );

    const verifiedDERFromSecp256k1SignatureHex = crypto.verify(
      "sha256",
      data,
      crypto.createPublicKey({
        key: publicKeyPem
      }),
      DERFromSecp256k1SignatureHex
    );
    // proof that a raw secp256k1 signature can be verified with node 12 crypto
    expect(verifiedDERFromSecp256k1SignatureHex).toBe(true);

    const sigObj = await signer(data);
    const uportSigObjInJoseFormat = sigObj.r + sigObj.s;
    const DERFromUport = help.joseToDer(
      Buffer.from(uportSigObjInJoseFormat, "hex"),
      "ES256"
    );
    const verifiedUPortDER = crypto.verify(
      "sha256",
      data,
      crypto.createPublicKey({
        key: publicKeyPem
      }),
      DERFromUport
    );
    // proof that uport signatures can be verified on node 12
    expect(verifiedUPortDER).toBe(true);

    // const joseSignatureFromDER = help
    //   .derToJose(signatureDER, "ES256")
    //   .toString("hex");

    // const verifiedJOSEFromDER = secp256k1.verify(
    //   digest,
    //   Buffer.from(joseSignatureFromDER, "hex"),
    //   Buffer.from(publicKeyHex, "hex")
    // );

    // // proof that a node 12 crypto signature can be verified with secp256k1
    // // WARNING: intermittent failure here! unknown why!
    // expect(verifiedJOSEFromDER).toBe(true);

    // const sigObj = await signer(digest);
    // const uportSigObjInJoseFormat = sigObj.r + sigObj.s;

    // const verifiedJOSEFromUPort = secp256k1.verify(
    //   digest,
    //   Buffer.from(uportSigObjInJoseFormat, "hex"),
    //   Buffer.from(publicKeyHex, "hex")
    // );
    // expect(verifiedJOSEFromUPort).toBe(true);

    // console.log(verifiedJOSEFromUPort);
  });

  //   it("node12 crypo", () => {
  //     const privateKey = crypto.createPrivateKey({
  //       key: `-----BEGIN PRIVATE KEY-----
  // MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgrhYFsBPF9q3+uZThy7B3
  // c4LDF/8wnozFUAEm5LLC4ZyhRANCAAR1YK8zh9N14zQqaWgXnvPG0E9dM7K2Ec8y
  // bUcIut13cN+rjFRjO4Z8Pjehp4xXIoVhN0pK4TC88ywnTzFzxF5Q
  // -----END PRIVATE KEY-----`
  //     });
  //     const publicKey = crypto.createPublicKey({
  //       key: `-----BEGIN PUBLIC KEY-----
  // MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEdWCvM4fTdeM0KmloF57zxtBPXTOythHP
  // Mm1HCLrdd3Dfq4xUYzuGfD43oaeMVyKFYTdKSuEwvPMsJ08xc8ReUA==
  // -----END PUBLIC KEY-----`
  //     });
  //     const data = Buffer.from("");
  //     const signature = crypto.sign("sha256", data, privateKey);

  //     const joseSignature = help.derToJose(signature, "ES256").toString("hex");

  //     console.log(joseSignature.length);

  //     const r = joseSignature.substring(0, 64);
  //     const s = joseSignature.substring(64, 128);

  //     // console.log(r, s);

  //     // console.log(joseSign.toString("hex"));

  //     const digest = crypto
  //       .createHash("sha256")
  //       .update(data)
  //       .digest();

  //     const verified = secp256k1.verify(
  //       Buffer.from(digest, "hex"),
  //       Buffer.from(r + s, "hex"),
  //       Buffer.from(publicKeyHex, "hex")
  //     );

  //     console.log(verified);
  //   });
});
