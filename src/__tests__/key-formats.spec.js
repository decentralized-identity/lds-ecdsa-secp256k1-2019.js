const jose = require("@panva/jose");
const keyto = require("@trust/keyto");
const secp256k1 = require("secp256k1");
const crypto = require("crypto");

const privateKeyHex =
  "ae1605b013c5f6adfeb994e1cbb0777382c317ff309e8cc5500126e4b2c2e19c";

const publicKeyHex =
  "027560af3387d375e3342a6968179ef3c6d04f5d33b2b611cf326d4708badd7770";

const publicKeyHexExpanded =
  "047560af3387d375e3342a6968179ef3c6d04f5d33b2b611cf326d4708badd7770dfab8c54633b867c3e37a1a78c57228561374a4ae130bcf32c274f3173c45e50";

describe("secp256k1 key and signature sanity", () => {
  it("raw secp256k1 signatures", async () => {
    const toBeSigned = "hello";
    const hash = crypto
      .createHash("sha256")
      .update(Buffer.from(toBeSigned))
      .digest();

    expect(
      secp256k1
        .publicKeyCreate(Buffer.from(privateKeyHex, "hex"))
        .toString("hex")
    ).toBe(publicKeyHex);

    const sigObj = secp256k1.sign(hash, Buffer.from(privateKeyHex, "hex"));
    const verified = secp256k1.verify(
      hash,
      sigObj.signature,
      Buffer.from(publicKeyHex, "hex")
    );
    expect(verified).toBe(true);
  });

  it("JOSE Signatures", async () => {
    // const key = jose.JWK.generateSync("EC", "secp256k1").toJWK(true);
    // console.log(key);

    const privateKey = jose.JWK.asKey({
      crv: "secp256k1",
      x: "dWCvM4fTdeM0KmloF57zxtBPXTOythHPMm1HCLrdd3A",
      y: "36uMVGM7hnw-N6GnjFcihWE3SkrhMLzzLCdPMXPEXlA",
      d: "rhYFsBPF9q3-uZThy7B3c4LDF_8wnozFUAEm5LLC4Zw",
      kty: "EC",
      kid: "JUvpllMEYUZ2joO59UNui_XYDqxVqiFLLAJ8klWuPBw"
    });
    const publicKey = jose.JWK.asKey({
      crv: "secp256k1",
      x: "dWCvM4fTdeM0KmloF57zxtBPXTOythHPMm1HCLrdd3A",
      y: "36uMVGM7hnw-N6GnjFcihWE3SkrhMLzzLCdPMXPEXlA",
      kty: "EC",
      kid: "JUvpllMEYUZ2joO59UNui_XYDqxVqiFLLAJ8klWuPBw"
    });
    const payload = {
      sub: "John Doe"
    };
    const signature = jose.JWS.sign(payload, privateKey);
    const verified = jose.JWS.verify(signature, publicKey);
    expect(verified).toEqual({ sub: "John Doe" });
  });

  it("can convert secp256k1 private key hex to jwk", async () => {
    const privateKey = jose.JWK.asKey({
      ...keyto.from(privateKeyHex, "blk").toJwk("private"),
      crv: "secp256k1"
    }).toJWK(true);

    const publicKey = jose.JWK.asKey({
      ...keyto.from(privateKeyHex, "blk").toJwk("private"),
      crv: "secp256k1"
    }).toJWK();

    expect(privateKey).toEqual({
      crv: "secp256k1",
      x: "dWCvM4fTdeM0KmloF57zxtBPXTOythHPMm1HCLrdd3A",
      y: "36uMVGM7hnw-N6GnjFcihWE3SkrhMLzzLCdPMXPEXlA",
      d: "rhYFsBPF9q3-uZThy7B3c4LDF_8wnozFUAEm5LLC4Zw",
      kty: "EC",
      kid: "JUvpllMEYUZ2joO59UNui_XYDqxVqiFLLAJ8klWuPBw"
    });

    expect(publicKey).toEqual({
      crv: "secp256k1",
      x: "dWCvM4fTdeM0KmloF57zxtBPXTOythHPMm1HCLrdd3A",
      y: "36uMVGM7hnw-N6GnjFcihWE3SkrhMLzzLCdPMXPEXlA",
      kty: "EC",
      kid: "JUvpllMEYUZ2joO59UNui_XYDqxVqiFLLAJ8klWuPBw"
    });
  });

  it("private key: hex -> pem -> jwk", async () => {
    const privateKeyPem = keyto
      .from(Buffer.from(privateKeyHex, "hex"), "blk")
      .toString("pem", "private_pkcs8");

    expect(privateKeyPem).toBe(`-----BEGIN PRIVATE KEY-----
MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgrhYFsBPF9q3+uZThy7B3
c4LDF/8wnozFUAEm5LLC4ZyhRANCAAR1YK8zh9N14zQqaWgXnvPG0E9dM7K2Ec8y
bUcIut13cN+rjFRjO4Z8Pjehp4xXIoVhN0pK4TC88ywnTzFzxF5Q
-----END PRIVATE KEY-----`);
    const privateKeyJWKFromPrivateKeyPem = jose.JWK.asKey({
      key: privateKeyPem,
      format: "pem",
      type: "pkcs8"
    }).toJWK(true);
    expect(privateKeyJWKFromPrivateKeyPem).toEqual({
      crv: "secp256k1",
      x: "dWCvM4fTdeM0KmloF57zxtBPXTOythHPMm1HCLrdd3A",
      y: "36uMVGM7hnw-N6GnjFcihWE3SkrhMLzzLCdPMXPEXlA",
      d: "rhYFsBPF9q3-uZThy7B3c4LDF_8wnozFUAEm5LLC4Zw",
      kty: "EC",
      kid: "JUvpllMEYUZ2joO59UNui_XYDqxVqiFLLAJ8klWuPBw"
    });
  });

  it("compress and expand keys", async () => {
    const uncompressedPublicKeyHex = secp256k1
      .publicKeyConvert(Buffer.from(publicKeyHex, "hex"), false)
      .toString("hex");

    expect(uncompressedPublicKeyHex).toBe(publicKeyHexExpanded);

    const compressedPublicKeyHex = secp256k1
      .publicKeyConvert(Buffer.from(uncompressedPublicKeyHex, "hex"), true)
      .toString("hex");

    expect(compressedPublicKeyHex).toBe(publicKeyHex);

    expect(
      secp256k1
        .publicKeyCreate(Buffer.from(privateKeyHex, "hex"))
        .toString("hex")
    ).toBe(compressedPublicKeyHex);
  });

  it("public key: hex -> pem -> jwk", async () => {
    const uncompressedPublicKeyHex = secp256k1
      .publicKeyConvert(Buffer.from(publicKeyHex, "hex"), false)
      .toString("hex");

    const publicKeyPem = keyto
      .from(uncompressedPublicKeyHex, "blk")
      .toString("pem", "public_pkcs8");

    expect(publicKeyPem).toBe(`-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEdWCvM4fTdeM0KmloF57zxtBPXTOythHP
Mm1HCLrdd3Dfq4xUYzuGfD43oaeMVyKFYTdKSuEwvPMsJ08xc8ReUA==
-----END PUBLIC KEY-----`);

    const publicKeyJWKFromPublicKeyPem = jose.JWK.asKey({
      key: publicKeyPem,
      format: "pem",
      type: "pkcs8"
    }).toJWK();

    expect(publicKeyJWKFromPublicKeyPem).toEqual({
      crv: "secp256k1",
      x: "dWCvM4fTdeM0KmloF57zxtBPXTOythHPMm1HCLrdd3A",
      y: "36uMVGM7hnw-N6GnjFcihWE3SkrhMLzzLCdPMXPEXlA",
      kty: "EC",
      kid: "JUvpllMEYUZ2joO59UNui_XYDqxVqiFLLAJ8klWuPBw"
    });
  });
});
