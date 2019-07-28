const jose = require("@panva/jose");
const keyto = require("@trust/keyto");

const privateKeyHex =
  "ae1605b013c5f6adfeb994e1cbb0777382c317ff309e8cc5500126e4b2c2e19c";

const publicKeyHex =
  "027560af3387d375e3342a6968179ef3c6d04f5d33b2b611cf326d4708badd7770";

const payload = {
  hello: true
};

const secp256k1JWS = require("../../../secp256k1-jws");

describe("bitcoin-ts", () => {
  it("can create a JWS", async () => {
    // const privateKeyJWKFromPrivateKeyPem = jose.JWK.asKey({
    //   key: keyto
    //     .from(Buffer.from(privateKeyHex, "hex"), "blk")
    //     .toString("pem", "private_pkcs8"),
    //   format: "pem",
    //   type: "pkcs8"
    // });
    // const signature = jose.JWS.sign(payload, privateKeyJWKFromPrivateKeyPem);
    // const decoded = jose.JWT.decode(signature, { complete: true });
    // console.log(decoded);

    const signature2 = await secp256k1JWS.signWithHex(payload, privateKeyHex);

    const verified2 = await secp256k1JWS.verifyWithHex(
      signature2,
      publicKeyHex
    );

    console.log(verified2);

    // const publicKey = jose.JWK.asKey({
    //   crv: "secp256k1",
    //   x: "dWCvM4fTdeM0KmloF57zxtBPXTOythHPMm1HCLrdd3A",
    //   y: "36uMVGM7hnw-N6GnjFcihWE3SkrhMLzzLCdPMXPEXlA",
    //   kty: "EC",
    //   kid: "JUvpllMEYUZ2joO59UNui_XYDqxVqiFLLAJ8klWuPBw"
    // });

    // const verified = jose.JWS.verify(signature2, publicKey);

    // console.log(verified);
  });
});
