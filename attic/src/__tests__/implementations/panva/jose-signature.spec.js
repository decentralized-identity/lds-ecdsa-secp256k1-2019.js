const jose = require("@panva/jose");

const privateKey = jose.JWK.asKey({
  crv: "secp256k1",
  x: "dWCvM4fTdeM0KmloF57zxtBPXTOythHPMm1HCLrdd3A",
  y: "36uMVGM7hnw-N6GnjFcihWE3SkrhMLzzLCdPMXPEXlA",
  d: "rhYFsBPF9q3-uZThy7B3c4LDF_8wnozFUAEm5LLC4Zw",
  kty: "EC"
});

const publicKey = jose.JWK.asKey({
  crv: "secp256k1",
  x: "dWCvM4fTdeM0KmloF57zxtBPXTOythHPMm1HCLrdd3A",
  y: "36uMVGM7hnw-N6GnjFcihWE3SkrhMLzzLCdPMXPEXlA",
  kty: "EC",
  kid: "JUvpllMEYUZ2joO59UNui_XYDqxVqiFLLAJ8klWuPBw"
});

describe("@panva/jose signatures", () => {
  // Beware that OpenSSL does not use deterministic k
  // https://crypto.stackexchange.com/questions/32551/openssl-signature-different-each-time
  it("These use node 12 under the hood", async () => {
    const payload = {
      sub: "John Doe"
    };
    const signature = jose.JWS.sign(payload, privateKey);
    console.log(jose.JWT.decode(signature, { complete: true }));

    const verified = jose.JWS.verify(signature, publicKey);

    expect(verified).toEqual({ sub: "John Doe" });
  });

  it("can verify from our library", () => {
    const sig =
      "eyJhbGciOiJFUzI1NksifQ.eyJoZWxsbyI6dHJ1ZX0.NdmDdVLxgeu-IcmzrE4RsZpB-245i_7qu5nRxK6CUepunNiTuA33EG2jeqU1yaAPbMRgdwgShPZGmUNyYF4Rgg";

    const verified = jose.JWS.verify(sig, publicKey);
    expect(verified).toEqual({ hello: true });
  });
});
