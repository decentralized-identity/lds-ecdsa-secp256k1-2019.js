const jose = require("jose");
const base64url = require("base64url-universal");

const key = {
  kty: "OKP",
  crv: "Ed25519",
  d: "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
  x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
};

const header = {
  alg: "EdDSA",
  b64: false,
  crit: ["b64"]
};
const data = new Uint8Array([128]);
const payload = Buffer.from(data.buffer, data.byteOffset, data.length);

describe("Detached JWS", () => {
  it("simple: sign & verify", async () => {
    const detached = jose.JWS.sign.flattened(
      payload,
      jose.JWK.asKey(key),
      header
    );
    expect(
      jose.JWS.verify({ ...detached, payload }, jose.JWK.asKey(key), {
        crit: ["b64"]
      })
    ).toBe(payload);
  });

  it("from strings sign & verify", async () => {
    const flat = jose.JWS.sign.flattened(payload, jose.JWK.asKey(key), header);
    const jws = flat.protected + ".." + flat.signature;
    const [encodedHeader, encodedSignature] = jws.split("..");
    const detached = {
      protected: encodedHeader,
      signature: encodedSignature
    };
    expect(
      jose.JWS.verify({ ...detached, payload }, jose.JWK.asKey(key), {
        crit: ["b64"]
      })
    ).toBe(payload);
  });
});
