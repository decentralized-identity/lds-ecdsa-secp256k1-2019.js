const crypto = require("crypto");

describe("crypto", () => {
  // Beware that OpenSSL does not use deterministic k
  // https://crypto.stackexchange.com/questions/32551/openssl-signature-different-each-time
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

    console.log(signature.toString("hex"));
    const verified = crypto.verify("sha256", data, publicKey, signature);
    expect(verified).toBe(true);
  });
});
