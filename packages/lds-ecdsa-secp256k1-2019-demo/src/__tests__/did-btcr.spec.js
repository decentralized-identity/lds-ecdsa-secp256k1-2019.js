const jsigs = require('jsonld-signatures');

const { AssertionProofPurpose } = jsigs.purposes;

const {
  EcdsaSecp256k1KeyClass2019,
  EcdsaSecp256k1Signature2019,
  defaultDocumentLoader,
} = require('@transmute/lds-ecdsa-secp256k1-2019');

jest.setTimeout(10 * 1000);

// because of UR bug.
// See: https://github.com/decentralized-identity/universal-resolver/issues/77
describe.skip('jsonld-signatures', () => {
  it('can sign and verify', async () => {
    const key = new EcdsaSecp256k1KeyClass2019({
      id:
        'did:btcr:xxcl-lzpq-q83a-0d5#key-JUvpllMEYUZ2joO59UNui_XYDqxVqiFLLAJ8klWuPBw',
      controller: 'did:btcr:xxcl-lzpq-q83a-0d5',
      privateKeyJwk: {
        crv: 'secp256k1',
        d: 'rhYFsBPF9q3-uZThy7B3c4LDF_8wnozFUAEm5LLC4Zw',
        kid: 'JUvpllMEYUZ2joO59UNui_XYDqxVqiFLLAJ8klWuPBw',
        kty: 'EC',
        x: 'dWCvM4fTdeM0KmloF57zxtBPXTOythHPMm1HCLrdd3A',
        y: '36uMVGM7hnw-N6GnjFcihWE3SkrhMLzzLCdPMXPEXlA',
      },
    });
    const signed = await jsigs.sign(
      {
        '@context': [
          {
            schema: 'http://schema.org/',
            name: 'schema:name',
            homepage: 'schema:url',
            image: 'schema:image',
          },
        ],
        name: 'Manu Sporny',
        homepage: 'https://manu.sporny.org/',
        image: 'https://manu.sporny.org/images/manu.png',
      },
      {
        compactProof: false,
        documentLoader: defaultDocumentLoader,
        purpose: new AssertionProofPurpose(),
        suite: new EcdsaSecp256k1Signature2019({
          key,
        }),
      }
    );

    // console.log(signed);

    // const didDoc = (await defaultDocumentLoader(
    //   signed.proof.verificationMethod.split('#').shift()
    // )).document;

    // didDoc.assertionMethod = [signed.proof.verificationMethod];

    // console.log(didDoc);

    const res = await jsigs.verify(signed, {
      suite: new EcdsaSecp256k1Signature2019({
        key,
      }),

      compactProof: false,
      // controller: didDoc,
      documentLoader: defaultDocumentLoader,
      purpose: new AssertionProofPurpose(),
    });
    // Leave for development purposes
    if (!res.verified) {
      // tslint:disable-next-line:no-console
      console.log(res);
    }
    expect(res.verified).toBe(true);
  });
});
