const jsigs = require('jsonld-signatures');

const { AssertionProofPurpose } = jsigs.purposes;

const {
  EcdsaSecp256k1KeyClass2019,
  EcdsaSecp256k1Signature2019,
  defaultDocumentLoader,
} = require('@transmute/lds-ecdsa-secp256k1-2019');

jest.setTimeout(10 * 1000);
describe('jsonld-signatures', () => {
  it('can sign and verify', async () => {
    const key = new EcdsaSecp256k1KeyClass2019({
      id:
        'did:elem:EiChaglAoJaBq7bGWp6bA5PAQKaOTzVHVXIlJqyQbljfmg#qfknmVDhMi3Uc190IHBRfBRqMgbEEBRzWOj1E9EmzwM',
      controller: 'did:elem:EiChaglAoJaBq7bGWp6bA5PAQKaOTzVHVXIlJqyQbljfmg',
      privateKeyJwk: {
        kty: 'EC',
        crv: 'secp256k1',
        d: 'wNZx20zCHoOehqaBOFsdLELabfv8sX0612PnuAiyc-g',
        x: 'NbASvplLIO_XTzP9R69a3MuqOO0DQw2LGnhJjirpd4w',
        y: 'EiZOvo9JWPz1yGlNNW66IV8uA44EQP_Yv_E7OZl1NG0',
        kid: 'qfknmVDhMi3Uc190IHBRfBRqMgbEEBRzWOj1E9EmzwM',
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
