import EcdsaSecp256k1KeyClass2019 from '../EcdsaSecp256k1KeyClass2019';
import EcdsaSecp256k1Signature2019 from '../EcdsaSecp256k1Signature2019';

import fixtures from './__fixtures__';

import jsigs from 'jsonld-signatures';
import defaultDocumentLoader from '../defaultDocumentLoader';

const { AssertionProofPurpose } = jsigs.purposes;

const testJwk = async () => {
  const key = new EcdsaSecp256k1KeyClass2019({
    controller: 'did:example:123',
    privateKeyJwk: fixtures.didDocJwks.keys[0],
  });
  const signed = await jsigs.sign(
    { ...fixtures.exampleDoc },
    {
      compactProof: false,
      documentLoader: fixtures.documentLoader,
      purpose: new AssertionProofPurpose(),
      suite: new EcdsaSecp256k1Signature2019({
        key,
      }),
    }
  );
  // console.log(JSON.stringify(signed, null, 2));
  const res = await jsigs.verify(signed, {
    suite: new EcdsaSecp256k1Signature2019({
      key,
    }),

    compactProof: false,
    documentLoader: fixtures.documentLoader,
    purpose: new AssertionProofPurpose(),
  });
  // Leave for development purposes
  if (!res.verified) {
    // tslint:disable-next-line:no-console
    console.log(res);
  }
  return expect(res.verified).toBe(true);
};

describe('test supported key types', () => {
  it('should be able to create a verify ', async () => {
    await Promise.all(fixtures.didDocJwks.keys.map(testJwk));
  });
});

describe('assertVerificationMethod', () => {
  it('Invalid key type. Key type must be "EcdsaSecp256k1VerificationKey2019".', async () => {
    expect.assertions(1);
    const key = new EcdsaSecp256k1KeyClass2019({
      controller: 'did:example:123',
      privateKeyJwk: fixtures.didDocJwks.keys[0],
    });
    const suite = new EcdsaSecp256k1Signature2019({ key });
    try {
      await suite.assertVerificationMethod({
        verificationMethod: '123',
      });
    } catch (e) {
      expect(e.message).toBe(
        'Invalid key type. Key type must be "EcdsaSecp256k1VerificationKey2019".'
      );
    }
  });

  it('works', async () => {
    expect.assertions(1);
    const key = new EcdsaSecp256k1KeyClass2019({
      controller: 'did:example:123',
      privateKeyJwk: fixtures.didDocJwks.keys[0],
    });
    const suite = new EcdsaSecp256k1Signature2019({ key });
    const res = await suite.assertVerificationMethod({
      verificationMethod: fixtures.didDoc.publicKey[1],
    });
    expect(res).toBeUndefined();
  });
});

describe('getVerificationMethod', () => {
  it('works', async () => {
    const key = new EcdsaSecp256k1KeyClass2019({
      controller: 'did:example:123',
      privateKeyJwk: fixtures.didDocJwks.keys[0],
    });
    const suite = new EcdsaSecp256k1Signature2019({ key });

    const signed = await jsigs.sign(
      { ...fixtures.exampleDoc },
      {
        compactProof: false,
        documentLoader: fixtures.documentLoader,
        purpose: new AssertionProofPurpose(),
        suite,
      }
    );

    const res = await suite.getVerificationMethod({
      proof: signed.proof,
      documentLoader: defaultDocumentLoader,
    });

    expect(res.id).toBe(
      'did:example:123#WqzaOweASs78whhl_YvCEvj1nd89IycryVlmZMefcjU'
    );
  });

  it('can get from proof', async () => {
    const key = new EcdsaSecp256k1KeyClass2019({
      controller: 'did:example:123',
      privateKeyJwk: fixtures.didDocJwks.keys[0],
    });
    let suite = new EcdsaSecp256k1Signature2019({ key });

    const signed = await jsigs.sign(
      { ...fixtures.exampleDoc },
      {
        compactProof: false,
        documentLoader: fixtures.documentLoader,
        purpose: new AssertionProofPurpose(),
        suite,
      }
    );

    // will get from proof
    suite = new EcdsaSecp256k1Signature2019({});

    const res = await suite.getVerificationMethod({
      proof: signed.proof,
      documentLoader: fixtures.documentLoader,
    });

    expect(res.id).toBe(
      'did:example:123#WqzaOweASs78whhl_YvCEvj1nd89IycryVlmZMefcjU'
    );
  });
});

describe('error cases', () => {
  it('A signer API has not been specified.', async () => {
    expect.assertions(1);
    const suite = new EcdsaSecp256k1Signature2019({});
    try {
      const signed = await jsigs.sign(
        { ...fixtures.exampleDoc },
        {
          compactProof: false,
          documentLoader: fixtures.documentLoader,
          purpose: new AssertionProofPurpose(),
          suite,
        }
      );
    } catch (e) {
      expect(e.message).toBe('A signer API has not been specified.');
    }
  });
});

describe('verifySignature', () => {
  it('fails with bad data', async () => {
    expect.assertions(1);
    const key = new EcdsaSecp256k1KeyClass2019({
      controller: 'did:example:123',
      privateKeyJwk: fixtures.didDocJwks.keys[0],
    });
    let suite = new EcdsaSecp256k1Signature2019({ key });

    const signed = await jsigs.sign(
      { ...fixtures.exampleDoc },
      {
        compactProof: false,
        documentLoader: fixtures.documentLoader,
        purpose: new AssertionProofPurpose(),
        suite,
      }
    );

    suite = new EcdsaSecp256k1Signature2019({});
    const res = await suite.verifySignature({
      verifyData: 'bad',
      verificationMethod: key,
      proof: signed.proof,
    });

    expect(res).toBe(false);
  });
});

describe('matchProof', () => {
  it('returns false when super fails', async () => {
    const key = new EcdsaSecp256k1KeyClass2019({
      controller: 'did:example:123',
      privateKeyJwk: fixtures.didDocJwks.keys[0],
    });

    const suite = new EcdsaSecp256k1Signature2019({ key });

    const signed = await jsigs.sign(
      { ...fixtures.exampleDoc },
      {
        compactProof: false,
        documentLoader: fixtures.documentLoader,
        purpose: new AssertionProofPurpose(),
        suite,
      }
    );

    signed.proof.type = 'bar';

    const res = await suite.matchProof({
      proof: signed.proof,
      document: signed,
      purpose: signed.proof.proofPurpose,
      documentLoader: fixtures.documentLoader,
      expansionMap: false,
    });

    expect(res).toBe(false);
  });
  it('returns true when no key exists... who knows why...', async () => {
    const key = new EcdsaSecp256k1KeyClass2019({
      controller: 'did:example:123',
      privateKeyJwk: fixtures.didDocJwks.keys[0],
    });

    let suite = new EcdsaSecp256k1Signature2019({ key });

    const signed = await jsigs.sign(
      { ...fixtures.exampleDoc },
      {
        compactProof: false,
        documentLoader: fixtures.documentLoader,
        purpose: new AssertionProofPurpose(),
        suite,
      }
    );
    suite = new EcdsaSecp256k1Signature2019({});

    const res = await suite.matchProof({
      proof: signed.proof,
      document: signed,
      purpose: signed.proof.proofPurpose,
      documentLoader: fixtures.documentLoader,
      expansionMap: false,
    });

    expect(res).toBe(true);
  });
});
