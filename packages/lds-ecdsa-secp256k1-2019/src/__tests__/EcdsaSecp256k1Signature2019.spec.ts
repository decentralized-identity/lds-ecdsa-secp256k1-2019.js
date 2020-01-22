import EcdsaSecp256k1KeyClass2019 from '../EcdsaSecp256k1KeyClass2019';
import EcdsaSecp256k1Signature2019 from '../EcdsaSecp256k1Signature2019';

import fixtures from './__fixtures__';

// const {
//   EcdsaSecp256k1KeyClass2019,
//   EcdsaSecp256k1Signature2019,
// } = require('../index');

// const { documentLoader, doc, didDocJwks } = require('./__fixtures__');

import jsigs from 'jsonld-signatures';

const { AssertionProofPurpose } = jsigs.purposes;

const testJwk = async (privateKeyJwk: any) => {
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
