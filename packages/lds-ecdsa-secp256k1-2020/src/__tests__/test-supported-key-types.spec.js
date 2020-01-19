const {
  MyLinkedDataKeyClass2019,
  JoseLinkedDataSignature2020,
} = require('../index');

const { documentLoader, doc, didDocJwks } = require('./__fixtures__');

const jsigs = require('jsonld-signatures');
const { AssertionProofPurpose } = jsigs.purposes;

const testJwk = async (privateKeyJwk) => {
  const key = new MyLinkedDataKeyClass2019({
    id: 'did:example:123#' + privateKeyJwk.kid,
    type: 'JoseVerificationKey2020',
    controller: 'did:example:123',
    privateKeyJwk: privateKeyJwk,
    // will be inferred
    // alg: "...",
  });

  const signed = await jsigs.sign(
    { ...doc },
    {
      suite: new JoseLinkedDataSignature2020({
        LDKeyClass: MyLinkedDataKeyClass2019,
        linkedDataSigantureType: 'JoseLinkedDataSignature2020',
        linkedDataSignatureVerificationKeyType: 'JoseVerificationKey2020',
        // will be inferred
        // alg: "...",
        key,
      }),
      purpose: new AssertionProofPurpose(),
      documentLoader: documentLoader,
      compactProof: false,
    }
  );

  const res = await jsigs.verify(signed, {
    suite: new JoseLinkedDataSignature2020({
      LDKeyClass: MyLinkedDataKeyClass2019,
      linkedDataSigantureType: 'JoseLinkedDataSignature2020',
      linkedDataSignatureVerificationKeyType: 'JoseVerificationKey2020',
      alg: JoseLinkedDataSignature2020.inferAlg(signed),
      key,
    }),
    purpose: new AssertionProofPurpose(),
    documentLoader: documentLoader,
    compactProof: false,
  });
  // Leave for development purposes
  if (!res.verified) {
    console.log(res);
  }
  return expect(res.verified).toBe(true);
};

describe('test supported key types', () => {
  it('should be able to create a verify ', async () => {
    await Promise.all(didDocJwks.keys.map(testJwk));
  });
});
