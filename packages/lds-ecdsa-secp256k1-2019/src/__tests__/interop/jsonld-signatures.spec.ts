import base64url from 'base64url';
import jsonld from 'jsonld';
import jsigs from 'jsonld-signatures';

const { Ed25519Signature2018 } = jsigs.suites;
const { AuthenticationProofPurpose } = jsigs.purposes;

const { Ed25519KeyPair } = jsigs;

const doc = {
  '@context': {
    action: 'schema:action',
    schema: 'http://schema.org/',
  },
  action: 'AuthenticateMe',
};

jest.setTimeout(10 * 1000);

const keypair = {
  privateKeyBase58:
    '3Mmk4UzTRJTEtxaKk61LxtgUxAa2Dg36jF6VogPtRiKvfpsQWKPCLesKSV182RMmvMJKk6QErH3wgdHp8itkSSiF',
  publicKeyBase58: 'GycSSui454dpYRKiFdsQ5uaE8Gy3ac6dSMPcAoQsk8yq',
};

const keyObject = {
  '@context': 'https://w3id.org/security/v2',
  id: 'https://example.com/i/alice/keys/2',
  type: 'Ed25519VerificationKey2018',

  controller: 'https://example.com/i/alice',
  publicKeyBase58: keypair.publicKeyBase58,
};

const controller = {
  '@context': 'https://w3id.org/security/v2',
  id: 'https://example.com/i/alice',
  publicKey: [keyObject],

  assertionMethod: [keyObject.id],
  authentication: [keyObject.id],
};

const testLoader = (url: string) => {
  switch (url) {
    case 'https://w3id.org/identity/v1':
      return require('./contexts/identity-v1.json');
    case 'https://w3id.org/did/v1':
      return require('./contexts/did-v1.json');
    case 'https://w3id.org/did/v0.11':
      return require('./contexts/did-v1_1.json');
    case 'https://w3id.org/security/v1':
      return require('./contexts/security-v1.json');
    case 'https://w3id.org/security/v2':
      return require('./contexts/security-v2.json');
    case 'https://example.com/i/alice/keys/2':
      return keyObject;
  }
};

describe('JSON-LD Signatures', () => {
  it('can sign and verify', async () => {
    const signed = await jsigs.sign(doc, {
      suite: new Ed25519Signature2018({
        documentLoader: testLoader,
        verificationMethod: keyObject.id,

        key: new Ed25519KeyPair(keypair),
      }),

      purpose: new AuthenticationProofPurpose({
        challenge: 'abc',
        domain: 'example.com',
      }),
    });

    const compacted = await jsonld.compact(
      signed,
      'https://w3id.org/security/v2',
      'http://schema.org/action'
    );

    expect(compacted.proof.type).toBe('Ed25519Signature2018');

    const result = await jsigs.verify(compacted, {
      documentLoader: testLoader,
      suite: new Ed25519Signature2018({
        key: new Ed25519KeyPair(keyObject),
      }),

      purpose: new AuthenticationProofPurpose({
        controller,

        challenge: 'abc',
        domain: 'example.com',
      }),
    });

    expect(result.verified).toBe(true);

    const jwsParts = compacted.proof.jws.split('..');
    const decodedParts = jwsParts.map((d: string) => {
      return base64url.decode(d);
    });

    const decodedheader = JSON.parse(decodedParts[0]);

    expect(decodedheader.alg).toBe('EdDSA');
    expect(decodedheader.b64).toBe(false);
    expect(decodedheader.crit).toEqual(['b64']);
  });
});
