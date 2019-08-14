import fixtures from './__fixtures__';

import { sign } from '../sign';
import { verify } from '../verify';

jest.setTimeout(10 * 1000);

describe('Sign & Verify without DIDs', () => {
  it('sign and verify detached jws with ES256K', async () => {
    const privateKeyJwk =
      fixtures.dids['did:example:123'].keys[
        'key-JUvpllMEYUZ2joO59UNui_XYDqxVqiFLLAJ8klWuPBw'
      ].privateKeyJwk;

    const proof = {
      created: '2019-01-16T20:13:10Z',
      domain: 'example.com',
      proofPurpose: 'assertionMethod',
      verificationMethod: 'https://example.com/i/alice/keys/1',
    };
    const options = {
      documentLoader: fixtures.documentLoader,
    };
    const signed = await sign(
      fixtures.documents.example,
      proof,
      privateKeyJwk,
      options
    );
    expect(signed['@context']).toBe('https://w3id.org/security/v2');
    expect(signed['http://schema.org/image']).toBe(
      'https://manu.sporny.org/images/manu.png'
    );
    expect(signed['http://schema.org/name']).toBe('Manu Sporny');
    expect(signed['http://schema.org/url']).toBe('https://manu.sporny.org/');
    expect(signed.proof.type).toBe('EcdsaSecp256k1Signature2019');
    expect(signed.proof.domain).toBe('example.com');
    expect(signed.proof.proofPurpose).toBe('assertionMethod');
    expect(signed.proof.verificationMethod).toBe(
      'https://example.com/i/alice/keys/1'
    );
    // note the ".." per https://tools.ietf.org/html/rfc7797#section-6
    expect(signed.proof.jws).toBe(
      'eyJhbGciOiJFUzI1NksiLCJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdfQ..3gehix87N0cEqORgravE6tur6KFyqhVbMtAbSMhhEKttCRh3S3kvZDhjiwFTfu9m2mcypYotzZo7o0HeAuPlng'
    );

    const verified = await verify(signed, {
      documentLoader: fixtures.documentLoader,
    });

    expect(verified).toBe(true);
  });
});
