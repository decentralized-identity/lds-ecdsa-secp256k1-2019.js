import fixtures from './__fixtures__';

import { sign, verify } from '../index';

// because of throttling of contexts hosted on the web.
jest.setTimeout(20 * 1000);

describe('Sign & Verify With DIDs & Universal Resolver', () => {
  it('sign and verify detached jws with ES256K', async () => {
    const privateKeyJwk =
      fixtures.dids['did:example:123'].keys[
        'key-JUvpllMEYUZ2joO59UNui_XYDqxVqiFLLAJ8klWuPBw'
      ].privateKeyJwk;

    const proof = {
      challenge: 'abc',
      created: '2019-01-16T20:13:10Z',
      domain: 'example.com',
      proofPurpose: 'authentication',
      verificationMethod:
        'did:btcr:xxcl-lzpq-q83a-0d5#key-JUvpllMEYUZ2joO59UNui_XYDqxVqiFLLAJ8klWuPBw',
    };

    const options = {
      // will default to default DocumentLoader + Universal Resolver
      // documentLoader: fixtures.documentLoader,
    };

    const signed = await sign(
      fixtures.documents.authMe,
      proof,
      privateKeyJwk,
      options
    );

    expect(signed['@context']).toBe('https://w3id.org/security/v2');
    expect(signed['http://schema.org/action']).toBe('AuthenticateMe');
    expect(signed.proof.type).toBe('EcdsaSecp256k1Signature2019');
    expect(signed.proof.challenge).toBe('abc');
    expect(signed.proof.domain).toBe('example.com');
    expect(signed.proof.proofPurpose).toBe('authentication');
    expect(signed.proof.verificationMethod).toBe(
      'did:btcr:xxcl-lzpq-q83a-0d5#key-JUvpllMEYUZ2joO59UNui_XYDqxVqiFLLAJ8klWuPBw'
    );
    // note the ".." per https://tools.ietf.org/html/rfc7797#section-6
    expect(signed.proof.jws).toBe(
      'eyJhbGciOiJFUzI1NksiLCJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdfQ..-9Qx1IzX1RfwFxMoNwk1XxT0z6Pv32etfUb9IGuiyFcXndzIiFlVqJYUC9aH0yY7Gk4zgbR03siotEtkPlqa0w'
    );

    const verified = await verify(signed, options);
    expect(verified).toBe(true);
  });

  it('should error when DID cannot be resolved', async () => {
    expect.assertions(1);
    const options = {
      // will default to default DocumentLoader + Universal Resolver
      // documentLoader: fixtures.documentLoader,
    };
    const badVc = { ...fixtures.documents.authMeSigned };
    badVc.proof.verificationMethod = 'did:bad:123';
    try {
      await verify(badVc, options);
    } catch (e) {
      expect(e.message).toBe('Could not resolve: did:bad:123');
    }
  });
});
