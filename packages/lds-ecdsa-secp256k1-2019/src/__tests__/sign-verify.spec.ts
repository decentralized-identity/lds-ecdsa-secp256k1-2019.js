const privateJWK = {
  crv: 'secp256k1',
  d: 'rhYFsBPF9q3-uZThy7B3c4LDF_8wnozFUAEm5LLC4Zw',
  kid: 'JUvpllMEYUZ2joO59UNui_XYDqxVqiFLLAJ8klWuPBw',
  kty: 'EC',
  x: 'dWCvM4fTdeM0KmloF57zxtBPXTOythHPMm1HCLrdd3A',
  y: '36uMVGM7hnw-N6GnjFcihWE3SkrhMLzzLCdPMXPEXlA',
};

const publicJWK = {
  crv: 'secp256k1',
  kid: 'JUvpllMEYUZ2joO59UNui_XYDqxVqiFLLAJ8klWuPBw',
  kty: 'EC',
  x: 'dWCvM4fTdeM0KmloF57zxtBPXTOythHPMm1HCLrdd3A',
  y: '36uMVGM7hnw-N6GnjFcihWE3SkrhMLzzLCdPMXPEXlA',
};

import { sign, verify } from '../index';

// because of throttling of contexts hosted on the web.
jest.setTimeout(10 * 1000);

describe('Sign & Verify', () => {
  it('sign and verify detached jws with ES256K', async () => {
    const signatureOptions = {
      challenge: 'abc',
      created: '2019-01-16T20:13:10Z',
      domain: 'example.com',
      proofPurpose: 'authentication',
      verificationMethod: 'https://example.com/i/alice/keys/2',
    };
    const doc = {
      '@context': {
        action: 'schema:action',
        schema: 'http://schema.org/',
      },
      action: 'AuthenticateMe',
    };
    const signed = await sign(doc, signatureOptions, privateJWK);
    expect(signed['@context']).toBe('https://w3id.org/security/v2');
    expect(signed['http://schema.org/action']).toBe('AuthenticateMe');
    expect(signed.proof.type).toBe('EcdsaSecp256k1Signature2019');
    expect(signed.proof.challenge).toBe('abc');
    expect(signed.proof.domain).toBe('example.com');
    expect(signed.proof.proofPurpose).toBe('authentication');
    expect(signed.proof.verificationMethod).toBe(
      'https://example.com/i/alice/keys/2'
    );
    // note the ".." per https://tools.ietf.org/html/rfc7797#section-6
    expect(signed.proof.jws).toBe(
      'eyJhbGciOiJFUzI1NksiLCJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdfQ..QgbRWT8w1LJet_KFofNfz_TVs27z4pwdPwUHhXYUaFlKicBQp6U1H5Kx-mST6uFvIyOqrYTJifDijZbtAfi0MA'
    );

    const verified = await verify(signed, publicJWK);
    expect(verified).toBe(true);
  });
});
