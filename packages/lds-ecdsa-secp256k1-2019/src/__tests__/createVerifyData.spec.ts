import createVerifyData from '../createVerifyData';

// because JSON-LD resolves urls over the web.
jest.setTimeout(20 * 1000);

import fixtures from './__fixtures__';

describe('createVerifyData', () => {
  it('createVerifyData', async () => {
    const signatureOptions = {
      challenge: 'abc',
      created: '2019-01-16T20:13:10Z',
      domain: 'example.com',
      proofPurpose: 'authentication',
      verificationMethod: 'https://example.com/i/alice/keys/2',
    };

    const options = {
      // no options needed.
    };
    const verifyData = await createVerifyData(
      fixtures.documents.authMe,
      signatureOptions,
      options
    );
    expect(verifyData).toEqual({
      framed: {
        '@context': 'https://w3id.org/security/v2',
        'http://schema.org/action': 'AuthenticateMe',
      },
      verifyDataHexString:
        '16ec94c1612c48b916bae6002db32df122e8c20d0fee156778c630e51f0cb3cba2b4396498daa20ab8acac405c8730802ffda5301c8502252b3f7da7cfabfac4',
    });
  });

  it('should error if signature options is missing verificationMethod or creator', async () => {
    expect.assertions(1);
    const signatureOptions = {
      challenge: 'abc',
      created: '2019-01-16T20:13:10Z',
      domain: 'example.com',
      proofPurpose: 'authentication',
    };

    const options = {
      // no options needed.
    };

    try {
      await createVerifyData(
        fixtures.documents.authMe,
        signatureOptions,
        options
      );
    } catch (e) {
      expect(e.message).toBe('signatureOptions.verificationMethod is required');
    }
  });

  it('should add verificationMethod from creator', async () => {
    expect.assertions(1);
    const signatureOptions = {
      challenge: 'abc',
      created: '2019-01-16T20:13:10Z',
      domain: 'example.com',
      proofPurpose: 'authentication',

      creator: 'https://example.com/i/alice/keys/2',
    };

    const options = {
      // no options needed.
    };
    const verifyData = await createVerifyData(
      fixtures.documents.authMe,
      signatureOptions,
      options
    );

    expect(verifyData).toEqual({
      framed: {
        '@context': 'https://w3id.org/security/v2',
        'http://schema.org/action': 'AuthenticateMe',
      },
      verifyDataHexString:
        '3c6c2d694ac5ffe17a0c991653892ae28ff20a22157ae6e90576f90a20628db6a2b4396498daa20ab8acac405c8730802ffda5301c8502252b3f7da7cfabfac4',
    });
  });

  it('should add created if missing', async () => {
    const signatureOptions = {
      challenge: 'abc',
      domain: 'example.com',
      proofPurpose: 'authentication',
      verificationMethod: 'https://example.com/i/alice/keys/2',
    } as any;

    const options = {
      // no options needed.
    };
    const verifyData = await createVerifyData(
      fixtures.documents.authMe,
      signatureOptions,
      options
    );

    // code smell, we should not be mutating signature options,
    // but there is not way to test this
    expect(signatureOptions.created).not.toBeDefined();
    expect(verifyData.framed).toEqual({
      '@context': 'https://w3id.org/security/v2',
      'http://schema.org/action': 'AuthenticateMe',
    });
  });
});
