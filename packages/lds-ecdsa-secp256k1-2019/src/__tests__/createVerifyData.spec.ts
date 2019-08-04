import createVerifyData from '../createVerifyData';

// because JSON-LD resolves urls over the web.
jest.setTimeout(10 * 1000);

describe('createVerifyData', () => {
  it('createVerifyData', async () => {
    const signatureOptions = {
      challenge: 'abc',
      created: '2019-01-16T20:13:10Z',
      domain: 'example.com',
      proofPurpose: 'authentication',
      verificationMethod: 'https://example.com/i/alice/keys/2',
    };
    const doc = {
      '@context': 'https://w3id.org/identity/v1',
      title: 'Hello World!',
    };
    const verifyData = await createVerifyData(doc, signatureOptions);
    expect(verifyData).toEqual({
      framed: {
        '@context': 'https://w3id.org/security/v2',
        'dc:title': 'Hello World!',
      },
      verifyDataHexString:
        '16ec94c1612c48b916bae6002db32df122e8c20d0fee156778c630e51f0cb3cb9ac6f24c9632f44d7c5752c5eed022f226c8ddb535ad2420d8852c9798f89175',
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
    const doc = {
      '@context': 'https://w3id.org/identity/v1',
      title: 'Hello World!',
    };

    try {
      await createVerifyData(doc, signatureOptions);
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
    const doc = {
      '@context': 'https://w3id.org/identity/v1',
      title: 'Hello World!',
    };
    const verifyData = await createVerifyData(doc, signatureOptions);

    expect(verifyData).toEqual({
      framed: {
        '@context': 'https://w3id.org/security/v2',
        'dc:title': 'Hello World!',
      },
      verifyDataHexString:
        '3c6c2d694ac5ffe17a0c991653892ae28ff20a22157ae6e90576f90a20628db69ac6f24c9632f44d7c5752c5eed022f226c8ddb535ad2420d8852c9798f89175',
    });
  });

  it('should add created if missing', async () => {
    const signatureOptions = {
      challenge: 'abc',
      domain: 'example.com',
      proofPurpose: 'authentication',
      verificationMethod: 'https://example.com/i/alice/keys/2',
    } as any;
    const doc = {
      '@context': 'https://w3id.org/identity/v1',
      title: 'Hello World!',
    };
    const verifyData = await createVerifyData(doc, signatureOptions);

    // code smell, we should not be mutating signature options,
    // but there is not way to test this
    expect(signatureOptions.created).not.toBeDefined();
    expect(verifyData.framed).toEqual({
      '@context': 'https://w3id.org/security/v2',
      'dc:title': 'Hello World!',
    });
  });
});
