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
});
