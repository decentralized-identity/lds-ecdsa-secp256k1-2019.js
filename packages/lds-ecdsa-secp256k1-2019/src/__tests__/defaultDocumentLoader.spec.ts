import defaultDocumentLoader from '../defaultDocumentLoader';

jest.setTimeout(10 * 1000);

describe('defaultDocumentLoader', () => {
  it('can resolve did context', async () => {
    const result = await defaultDocumentLoader('https://www.w3.org/ns/did/v1');
    expect(result.documentUrl).toBe('https://www.w3.org/ns/did/v1');
  });

  it('can resolve did document', async () => {
    const result = await defaultDocumentLoader(
      'did:elem:EiChaglAoJaBq7bGWp6bA5PAQKaOTzVHVXIlJqyQbljfmg'
    );
    expect(result.document.id).toBe(
      'did:elem:EiChaglAoJaBq7bGWp6bA5PAQKaOTzVHVXIlJqyQbljfmg'
    );
  });

  it('can resolve did document public key', async () => {
    const result = await defaultDocumentLoader(
      'did:elem:EiChaglAoJaBq7bGWp6bA5PAQKaOTzVHVXIlJqyQbljfmg#qfknmVDhMi3Uc190IHBRfBRqMgbEEBRzWOj1E9EmzwM'
    );
    expect(result.document.id).toBe(
      'did:elem:EiChaglAoJaBq7bGWp6bA5PAQKaOTzVHVXIlJqyQbljfmg#qfknmVDhMi3Uc190IHBRfBRqMgbEEBRzWOj1E9EmzwM'
    );
  });
});
