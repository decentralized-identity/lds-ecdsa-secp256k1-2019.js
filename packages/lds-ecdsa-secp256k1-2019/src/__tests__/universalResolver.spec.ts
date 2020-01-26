import universalResolver, { normalizeDocument } from '../universalResolver';

jest.setTimeout(10 * 1000);

import btcrURDidDoc from './__fixtures__/btcrURDidDoc.json';

describe('universalResolver', () => {
  it('can resolve a did:elem directly against our public http endpoint', async () => {
    const result = await universalResolver.resolve(
      'did:elem:EiChaglAoJaBq7bGWp6bA5PAQKaOTzVHVXIlJqyQbljfmg'
    );
    expect(result.id).toBe(
      'did:elem:EiChaglAoJaBq7bGWp6bA5PAQKaOTzVHVXIlJqyQbljfmg'
    );
  });

  it('fails for invalid ur did', async () => {
    try {
      await universalResolver.resolve(
        'did:foo:EiChaglAoJaBq7bGWp6bA5PAQKaOTzVHVXIlJqyQbljfmg'
      );
    } catch (e) {
      expect(e.message).toBe(
        'Error: Could not resolve DID with Universal Resolver.'
      );
    }
  });
});

describe('normalizeDocument', () => {
  it('can handle continuation', async () => {
    await normalizeDocument(btcrURDidDoc);
  });

  it('can handle continuation with publicKey', async () => {
    await normalizeDocument(btcrURDidDoc);
  });
});
