import universalResolver from '../universalResolver';

jest.setTimeout(10 * 1000);

describe('universalResolver', () => {
  it('can resolve a did:elem directly against our public http endpoint', async () => {
    const result = await universalResolver.resolve(
      'did:elem:EiChaglAoJaBq7bGWp6bA5PAQKaOTzVHVXIlJqyQbljfmg'
    );
    expect(result.id).toBe(
      'did:elem:EiChaglAoJaBq7bGWp6bA5PAQKaOTzVHVXIlJqyQbljfmg'
    );
  });
});
