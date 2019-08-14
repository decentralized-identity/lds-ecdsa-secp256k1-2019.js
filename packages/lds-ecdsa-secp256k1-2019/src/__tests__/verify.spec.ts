import fixtures from './__fixtures__';

import { verify } from '../index';

// because of throttling of contexts hosted on the web.
jest.setTimeout(20 * 1000);

describe('Verify', () => {
  it('will convert publicKeyHex to publicKeyJwk automatically', async () => {
    const options = {
      documentLoader: fixtures.documentLoader,
    };
    const verified = await verify(
      fixtures.documents.authMeSignedExampleHex,
      options
    );
    expect(verified).toBe(true);
  });

  it('will fail when called on invalid key type', async () => {
    const options = {
      documentLoader: fixtures.documentLoader,
    };

    const badVc = { ...fixtures.documents.authMeSignedExampleHex };
    badVc.proof.verificationMethod = 'did:example:123#yubikey';
    try {
      await verify(badVc, options);
    } catch (e) {
      expect(e.message).toBe('Invalid verificationMethod key format');
    }
  });
});
