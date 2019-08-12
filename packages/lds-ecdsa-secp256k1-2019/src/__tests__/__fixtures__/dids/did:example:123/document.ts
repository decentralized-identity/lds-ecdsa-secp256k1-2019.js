import keys from './keys';

export default {
  '@context': 'https://w3id.org/did/v1',
  id: 'did:example:123',
  publicKey: [
    {
      controller: 'did:example:123',
      id: 'did:example:123#key-JUvpllMEYUZ2joO59UNui_XYDqxVqiFLLAJ8klWuPBw',
      publicKeyJwk:
        keys['key-JUvpllMEYUZ2joO59UNui_XYDqxVqiFLLAJ8klWuPBw'].publicKeyJwk,
      type: 'EcdsaSecp256k1VerificationKey2019',
    },
  ],
  service: [
    {
      // used to retrieve Verifiable Credentials associated with the DID
      type: 'VerifiableCredentialService',

      serviceEndpoint: 'https://example.com/vc/',
    },
  ],
};
