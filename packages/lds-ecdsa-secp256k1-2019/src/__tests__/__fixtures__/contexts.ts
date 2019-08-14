import dids from './dids';

export default {
  'https://example.com/coolCustomContext/v1': {
    '@context': {
      '@version': 1.1,
      dc: 'http://purl.org/dc/terms/',
      id: '@id',
      myCustomProperty1337: 'coolCustomContext:myCustomProperty1337',
      rdfs: 'http://www.w3.org/2000/01/rdf-schema#',
      schema: 'http://schema.org/',
      type: '@type',
    },
  },
  'https://example.com/i/alice/keys/1': {
    controller: 'https://example.com/i/alice',
    id: 'https://example.com/i/alice/keys/1',
    publicKeyJwk:
      dids['did:example:123'].keys[
        'key-JUvpllMEYUZ2joO59UNui_XYDqxVqiFLLAJ8klWuPBw'
      ].publicKeyJwk,
    type: 'EcdsaSecp256k1VerificationKey2019',
  },
} as any;
