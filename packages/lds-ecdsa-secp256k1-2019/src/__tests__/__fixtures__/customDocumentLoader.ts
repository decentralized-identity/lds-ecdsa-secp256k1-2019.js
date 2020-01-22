import fs from 'fs';
import path from 'path';

const contexts: any = {
  'https://w3id.org/did/v1': require('./contexts/did-v0.11.json'),
};

import fixtures from '../__fixtures__';

const customLoader = (url: string) => {
  const context = contexts[url];

  if (context) {
    return {
      contextUrl: null, // this is for a context via a link header
      document: context, // this is the actual document that was loaded
      documentUrl: url, // this is the actual context URL after redirects
    };
  }

  if (url === 'did:example:123') {
    return {
      contextUrl: null, // this is for a context via a link header
      document: fixtures.didDoc, // this is the actual document that was loaded
      documentUrl: url, // this is the actual context URL after redirects
    };
  }

  if (url === 'did:example:123#WqzaOweASs78whhl_YvCEvj1nd89IycryVlmZMefcjU') {
    return {
      contextUrl: null, // this is for a context via a link header
      document: fixtures.didDoc.publicKey[1], // this is the actual document that was loaded
      documentUrl: url, // this is the actual context URL after redirects
    };
  }
  throw new Error('No custom context support for ' + url);
};

export default customLoader;
