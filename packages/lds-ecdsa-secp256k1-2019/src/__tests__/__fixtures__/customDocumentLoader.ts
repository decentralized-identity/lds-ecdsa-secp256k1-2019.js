import fs from 'fs';
import path from 'path';

const contexts: any = {
  'https://w3id.org/did/v1': require('./contexts/did-v0.11.json'),
  'https://w3id.org/security/v1': require('./contexts/security-v1.json'),
  'https://w3id.org/security/v2': require('./contexts/security-v2.json'),
};

import fixtures from '../__fixtures__';

const customLoader = (url: string) => {
  // console.log(url);
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
      document: fixtures.didDoc, // this is the actual document that was loaded
      documentUrl: 'did:example:123', // this is the actual context URL after redirects
    };
  }
  throw new Error('No custom context support for ' + url);
};

export default customLoader;
