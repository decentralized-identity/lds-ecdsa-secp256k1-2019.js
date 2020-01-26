import fetch from 'node-fetch';

import convertFragmentsToURIs from './convertFragmentsToURIs';

const getJson = async (url: string) =>
  fetch(url, {
    headers: {
      Accept: 'application/ld+json',
    },
    method: 'get',
  }).then((data: any) => data.json());

const normalizeDocument = (res: any) => {
  const didDoc =
    res.id && res.id.indexOf('did:') === 0 ? res : { ...res.didDocument };
  // hack for BTCR.
  if (res.methodMetadata) {
    if (res.methodMetadata.continuation.publicKey) {
      didDoc.publicKey = res.methodMetadata.continuation.publicKey;
    }
    if (res.methodMetadata.continuation.assertionMethod) {
      didDoc.assertionMethod = res.methodMetadata.continuation.assertionMethod;
    }

    if (res.methodMetadata.continuation.authentication) {
      didDoc.authentication = res.methodMetadata.continuation.authentication;
    }

    if (res.methodMetadata.continuation.capabilityInvocation) {
      didDoc.capabilityInvocation =
        res.methodMetadata.continuation.capabilityInvocation;
    }

    if (res.methodMetadata.continuation.capabilityDelegation) {
      didDoc.capabilityDelegation =
        res.methodMetadata.continuation.capabilityDelegation;
    }

    if (res.methodMetadata.continuation.keyAgreement) {
      didDoc.keyAgreement = res.methodMetadata.continuation.keyAgreement;
    }
  }

  return didDoc;
};

export default {
  resolve: async (didUri: string) => {
    try {
      const didMethod = didUri
        .split(':')
        .splice(0, 2)
        .join(':');

      let res;
      // this avoids jsonld parsing done the universal resolver,
      // which sometimes breaks things.
      switch (didMethod) {
        case 'did:elem':
          res = await getJson(
            'https://element-did.com/api/v1/sidetree/' + didUri
          );
          break;
        default:
          res = await getJson(
            'https://uniresolver.io/1.0/identifiers/' + didUri
          );
      }

      const normalizedDoc = await normalizeDocument(res);
      const deFragmented = convertFragmentsToURIs(normalizedDoc);
      const finalDoc = deFragmented;
      return finalDoc;
    } catch (e) {
      // tslint:disable-next-line:no-console
      console.error('Could not resolve: ' + didUri);
      throw new Error(e);
    }
  },
};
