import fetch from 'node-fetch';

const getJson = async (url: string) =>
  fetch(url, {
    headers: {
      Accept: 'application/ld+json',
    },
    method: 'get',
  }).then((data: any) => data.json());

const normalizeDocument = (res: any) => {
  const didDoc = { ...res.didDocument };
  // hack for BTCR.
  if (res.methodMetadata) {
    didDoc.publicKey = res.methodMetadata.continuation.publicKey;
  }

  return didDoc;
};

export default {
  resolve: async (didUri: string) => {
    try {
      const res = await getJson(
        'https://uniresolver.io/1.0/identifiers/' + didUri
      );
      const doc = await normalizeDocument(res);
      return doc;
    } catch (e) {
      throw new Error('Could not resolve: ' + didUri);
    }
  },
};
