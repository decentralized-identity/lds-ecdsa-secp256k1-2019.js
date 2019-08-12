import jsonld from 'jsonld';
import resolver from './universalResolver';

const _nodejs =
  // tslint:disable-next-line
  typeof process !== 'undefined' && process.versions && process.versions.node;
const _browser =
  // tslint:disable-next-line
  !_nodejs && (typeof window !== 'undefined' || typeof self !== 'undefined');

const documentLoader = _browser
  ? jsonld.documentLoaders.xhr()
  : jsonld.documentLoaders.node();

export default async (url: string, callback: any) => {
  // console.log(url);
  // are we handling a DID?
  if (url.indexOf('did:') === 0) {
    const doc = await resolver.resolve(url);
    if (!doc) {
      throw new Error('Could not resolve: ' + url);
    }
    // TODO: add proper jsonld logic for iterating all possible DID URIs.
    // iterate public keys, find the correct id...
    for (const publicKey of doc.publicKey) {
      if (publicKey.id === url) {
        return callback(null, {
          contextUrl: null, // this is for a context via a link header
          document: publicKey, // this is the actual document that was loaded
          documentUrl: url, // this is the actual context URL after redirects
        });
      }
    }
  }

  //   is this a published (public) context?
  return documentLoader(url, callback);
};
