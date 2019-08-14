import jsonld from 'jsonld';
import contexts from './contexts';
import resolver from './resolver';

const nodeDocumentLoader = jsonld.documentLoaders.node();

export default async (url: string, callback: any) => {
  // console.log(url);
  // are we handling a DID?
  if (url.indexOf('did') === 0) {
    let doc;
    try {
      doc = await resolver.resolve(url);
    } catch (e) {
      callback(e);
    }
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

  //   are we handling a custom context?
  if (url in contexts) {
    const document = contexts[url];
    return callback(null, {
      contextUrl: null, // this is for a context via a link header
      document, // this is the actual document that was loaded
      documentUrl: url, // this is the actual context URL after redirects
    });
  }

  //   is this a published (public) context?
  return nodeDocumentLoader(url, callback);
};
