import crypto from 'crypto';
import jsonld from 'jsonld';

const canonize = async (data: any) => {
  return jsonld.canonize(data);
};

const sha256 = (data: any) => {
  const h = crypto.createHash('sha256');
  h.update(data);
  return h.digest('hex');
};

const cannonizeSignatureOptions = (signatureOptions: any) => {
  const _signatureOptions = {
    ...signatureOptions,
    '@context': 'https://w3id.org/security/v2',
  };
  delete _signatureOptions.jws;
  delete _signatureOptions.signatureValue;
  delete _signatureOptions.proofValue;
  return canonize(_signatureOptions);
};

const cannonizeDocument = (doc: any) => {
  const _doc = { ...doc };
  delete _doc.proof;
  return canonize(_doc);
};

/**
 * Example
 * ```ts
 * const signatureOptions = {
 *    challenge: 'abc',
 *    created: '2019-01-16T20:13:10Z',
 *    domain: 'example.com',
 *    proofPurpose: 'authentication',
 *    verificationMethod: 'https://example.com/i/alice/keys/2',
 * };
 * const doc = {
 *    '@context': 'https://w3id.org/identity/v1',
 *    title: 'Hello World!',
 * };
 *
 * const verifyData = await createVerifyData(doc, signatureOptions);
 * expect(verifyData).toEqual({
 *    framed: {
 *      '@context': 'https://w3id.org/security/v2',
 *      'dc:title': 'Hello World!',
 *    },
 *    verifyDataHexString:
 *      '16ec94c1612c48b916bae6002db32df122e8c20d0fee156778c630e51f0cb3cb9ac6f24c9632f44d7c5752c5eed022f226c8ddb535ad2420d8852c9798f89175',
 * });
 * ```
 * This functions takes a json-ld document and signature options,
 * and produces the hex encoded data used by json-ld signature suite.
 * See [create-verify-hash-algorithm](https://w3c-dvcg.github.io/ld-signatures/#create-verify-hash-algorithm)
 */
const createVerifyData = async (data: any, signatureOptions: any) => {
  const options = { ...signatureOptions };
  if (options.creator) {
    options.verificationMethod = signatureOptions.creator;
  }
  if (!options.verificationMethod) {
    throw new Error('signatureOptions.verificationMethod is required');
  }
  if (!options.created) {
    options.created = new Date().toISOString();
  }

  const [expanded] = await jsonld.expand(data);
  const framed = await jsonld.compact(
    expanded,
    'https://w3id.org/security/v2',
    { skipExpansion: true }
  );

  const cannonizedSignatureOptions = await cannonizeSignatureOptions(options);
  const hashOfCannonizedSignatureOptions = sha256(cannonizedSignatureOptions);
  const cannonizedDocument = await cannonizeDocument(framed);
  const hashOfCannonizedDocument = sha256(cannonizedDocument);

  return {
    framed,
    verifyDataHexString:
      hashOfCannonizedSignatureOptions + hashOfCannonizedDocument,
  };
};

export default createVerifyData;
