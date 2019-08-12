import createVerifyData from './createVerifyData';

import { JWS } from '@transmute/es256k-jws-ts';

import defaultDocumentLoader from './defaultDocumentLoader';

/**
 * Example
 * ```ts
 * const privateJWK = {
 *  crv: 'secp256k1',
 *  d: 'rhYFsBPF9q3-uZThy7B3c4LDF_8wnozFUAEm5LLC4Zw',
 *  kid: 'JUvpllMEYUZ2joO59UNui_XYDqxVqiFLLAJ8klWuPBw',
 *  kty: 'EC',
 *  x: 'dWCvM4fTdeM0KmloF57zxtBPXTOythHPMm1HCLrdd3A',
 *  y: '36uMVGM7hnw-N6GnjFcihWE3SkrhMLzzLCdPMXPEXlA',
 * };
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
 * const signed = await sign(doc, signatureOptions, privateJWK);
 * ```
 *
 * This functions takes a json-ld document, signature options,
 * and a JWK private key, and returns the document with a proof attribute.
 */
export const sign = async (
  payload: any,
  signatureOptions: any,
  privateKeyJwk: any,
  options: any
) => {
  const proof = { ...signatureOptions, type: 'EcdsaSecp256k1Signature2019' };

  const documentLoader = options.documentLoader || defaultDocumentLoader;

  const { framed, verifyDataHexString } = await createVerifyData(
    payload,
    proof,
    documentLoader
  );

  const verifyDataBuffer = Buffer.from(verifyDataHexString, 'hex') as any;
  const jws = await JWS.signDetached(verifyDataBuffer, privateKeyJwk);
  const documentWithProof = {
    ...framed,
    proof: {
      ...proof,
      jws,
    },
  };
  return documentWithProof;
};
