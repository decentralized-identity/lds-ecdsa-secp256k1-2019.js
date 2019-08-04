import createVerifyData from './createVerifyData';

import { JWS } from '@transmute/es256k-jws-ts';

/**
 * Example
 *
 * ```js
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
  privateKeyJwk: any
) => {
  const options = { ...signatureOptions, type: 'EcdsaSecp256k1Signature2019' };

  const { framed, verifyDataHexString } = await createVerifyData(
    payload,
    options
  );

  const verifyDataBuffer = Buffer.from(verifyDataHexString, 'hex') as any;
  const jws = await JWS.signDetached(verifyDataBuffer, privateKeyJwk);
  const documentWithProof = {
    ...framed,
    proof: {
      ...options,
      jws,
    },
  };
  return documentWithProof;
};

/**
 * Example
 *
 * ```js
 * const publicJWK = {
 *   crv: 'secp256k1',
 *   kid: 'JUvpllMEYUZ2joO59UNui_XYDqxVqiFLLAJ8klWuPBw',
 *   kty: 'EC',
 *   x: 'dWCvM4fTdeM0KmloF57zxtBPXTOythHPMm1HCLrdd3A',
 *   y: '36uMVGM7hnw-N6GnjFcihWE3SkrhMLzzLCdPMXPEXlA',
 * };
 * const signed = {
 *   '@context': 'https://w3id.org/security/v2',
 *   'http://schema.org/action': 'AuthenticateMe',
 *   proof: {
 *     challenge: 'abc',
 *     created: '2019-01-16T20:13:10Z',
 *     domain: 'example.com',
 *     proofPurpose: 'authentication',
 *     verificationMethod: 'https://example.com/i/alice/keys/2',
 *     type: 'EcdsaSecp256k1Signature2019',
 *     jws: 'eyJhbGciOiJFUzI1NksiLCJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdfQ..QgbRWT8w1LJet_KFofNfz_TVs27z4pwdPwUHhXYUaFlKicBQp6U1H5Kx-mST6uFvIyOqrYTJifDijZbtAfi0MA'
 *   }
 * }
 *
 * const verified = await verify(signed, publicJWK);
 * ```
 *
 * This functions takes a signed json-ld document, and JWK public key and
 * returns true if the document was signed by the public key, false otherwise.
 */
export const verify = async (payload: any, publicKeyJwk: any) => {
  const { framed, verifyDataHexString } = await createVerifyData(
    payload,
    payload.proof
  );
  const verifyDataBuffer = Buffer.from(verifyDataHexString, 'hex') as any;

  return JWS.verifyDetached(payload.proof.jws, verifyDataBuffer, publicKeyJwk);
};

export default {
  sign,
  verify,
};
