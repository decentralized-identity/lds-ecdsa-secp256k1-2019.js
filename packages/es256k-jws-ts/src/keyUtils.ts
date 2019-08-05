import keyto from '@trust/keyto';
import base64url from 'base64url';
import crypto from 'crypto';

import { binToHex, hexToBin, instantiateSecp256k1 } from 'bitcoin-ts';

import stringify from 'json-stringify-deterministic';

const compressedHexEncodedPublicKeyLength = 66;

/** Secp256k1 Private Key JWK  */
export interface ISecp256k1PrivateKeyJWK {
  /** key type */
  kty: string;

  /** curve */
  crv: string;

  /** private point */
  d: string;

  /** public point */
  x: string;

  /** public point */
  y: string;

  /** key id */
  kid: string;
}

/** Secp256k1 Public Key JWK  */
export interface ISecp256k1PublicJWK {
  /** key type */
  kty: string;

  /** curve */
  crv: string;

  /** public point */
  x: string;

  /** public point */
  y: string;

  /** key id */
  kid: string;
}

/**
 * Example
 * ```js
 * {
 *  kty: 'EC',
 *  crv: 'secp256k1',
 *  d: 'rhYFsBPF9q3-uZThy7B3c4LDF_8wnozFUAEm5LLC4Zw',
 *  x: 'dWCvM4fTdeM0KmloF57zxtBPXTOythHPMm1HCLrdd3A',
 *  y: '36uMVGM7hnw-N6GnjFcihWE3SkrhMLzzLCdPMXPEXlA',
 *  kid: 'JUvpllMEYUZ2joO59UNui_XYDqxVqiFLLAJ8klWuPBw'
 * }
 * ```
 * See [rfc7638](https://tools.ietf.org/html/rfc7638) for more details on JWK.
 */
export const getKid = (jwk: ISecp256k1PrivateKeyJWK | ISecp256k1PublicJWK) => {
  const copy = { ...jwk } as any;
  delete copy.d;
  delete copy.kid;
  delete copy.alg;
  const digest = crypto
    .createHash('sha256')
    .update(stringify(copy))
    .digest();

  return base64url.encode(Buffer.from(digest));
};

/** convert compressed hex encoded private key to jwk */
export const privateJWKFromPrivateKeyHex = async (privateKeyHex: string) => {
  const jwk = {
    ...keyto.from(privateKeyHex, 'blk').toJwk('private'),
    crv: 'secp256k1',
  };
  const kid = getKid(jwk);
  return {
    ...jwk,
    kid,
  };
};

/** convert compressed hex encoded public key to jwk */
export const publicJWKFromPublicKeyHex = async (publicKeyHex: string) => {
  const secp256k1 = await instantiateSecp256k1();
  let key = publicKeyHex;
  if (publicKeyHex.length === compressedHexEncodedPublicKeyLength) {
    key = binToHex(secp256k1.uncompressPublicKey(hexToBin(publicKeyHex)));
  }
  const jwk = {
    ...keyto.from(key, 'blk').toJwk('public'),
    crv: 'secp256k1',
  };
  const kid = getKid(jwk);

  return {
    ...jwk,
    kid,
  };
};

/** convert pem encoded private key to jwk */
export const privateJWKFromPrivateKeyPem = (privateKeyPem: string) => {
  const jwk = {
    ...keyto.from(privateKeyPem, 'pem').toJwk('private'),
    crv: 'secp256k1',
  };
  // console.log(jwk);
  const kid = getKid(jwk);

  return {
    ...jwk,
    kid,
  };
};

/** convert pem encoded private key to jwk */
export const publicJWKFromPublicKeyPem = (publicKeyPem: string) => {
  const jwk = {
    ...keyto.from(publicKeyPem, 'pem').toJwk('public'),
    crv: 'secp256k1',
  };
  const kid = getKid(jwk);

  return {
    ...jwk,
    kid,
  };
};

/** convert jwk to hex encoded private key */
export const privateKeyHexFromJWK = async (jwk: ISecp256k1PrivateKeyJWK) =>
  keyto
    .from(
      {
        ...jwk,
        crv: 'K-256',
      },
      'jwk'
    )
    .toString('blk', 'private');

/** convert jwk to hex encoded public key */
export const publicKeyHexFromJWK = async (jwk: ISecp256k1PublicJWK) => {
  const secp256k1 = await instantiateSecp256k1();
  const uncompressedPublicKey = keyto
    .from(
      {
        ...jwk,
        crv: 'K-256',
      },
      'jwk'
    )
    .toString('blk', 'public');
  const compressed = secp256k1.compressPublicKey(
    hexToBin(uncompressedPublicKey)
  );
  return binToHex(compressed);
};

/** convert jwk to binary encoded private key */
export const privateKeyUInt8ArrayFromJWK = async (
  jwk: ISecp256k1PrivateKeyJWK
) => {
  const privateKeyHex = await privateKeyHexFromJWK(jwk);
  return hexToBin(privateKeyHex);
};

/** convert jwk to binary encoded public key */
export const publicKeyUInt8ArrayFromJWK = async (jwk: ISecp256k1PublicJWK) => {
  const publicKeyHex = await publicKeyHexFromJWK(jwk);
  return hexToBin(publicKeyHex);
};

export default {
  binToHex,
  getKid,
  hexToBin,
  privateJWKFromPrivateKeyHex,
  privateJWKFromPrivateKeyPem,
  privateKeyHexFromJWK,
  privateKeyUInt8ArrayFromJWK,
  publicJWKFromPublicKeyHex,
  publicJWKFromPublicKeyPem,
  publicKeyHexFromJWK,
  publicKeyUInt8ArrayFromJWK,
};
