import {
  ISecp256k1PrivateKeyJWK,
  ISecp256k1PublicKeyJWK,
  privateKeyUInt8ArrayFromJWK,
  publicKeyUInt8ArrayFromJWK,
} from './keyUtils';

import base64url from 'base64url';
import { binToHex, hexToBin, instantiateSecp256k1 } from 'bitcoin-ts';
import crypto from 'crypto';

class JWSVerificationFailed extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'JWSVerificationFailed';
  }
}

export const sign = async (
  payload: object,
  privateKeyJWK: ISecp256k1PrivateKeyJWK
) => {
  const privateKeyUInt8Array = await privateKeyUInt8ArrayFromJWK(privateKeyJWK);
  const secp256k1 = await instantiateSecp256k1();
  const header = { alg: 'ES256K' };
  const encodedHeader = base64url.encode(JSON.stringify(header));
  const encodedPayload = base64url.encode(JSON.stringify(payload));
  const toBeSigned = encodedHeader + '.' + encodedPayload;
  const message = Buffer.from(toBeSigned);
  const digest = crypto
    .createHash('sha256')
    .update(message)
    .digest()
    .toString('hex');
  const messageHashUInt8Array = hexToBin(digest);
  const signatureUInt8Array = secp256k1.signMessageHashCompact(
    privateKeyUInt8Array,
    messageHashUInt8Array
  );
  const signatureHex = binToHex(signatureUInt8Array);
  const encodedSignature = base64url.encode(Buffer.from(signatureHex, 'hex'));
  return `${encodedHeader}.${encodedPayload}.${encodedSignature}`;
};

export const verify = async (
  jws: string,
  publicKeyJWK: ISecp256k1PublicKeyJWK
) => {
  const secp256k1 = await instantiateSecp256k1();
  const publicKeyUInt8Array = await publicKeyUInt8ArrayFromJWK(publicKeyJWK);
  const [encodedHeader, encodedPayload, encodedSignature] = jws.split('.');
  const toBeSigned = encodedHeader + '.' + encodedPayload;

  const message = Buffer.from(toBeSigned);
  const digest = crypto
    .createHash('sha256')
    .update(message)
    .digest()
    .toString('hex');

  const messageHashUInt8Array = hexToBin(digest);

  const signatureUInt8Array = hexToBin(
    base64url.toBuffer(encodedSignature).toString('hex')
  );

  const verified = secp256k1.verifySignatureCompact(
    signatureUInt8Array,
    publicKeyUInt8Array,
    messageHashUInt8Array
  );
  if (verified) {
    return JSON.parse(base64url.decode(encodedPayload));
  }
  throw new JWSVerificationFailed('signature verification failed');
};

export const decode = (jws: string, options = { complete: false }) => {
  const [encodedHeader, encodedPayload, encodedSignature] = jws.split('.');

  if (!options.complete) {
    return JSON.parse(base64url.decode(encodedPayload));
  }
  if (options.complete) {
    return {
      header: JSON.parse(base64url.decode(encodedHeader)),
      payload: JSON.parse(base64url.decode(encodedPayload)),
      signature: encodedSignature,
    };
  }
};

export default {
  decode,
  sign,
  verify,
};
