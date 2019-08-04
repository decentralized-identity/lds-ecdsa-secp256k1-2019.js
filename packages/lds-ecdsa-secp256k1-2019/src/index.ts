import createVerifyData from './createVerifyData';

import { JWS } from '@transmute/es256k-jws-ts';

export const sign = async (
  payload: any,
  signatureOptions: any,
  privateKeyJwk: any
) => {
  const { framed, verifyDataHexString } = await createVerifyData(
    payload,
    signatureOptions
  );
  const verifyDataBuffer = Buffer.from(verifyDataHexString, 'hex') as any;
  const jws = await JWS.signDetached(verifyDataBuffer, privateKeyJwk);
  const documentWithProof = {
    ...framed,
    proof: {
      ...signatureOptions,
      jws,
    },
  };
  return documentWithProof;
};

export const verify = async (payload: any, publicKeyJwk: any) => {
  const { framed, verifyDataHexString } = await createVerifyData(
    payload,
    payload.proof
  );
  const verifyDataBuffer = Buffer.from(verifyDataHexString, 'hex') as any;

  return JWS.verifyDetached(payload.proof.jws, verifyDataBuffer, publicKeyJwk);
};
