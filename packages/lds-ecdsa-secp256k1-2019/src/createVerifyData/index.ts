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

const createVerifyData = async (data: any, signatureOptions: any) => {
  if (signatureOptions.creator) {
    signatureOptions.verificationMethod = signatureOptions.creator;
  }
  if (!signatureOptions.verificationMethod) {
    throw new Error('signatureOptions.verificationMethod is required');
  }
  if (!signatureOptions.created) {
    signatureOptions.created = new Date().toISOString();
  }

  signatureOptions.type = 'EcdsaSecp256k1Signature2019';

  const [expanded] = await jsonld.expand(data);
  const framed = await jsonld.compact(
    expanded,
    'https://w3id.org/security/v2',
    { skipExpansion: true }
  );

  const cannonizedSignatureOptions = await cannonizeSignatureOptions(
    signatureOptions
  );
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
