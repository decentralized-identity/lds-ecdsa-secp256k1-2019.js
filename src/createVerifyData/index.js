const jsonld = require('jsonld');
const crypto = require('crypto');

const canonize = async data => jsonld.canonize(data);

const sha256 = (data) => {
  const h = crypto.createHash('sha256');
  h.update(data);
  return h.digest('hex');
};

const cannonizeSignatureOptions = (signatureOptions) => {
  const newSignatureOptions = {
    ...signatureOptions,
    '@context': 'https://w3id.org/security/v2',
  };
  delete newSignatureOptions.jws;
  delete newSignatureOptions.signatureValue;
  delete newSignatureOptions.proofValue;
  return canonize(newSignatureOptions);
};

const cannonizeDocument = (doc) => {
  const newDoc = { ...doc };
  delete newDoc.proof;
  return canonize(newDoc);
};

const createVerifyData = async (data, signatureOptions) => {
  const newSignatureOptions = { ...signatureOptions };
  if (signatureOptions.creator) {
    newSignatureOptions.verificationMethod = signatureOptions.creator;
  }
  if (!newSignatureOptions.verificationMethod) {
    throw new Error('signatureOptions.verificationMethod is required');
  }
  if (!signatureOptions.created) {
    newSignatureOptions.created = new Date().toISOString();
  }

  newSignatureOptions.type = 'EcdsaSecp256k1Signature2019';

  const [expanded] = await jsonld.expand(data);
  const framed = await jsonld.compact(
    expanded,
    'https://w3id.org/security/v2',
    { skipExpansion: true },
  );

  const cannonizedSignatureOptions = await cannonizeSignatureOptions(
    signatureOptions,
  );
  const hashOfCannonizedSignatureOptions = sha256(cannonizedSignatureOptions);
  const cannonizedDocument = await cannonizeDocument(framed);
  const hashOfCannonizedDocument = sha256(cannonizedDocument);

  return {
    framed,
    verifyDataHexString: `${hashOfCannonizedSignatureOptions}${hashOfCannonizedDocument}`,
  };
};

module.exports = createVerifyData;
