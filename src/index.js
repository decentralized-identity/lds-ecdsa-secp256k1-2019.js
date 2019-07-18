const suite = require('./suite');
const createVerifyData = require('./createVerifyData');

const sign = async ({ data, signatureOptions, privateKey }) => {
  const { framed, verifyDataHexString } = await createVerifyData(
    data,
    signatureOptions,
  );

  const signatureValue = await suite.sign({
    verifyData: verifyDataHexString,
    privateKey,
  });

  const documentWithProof = {
    ...framed,
    proof: {
      ...signatureOptions,
      signatureValue,
    },
  };
  return documentWithProof;
};

const verify = async ({ data, publicKey }) => {
  const { framed, verifyDataHexString } = await createVerifyData(
    data,
    data.proof,
  );

  return suite.verify({
    verifyData: verifyDataHexString,
    signature: data.proof.signatureValue,
    publicKey,
  });
};

module.exports = {
  sign,
  verify,
};
