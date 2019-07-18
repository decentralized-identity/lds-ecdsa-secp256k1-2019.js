const bip39 = require('bip39');
const hdkey = require('hdkey');
const ethUtil = require('ethereumjs-util');

const { sign, verify } = require('../index');

const fixtures = require('./__fixtures__');

describe('EcdsaKoblitzSignature2016', () => {
  it('supports bip39 / ethereum', async () => {
    // const  mnemonic = bip39.generateMnemonic();
    const mnemonic = 'start fuel hybrid exit sell now gas salmon defense chest attend cycle';
    //   m / purpose' / coin_type' / account' / change / address_index
    const hdPath = "m/44'/60'/0'/0";
    const seed = bip39.mnemonicToSeed(mnemonic);
    const root = hdkey.fromMasterSeed(seed);
    const addrNode = root.derive(hdPath);

    // eslint-disable-next-line no-underscore-dangle
    const privateKey = addrNode._privateKey.toString('hex');

    const ethPublicKey = ethUtil.privateToPublic(
      Buffer.from(privateKey, 'hex'),
    );
    const ethAddress = ethUtil.toChecksumAddress(
      ethUtil.pubToAddress(ethPublicKey).toString('hex'),
    );

    const ethIdentity = {
      ethAddress,
      ethPublicKey: ethPublicKey.toString('hex'),
      ethPrivateKey: privateKey,
    };

    const message = 'hello world';

    const signedEthereum = await ethUtil.ecsign(
      ethUtil.sha256(message),
      Buffer.from(ethIdentity.ethPrivateKey, 'hex'),
    );

    const recoveredEthereum = await ethUtil.ecrecover(
      ethUtil.sha256(message),
      signedEthereum.v,
      signedEthereum.r,
      signedEthereum.s,
    );

    expect(
      ethUtil.toChecksumAddress(
        ethUtil.pubToAddress(recoveredEthereum).toString('hex'),
      ),
    ).toBe(ethIdentity.ethAddress);

    // let result = await sign({
    //   data: { ...fixtures.linkedData },
    //   creator: `did:example:123`,
    //   privateKey: ethIdentity.ethPrivateKey
    // });

    // expect(result.signature).toBeDefined();
    // result = await verify({
    //   data: result,
    //   publicKey: ethIdentity.ethPublicKey
    // });
    // expect(result).toBe(true);
  });
});
