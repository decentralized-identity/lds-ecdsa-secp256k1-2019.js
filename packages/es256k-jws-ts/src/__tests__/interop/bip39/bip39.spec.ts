import * as bip39 from 'bip39';
import hdkey from 'hdkey';

import { keyUtils } from '../../../index';

describe('BIP39', () => {
  it('supports bip39 private key derivation', async () => {
    const mnemonic =
      'start fuel hybrid exit sell now gas salmon defense chest attend cycle';
    const hdPath = "m/44'/60'/0'/0";
    const seed = await bip39.mnemonicToSeed(mnemonic);
    const root = hdkey.fromMasterSeed(seed);
    const addrNode = root.derive(hdPath);
    const privateKey = addrNode.privateKey.toString('hex');
    expect(privateKey).toBe(
      '617e062ea82d0cc631bc6b315b444f2efb55319ea8e0b64f6f8a807ef7588e41'
    );
    const privateKeyJWK = await keyUtils.privateJWKFromPrivateKeyHex(
      privateKey
    );
    expect(privateKeyJWK).toEqual({
      crv: 'secp256k1',
      kid: 'b0pjci0P8v5hgFGyEa5yCWTx5XqSFhSa4915yqtd7Xg',
      kty: 'EC',

      d: 'YX4GLqgtDMYxvGsxW0RPLvtVMZ6o4LZPb4qAfvdYjkE',
      x: 'I0vpvN8EH3Uwl5uLiLfcYt1QWnWIPIIR86glBTT5bcA',
      y: 'wJuz6QuuiiuKXUE21UgY-JLEAXb4KZRSApjkF3fZfg4',
    });
  });
});
