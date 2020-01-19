const base64url = require('base64url');
const { MyLinkedDataKeyClass2019 } = require('../index');
const { didDocJwks } = require('./__fixtures__');

const key = new MyLinkedDataKeyClass2019({
  type: 'EcdsaSecp256k1VerificationKey2019',
  controller: 'did:example:123',
  privateKeyJwk: didDocJwks.keys[0],
});

const { sign } = key.signer();
const { verify } = key.verifier();
const data = new Uint8Array([128]);

describe('MyLinkedDataKeyClass2019', () => {
  it('generate', async () => {
    let myLdKey = await MyLinkedDataKeyClass2019.generate('EC', 'secp256k1', {
      type: 'EcdsaSecp256k1VerificationKey2019',
      controller: 'did:example:123',
    });

    expect(myLdKey.type).toBe('EcdsaSecp256k1VerificationKey2019');
    expect(myLdKey.controller).toBe('did:example:123');

    expect(myLdKey.privateKeyJwk).toBeDefined();
    expect(myLdKey.publicKeyJwk).toBeDefined();
  });

  it('sign', async () => {
    expect(typeof sign).toBe('function');
    const signature = await sign({ data });
    const [encodedHeader, encodedSignature] = signature.split('..');
    const header = JSON.parse(base64url.decode(encodedHeader));
    expect(header.b64).toBe(false);
    expect(header.crit).toEqual(['b64']);
    expect(encodedSignature).toBeDefined();
  });

  it('verify', async () => {
    expect(typeof verify).toBe('function');
    const signature =
      'eyJhbGciOiJFUzI1NksiLCJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdfQ..W-m93vXutl3rNIQDtHw5l_PD7oppZzCioTCSNRR-kO1-Yjv8EhJ097KazuSoVB9gyHm-aAZusO7yW4G_wz787g';
    const result = await verify({
      data,
      signature,
    });
    expect(result).toBe(true);
  });
});
