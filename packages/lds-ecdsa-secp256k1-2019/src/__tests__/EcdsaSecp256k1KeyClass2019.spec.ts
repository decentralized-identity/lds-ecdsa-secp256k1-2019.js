import base64url from 'base64url';
import EcdsaSecp256k1KeyClass2019 from '../EcdsaSecp256k1KeyClass2019';

import fixtures from './__fixtures__';

// const { EcdsaSecp256k1KeyClass2019 } = require('../index');
// const { didDocJwks } = require('./__fixtures__');

const data = new Uint8Array([128]);
let key: EcdsaSecp256k1KeyClass2019;

describe('EcdsaSecp256k1KeyClass2019', () => {
  it('can import a jwk', async () => {
    key = new EcdsaSecp256k1KeyClass2019({
      controller: 'did:example:123',
      privateKeyJwk: fixtures.didDocJwks.keys[0],
    });
    expect(key.id).toBe(
      'did:example:123#WqzaOweASs78whhl_YvCEvj1nd89IycryVlmZMefcjU'
    );
    expect(key.type).toBe('EcdsaSecp256k1VerificationKey2019');
    expect(key.controller).toBe('did:example:123');
    expect(key.privateKeyJwk).toBeDefined();
    expect(key.publicKeyJwk).toBeDefined();
  });

  it('sign', async () => {
    const { sign } = key.signer();
    expect(typeof sign).toBe('function');
    const signature = await sign({ data });
    const [encodedHeader, encodedSignature] = signature.split('..');
    const header = JSON.parse(base64url.decode(encodedHeader));
    expect(header.b64).toBe(false);
    expect(header.crit).toEqual(['b64']);
    // Note: only works with deterministic K.
    expect(encodedSignature).toBe(
      'hi293ia5YYznl0mS9_-Z0wHoFcSuo3qaWVVJwEXtwn0olNhSi95nx9RIJbsAcUNMmLc4ISih7HxyUs9pXyzcrw'
    );
  });

  it('verify', async () => {
    const { verify } = key.verifier();
    expect(typeof verify).toBe('function');
    const signature =
      'eyJhbGciOiJFUzI1NksiLCJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdfQ..hi293ia5YYznl0mS9_-Z0wHoFcSuo3qaWVVJwEXtwn0olNhSi95nx9RIJbsAcUNMmLc4ISih7HxyUs9pXyzcrw';
    const result = await verify({
      data,
      signature,
    });
    expect(result).toBe(true);
  });

  it('can not sign with out a private key', async () => {
    expect.assertions(6);
    key = new EcdsaSecp256k1KeyClass2019({
      controller: 'did:example:123',
      publicKeyJwk: fixtures.didDocJwks.keys[0],
    });
    expect(key.id).toBe(
      'did:example:123#WqzaOweASs78whhl_YvCEvj1nd89IycryVlmZMefcjU'
    );
    expect(key.type).toBe('EcdsaSecp256k1VerificationKey2019');
    expect(key.controller).toBe('did:example:123');
    expect(key.privateKeyJwk).toBeUndefined();
    expect(key.publicKeyJwk).toBeDefined();

    const { sign } = key.signer();

    try {
      await sign('test');
    } catch (e) {
      expect(e.message).toBe('No private key to sign with.');
    }
  });

  it('can not verify with out a private key', async () => {
    expect.assertions(6);
    key = new EcdsaSecp256k1KeyClass2019({
      controller: 'did:example:123',
      privateKeyJwk: fixtures.didDocJwks.keys[0],
    });
    expect(key.id).toBe(
      'did:example:123#WqzaOweASs78whhl_YvCEvj1nd89IycryVlmZMefcjU'
    );
    expect(key.type).toBe('EcdsaSecp256k1VerificationKey2019');
    expect(key.controller).toBe('did:example:123');
    expect(key.privateKeyJwk).toBeDefined();
    expect(key.publicKeyJwk).toBeDefined();

    delete key.publicKeyJwk;

    const { verify } = key.verifier();

    try {
      await verify('test');
    } catch (e) {
      expect(e.message).toBe('No public key to verify with.');
    }
  });

  it('verify fails when header is bad', async () => {
    expect.assertions(2);
    key = new EcdsaSecp256k1KeyClass2019({
      controller: 'did:example:123',
      privateKeyJwk: fixtures.didDocJwks.keys[0],
    });
    const { verify } = key.verifier();
    expect(typeof verify).toBe('function');

    const signature =
      'eyJhbGciOiJFUzI1NksiLCJiNjQiOmZhbHNlfQ..hi293ia5YYznl0mS9_-Z0wHoFcSuo3qaWVVJwEXtwn0olNhSi95nx9RIJbsAcUNMmLc4ISih7HxyUs9pXyzcrw';
    const result = await verify({
      data,
      signature,
    });

    expect(result).toBe(false);
  });

  it('verify fails with broken header', async () => {
    expect.assertions(1);
    key = new EcdsaSecp256k1KeyClass2019({
      controller: 'did:example:123',
      privateKeyJwk: fixtures.didDocJwks.keys[0],
    });
    const { verify } = key.verifier();

    try {
      const signature =
        'eyJhbGciOiJFUzNksiLCJiNjQiOmZhbHNlfQ..hi293ia5YYznl0mS9_-Z0wHoFcSuo3qaWVVJwEXtwn0olNhSi95nx9RIJbsAcUNMmLc4ISih7HxyUs9pXyzcrw';
      const result = await verify({
        data,
        signature,
      });
    } catch (e) {
      expect(e.message).toBe(
        'Could not parse JWS header; SyntaxError: Unexpected token � in JSON at position 14'
      );
    }
  });
});
