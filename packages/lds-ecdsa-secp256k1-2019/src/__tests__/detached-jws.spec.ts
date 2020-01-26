import * as ES256K from '@transmute/es256k-jws-ts';
import jose from 'jose';

const privateKeyJwk = {
  crv: 'secp256k1',
  d: 'JCvMpuoQ4CJ_-1mSFtG6gIeqXoS-9joKOon1_DmP6JY',
  kid: 'WqzaOweASs78whhl_YvCEvj1nd89IycryVlmZMefcjU',
  kty: 'EC',
  x: '4xAbUxbGGFPv4qpHlPFAUJdzteUGR1lRK-CELCufU9w',
  y: 'EYcgCTsff1qtZjI9_ckZTXDSKAIuM0BknrKgo0BZ_Is',
};

const header = {
  alg: 'ES256K',
  b64: false,
  crit: ['b64'],
};
const data = new Uint8Array([128]);
const payload = Buffer.from(data.buffer, data.byteOffset, data.length);

describe('ES256K Detached JWS', () => {
  it('jose: sign & verify', async () => {
    const detached = jose.JWS.sign.flattened(
      payload,
      jose.JWK.asKey(privateKeyJwk),
      header
    );

    const flattened: any = { ...detached, payload };
    expect(
      jose.JWS.verify(flattened, jose.JWK.asKey(privateKeyJwk), {
        crit: ['b64'],
      })
    ).toBe(payload);
  });

  it('self - sign and verify', async () => {
    const signed = await ES256K.JWS.signDetached(
      payload,
      privateKeyJwk,
      header
    );
    const verified = await ES256K.JWS.verifyDetached(
      signed,
      payload,
      privateKeyJwk
    );
    expect(verified).toBe(true);
  });

  it('self - verify signed with jose', async () => {
    const flattened = jose.JWS.sign.flattened(
      payload,
      jose.JWK.asKey(privateKeyJwk),
      header
    );
    const jws = flattened.protected + '..' + flattened.signature;
    const verified = await ES256K.JWS.verifyDetached(
      jws,
      payload,
      privateKeyJwk
    );
    expect(verified).toBe(true);
  });

  it('jose - verify signed with self', async () => {
    const signed = await ES256K.JWS.signDetached(
      payload,
      privateKeyJwk,
      header
    );

    const [encodedHeader, encodedSignature] = signed.split('..');
    const detached = {
      protected: encodedHeader,
      signature: encodedSignature,
    };
    const flattened: any = { ...detached, payload };
    expect(
      jose.JWS.verify(flattened, jose.JWK.asKey(privateKeyJwk), {
        crit: ['b64'],
      })
    ).toBe(payload);
  });
});
