import base64url from 'base64url';
import JWS from './JWS';

const privateJWK = {
  crv: 'secp256k1',
  d: 'rhYFsBPF9q3-uZThy7B3c4LDF_8wnozFUAEm5LLC4Zw',
  kid: 'JUvpllMEYUZ2joO59UNui_XYDqxVqiFLLAJ8klWuPBw',
  kty: 'EC',
  x: 'dWCvM4fTdeM0KmloF57zxtBPXTOythHPMm1HCLrdd3A',
  y: '36uMVGM7hnw-N6GnjFcihWE3SkrhMLzzLCdPMXPEXlA',
};

const publicJWK = {
  crv: 'secp256k1',
  kid: 'JUvpllMEYUZ2joO59UNui_XYDqxVqiFLLAJ8klWuPBw',
  kty: 'EC',
  x: 'dWCvM4fTdeM0KmloF57zxtBPXTOythHPMm1HCLrdd3A',
  y: '36uMVGM7hnw-N6GnjFcihWE3SkrhMLzzLCdPMXPEXlA',
};

// https://tools.ietf.org/html/rfc7797#section-6
describe('Detached Payload JWS', () => {
  it('creates a proper JWS according to rfc7797', async () => {
    const payload = Buffer.from('hello');

    const jws = await JWS.signDetached(payload, privateJWK);

    const [encodedHeader, encodedSignature] = jws.split('..');

    const [decodedHeader, decodedSignature] = [
      encodedHeader,
      encodedSignature,
    ].map((d: string) => {
      return base64url.decode(d);
    });

    const parsedHeader = JSON.parse(decodedHeader);

    expect(parsedHeader.alg).toBe('ES256K');
    expect(parsedHeader.b64).toBe(false);
    expect(parsedHeader.crit).toEqual(['b64']);

    const verified = await JWS.verifyDetached(jws, payload, publicJWK);
    expect(verified).toBe(true);
  });
});
