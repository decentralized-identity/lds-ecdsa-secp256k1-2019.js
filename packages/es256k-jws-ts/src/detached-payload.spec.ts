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

const payload = Buffer.from('hello');

// https://tools.ietf.org/html/rfc7797#section-6
describe('Detached Payload JWS', () => {
  it('creates a proper JWS according to rfc7797', async () => {
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

  it('should error when verifying a non detached', async () => {
    const jws =
      'eyJhbGciOiJFUzI1NksifQ.eyJoZWxsbyI6dHJ1ZX0.NdmDdVLxgeu-IcmzrE4RsZpB-245i_7qu5nRxK6CUepunNiTuA33EG2jeqU1yaAPbMRgdwgShPZGmUNyYF4Rgg';
    expect.assertions(1);
    try {
      await JWS.verifyDetached(jws, Buffer.from('hello'), publicJWK);
    } catch (e) {
      expect(e.message).toBe('not a valid rfc7797 jws.');
    }
  });

  it('should error when alg is wrong', async () => {
    expect.assertions(1);
    const jws = await JWS.signDetached(payload, privateJWK, {
      alg: 'ES256',
    } as any);

    try {
      await JWS.verifyDetached(jws, payload, publicJWK);
    } catch (e) {
      expect(e.message).toBe('JWS alg is not signed with ES256K.');
    }
  });

  it('should error when header is wrong', async () => {
    expect.assertions(1);
    const jws = await JWS.signDetached(payload, privateJWK, {
      alg: 'ES256K',
    } as any);

    try {
      await JWS.verifyDetached(jws, payload, publicJWK);
    } catch (e) {
      expect(e.message).toBe(
        'JWS Header is not in rfc7797 format (not detached).'
      );
    }
  });

  it('should return false when signature is tampered', async () => {
    expect.assertions(1);

    // tslint:disable-next-line:max-line-length
    const brokenJWs = `eyJhbGciOiJFUzI1NksiLCJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdfQ..s6JgLOw7kPIGyNzRqoCcNEuscED32DsX3THfwyWPcfUna010iC9-ZYSG78Njknc_t3P11-yuceQuL9AXXNBDMD`;

    try {
      const d = await JWS.verifyDetached(brokenJWs, payload, publicJWK);
    } catch (e) {
      expect(e.message).toBe('Cannot verify detached signature.');
    }
  });
});
