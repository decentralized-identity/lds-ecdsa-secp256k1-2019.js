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

const payload = {
  hello: true,
};

describe('JWS', () => {
  describe('sign', () => {
    it('should produce a JWS', async () => {
      const signature = await JWS.sign(payload, privateJWK);
      expect(signature).toBe(
        'eyJhbGciOiJFUzI1NksifQ.eyJoZWxsbyI6dHJ1ZX0.NdmDdVLxgeu-IcmzrE4RsZpB-245i_7qu5nRxK6CUepunNiTuA33EG2jeqU1yaAPbMRgdwgShPZGmUNyYF4Rgg'
      );
    });
  });

  describe('verify', () => {
    it('should return the decoded payload for a valid JWS', async () => {
      const jws =
        'eyJhbGciOiJFUzI1NksifQ.eyJoZWxsbyI6dHJ1ZX0.NdmDdVLxgeu-IcmzrE4RsZpB-245i_7qu5nRxK6CUepunNiTuA33EG2jeqU1yaAPbMRgdwgShPZGmUNyYF4Rgg';
      const verified = await JWS.verify(jws, publicJWK);
      expect(verified).toEqual(payload);
    });
  });

  describe('decode', () => {
    it('should return the decoded payload for a JWS', async () => {
      const jws =
        'eyJhbGciOiJFUzI1NksifQ.eyJoZWxsbyI6dHJ1ZX0.NdmDdVLxgeu-IcmzrE4RsZpB-245i_7qu5nRxK6CUepunNiTuA33EG2jeqU1yaAPbMRgdwgShPZGmUNyYF4Rgg';
      const decoded = await JWS.decode(jws);
      expect(decoded).toEqual(payload);
    });

    it('should return the decoded complete payload for a JWS', async () => {
      const jws =
        'eyJhbGciOiJFUzI1NksifQ.eyJoZWxsbyI6dHJ1ZX0.NdmDdVLxgeu-IcmzrE4RsZpB-245i_7qu5nRxK6CUepunNiTuA33EG2jeqU1yaAPbMRgdwgShPZGmUNyYF4Rgg';
      const decoded = await JWS.decode(jws, { complete: true });
      expect(decoded.payload).toEqual(payload);
      expect(decoded.header).toEqual({ alg: 'ES256K' });
      expect(decoded.signature).toBe(
        'NdmDdVLxgeu-IcmzrE4RsZpB-245i_7qu5nRxK6CUepunNiTuA33EG2jeqU1yaAPbMRgdwgShPZGmUNyYF4Rgg'
      );
    });
  });
});
