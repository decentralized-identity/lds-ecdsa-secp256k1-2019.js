import JWT from './JWT';

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

describe('JWT', () => {
  describe('sign', () => {
    it('should produce a JWT', async () => {
      const jwt = await JWT.sign(payload, privateJWK);
      const decoded = await JWT.decode(jwt, { complete: true });
      expect(decoded.header.alg).toBe('ES256K');
      expect(decoded.header.kid).toBe(
        'JUvpllMEYUZ2joO59UNui_XYDqxVqiFLLAJ8klWuPBw'
      );
      expect(decoded.payload.hello).toBe(true);
      expect(decoded.payload.iat).toBeDefined();
      expect(decoded.payload.exp).toBeDefined();
    });
  });

  describe('verify', () => {
    it('should return decoded JWT if JWS and exp are good', async () => {
      const jwt = await JWT.sign(payload, privateJWK);
      const decoded = await JWT.verify(jwt, publicJWK);
      expect(decoded.hello).toBe(true);
      expect(decoded.iat).toBeDefined();
      expect(decoded.exp).toBeDefined();
    });

    it('should return JWTVerificationFailed when expired', async () => {
      expect.assertions(2);
      const jwt = await JWT.sign(
        { ...payload, exp: Math.floor(Date.now() / 1000) - 30 },
        privateJWK
      );
      try {
        await JWT.verify(jwt, publicJWK);
      } catch (e) {
        expect(e.name).toBe('JWTVerificationFailed');
        expect(e.message).toBe('token is expired');
      }
    });
  });
});
