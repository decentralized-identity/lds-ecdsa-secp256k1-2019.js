import keyUtils from './keyUtils';

describe('keyUtils', () => {
  describe('getKid', () => {
    it('should convert a jwk to a kid', async () => {
      const jwk = {
        alg: 'RS256',
        e: 'AQAB',
        kid: '2011-04-29',
        kty: 'RSA',
        n:
          // tslint:disable-next-line:max-line-length
          '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw',
      };
      const kid = keyUtils.getKid(jwk as any);
      expect(kid).toBe('NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs');
    });
  });

  describe('privateJWKFromPrivateKeyHex', () => {
    it('should convert a hex encoded keyUtils to a JWK', async () => {
      const privateKeyHex =
        'ae1605b013c5f6adfeb994e1cbb0777382c317ff309e8cc5500126e4b2c2e19c';

      const jwk = await keyUtils.privateJWKFromPrivateKeyHex(privateKeyHex);
      expect(jwk.kty).toBe('EC');
      expect(jwk.crv).toBe('secp256k1');
      expect(jwk.kid).toBe('JUvpllMEYUZ2joO59UNui_XYDqxVqiFLLAJ8klWuPBw');
      expect(jwk.d).toBe('rhYFsBPF9q3-uZThy7B3c4LDF_8wnozFUAEm5LLC4Zw');
      expect(jwk.x).toBe('dWCvM4fTdeM0KmloF57zxtBPXTOythHPMm1HCLrdd3A');
      expect(jwk.y).toBe('36uMVGM7hnw-N6GnjFcihWE3SkrhMLzzLCdPMXPEXlA');
    });
  });

  describe('publicJWKFromPublicKeyHex', () => {
    it('should convert a hex encoded keyUtils to a JWK', async () => {
      const publicKeyHex =
        '027560af3387d375e3342a6968179ef3c6d04f5d33b2b611cf326d4708badd7770';
      const jwk = await keyUtils.publicJWKFromPublicKeyHex(publicKeyHex);
      expect(jwk.kty).toBe('EC');
      expect(jwk.crv).toBe('secp256k1');
      expect(jwk.kid).toBe('JUvpllMEYUZ2joO59UNui_XYDqxVqiFLLAJ8klWuPBw');
      expect(jwk.x).toBe('dWCvM4fTdeM0KmloF57zxtBPXTOythHPMm1HCLrdd3A');
      expect(jwk.y).toBe('36uMVGM7hnw-N6GnjFcihWE3SkrhMLzzLCdPMXPEXlA');
    });
  });

  describe('privateJWKFromPrivateKeyPem', () => {
    it('should convert a hex encoded keyUtils to a JWK', async () => {
      const privateKeyPem = `-----BEGIN PRIVATE KEY-----
MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgrhYFsBPF9q3+uZThy7B3
c4LDF/8wnozFUAEm5LLC4ZyhRANCAAR1YK8zh9N14zQqaWgXnvPG0E9dM7K2Ec8y
bUcIut13cN+rjFRjO4Z8Pjehp4xXIoVhN0pK4TC88ywnTzFzxF5Q
-----END PRIVATE KEY-----`;

      const jwk = await keyUtils.privateJWKFromPrivateKeyPem(privateKeyPem);
      expect(jwk.kty).toBe('EC');
      expect(jwk.crv).toBe('secp256k1');
      expect(jwk.kid).toBe('JUvpllMEYUZ2joO59UNui_XYDqxVqiFLLAJ8klWuPBw');
      expect(jwk.d).toBe('rhYFsBPF9q3-uZThy7B3c4LDF_8wnozFUAEm5LLC4Zw');
      expect(jwk.x).toBe('dWCvM4fTdeM0KmloF57zxtBPXTOythHPMm1HCLrdd3A');
      expect(jwk.y).toBe('36uMVGM7hnw-N6GnjFcihWE3SkrhMLzzLCdPMXPEXlA');
    });
  });

  describe('publicJWKFromPublicKeyPem', () => {
    it('should convert a hex encoded keyUtils to a JWK', async () => {
      const privateKeyPem = `-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEdWCvM4fTdeM0KmloF57zxtBPXTOythHP
Mm1HCLrdd3Dfq4xUYzuGfD43oaeMVyKFYTdKSuEwvPMsJ08xc8ReUA==
-----END PUBLIC KEY-----`;

      const jwk = await keyUtils.publicJWKFromPublicKeyPem(privateKeyPem);
      expect(jwk.kty).toBe('EC');
      expect(jwk.crv).toBe('secp256k1');
      expect(jwk.kid).toBe('JUvpllMEYUZ2joO59UNui_XYDqxVqiFLLAJ8klWuPBw');
      expect(jwk.x).toBe('dWCvM4fTdeM0KmloF57zxtBPXTOythHPMm1HCLrdd3A');
      expect(jwk.y).toBe('36uMVGM7hnw-N6GnjFcihWE3SkrhMLzzLCdPMXPEXlA');
    });
  });

  describe('privateKeyHexFromJWK', () => {
    it('should convert a hex encoded keyUtils to a JWK', async () => {
      const privateJWK = {
        crv: 'secp256k1',
        d: 'rhYFsBPF9q3-uZThy7B3c4LDF_8wnozFUAEm5LLC4Zw',
        kid: 'JUvpllMEYUZ2joO59UNui_XYDqxVqiFLLAJ8klWuPBw',
        kty: 'EC',
        x: 'dWCvM4fTdeM0KmloF57zxtBPXTOythHPMm1HCLrdd3A',
        y: '36uMVGM7hnw-N6GnjFcihWE3SkrhMLzzLCdPMXPEXlA',
      };

      const privateKeyHex = await keyUtils.privateKeyHexFromJWK(privateJWK);
      expect(privateKeyHex).toBe(
        'ae1605b013c5f6adfeb994e1cbb0777382c317ff309e8cc5500126e4b2c2e19c'
      );
    });
  });

  describe('publicKeyHexFromJWK', () => {
    it('should convert a jwk to compressed hex', async () => {
      const publicJWK = {
        crv: 'secp256k1',
        kid: 'JUvpllMEYUZ2joO59UNui_XYDqxVqiFLLAJ8klWuPBw',
        kty: 'EC',
        x: 'dWCvM4fTdeM0KmloF57zxtBPXTOythHPMm1HCLrdd3A',
        y: '36uMVGM7hnw-N6GnjFcihWE3SkrhMLzzLCdPMXPEXlA',
      };

      const publicKeyHex = await keyUtils.publicKeyHexFromJWK(publicJWK);
      expect(publicKeyHex).toBe(
        '027560af3387d375e3342a6968179ef3c6d04f5d33b2b611cf326d4708badd7770'
      );
    });
  });

  describe('privateKeyUInt8ArrayFromJWK', () => {
    it('should convert a jwk to UInt8Array', async () => {
      const privateJWK = {
        crv: 'secp256k1',
        d: 'rhYFsBPF9q3-uZThy7B3c4LDF_8wnozFUAEm5LLC4Zw',
        kid: 'JUvpllMEYUZ2joO59UNui_XYDqxVqiFLLAJ8klWuPBw',
        kty: 'EC',
        x: 'dWCvM4fTdeM0KmloF57zxtBPXTOythHPMm1HCLrdd3A',
        y: '36uMVGM7hnw-N6GnjFcihWE3SkrhMLzzLCdPMXPEXlA',
      };
      const privateKeyUInt8Array = await keyUtils.privateKeyUInt8ArrayFromJWK(
        privateJWK
      );
      expect(privateKeyUInt8Array).toEqual(
        new Uint8Array([
          174,
          22,
          5,
          176,
          19,
          197,
          246,
          173,
          254,
          185,
          148,
          225,
          203,
          176,
          119,
          115,
          130,
          195,
          23,
          255,
          48,
          158,
          140,
          197,
          80,
          1,
          38,
          228,
          178,
          194,
          225,
          156,
        ])
      );
    });
  });

  describe('publicKeyUInt8ArrayFromJWK', () => {
    it('should convert a jwk to UInt8Array', async () => {
      const publicJWK = {
        crv: 'secp256k1',
        kid: 'JUvpllMEYUZ2joO59UNui_XYDqxVqiFLLAJ8klWuPBw',
        kty: 'EC',
        x: 'dWCvM4fTdeM0KmloF57zxtBPXTOythHPMm1HCLrdd3A',
        y: '36uMVGM7hnw-N6GnjFcihWE3SkrhMLzzLCdPMXPEXlA',
      };
      const publicKeyUInt8Array = await keyUtils.publicKeyUInt8ArrayFromJWK(
        publicJWK
      );

      expect(publicKeyUInt8Array).toEqual(
        new Uint8Array([
          2,
          117,
          96,
          175,
          51,
          135,
          211,
          117,
          227,
          52,
          42,
          105,
          104,
          23,
          158,
          243,
          198,
          208,
          79,
          93,
          51,
          178,
          182,
          17,
          207,
          50,
          109,
          71,
          8,
          186,
          221,
          119,
          112,
        ])
      );
    });
  });
});
