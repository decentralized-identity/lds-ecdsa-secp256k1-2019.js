import didJWT from 'did-jwt';
import { JWS, keyUtils } from '../../../index';

const privateKeyHex =
  'ae1605b013c5f6adfeb994e1cbb0777382c317ff309e8cc5500126e4b2c2e19c';

const publicKeyHex =
  '027560af3387d375e3342a6968179ef3c6d04f5d33b2b611cf326d4708badd7770';

const signer = didJWT.SimpleSigner(privateKeyHex);

describe('UPort', () => {
  it('raw signature', async () => {
    const data = '';
    const sig = (await signer(data)) as any;
    expect(sig.r).toBe(
      '01dcf356a9d429b1139bf2960ff4b2537082b242b5a6fd0eb161cbfa413c7ed4'
    );
    expect(sig.s).toBe(
      'fb213ad94ac20c87839005e50e81f774438e48ab4d75bbfa2a6c44961ab9892e'
    );
    expect(sig.recoveryParam).toBe(1);
  });

  it('Our library can verify UPort ES256K JWT', async () => {
    const jwt = await didJWT.createJWT(
      {
        aud: 'did:example:123',
        exp: 1957463421,
        name: 'uPort Developer',
      },
      {
        alg: 'ES256K',
        issuer: 'did:example:123',
        signer,
      }
    );

    const verified = await JWS.verify(
      jwt,
      await keyUtils.publicJWKFromPublicKeyHex(publicKeyHex)
    );

    expect(verified.iat).toBeDefined();
    expect(verified.exp).toBeDefined();
    expect(verified.aud).toBeDefined();
    expect(verified.name).toBeDefined();
    expect(verified.iss).toBeDefined();
  });
});
