import JWS from './JWS';

import { ISecp256k1PrivateKeyJWK, ISecp256k1PublicJWK } from './keyUtils';

/** default expiration in hours added automatically */
const defaultExpiresInHours = 1;

class JWTVerificationFailed extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'JWTVerificationFailed';
  }
}

/** return a JWT singed with ES256K JWS */
export const sign = async (
  payload: any,
  privateKeyJWK: ISecp256k1PrivateKeyJWK
) => {
  const iat = Math.floor(Date.now() / 1000);

  const exp = iat + 60 * 60 * defaultExpiresInHours;

  return JWS.sign(
    {
      ...payload,
      exp: payload.exp || exp,
      iat,
    },
    privateKeyJWK,
    {
      alg: 'ES256K',
      kid: privateKeyJWK.kid,
    }
  );
};

/** verify a JWT singed with ES256K JWS */
export const verify = async (
  jwt: string,
  publicKeyJWK: ISecp256k1PublicJWK
) => {
  const verified = await JWS.verify(jwt, publicKeyJWK);
  if (Math.floor(Date.now() / 1000) > verified.exp) {
    throw new JWTVerificationFailed('token is expired');
  }
  return verified;
};

export default { sign, decode: JWS.decode, verify };
