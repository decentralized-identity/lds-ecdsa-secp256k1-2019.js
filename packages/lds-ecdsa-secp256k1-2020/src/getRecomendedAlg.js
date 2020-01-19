const getRecomendedAlg = ({ kty, crv }) => {
  if (kty === "OKP" && crv === "Ed25519") {
    return "EdDSA";
  }
  if (kty === "EC" && crv === "secp256k1") {
    return "ES256K";
  }
  if (kty === "EC" && crv === "P-256") {
    return "ES256";
  }
  if (kty === "RSA") {
    return "PS256";
  }
};

module.exports = getRecomendedAlg;
