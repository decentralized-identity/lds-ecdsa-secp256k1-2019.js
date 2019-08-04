

# These Signatures are not encoded correctly for ES256K (JOSE)
# However, OpenSSL and Node 12 Crypto both produce secp256k1 signatures with
# Non deterministic K, and this code might help if you are exploring that.
# See @panva/jose.

openssl dgst -sha256 -sign ./privateKey.pem -out sign.sha256 ./msg.txt
openssl base64 -in ./sign.sha256 -out ./signature.base64

cat ./signature.base64

openssl base64 -d -in ./signature.base64 -out ./sign.sha256
openssl dgst -sha256 -verify ./publicKey.pem -signature ./sign.sha256 ./msg.txt
