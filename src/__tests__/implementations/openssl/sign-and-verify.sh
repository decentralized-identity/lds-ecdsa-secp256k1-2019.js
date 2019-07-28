


openssl dgst -sha256 -sign ./privateKey.pem -out sign.sha256 ./msg.txt 
openssl base64 -in ./sign.sha256 -out ./signature.base64

cat ./signature.base64

openssl base64 -d -in ./signature.base64 -out ./sign.sha256
openssl dgst -sha256 -verify ./publicKey.pem -signature ./sign.sha256 ./msg.txt