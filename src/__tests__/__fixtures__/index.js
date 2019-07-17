const linkedData = require('./LinkedDataExample.json');
const signedLinkedData = require('./SignedLinkedDataExample.json');

const keypair = {
  publicKey:
    '045b767b4fcf8664e3e4c32dd41d5b4c3b88680c10946e063e4100d3c7484a563b99576ba1de98cb77366ecafd47730ed5830a6c3e7faed48010b49532d0b01585',
  privateKey: '43541f3508552e5b55e4cc259d571665925dd2a8525c4efe28190879e70dcf33',
};

const creator = 'http://example.com:1337/user/did:example:123#main-key';

const signatureHex = 'b7b1f1850828fa3c649e32d3a48d3683579232f2f9d677e2ac1b8a30d83b0350813b955401b52fc78d460c9f0bd6c0e086562d689e58e6681460a8963ce8c88801';

const base64UrlEncoded = '3HeUs2ZWwLfiYWXUF83jteAh5kEwFOz7Of3RCwnAIntEmMCIlCra_JYz7O0k7i2lqNoT4UoiP2ltiH0xtl4m3wA';

const uportJWT = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiJ9.eyJpYXQiOjE1NDc3NzU4NzcsImF1ZCI6ImRpZDpleGFtcGxlOjEyMyIsImV4cCI6MTk1NzQ2MzQyMSwibmFtZSI6InVQb3J0IERldmVsb3BlciIsImlzcyI6ImRpZDpleGFtcGxlOjEyMyJ9.JpJzcFttM0HlYh0J-wwYCAXJ_b5Dx2x2LpzoQjwwzNEQPLtTm4p1sCqotiDpm-JYKphvvYbReUIB_1zonbD2hQA';

module.exports = {
  uportJWT,
  signatureHex,
  base64UrlEncoded,
  linkedData,
  signedLinkedData,
  keypair,
  creator,
};
