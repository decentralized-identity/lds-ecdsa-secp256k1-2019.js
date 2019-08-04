import React from 'react';

import * as ES256K from '@transmute/es256k-jws-ts';

import * as EcsdaSecp256k1Signature2019 from '@transmute/lds-ecdsa-secp256k1-2019';

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

const signatureOptions = {
  challenge: 'abc',
  created: '2019-01-16T20:13:10Z',
  domain: 'example.com',
  proofPurpose: 'authentication',
  verificationMethod: 'https://example.com/i/alice/keys/2',
};
const doc = {
  '@context': {
    action: 'schema:action',
    schema: 'http://schema.org/',
  },
  action: 'AuthenticateMe',
};

class App extends React.Component {
  state = {
    JWS: '',
  };
  async componentWillMount() {
    const jws = await ES256K.JWS.sign(
      {
        hello: 'world',
      },
      privateJWK
    );
    const verified = await ES256K.JWS.verify(jws, publicJWK);
    this.setState({
      jws,
      verified,
    });

    const ldSig = await EcsdaSecp256k1Signature2019.sign(
      doc,
      signatureOptions,
      privateJWK
    );

    const lsSigVerified = await EcsdaSecp256k1Signature2019.verify(
      ldSig,
      publicJWK
    );

    this.setState({
      ldSig,
      lsSigVerified,
    });
  }
  render() {
    return (
      <div className="App">
        <h4>ES256K</h4>

        <h5>Public Key</h5>
        <pre>{JSON.stringify(publicJWK, null, 2)}</pre>

        <h5>JWS</h5>
        <code>{this.state.jws}</code>

        <h5>Verified Payload</h5>
        <code>{JSON.stringify(this.state.verified, null, 2)}</code>

        <hr />

        <h5>JSON-LD Signature</h5>
        <pre>{JSON.stringify(this.state.ldSig, null, 2)}</pre>

        <h5>Verified JSON-LD Signature</h5>
        <code>{JSON.stringify(this.state.lsSigVerified, null, 2)}</code>
      </div>
    );
  }
}

export default App;
