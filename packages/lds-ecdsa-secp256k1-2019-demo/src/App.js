import React from "react";

import * as ES256K from "@transmute/es256k-jws-ts";

const privateJWK = {
  crv: "secp256k1",
  d: "rhYFsBPF9q3-uZThy7B3c4LDF_8wnozFUAEm5LLC4Zw",
  kid: "JUvpllMEYUZ2joO59UNui_XYDqxVqiFLLAJ8klWuPBw",
  kty: "EC",
  x: "dWCvM4fTdeM0KmloF57zxtBPXTOythHPMm1HCLrdd3A",
  y: "36uMVGM7hnw-N6GnjFcihWE3SkrhMLzzLCdPMXPEXlA"
};

const publicJWK = {
  crv: "secp256k1",
  kid: "JUvpllMEYUZ2joO59UNui_XYDqxVqiFLLAJ8klWuPBw",
  kty: "EC",
  x: "dWCvM4fTdeM0KmloF57zxtBPXTOythHPMm1HCLrdd3A",
  y: "36uMVGM7hnw-N6GnjFcihWE3SkrhMLzzLCdPMXPEXlA"
};

console.log(ES256K);

class App extends React.Component {
  state = {
    JWS: ""
  };
  async componentWillMount() {
    const jws = await ES256K.JWS.sign(
      {
        hello: "world"
      },
      privateJWK
    );
    const verified = await ES256K.JWS.verify(jws, publicJWK);
    this.setState({
      jws,
      verified
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
      </div>
    );
  }
}

export default App;
