const privateKeyJwk = {
  crv: 'secp256k1',
  d: 'rhYFsBPF9q3-uZThy7B3c4LDF_8wnozFUAEm5LLC4Zw',
  kid: 'JUvpllMEYUZ2joO59UNui_XYDqxVqiFLLAJ8klWuPBw',
  kty: 'EC',
  x: 'dWCvM4fTdeM0KmloF57zxtBPXTOythHPMm1HCLrdd3A',
  y: '36uMVGM7hnw-N6GnjFcihWE3SkrhMLzzLCdPMXPEXlA',
};

const publicKeyJwk = {
  crv: 'secp256k1',
  kid: 'JUvpllMEYUZ2joO59UNui_XYDqxVqiFLLAJ8klWuPBw',
  kty: 'EC',
  x: 'dWCvM4fTdeM0KmloF57zxtBPXTOythHPMm1HCLrdd3A',
  y: '36uMVGM7hnw-N6GnjFcihWE3SkrhMLzzLCdPMXPEXlA',
};

export default {
  ['key-JUvpllMEYUZ2joO59UNui_XYDqxVqiFLLAJ8klWuPBw']: {
    privateKeyJwk,
    publicKeyJwk,
  },
};
