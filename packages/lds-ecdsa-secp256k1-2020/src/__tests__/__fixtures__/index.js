const documentLoader = require('./customDocumentLoader');

const didDocJwks = require('./didDocJwks');

const doc = {
  '@context': [
    {
      schema: 'http://schema.org/',
      name: 'schema:name',
      homepage: 'schema:url',
      image: 'schema:image',
    },
  ],
  name: 'Manu Sporny',
  homepage: 'https://manu.sporny.org/',
  image: 'https://manu.sporny.org/images/manu.png',
};

module.exports = {
  doc,
  documentLoader,
  didDocJwks,
};
