import convertFragmentsToURIs from '../convertFragmentsToURIs';

import elementURDidDoc from './__fixtures__/elementURDidDoc.json';

describe('convertFragmentsToURIs', () => {
  it('can convert element did', async () => {
    const converted = convertFragmentsToURIs(elementURDidDoc);
    expect(converted.publicKey[0].id).toBe(
      elementURDidDoc.id + elementURDidDoc.publicKey[0].id
    );
  });
});
