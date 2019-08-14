import dids from './dids';

const resolver = {
  resolve: async (didUri: string) => {
    const did = didUri.split('#')[0];

    if (!dids[did]) {
      throw new Error('Could not resolve: ' + didUri);
    }
    return dids[did].document;
  },
};

export default resolver;
