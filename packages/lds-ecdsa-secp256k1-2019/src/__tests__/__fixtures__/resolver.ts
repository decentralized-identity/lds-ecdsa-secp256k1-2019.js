import dids from './dids';

const resolver = {
  resolve: (didUri: string) => {
    const did = didUri.split('#')[0];
    return dids[did] ? dids[did].document : null;
  },
};

export default resolver;
