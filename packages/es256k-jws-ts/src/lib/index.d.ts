declare module '@trust/keyto';
declare module 'base64url';
declare module 'json-stringify-deterministic';

// dev deps for integration tests
declare module 'bip39';
declare module 'hdkey';

/** hackaround typescript */
type BigInt = number;
