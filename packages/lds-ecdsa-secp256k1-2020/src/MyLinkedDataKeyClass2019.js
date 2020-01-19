const jose = require('jose');
const base64url = require('base64url');

const getRecomendedAlg = require('./getRecomendedAlg');

class MyLinkedDataKeyClass2019 {
  /**
   * @param {KeyPairOptions} options - The options to use.
   * @param {string} options.id - The key ID.
   * @param {string} options.controller - The key controller.
   * @param {string} options.publicKeyJwk - The JWK encoded Public Key.
   * @param {string} options.privateKeyJwk - The JWK Private Key.
   * @param {string} options.alg - The JWS alg for this key.
   */
  constructor(options = {}) {
    this.id = options.id;
    this.type = options.type;
    this.controller = options.controller;
    this.privateKeyJwk = options.privateKeyJwk;
    this.publicKeyJwk = options.publicKeyJwk;
    this.alg = 'ES256K';

    if (this.publicKeyJwk === undefined) {
      this.publicKeyJwk = jose.JWK.asKey(this.privateKeyJwk).toJWK(false);
    }

    if (this.alg === undefined) {
      this.alg = getRecomendedAlg(this.publicKeyJwk);
    }

    if (this.id === undefined) {
      this.id = this.controller + '#' + this.fingerprint();
    }
  }

  /**
   * Returns the JWK encoded public key.
   *
   * @returns {string} The JWK encoded public key.
   */
  get publicKey() {
    return this.publicKeyJwk;
  }

  /**
   * Returns the JWK encoded private key.
   *
   * @returns {string} The JWK encoded private key.
   */
  get privateKey() {
    return this.privateKeyJwk;
  }

  /**
   * Generates a KeyPair with an optional deterministic seed.
   * @param {KeyPairOptions} [options={}] - The options to use.
   *
   * @returns {Promise<MyLinkedDataKeyClass2019>} Generates a key pair.
   */
  static async generate(kty, crv, options = {}) {
    let key = jose.JWK.generateSync(kty, crv);
    return new MyLinkedDataKeyClass2019({
      privateKeyJwk: key.toJWK(true),
      publicKeyJwk: key.toJWK(),
      ...options,
    });
  }

  /**
   * Returns a signer object for use with jsonld-signatures.
   *
   * @returns {{sign: Function}} A signer for the json-ld block.
   */
  signer() {
    return joseSignerFactory(this);
  }

  /**
   * Returns a verifier object for use with jsonld-signatures.
   *
   * @returns {{verify: Function}} Used to verify jsonld-signatures.
   */
  verifier() {
    return joseVerifierFactory(this);
  }

  /**
   * Adds a public key base to a public key node.
   *
   * @param {Object} publicKeyNode - The public key node in a jsonld-signature.
   * @param {string} publicKeyNode.publicKeyJwk - JWK Public Key for
   *   jsonld-signatures.
   *
   * @returns {Object} A PublicKeyNode in a block.
   */
  addEncodedPublicKey(publicKeyNode) {
    publicKeyNode.publicKeyJwk = this.publicKeyJwk;
    return publicKeyNode;
  }

  /**
   * Generates and returns a public key fingerprint using https://tools.ietf.org/html/rfc7638
   *
   * @param {string} publicKeyJwk - The jwk encoded public key material.
   *
   * @returns {string} The fingerprint.
   */
  static fingerprintFromPublicKey({ publicKeyJwk }) {
    const temp = { ...publicKeyJwk };
    delete temp.kid;
    const k = jose.JWK.asKey(temp);
    return k.kid;
  }

  /**
   * Generates and returns a public key fingerprint using https://tools.ietf.org/html/rfc7638
   *
   * @returns {string} The fingerprint.
   */
  fingerprint() {
    const temp = { ...this.publicKeyJwk };
    delete temp.kid;
    const k = jose.JWK.asKey(temp);
    return k.kid;
  }

  /**
   * Tests whether the fingerprint was generated from a given key pair.
   *
   * @param {string} fingerprint - A JWK public key.
   *
   * @returns {Object} An object indicating valid is true or false.
   */
  verifyFingerprint(/*fingerprint*/) {
    // TODO: implement
    throw new Error('`verifyFingerprint` API is not implemented.');
  }

  static async from(options) {
    return new MyLinkedDataKeyClass2019(options);
  }

  /**
   * Contains the public key for the KeyPair
   * and other information that json-ld Signatures can use to form a proof.
   * @param {Object} [options={}] - Needs either a controller or owner.
   * @param {string} [options.controller=this.controller]  - DID of the
   * person/entity controlling this key pair.
   *
   * @returns {Object} A public node with
   * information used in verification methods by signatures.
   */
  publicNode({ controller = this.controller } = {}) {
    const publicNode = {
      id: this.id,
      type: this.type,
    };
    if (controller) {
      publicNode.controller = controller;
    }
    this.addEncodedPublicKey(publicNode); // Subclass-specific
    return publicNode;
  }
}

/**
 * @ignore
 * Returns an object with an async sign function.
 * The sign function is bound to the KeyPair
 * and then returned by the KeyPair's signer method.
 * @param {MyLinkedDataKeyClass2019} key - An MyLinkedDataKeyClass2019.
 *
 * @returns {{sign: Function}} An object with an async function sign
 * using the private key passed in.
 */
function joseSignerFactory(key) {
  if (!key.privateKeyJwk) {
    return {
      async sign() {
        throw new Error('No private key to sign with.');
      },
    };
  }

  return {
    async sign({ data }) {
      const header = {
        alg: 'ES256K',
        b64: false,
        crit: ['b64'],
      };
      toBeSigned = Buffer.from(data.buffer, data.byteOffset, data.length);
      const flattened = jose.JWS.sign.flattened(
        toBeSigned,
        jose.JWK.asKey(key.privateKeyJwk),
        header
      );
      return flattened.protected + '..' + flattened.signature;
    },
  };
}

/**
 * @ignore
 * Returns an object with an async verify function.
 * The verify function is bound to the KeyPair
 * and then returned by the KeyPair's verifier method.
 * @param {MyLinkedDataKeyClass2019} key - An MyLinkedDataKeyClass2019.
 *
 * @returns {{verify: Function}} An async verifier specific
 * to the key passed in.
 */
joseVerifierFactory = (key) => {
  if (!key.publicKeyJwk) {
    return {
      async sign() {
        throw new Error('No public key to verify with.');
      },
    };
  }

  return {
    async verify({ data, signature }) {
      const alg = key.alg; // Ex: "EdDSA";
      const type = key.type; //Ex: "Ed25519Signature2018";
      const [encodedHeader, encodedSignature] = signature.split('..');
      let header;
      try {
        header = JSON.parse(base64url.decode(encodedHeader));
      } catch (e) {
        throw new Error('Could not parse JWS header; ' + e);
      }
      if (!(header && typeof header === 'object')) {
        throw new Error('Invalid JWS header.');
      }

      // confirm header matches all expectations
      if (
        !(
          header.alg === alg &&
          header.b64 === false &&
          Array.isArray(header.crit) &&
          header.crit.length === 1 &&
          header.crit[0] === 'b64'
        ) &&
        Object.keys(header).length === 3
      ) {
        throw new Error(`Invalid JWS header parameters for ${type}.`);
      }

      let verified = false;

      const detached = {
        protected: encodedHeader,
        signature: encodedSignature,
      };

      const payload = Buffer.from(data.buffer, data.byteOffset, data.length);

      try {
        jose.JWS.verify(
          { ...detached, payload },
          jose.JWK.asKey(key.publicKeyJwk),
          {
            crit: ['b64'],
          }
        );
        verified = true;
      } catch (e) {
        console.error('An error occurred when verifying signature: ', e);
      }
      return verified;
    },
  };
};

module.exports = MyLinkedDataKeyClass2019;
