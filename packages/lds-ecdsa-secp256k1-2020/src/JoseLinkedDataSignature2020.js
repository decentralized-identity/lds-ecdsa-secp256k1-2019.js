const {
  suites: { LinkedDataSignature }
} = require("jsonld-signatures");

const base64url = require("base64url");

const getRecomendedAlg = require("./getRecomendedAlg");

class JoseLinkedDataSignature2020 extends LinkedDataSignature {
  static inferAlg(lds) {
    const { alg } = JSON.parse(base64url.decode(lds.proof.jws.split("..")[0]));
    return alg;
  }
  /**
   * @param linkedDataSigantureType {string} The name of the signature suite.
   * @param linkedDataSignatureVerificationKeyType {string} The name verification key type for the signature suite.
   *
   * @param alg {string} JWS alg provided by subclass.
   * @param [LDKeyClass] {LDKeyClass} provided by subclass or subclass
   *   overrides `getVerificationMethod`.
   *
   *
   * This parameter is required for signing:
   *
   * @param [signer] {function} an optional signer.
   *
   * @param [proofSignatureKey] {string} the property in the proof that will contain the signature.
   * @param [date] {string|Date} signing date to use if not passed.
   * @param [key] {LDKeyPair} an optional crypto-ld KeyPair.
   * @param [useNativeCanonize] {boolean} true to use a native canonize
   *   algorithm.
   */
  constructor({
    linkedDataSigantureType,
    linkedDataSignatureVerificationKeyType,
    alg,
    LDKeyClass,
    signer,
    key,
    proofSignatureKey,
    date,
    useNativeCanonize
  } = {}) {
    super({
      type: linkedDataSigantureType,
      LDKeyClass,
      alg,
      date,
      useNativeCanonize
    });
    this.alg = alg;
    this.LDKeyClass = LDKeyClass;
    this.signer = signer;
    this.requiredKeyType = linkedDataSignatureVerificationKeyType;
    this.proofSignatureKey = proofSignatureKey || "jws";

    if (key) {
      const publicKey = key.publicNode();
      this.verificationMethod = publicKey.id;
      this.key = key;
      if (typeof key.signer === "function") {
        this.signer = key.signer();
      }
      if (typeof key.verifier === "function") {
        this.verifier = key.verifier(key, this.alg, this.type);
      }
    }

    if (this.alg === undefined) {
      this.alg = getRecomendedAlg(key.publicKeyJwk);
    }
  }

  /**
   * @param verifyData {Uint8Array}.
   * @param proof {object}
   *
   * @returns {Promise<{object}>} the proof containing the signature value.
   */
  async sign({ verifyData, proof }) {
    if (!(this.signer && typeof this.signer.sign === "function")) {
      throw new Error("A signer API has not been specified.");
    }

    proof[this.proofSignatureKey] = await this.signer.sign({
      data: verifyData
    });
    return proof;
  }

  /**
   * @param verifyData {Uint8Array}.
   * @param verificationMethod {object}.
   * @param document {object} the document the proof applies to.
   * @param proof {object} the proof to be verified.
   * @param purpose {ProofPurpose}
   * @param documentLoader {function}
   * @param expansionMap {function}
   *
   * @returns {Promise<{boolean}>} Resolves with the verification result.
   */
  async verifySignature({ verifyData, verificationMethod, proof }) {
    let { verifier } = this;

    if (!verifier) {
      const key = await this.LDKeyClass.from(verificationMethod);
      verifier = key.verifier(key, this.alg, this.type);
    }
    return await verifier.verify({
      data: Buffer.from(verifyData),
      signature: proof[this.proofSignatureKey]
    });
  }

  async assertVerificationMethod({ verificationMethod }) {
    if (!jsonld.hasValue(verificationMethod, "type", this.requiredKeyType)) {
      throw new Error(
        `Invalid key type. Key type must be "${this.requiredKeyType}".`
      );
    }
  }

  async getVerificationMethod({ proof, documentLoader }) {
    if (this.key) {
      return this.key.publicNode();
    }

    const verificationMethod = await super.getVerificationMethod({
      proof,
      documentLoader
    });
    await this.assertVerificationMethod({ verificationMethod });
    return verificationMethod;
  }

  async matchProof({ proof, document, purpose, documentLoader, expansionMap }) {
    if (
      !(await super.matchProof({
        proof,
        document,
        purpose,
        documentLoader,
        expansionMap
      }))
    ) {
      return false;
    }
    if (!this.key) {
      // no key specified, so assume this suite matches and it can be retrieved
      return true;
    }

    let { verificationMethod } = proof;
    if (!verificationMethod) {
      verificationMethod = proof.creator;
    }
    // only match if the key specified matches the one in the proof
    if (typeof verificationMethod === "object") {
      return verificationMethod.id === this.key.id;
    }
    return verificationMethod === this.key.id;
  }
}

module.exports = JoseLinkedDataSignature2020;
