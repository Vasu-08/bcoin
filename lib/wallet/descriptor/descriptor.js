/*!
 * descriptor.js - descriptor object for bcoin
 * Copyright (c) 2015-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const {stringType, addChecksum} = require('./common');

/**
 * Descriptor
 * Represents an output script
 * @property {String} name
 * @property {PubkeyProvider[]} pubkeys
 * @property {Descriptor[]} subdescriptors
 * @property {Network} network
 */

class Descriptor {
  /**
   * Create a descriptor
   * @constructor
   * @param {Object} options
   */

  constructor(options) {
    this.name = null;
    this.pubkeys = [];
    this.subdescriptors = [];
    this.network = null;
    if (options) {
      this.fromOptions(options);
    }
  }

  /**
   * Inject properties from options object.
   * @private
   * @param {Object} options
   * @returns {Descriptor}
   */

  fromOptions(options) {
    return this.fromOptions(options);
  }

  /**
   * Instantiate descriptor from options object.
   * @param {Object} options
   * @returns {Descriptor}
   */

  static fromOptions(options) {
    return new this().fromOptions(options);
  }

  /**
   * Test whether the descriptor contains a private key.
   * @returns {Boolean}
   */

  hasPrivateKeys() {
    for (const key of this.pubkeys) {
      if (key.getPrivatekey() !== null) {
        return true;
      }
    }
    return false;
  }

  /**
   * Test whether the descriptor contains public/private keys
   * in the form of HD chains
   * @returns {Boolean}
   */

  isRange() {
    for (const key of this.pubkeys) {
      if (key.isRange()) {
        return true;
      }
    }
    for (const subdesc of this.subdescriptors) {
      if (subdesc.isRange()) {
        return true;
      }
    }
    return false;
  }

  /**
   * Whether this descriptor has all information about signing
   * (igonoring private keys).
   * Returns false only for `addr` and `raw` type.
   * @returns {Boolean}
   */

  isSolvable() {
    for (const subdesc of this.subdescriptors) {
      if (!subdesc.isSolvable()) {
        return false;
      }
    }
    return true;
  }

  getStringExtra() {
    return '';
  }

  getStringSubScriptHelper(type) {
    let res = '';
    let pos = 0;

    for (const subdesc of this.subdescriptors) {
      if (pos++) {
        res += ',';
      }
      res += subdesc.getStringHelper(type);
    }

    return res;
  }

  /**
   * Helper function to get a descriptor in string form based on string type
   * (Public, Private, Normalized)
   * @param {String} type
   * @returns {String}
   */

  getStringHelper(type) {
    const extra = this.getStringExtra();
    let pos = extra.length === 0 ? 0 : 1;
    let res = this.name + '(' + extra;

    for (const pubkey of this.pubkeys) {
      if (pos++) {
        res += ',';
      }
      switch (type) {
        case stringType.PUBLIC:
          res += pubkey.toString();
          break;
        case stringType.PRIVATE:
          res += pubkey.toPrivateString();
          break;
        case stringType.NORMALIZED:
          res += pubkey.toNormalizedString();
      }
    }

    const subdesc = this.getStringSubScriptHelper(type);

    if (pos && subdesc.length) {
      res += ',';
    }

    res += subdesc + ')';
    return res;
  }

  /**
   * Get a descriptor string (public keys only)
   * @returns {String}
   */

  getString() {
    const res = this.getStringHelper(stringType.PUBLIC);
    return addChecksum(res);
  }

  /**
   * Get descriptor string including private keys if available
   * @returns {String}
   */

  getPrivateString() {
    const res = this.getStringHelper(stringType.PRIVATE);
    return addChecksum(res);
  }

  /**
   * Get descriptor string with the xpub at last hardened derivation step
   * @returns {String}
   */

  getNormalizedString() {
    const res = this.getStringHelper(stringType.NORMALIZED);
    return addChecksum(res);
  }
}

/*
 * Expose
 */

module.exports = Descriptor;

