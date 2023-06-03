/*!
 * descriptor.js - descriptor object for bcoin
 * Copyright (c) 2015-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const {stringType, addChecksum} = require('./common');
// const assert = require('bsert');

/**
 * Descriptor
 * Base class for descriptors
 * @property {String} name
 * @property {PubkeyProvider[]} pubkeys
 * @property {Descriptor[]} subdescriptors
 * @property {Network} network
 */

class Descriptor {
  /**
   * Create a descriptor
   * @constructor
   */

  constructor() {
    this.name = null;
    this.pubkeys = [];
    this.subdescriptors = [];
    this.network = null;
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

  toStringExtra() {
    return '';
  }

  toStringSubScriptHelper(type) {
    let res = '';
    let pos = 0;

    for (const subdesc of this.subdescriptors) {
      if (pos++) {
        res += ',';
      }
      res += subdesc.toStringHelper(type);
    }

    return res;
  }

  /**
   * Helper function to get a descriptor in string form based on string type
   * (Public, Private, Normalized)
   * @param {String} type
   * @returns {String}
   */

  toStringHelper(type) {
    const extra = this.toStringExtra();
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

    const subdesc = this.toStringSubScriptHelper(type);

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

  toString() {
    const res = this.toStringHelper(stringType.PUBLIC);
    return addChecksum(res);
  }

  /**
   * Get descriptor string including private keys if available
   * @returns {String}
   */

  toPrivateString() {
    const res = this.toStringHelper(stringType.PRIVATE);
    return addChecksum(res);
  }

  /**
   * Get descriptor string with the xpub at last hardened derivation step
   * @returns {String}
   */

  toNormalizedString() {
    const res = this.toStringHelper(stringType.NORMALIZED);
    return addChecksum(res);
  }
}

/*
 * Expose
 */

module.exports = Descriptor;
