/*!
 * pubkeyprovider.js - parsed public key object for descriptor in bcoin
 * Copyright (c) 2015-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const HD = require('../../hd');
const {HARDENED} = require('../../hd/common');
const hash160 = require('bcrypto/lib/hash160');
const {deriveType} = require('./common');

/**
 * PubkeyProvider
 * Represents a public key object for a in a descriptor
 * @property {KeyRing} ring
 * @property {Number} index - index of the key in the descriptor
 */

class PubkeyProvider {
  /**
   * @constructor
   * @param {Object} options
   */

  constructor(options) {
    this.ring = null;
    this.index = 0;
    this.network = null;

    if (options) {
      this.fromOptions(options);
    }
  }

  /**
   * Inject properties from options object.
   * @param {Object} options
   */

  fromOptions(options) {
    this.ring = options.ring;
    this.index = options.index;
    this.network = options.network;
  }

  /**
   * Instantiate pubkey from options.
   * @param {Object} options
   * @returns {PubkeyProvider}
   */

  static fromOptions(options) {
    return new this().fromOptions(options);
  }

  /**
   * Test whether this represent multiple public keys at different positions
   * @returns {Boolean}
   */

  isRange() {
    return false;
  }

  /**
   * Get the size of the generated public key(s) in bytes
   * @returns {Number} 33 or 65
   */

  getSize() {
    return null;
  }

  /**
   * Get the string form of the public key
   * @returns {String}
   */

  toString() {
    return null;
  }

  /**
   * Get the string form of the private key (if available)
   * @returns {String}
   */

  toPrivateString() {
    return null;
  }

  /**
   * Get the string form with the xpub at the last hardened derivation
   * @returns {String}
   */

  toNormalizedString() {
    return null;
  }

  /**
   * Get the private key (if available)
   * @returns {String} base58 private key
   */

  getPrivatekey() {
    const privKey = this.ring.getPrivateKey('base58', this.network);
    return privKey;
  }

  /**
   * Get the public key
   * @returns {String} public key in base58
   */

  getPubkey() {
    return this.ring.getPublicKey('base58');
  }
}

class ConstPubkeyProvider extends PubkeyProvider {
  constructor(options) {
    super(options);
  }

  getSize() {
    const len = this.ring.publicKey.length;
    return len;
  }

  toString() {
    const str = this.ring.getPublicKey('hex');
    return str;
  }

  toPrivateString() {
    const str = this.ring.getPrivateKey('base58', this.network);
    return str;
  }

  toNormalizedString() {
    const str = this.ring.getPublicKey('hex');
    return str;
  }

  getPubkey() {
    return this.ring.getPubkey('base58');
  }
}

/**
 * HDKeyProvider
 * Represents an extended public key object in a descriptor
 * @extends PubkeyProvider
 * @property {HDPublic|HDPrivate} hdkey
 * @property {Number[]} path - array of derivation indices
 * (not to be confused with origin info)
 * @property {String} type - Normal, Hardened, or Unhardened
 */

class HDPubkeyProvider extends PubkeyProvider {
  constructor(options) {
    super(options);
    this.hdkey = options.hdkey;
    this.path = options.path;
    this.type = options.type;
  }

  isRange() {
    if (this.type === deriveType.NO) {
      return false;
    }
    return true;
  }

  /**
   * Test whether this is normal, hardened, unhardened
   * @returns {Boolean}
   */

  isHardened() {
    if (this.type === deriveType.HARDENED) {
      return true;
    }
    for (let i = 0; i < this.path.length; i++) {
      if (this.path[i] & HARDENED) {
        return true;
      }
    }
    return false;
  }

  getSize() {
    return 33;
  }

  toString() {
    let str = this.hdkey.xpubkey(this.network) + format(this.path);
    if (this.isRange()) {
      str += '/*';
      if (this.type === deriveType.HARDENED) {
        str += '\'';
      }
    }
    return str;
  }

  toPrivateString() {
    if (this.ring.privateKey) {
      let str = this.hdkey.xprivkey(this.network) + format(this.path);
      if (this.isRange()) {
        str += '/*';
        if (this.type === deriveType.HARDENED) {
          str += '\'';
        }
      }
      return str;
    }
    return null;
  }

  /**
   * Get the last hardened private key
   * @returns {HDPrivateKey|HDPublicKey}
   * @throws error if no private key is available
   */

  getLastxpriv() {
    if (!this.getPrivatekey()) {
      return null;
    }

    let lastHardened;
    let key = this.hdkey;
    for (const index of this.path) {
      key = key.derive(index);
      if (index & HARDENED) {
        lastHardened = key;
      }
    }
    return lastHardened;
  }

  toNormalizedString() {
    if (this.type === deriveType.HARDENED) {
      return this.toString();
    }
    // step backwards until we find a non-hardened path component
    let pos = this.path.length - 1;

    while (pos >= 0) {
      if (this.path[pos] & HARDENED) {
        break;
      }
      pos--;
    }

    if (pos === -1) {
      return this.toString();
    }

    const originPath = this.path.slice(0, pos + 1);
    const endPath = this.path.slice(pos + 1);
    const fp = hash160.digest(this.hdkey.publicKey);
    const fingerprint = fp.readUInt32BE(0, true);
    const originInfo = HD.KeyOriginInfo.fromOptions({
      path: originPath,
      fingerPrint: fingerprint
    });
    const lastxpriv = this.getLastxpriv();
    const xpub = lastxpriv.toPublic();
    const formattedInfo = originInfo.format();
    const {fingerPrint, path} = formattedInfo;
    const originStr = `${fingerPrint}${path}`;
    const keyStr = xpub.toBase58(this.network);
    const result = `[${originStr}]${keyStr}${format(endPath)}}`;
    return result;
  }

  getPubkey() {
    let derivedKey = this.hdkey;

    if (!this.isHardened()) {
      for (const index of this.path) {
        derivedKey = derivedKey.derive(index, false);
      }
    }

    let key = this.hdkey;
    for (let i = 0; i < this.path.length; i++) {
      key = key.derive(this.path[i], false);
    }

    return key.publicKey;
  }
}

/**
 * OriginPubkeyProvider
 * Represents an extended public key object along with origin info
 * in a descriptor
 * @extends PubkeyProvider
 * @property {KeyOriginInfo} originInfo
 * @property {HDPubkeyProvider} provider
 */

class OriginPubkeyProvider extends PubkeyProvider {
  constructor(options) {
    super(options);
    this.originInfo = options.originInfo;
    this.provider = options.provider;
    this.ring = options.provider.ring;
    this.index = options.provider.index;
    this.network = options.network;
  }

  isRange() {
    return this.provider.isRange();
  }

  getOriginString() {
    const fingerPrint = this.originInfo.fingerPrint.toString(16);
    const path = format(this.originInfo.path);
    const result = `[${fingerPrint}${path}]`;
    return result;
  }

  toString() {
    return this.getOriginString() + this.provider.toString();
  }

  getSize() {
    return this.provider.getSize();
  }
}

/**
 * Helpers
 */

function format(path) {
  let formattedpath = '';
  for (const p of path) {
    const hardened = p & HARDENED ? '\'' : '';
    formattedpath += `/${p & 0x7fffffff}${hardened}`;
  }
  return formattedpath;
}

/**
 * Expose
 */

module.exports = {
  PubkeyProvider,
  ConstPubkeyProvider,
  HDPubkeyProvider,
  OriginPubkeyProvider
};
