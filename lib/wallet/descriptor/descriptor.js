/*!
 * descriptor.js - descriptor object for bcoin
 * Copyright (c) 2015-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('bsert');
const HD = require('../../hd/hd');
const { HARDENED } = require('../../hd/common');
const KeyRing = require('../../primitives/keyring');
const BN = require('bcrypto/lib/bn.js');

const {
  ConstPubkeyProvider,
  OriginPubkeyProvider,
  HDPubkeyProvider
} = require('./pubkeyprovider');

const {
  scriptContext,
  deriveType,
  stringType,
  outputTypes,
  INPUT_CHARSET,
  CHECKSUM_CHARSET,
  descType,
  strip,
  giveExpr,
  isHex,
  isCompressed
} = require('./common');

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
    return this.fromJSON(options);
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
    return Descriptor.addChecksum(res);
  }

  /**
   * Get descriptor string including private keys if available
   * @returns {String}
   */

  getPrivateString() {
    const res = this.getStringHelper(stringType.PRIVATE);
    return Descriptor.addChecksum(res);
  }

  /**
   * Get descriptor string with the xpub at last hardened derivation step
   * @returns {String}
   */

  getNormalizedString() {
    const res = this.getStringHelper(stringType.NORMALIZED);
    return Descriptor.addChecksum(res);
  }

  static polyMod(c, val) {
    const c0 = c.ushr(BN.from(35, 10, 'be'));
    const c1 = BN.from('7ffffffff', 16, 'be');
    c = c.and(c1).ushl(BN.from(5, 10, 'be')).xor(val);
    if (c0.and(BN.from(1, 10, 'be')).toNumber())
      c = c.xor(BN.from('f5dee51989', 16, 'be'));
    if (c0.and(BN.from(2, 10, 'be')).toNumber())
      c = c.xor(BN.from('a9fdca3312', 16, 'be'));
    if (c0.and(BN.from(4, 10, 'be')).toNumber())
      c = c.xor(BN.from('1bab10e32d', 16, 'be'));
    if (c0.and(BN.from(8, 10, 'be')).toNumber())
      c = c.xor(BN.from('3706b1677a', 16, 'be'));
    if (c0.and(BN.from(16, 10, 'be')).toNumber())
      c = c.xor(BN.from('644d626ffd', 16, 'be'));

    return c;
  }

  /**
   * Get the checksum of a descriptor string
   * @param {String} desc
   * @returns {String}
   */

  static createChecksum(desc) {
    let c = BN.from(1, 10, 'be');
    let cls = BN.from(0, 10, 'be');
    let clsCount = 0;

    for (const ch of desc) {
      const pos = BN.from(INPUT_CHARSET.indexOf(ch), 10, 'be');
      assert(pos.toNumber() !== -1, `Character ${ch} invalid`);
      c = this.polyMod(c, pos.and(BN.from(31, 10, 'be')));
      cls = cls.mul(BN.from(3, 10, 'be'));
      cls = cls.add(pos.ushr(BN.from(5, 10, 'be')));

      if (++clsCount === 3) {
        c = this.polyMod(c, cls);
        cls = BN.from(0, 10, 'be');
        clsCount = 0;
      }
    }

    if (clsCount > 0) {
      c = this.polyMod(c, cls);
    }

    for (let j = 0; j < 8; ++j) {
      c = this.polyMod(c, BN.from(0, 10, 'be'));
    }

    c = c.xor(BN.from(1, 10, 'be'));
    let checksum = '';

    for (let j = 0; j < 8; ++j) {
      const c1 = BN.from(5 * (7 - j), 10, 'be');
      const c2 = BN.from(31, 10, 'be');
      const index = c.ushr(c1).and(c2);
      checksum += CHECKSUM_CHARSET[index.toNumber()];
    }

    return checksum;
  }

  /**
   * Test whether the descriptor has valid checksum (if present).
   * If requireChecksum is true, will error if no checksum is present.
   * @param {String} desc
   * @param {Boolean} requireChecksum
   * @returns {String} descriptor string without checksum part
   */

  static checkChecksum(desc, requireChecksum) {
    const checkSplit = desc.split('#');
    assert(checkSplit.length <= 2, 'Multiple # symbols');
    if (checkSplit.length === 1) {
      assert(!requireChecksum, 'Missing checksum');
    }

    if (checkSplit.length === 2) {
      assert(
        checkSplit[1].length === 8,
        `Expected 8 characters checksum, not ${checkSplit[1].length} characters`
      );
    }

    const checksum = this.createChecksum(checkSplit[0]);

    if (checkSplit.length === 2) {
      assert(
        checksum === checkSplit[1],
        `Expected checksum ${checksum}, found ${checkSplit[1]}`
      );
    }

    return checkSplit[0];
  }

  /**
   * Get descriptor string with checksum appended.
   * @param {String} desc
   * @returns
   */

  static addChecksum(desc) {
    const split = desc.split('#');
    const checksum = this.createChecksum(split[0]);
    const result = split[0] + '#' + checksum;
    return result;
  }

  /**
   * Get the parsed public key object with derivation path
   * excluding the origin info
   * @param {String} desc
   * @param {Object} keyIndex
   * @param {String} context
   * @param {Network} network
   * @returns {ConstPubkeyProvider|HDPubkeyProvider}
   */

  parsePubkeyInner(desc, keyIndex, context, network) {
    // split the key and derivation path
    const keySplit = desc.split('/');
    const index = keyIndex.index;
    assert(keySplit.length > 0, 'No key provided');

    const str = keySplit[0];
    // check whether uncompressed keys are allowed or not
    const permitUncompressed =
      context === scriptContext.TOP || context === scriptContext.P2SH;

    // keySplit size 1 means that no derivation path is provided
    if (keySplit.length === 1) {
      /*
       * if the key is hex, it is a public key and it will be parsed into
       * ConstPubkeyProvider object.
       * if the key is base58, it can be either
       * extended public key, extended private key or a WIF format private key
       * if the key is extended private key or public key
       * it will be parsed into HDKeyProvider object
       * else it will be parsed into ConstPubkeyProvider object
       */
      if (isHex(str)) {
        const serializedKey = Buffer.from(str, 'hex');
        const ring = KeyRing.fromPublic(serializedKey);
        if (permitUncompressed || isCompressed(ring.publicKey)) {
          const options = {
            index,
            ring
          };
          return new ConstPubkeyProvider(options);
        } else {
          throw new Error('Uncompressed keys are not allowed');
        }
      }

      if (!HD.PrivateKey.isBase58(str, network)) {
        const ring = KeyRing.fromSecret(str, network);
        if (permitUncompressed || isCompressed(ring.publicKey)) {
          const options = {
            index,
            ring
          };
          return new ConstPubkeyProvider(options);
        } else {
          throw new Error('Uncompressed keys are not allowed');
        }
      }
    }

    assert(HD.isBase58(str, network), 'Invalid base58 key');

    let options;

    if (HD.PrivateKey.isBase58(str, network)) {
      const hdkey = HD.PrivateKey.fromBase58(str, network);
      const ring = KeyRing.fromPrivate(hdkey.privateKey, true);
      options = {
        index,
        hdkey,
        ring
      };
    } else {
      const hdkey = HD.PublicKey.fromBase58(str, network);
      const ring = KeyRing.fromPublic(hdkey.publicKey);
      options = {
        index,
        hdkey,
        ring
      };
    }

    options.type = deriveType.NO;
    const last = keySplit[keySplit.length - 1];

    if (last.length === 1 && last === '*') {
      options.type = deriveType.UNHARDENED;
      keySplit.pop();
    } else if (last.length === 2 && (last === '*\'' || last === '*h')) {
      options.type = deriveType.HARDENED;
      keySplit.pop();
    }

    const path = this.parsekeyPath(keySplit.slice(1));
    options.path = path;

    return new HDPubkeyProvider(options);
  }

  /**
   * Parse a derivation path and return an array of indexes.
   * @param {String} path
   * @returns {Number[]}
   */

  parsekeyPath(path) {
    const result = [];
    for (let i = 0; i < path.length; i++) {
      let part = path[i];
      const last = part[part.length - 1];
      let hardened = false;

      if (last === '\'' || last === 'h') {
        part = part.slice(0, -1);
        hardened = true;
      }

      if (part.length > 10) {
        throw new Error('Path index too large.');
      }

      if (!/^\d+$/.test(part)) {
        throw new Error('Path index is non-numeric.');
      }

      let index = parseInt(part, 10);

      if (index >>> 0 !== index) {
        throw new Error('Path index out of range.');
      }

      if (hardened) {
        index |= HARDENED;
        index >>>= 0;
      }
      result.push(index);
    }
    return result;
  }

  /**
   * Get the parsed public key object including the KeyOrigin info
   * @param {String} desc
   * @param {Object} keyIndex
   * @param {String} context
   * @param {Network} network
   * @returns {OriginPubkeyProvider}
   * @throws parse error
   */

  parsePubkey(desc, keyIndex, context, network) {
    const originSplit = desc.split(']');

    assert(
      originSplit.length <= 2,
      'Multiple ] characters found for a single pubkey'
    );

    if (originSplit.length === 1) {
      const provider = this.parsePubkeyInner(
        originSplit[0],
        keyIndex,
        context,
        network
      );
      return provider;
    }

    assert(
      originSplit.length && originSplit[0][0] === '[',
      `Expected[, found ${originSplit[0][0]} instead`
    );

    originSplit[0] = originSplit[0].slice(1);
    const slashSplit = originSplit[0].split('/');

    assert(
      slashSplit[0].length === 8,
      `Expected 8 characters fingerprint, found ${slashSplit[0].length} instead`
    );

    const fingerprintHex = slashSplit[0];

    assert(isHex(fingerprintHex), `Fingerprint ${fingerprintHex} is not hex`);

    const fingerPrint = parseInt(fingerprintHex, 16);
    const path = this.parsekeyPath(slashSplit.slice(1));
    const originInfo = HD.KeyOriginInfo.fromOptions({ fingerPrint, path });

    const provider = this.parsePubkeyInner(
      originSplit[1],
      keyIndex,
      context,
      network
    );

    return new OriginPubkeyProvider({
      originInfo,
      provider
    });
  }

  /**
   * Parse the descriptor string based on script type at top level.
   * Recursive function for parsing wsh and sh descriptors.
   * @param {String} desc
   * @param {Object} keyIndex
   * @param {String} context
   * @param {Network} network
   * @returns {Descriptor}
   * @throws parse error
   */

  parseType(desc, keyIndex, context, network) {
    const expr = giveExpr(desc);

    // parsing pk and pkh descriptor
    if (descType('pk', expr)) {
      desc = strip('pk', expr);
      const pubkeyprovider = this.parsePubkey(desc, keyIndex, context, network);
      keyIndex.index++;
      return PKDescriptor.fromOptions({
        pubkeys: [pubkeyprovider]
      });
    }

    // parsing pkh descriptor
    if (
      (context === scriptContext.TOP
        || context === scriptContext.P2SH
        || context === scriptContext.P2WSH
      )
      && descType('pkh', expr)
    ) {
      desc = strip('pkh', expr);
      const pubkeyprovider = this.parsePubkey(desc, keyIndex, context, network);
      keyIndex.index++;
      return PKHDescriptor.fromOptions({
        pubkeys: [pubkeyprovider]
      });
    }
    assert(
      !descType('pkh', expr),
      'Can only have pkh() at top level, in sh(), or in wsh()'
    );

    // parsing combo descriptor
    if (context === scriptContext.TOP && descType('combo', expr)) {
      desc = strip('combo', expr);
      const pubkeyprovider = this.parsePubkey(desc, keyIndex, context, network);
      keyIndex.index++;
      return ComboDescriptor.fromOptions({
        pubkeys: [pubkeyprovider]
      });
    }
    assert(!descType('combo', expr), 'Can only have combo() at top level');

    // parsing wpkh descriptor
    if (context === scriptContext.TOP && descType('wpkh', expr)) {
      desc = strip('wpkh', expr);
      const pubkeyprovider = this.parsePubkey(desc, keyIndex, context, network);
      keyIndex.index++;
      return WPKHDescriptor.fromOptions({
        pubkeys: [pubkeyprovider]
      });
    }
    assert(
      !descType('wpkh', expr),
      'Can only have wpkh() at top level or inside sh()'
    );

    // parsing sh descriptor
    if (context === scriptContext.TOP && descType('sh', expr)) {
      desc = strip('sh', expr);
      const subdesc = this.parseType(
        desc,
        keyIndex,
        scriptContext.P2SH,
        network
      );
      return SHDescriptor.fromOptions({
        subdescriptors: [subdesc]
      });
    }
    assert(!descType('sh', expr), 'Can only have sh() at top level');

    // parsing wsh descriptor
    if (
      (context === scriptContext.TOP || context === scriptContext.P2SH)
      && descType('wsh', expr)
    ) {
      desc = strip('wsh', expr);
      const subdesc = this.parseType(
        desc,
        keyIndex,
        scriptContext.P2WSH,
        network
      );
      return WSHDescriptor.fromOptions({
        subdescriptors: [subdesc]
      });
    }
    assert(
      !descType('wsh', expr),
      'Can only have wsh() at top level or inside sh()'
    );

    return null;
  }

  /**
   * Initial step for parsing a descriptor.
   * First validate checksum and strip the descriptor string
   * At each successive parsing step, the descriptor string
   * is stripped of the part that was parsed.
   * @param {String} desc
   * @param {Network} network
   * @returns {Descriptor} return the parsed descriptor object
   */

  parse(desc, network) {
    // keyIndex represents the index of the key in the descriptor
    const keyIndex = { index: 0 };
    desc = Descriptor.checkChecksum(desc, false);
    return this.parseType(desc, keyIndex, scriptContext.TOP, network);
  }

  /**
   * Inject properties from string
   * @param {*} desc
   * @param {*} network
   * @returns {Descriptor}
   * @throws parse error
   */

  fromString(desc, network) {
    assert(typeof desc === 'string', 'Descriptor must be a string');
    assert(desc.length > 0, 'Descriptor string is empty');
    return this.parse(desc, network);
  }

  /**
   * Instantiate a descriptor from string
   * @param {*} desc
   * @param {*} network
   * @returns {Descriptor}
   */

  static fromString(desc, network) {
    return new this().fromString(desc, network);
  }
}

class PKDescriptor extends Descriptor {
  constructor() {
    super();
    this.name = 'pk';
  }

  fromOptions(options) {
    this.pubkeys = options.pubkeys;
    return this;
  }

  static fromOptions(options) {
    return new this().fromOptions(options);
  }

  isSingleType() {
    return true;
  }

  getScriptType() {
    return outputTypes.PUBKEY;
  }

  isSolvable() {
    return true;
  }
}

class PKHDescriptor extends Descriptor {
  constructor(options) {
    super();
    this.name = 'pkh';
  }

  fromOptions(options) {
    this.pubkeys = options.pubkeys;
    return this;
  }

  static fromOptions(options) {
    return new this().fromOptions(options);
  }

  isSingleType() {
    return true;
  }

  getScriptType() {
    return outputTypes.PUBKEYHASH;
  }

  isSolvable() {
    return true;
  }
}

class ComboDescriptor extends Descriptor {
  constructor() {
    super();
    this.name = 'combo';
  }

  fromOptions(options) {
    this.pubkeys = options.pubkeys;
    return this;
  }

  static fromOptions(options) {
    return new this().fromOptions(options);
  }
  isSingleType() {
    return false;
  }

  isSolvable() {
    return true;
  }
}

class SHDescriptor extends Descriptor {
  constructor() {
    super();
    this.name = 'sh';
  }

  fromOptions(options) {
    this.subdescriptors = options.subdescriptors;
    return this;
  }

  static fromOptions(options) {
    return new this().fromOptions(options);
  }

  isSingleType() {
    return true;
  }

  isSolvable() {
    return true;
  }
}

class WPKHDescriptor extends Descriptor {
  constructor() {
    super();
    this.name = 'wpkh';
  }

  fromOptions(options) {
    this.pubkeys = options.pubkeys;
    return this;
  }

  static fromOptions(options) {
    return new this().fromOptions(options);
  }

  isSingleType() {
    return true;
  }

  getScriptType() {
    return outputTypes.WITNESSPUBKEYHASH;
  }

  isSolvable() {
    return true;
  }
}

class WSHDescriptor extends Descriptor {
  constructor() {
    super();
    this.name = 'wsh';
  }

  fromOptions(options) {
    this.subdescriptors = options.subdescriptors;
    return this;
  }

  static fromOptions(options) {
    return new this().fromOptions(options);
  }

  isSingleType() {
    return true;
  }

  isSolvable() {
    return true;
  }
}

/*
 * Expose
 */

module.exports = Descriptor;
