'use strict';

const assert = require('bsert');
const HD = require('../../hd/hd');
const {HARDENED} = require('../../hd/common');
// const Descriptor = require('./descriptor');
const KeyRing = require('../../primitives/keyring');
const PKDescriptor = require('./pk');
const PKHDescriptor = require('./pkh');
const WPKHDescriptor = require('./wpkh');
const SHDescriptor = require('./sh');
const WSHDescriptor = require('./wsh');
const ComboDescriptor = require('./combo');
const Network = require('../../protocol/network');

const {
  ConstPubkeyProvider,
  OriginPubkeyProvider,
  HDPubkeyProvider
} = require('./pubkeyprovider');

const {
  scriptContext,
  deriveType,
  descType,
  strip,
  giveExpr,
  isHex,
  isCompressed,
  checkChecksum
} = require('./common');

/**
 * DescriptorParser
 * Parser for descriptor
 * @property {Descriptor} descriptor
 * @property {Network} network
 */

class DescriptorParser {
  /**
   * @constructor
   * @param {Object} options
   */

  constructor(options) {
    this.descriptor = null;
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
    this.descriptor = options.descriptor;
    this.network = Network.get(options.network);
  }

  /**
   * Instantiate descriptor from options.
   * @param {Object} options
   * @returns {Descriptor}
   */

  static fromOptions(options) {
    return new this().fromOptions(options);
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
    } else if (last.length === 2 && (last === '*\''
     || last === '*h')) {
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
    const originInfo = HD.KeyOriginInfo.fromOptions({fingerPrint, path});

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
      (context === scriptContext.TOP ||
        context === scriptContext.P2SH ||
        context === scriptContext.P2WSH) &&
      descType('pkh', expr)
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
      (context === scriptContext.TOP || context === scriptContext.P2SH) &&
      descType('wsh', expr)
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

  parse(desc, network, requireChecksum) {
    // keyIndex represents the index of the key in the descriptor
    const keyIndex = {index: 0};
    desc = checkChecksum(desc, requireChecksum);
    return this.parseType(desc, keyIndex, scriptContext.TOP, network);
  }

  /**
   * Inject properties from string
   * @param {*} desc
   * @param {*} network
   * @returns {Descriptor}
   * @throws parse error
   */

  fromString(desc, network, requireChecksum) {
    assert(typeof desc === 'string', 'Descriptor must be a string');
    assert(desc.length > 0, 'Descriptor string is empty');
    this.descriptor = this.parse(desc, network, requireChecksum);
    this.network = Network.get(network);
    return this.descriptor;
  }

  /**
   * Instantiate a descriptor from string
   * @param {*} desc
   * @param {*} network
   * @returns {Descriptor}
   */

  static fromString(desc, network, requireChecksum) {
    return new this().fromString(desc, network, requireChecksum);
  }
}

module.exports = DescriptorParser;
