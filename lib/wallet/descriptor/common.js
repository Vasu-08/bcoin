/*!
 * common.js - common functions for descriptor
 * Copyright (c) 2015-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const secp256k1 = require('bcrypto/lib/secp256k1');
const assert = require('bsert');
const {types} = require('../../script/common');
const common = exports;

/**
 * parse script context for descriptor
 * @const {Object}
 */

common.scriptContext = {
  TOP: 'TOP',
  P2SH: 'P2SH',
  P2WPKH: 'P2WPKH',
  P2WSH: 'P2WSH',
  P2TR: 'P2TR'
};

/**
 * Derive type for parsed key object in a descriptor
 * @const {Object}
 */

common.deriveType = {
  NO: 'NO',
  UNHARDENED: 'UNHARDENED',
  HARDENED: 'HARDENED'
};

/**
 * String type for key object in a descriptor
 * @const {Object}
 */

common.stringType = {
  PUBLIC: 'PUBLIC',
  PRIVATE: 'PRIVATE',
  NORMALIZED: 'NORMALIZED'
};

/**
 * Output types for descriptor
 * @const {Object}
 */

common.outputTypes = types;

/**
 * Valid input characters for input in a descriptor
 * and used for calculating checksum
 * @const {String}
 */

common.INPUT_CHARSET = '0123456789()[],\'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ' +
                       '&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#"\\ ';

                       /**
 * Checksum character set for calculating checksum
 */

common.CHECKSUM_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

/**
 * Test whether this descriptor is of scriptType or not
 * @param {String} scriptType type of script
 * @param {String} desc descriptor string
 * @returns {Boolean}
 */

common.descType = function descType(scriptType, desc) {
  if (
    desc.length >= scriptType.length + 2 &&
    desc[scriptType.length] === '(' &&
    desc[desc.length - 1] === ')' &&
    scriptType === desc.substring(0, scriptType.length)
  ) {
    return true;
  }
  return false;
};

/**
 * Strip outer level script string from descriptor
 * @param {String} str
 * @param {String} s
 * @returns {String} stripped descriptor string
 */

common.strip = function strip(scriptType, desc) {
  desc = desc.substring(scriptType.length + 1, desc.length - 1);
  return desc;
};

/**
 * Extract the expression that str begins with.
 * This function will return the initial part of str, up to
 * (but not including) the first comma or closing brace,
 * skipping ones that are surrounded by braces. So for example,
 * for "hello(world)(),(" the initial part
 * "hello(world)()" will be returned. sp will be
 * updated to skip the initial part that is returned.
 * @param {String} str
 * @returns {String}
 */

common.giveExpr = function giveExpr(str) {
  let level = 0;
  let it = 0;

  while (it < str.length) {
    if (str[it] === '(' || str[it] === '{') {
      level++;
    } else if (level && (str[it] === ')' || str[it] === '}')) {
      level--;
    } else if (
      level === 0 &&
      (str[it] === ')' || str[it] === '}' || str[it] === ',')
    ) {
      break;
    }
    it++;
  }

  const ret = str.slice(0, it);
  return ret;
};
console.log(common.giveExpr('hello(world)(),()'));

common.isHex = function isHex(str) {
  const regexp = /^[0-9a-fA-F]+$/;
  return regexp.test(str);
};

common.isCompressed = function isCompressed(key) {
  assert(secp256k1.publicKeyVerify(key), 'Invalid public key');
  const isCompressed =
    key.length === 33 && (key[0] === 0x02 || key[0] === 0x03);

  return isCompressed;
};
