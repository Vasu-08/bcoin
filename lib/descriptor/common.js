/*!
 * common.js - common functions for descriptor
 * Copyright (c) 2015-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('bsert');
const {types} = require('../script/common');
const BN = require('bcrypto/lib/bn.js');
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
 * Derive type for a key object in a descriptor
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
 * Test whether this descriptor is of scriptType
 * ('pk', 'pkh', 'wpkh' etc.) or not
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

/**
 * Test whether a string is a hex string or not
 * @param {String} str
 * @returns {Boolean}
 */

common.isHex = function isHex(str) {
  const regexp = /^[0-9a-fA-F]+$/;
  return regexp.test(str);
};

common.polyMod = function polyMod(c, val) {
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
};

/**
 * Get the checksum of a descriptor string
 * @param {String} desc
 * @returns {String} checksum string
 */

common.createChecksum = function createChecksum(desc) {
  let c = BN.from(1, 10, 'be');
  let cls = BN.from(0, 10, 'be');
  let clsCount = 0;

  for (let i = 0; i < desc.length; ++i) {
    const ch = desc[i];
    const pos = BN.from(common.INPUT_CHARSET.indexOf(ch), 10, 'be');
    assert(pos.toNumber() !== -1, `Invalid character ${ch} at position ${i}`);
    c = common.polyMod(c, pos.and(BN.from(31, 10, 'be')));
    cls = cls.mul(BN.from(3, 10, 'be'));
    cls = cls.add(pos.ushr(BN.from(5, 10, 'be')));

    if (++clsCount === 3) {
      c = common.polyMod(c, cls);
      cls = BN.from(0, 10, 'be');
      clsCount = 0;
    }
  }

  if (clsCount > 0) {
    c = common.polyMod(c, cls);
  }

  for (let j = 0; j < 8; ++j) {
    c = common.polyMod(c, BN.from(0, 10, 'be'));
  }

  c = c.xor(BN.from(1, 10, 'be'));
  let checksum = '';

  for (let j = 0; j < 8; ++j) {
    const c1 = BN.from(5 * (7 - j), 10, 'be');
    const c2 = BN.from(31, 10, 'be');
    const index = c.ushr(c1).and(c2);
    checksum += common.CHECKSUM_CHARSET[index.toNumber()];
  }

  return checksum;
};

/**
 * Test whether the descriptor has valid checksum (if present).
 * If requireChecksum is true, will error if no checksum is present.
 * @param {String} desc
 * @param {Boolean} requireChecksum
 * @returns {String} descriptor string without checksum part
 */

common.checkChecksum = function checkChecksum(desc, requireChecksum) {
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

  const checksum = common.createChecksum(checkSplit[0]);

  if (checkSplit.length === 2) {
    assert(
      checksum === checkSplit[1],
      `Expected checksum ${checksum}, found ${checkSplit[1]}`
    );
  }

  return checkSplit[0];
};

/**
 * Get descriptor string with checksum appended.
 * @param {String} desc
 * @returns {String} descriptor string with checksum appended
 */

common.addChecksum = function addChecksum(desc) {
  const split = desc.split('#');
  const checksum = common.createChecksum(split[0]);
  const result = split[0] + '#' + checksum;
  return result;
};
