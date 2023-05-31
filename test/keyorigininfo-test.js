/* eslint-disable quotes */
/* eslint-disable no-unused-vars */
'use strict';
const HD = require('../lib/hd');
const assert = require('bsert');
const {HARDENED} = require('../lib/hd/common');

function parsekeyPath(path) {
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
  };

describe('KeyOriginInfo', function () {
  it('should create a KeyOriginInfo object for a valid origin info', () => {
    let str = `[d34db33f/44'/0'/0']`;
    str = str.slice(1, -1);
    const slashSplit = str.split('/');
    const fingerPrint = parseInt(slashSplit[0], 16);
    const path = parsekeyPath(slashSplit.slice(1));
    const keyOriginInfo = HD.KeyOriginInfo.fromOptions({fingerPrint, path});
    const expectedFingerPrint = 3545084735;
    const expectedPath = [2147483692, 2147483648, 2147483648];
    assert.strictEqual(keyOriginInfo.fingerPrint, expectedFingerPrint);
    assert.deepStrictEqual(keyOriginInfo.path, expectedPath);
  });

  it('should create a KeyOriginInfo object for a valid origin info when path type is string', () => {
    let str = `[d34db33f/44'/0'/0']`;
    str = str.slice(1, -1);
    const slashSplit = str.split('/');
    const fingerPrint = parseInt(slashSplit[0], 16);
    const path = `m/` + slashSplit.slice(1).join('/');
    const keyOriginInfo = HD.KeyOriginInfo.fromOptions({fingerPrint, path});
    const expectedFingerPrint = 3545084735;
    const expectedPath = [2147483692, 2147483648, 2147483648];
    assert.strictEqual(keyOriginInfo.fingerPrint, expectedFingerPrint);
    assert.deepStrictEqual(keyOriginInfo.path, expectedPath);
  });

  it('should error while creating a KeyOriginInfo object for fingerprint out of range', () => {
    let str = `[aaaaaaaaa]`;
    str = str.slice(1, -1);
    const slashSplit = str.split('/');
    const fingerPrint = parseInt(slashSplit[0], 16);
    const path = parsekeyPath(slashSplit.slice(1));
    let error = null;
    try {
      HD.KeyOriginInfo.fromOptions({fingerPrint, path});
    } catch (e) {
      error = e;
    }
    assert.strictEqual(error.message, 'fingerPrint must be uint32');
  });

  it('should return a KeyOriginInfo with formatted path ', () => {
    let str = `[d34db33f/44'/0'/0']`;
    str = str.slice(1, -1);
    const slashSplit = str.split('/');
    const fingerPrint = parseInt(slashSplit[0], 16);
    const path = parsekeyPath(slashSplit.slice(1));
    const keyOriginInfo = HD.KeyOriginInfo.fromOptions({fingerPrint, path});
    const expectedPath = `m/44'/0'/0'`;
    assert.strictEqual(keyOriginInfo.format().path, expectedPath);
  });

  it('should correctly validate two equal KeyOriginInfo objects', () => {
    let str = `[d34db33f/44'/0'/0']`;
    str = str.slice(1, -1);
    const slashSplit = str.split('/');
    const fingerPrint = parseInt(slashSplit[0], 16);
    const path = parsekeyPath(slashSplit.slice(1));
    const keyOriginInfo1 = HD.KeyOriginInfo.fromOptions({fingerPrint, path});
    const keyOriginInfo2 = HD.KeyOriginInfo.fromOptions({fingerPrint, path});
    assert.strictEqual(keyOriginInfo1.equals(keyOriginInfo2), true);
  });

  it('should create a JSON object', () => {
    let str = `[d34db33f/44'/0'/0']`;
    str = str.slice(1, -1);
    const slashSplit = str.split('/');
    const fingerPrint = parseInt(slashSplit[0], 16);
    const path = parsekeyPath(slashSplit.slice(1));
    const keyOriginInfo = HD.KeyOriginInfo.fromOptions({fingerPrint, path});
    const actualJSON = keyOriginInfo.toJSON();
    const expectedJSON = {
      fingerPrint: 'd34db33f',
      path: `m/44'/0'/0'`
    };
    assert.deepStrictEqual(actualJSON, expectedJSON);
  });
});
