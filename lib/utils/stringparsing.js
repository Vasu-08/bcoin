/* eslint-disable max-len */
'use strict';
const secp256k1 = require('bcrypto/lib/secp256k1');
const assert = require('bsert');

exports.checkScriptType = function checkScriptType(str, s) {
    if (s.length >= str.length + 2 && s[str.length] === '(' && s[s.length - 1] === ')' && str === s.substring(0, str.length)) {
        // s = s.substring(str.length + 1, s.length - 1);
        return true;
    }
    return false;
};

exports.stringAfterScriptType = function stringAfterScriptType(str, s) {
    s = s.substring(str.length + 1, s.length - 1);
    return s;
};

exports.giveExpr = function giveExpr(str) {
    let level = 0;
    let it = 0;

    while (it < str.length) {
        if (str[it] === '(' || str[it] === '{') {
            level++;
        } else if (level && (str[it] === ')' || str[it] === '}')) {
            level--;
        } else if (level === 0 && (str[it] === ')' || str[it] === '}' || str[it] === ',')) {
            break;
        }
        it++;
    }

    const ret = str.slice(0, it);
    // str = str.slice(it);
    return ret;
};

// eslint-disable-next-line valid-jsdoc
/**
 * @TODO write tests
 */
exports.isHex = function isHex(str) {
    const regexp = /^[0-9a-fA-F]+$/;
    return regexp.test(str);
};

exports.isCompressed = function isCompressed(key) {
    assert(secp256k1.publicKeyVerify(key), 'Invalid public key');
    const iscompressed = key.length === 33 && (key[0] === 0x02 || key[0] === 0x03);
    return iscompressed;
};
