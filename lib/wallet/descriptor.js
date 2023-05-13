/*!
 * public.js - descriptor object for bcoin
 * Copyright (c) 2015-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */
/* eslint-disable max-len */
'use strict';
const assert = require('bsert');
const BN = require('bcrypto/lib/bn.js');

class Descriptor {
    static polyMod(c, val) {
        const c0 = c.ushr(BN.from(35, 10, 'be'));
        c = c.and(BN.from('7ffffffff', 16, 'be')).ushl(BN.from(5, 10, 'be')).xor(val);
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

    static createChecksum(desc) {
        const INPUT_CHARSET =
            '0123456789()[],\'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#"\\ ';
        const CHECKSUM_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
        let c = BN.from(1, 10, 'be');
        let cls = BN.from(0, 10, 'be');
        let clsCount = 0;

        for (const ch of desc) {
            const pos = BN.from(INPUT_CHARSET.indexOf(ch), 10, 'be');
            assert(pos.toNumber() !== -1, 'Invalid characters in payload');
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
            const index = c.ushr(BN.from(5 * (7 - j), 10, 'be')).and(BN.from(31, 10, 'be'));
            checksum += CHECKSUM_CHARSET[index.toNumber()];
        }
        return checksum;
    }

    static addChecksum(desc) {
        const checksum = this.createChecksum(desc);
        return desc + '#' + checksum;
    }
    static checkChecksum(desc, requireChecksum) {
        const checkSplit = desc.split('#');
        assert(checkSplit.length <= 2, 'Multiple # symbols');
        if (checkSplit.length === 1) {
            assert(!requireChecksum, 'Missing checksum');
        }
        if (checkSplit.length === 2) {
            assert(checkSplit[1].length === 8, `Expected 8 characters checksum, not ${checkSplit[1].length} characters`);
        }
        const checksum = this.createChecksum(checkSplit[0]);
        if (checkSplit.length === 2) {
            assert(checksum === checkSplit[1], `Provided checksum ${checkSplit[1]} does not match computed checksum`);
        }
        return checkSplit[0];
    }
}

/*
 * Expose
 */

module.exports = Descriptor;
