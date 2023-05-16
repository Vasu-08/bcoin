/*!
 * descriptor.js - descriptor object for bcoin
 * Copyright (c) 2015-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */
/* eslint-disable max-len */
/**
 * @TODO Network object
 */
'use strict';
const assert = require('bsert');
// const Network = require('../protocol/network');
const BN = require('bcrypto/lib/bn.js');
const { checkScriptType, stringAfterScriptType, giveExpr, isHex, isCompressed } = require('../utils/stringparsing');
const KeyRing = require('../primitives/keyring');
const { ConstPubkeyProvider, OriginPubkeyProvider, HDPubkeyProvider } = require('./pubkeyprovider');
const HD = require('../hd/hd');
const common = require('../hd/common');
const scriptTypes = require('../script/common').types;
const scriptContext = {
    TOP: 'TOP',
    P2SH: 'P2SH',
    P2WPKH: 'P2WPKH',
    P2WSH: 'P2WSH',
    P2TR: 'P2TR'
};
const DeriveType = {
    NO: 'NO',
    UNHARDENED: 'UNHARDENED',
    HARDENED: 'HARDENED'
};

const StringType = {
    PUBLIC: 'PUBLIC',
    PRIVATE: 'PRIVATE',
    NORMALIZED: 'NORMALIZED'
};

class Descriptor {
    constructor(options, network) {
        this.name = null;
        this.pubkeys = [];
        this.subdescriptors = [];
        if (options)
            this.fromOptions(options, network);
    }
    hasPrivateKeys() {
        for (const key of this.pubkeys) {
            if (key.getPrivatekey() !== null)
                return true;
        }
        return false;
    }
    isRange() {
        for (const key of this.pubkeys) {
            if (key.isRange())
                return true;
        }
        return false;
    }
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
            if (pos++)
                res += ',';
            res += subdesc.getStringHelper(type);
        }
        return res;
    }
    getStringHelper(type) {
        const extra = this.getStringExtra();
        let pos = extra.length === 0 ? 0 : 1;
        let res = this.name + '(' + extra;
        for (const pubkey of this.pubkeys) {
            if (pos++)
                res += ',';
            switch (type) {
                case StringType.PUBLIC:
                    res += pubkey.toString();
                    break;
                case StringType.PRIVATE:
                    res += pubkey.toPrivateString();
                    break;
                case StringType.NORMALIZED:
                    res += pubkey.toNormalizedString();
            }
        }
        const subdesc = this.getStringSubScriptHelper(type);
        if (pos && subdesc.length)
            res += ',';
        res += subdesc + ')';
        return res;
    }
    getString() {
        const res = this.getStringHelper(StringType.PUBLIC);
        return Descriptor.addChecksum(res);
    }
    getPrivateString() {
        const res = this.getStringHelper(StringType.PRIVATE);
        return Descriptor.addChecksum(res);
    }
    getNormalizedString() {
        const res = this.getStringHelper(StringType.NORMALIZED);
        return Descriptor.addChecksum(res);
    }
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
            assert(checksum === checkSplit[1], `Provided checksum ${checkSplit[1]} does not match computed checksum ${checksum}`);
        }
        return checkSplit[0];
    }
    static addChecksum(desc) {
        const split = desc.split('#');
        assert(split.length === 1, 'Descriptor already has a checksum');
        const checksum = this.createChecksum(desc);
        return desc + '#' + checksum;
    }
    parsePubkeyInner(desc, keyIndex, context, network) {
        const keySplit = desc.split('/');
        assert(keySplit.length > 0, 'No key provided');
        const str = keySplit[0];
        const permitUncompressed = context === scriptContext.TOP || context === scriptContext.P2SH;
        if (keySplit.length === 1) {
            if (isHex(str)) {
                const serializedKey = Buffer.from(str, 'hex');
                const ring = KeyRing.fromPublic(serializedKey);
                if (permitUncompressed || isCompressed(ring.publicKey)) {
                    const index = keyIndex.index;
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
                    const index = keyIndex.index;
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
        const index = keyIndex.index;
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
            // console.log('ring', hdkey.xpubkey(network));
            options = {
                index,
                hdkey,
                ring
            };
        }
        options.type = DeriveType.NO;
        const last = keySplit[keySplit.length - 1];
        if (last.length === 1 && last === '*') {
            options.type = DeriveType.UNHARDENED;
            keySplit.pop();
        } else if (last.length === 2 && (last === '*\'' || last === '*h')) {
            options.type = DeriveType.HARDENED;
            keySplit.pop();
        }
        const path = this.parsekeyPath(keySplit.slice(1));
        options.path = path;
        return new HDPubkeyProvider(options);
    }

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
            if (part.length > 10)
                throw new Error('Path index too large.');

            if (!/^\d+$/.test(part))
                throw new Error('Path index is non-numeric.');

            let index = parseInt(part, 10);
            if ((index >>> 0) !== index)
                throw new Error('Path index out of range.');

            if (hardened) {
                index |= common.HARDENED;
                index >>>= 0;
            }
            result.push(index);
            // assert(pathValue >= 0 && pathValue <= 0x7fffffff, `Key path value ${part} is out of range`);
            // pathValue = pathValue + (hardened ? 0x80000000 : 0);
            // path.push(pathValue);
        }
        return result;
    }

    parsePubkey(desc, keyIndex, context, network) {
        const originSplit = desc.split(']');
        assert(originSplit.length <= 2, 'Multiple \']\' characters found for a single pubkey');
        if (originSplit.length === 1) {
            const provider = this.parsePubkeyInner(originSplit[0], keyIndex, context, network);
            return provider;
        }
        assert(originSplit.length && originSplit[0][0] === '[', `Key origin start [ character expected but not found, got ${originSplit[0][0]} instead`);
        originSplit[0] = originSplit[0].slice(1);
        const slashSplit = originSplit[0].split('/');
        assert(slashSplit[0].length === 8, `Fingerprint is not 4 bytes, ${slashSplit[0].length} characters found instead of 8 characters`);
        const fingerprintHex = slashSplit[0];
        assert(isHex(fingerprintHex), `Fingerprint ${fingerprintHex} is not hex`);
        const fingerPrint = parseInt(fingerprintHex, 16);
        const path = this.parsekeyPath(slashSplit.slice(1));
        const originInfo = HD.KeyOriginInfo.fromOptions({ fingerPrint, path });
        const provider = this.parsePubkeyInner(originSplit[1], keyIndex, context, network);
        const options = {
            originInfo,
            provider
        };
        return new OriginPubkeyProvider(options);
    }

    parseScript(desc, keyIndex, context, network) {
        const expr = giveExpr(desc);

        // parsing pk and pkh descriptor
        if (checkScriptType('pk', expr)) {
            desc = stringAfterScriptType('pk', expr);
            const pubkeyprovider = this.parsePubkey(desc, keyIndex, context, network);
            keyIndex.index++;
            const options = {
                pubkeys: [pubkeyprovider]
            };
            return PKDescriptor.fromOptions(options);
        }

        // parsing pkh descriptor
        if ((context === scriptContext.TOP || context === scriptContext.P2SH || context === scriptContext.P2WSH) && checkScriptType('pkh', expr)) {
            desc = stringAfterScriptType('pkh', expr);
            const pubkeyprovider = this.parsePubkey(desc, keyIndex, context, network);
            keyIndex.index++;
            const options = {
                pubkeys: [pubkeyprovider]
            };
            return PKHDescriptor.fromOptions(options);
        }
        assert(!checkScriptType('pkh', expr), 'Can only have pkh() at top level, in sh(), or in wsh()');

        // parsing combo descriptor
        if (context === scriptContext.TOP && checkScriptType('combo', expr)) {
            desc = stringAfterScriptType('combo', expr);
            const pubkeyprovider = this.parsePubkey(desc, keyIndex, context, network);
            keyIndex.index++;
            const options = {
                pubkeys: [pubkeyprovider]
            };
            return ComboDescriptor.fromOptions(options);
        }
        assert(!checkScriptType('combo', expr), 'Can only have combo() at top level');

        // wpkh
        if (context === scriptContext.TOP && checkScriptType('wpkh', expr)) {
            desc = stringAfterScriptType('wpkh', expr);
            const pubkeyprovider = this.parsePubkey(desc, keyIndex, context, network);
            keyIndex.index++;
            const options = {
                pubkeys: [pubkeyprovider]
            };
            return WPKHDescriptor.fromOptions(options);
        }
        assert(!checkScriptType('wpkh', expr), 'Can only have wpkh() at top level or inside sh()');

        // parsing sh descriptor
        if (context === scriptContext.TOP && checkScriptType('sh', expr)) {
            desc = stringAfterScriptType('sh', expr);
            const subdesc = this.parseScript(desc, keyIndex, scriptContext.P2SH, network);
            const options = {
                subdescriptors: [subdesc]
            };
            return SHDescriptor.fromOptions(options);
        }
        assert(!checkScriptType('sh', expr), 'Can only have sh() at top level');

        // parsing wsh descriptor
        if ((context === scriptContext.TOP || context === scriptContext.P2SH) && checkScriptType('wsh', expr)) {
            desc = stringAfterScriptType('wsh', expr);
            const subdesc = this.parseScript(desc, keyIndex, scriptContext.P2WSH, network);
            const options = {
                subdescriptors: [subdesc]
            };
            return WSHDescriptor.fromOptions(options);
        }
        assert(!checkScriptType('wsh', expr), 'Can only have wsh() at top level or inside sh()');

        return null;
    }

    parse(desc, network) {
        const keyIndex = { index: 0 };
        desc = Descriptor.checkChecksum(desc, false);
        return this.parseScript(desc, keyIndex, scriptContext.TOP, network);
    }

    fromString(desc, network) {
        assert(typeof desc === 'string', 'Descriptor must be a string');
        assert(desc.length > 0, 'Descriptor string is empty');
        return this.parse(desc, network);
    }

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
        return scriptTypes.PUBKEY;
    }
    isSolvable() {
        return true;
    }
}

class PKHDescriptor extends Descriptor {
    constructor() {
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
        return scriptTypes.PUBKEYHASH;
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
        return scriptTypes.WITNESSPUBKEYHASH;
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
    /**
     * @TODO getScriptType function here
     */
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
    /**
    * @TODO getScriptType function here
    */
}
/*
 * Expose
 */

module.exports = Descriptor;
