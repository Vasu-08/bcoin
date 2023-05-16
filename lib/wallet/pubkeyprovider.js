/* eslint-disable max-len */
/* eslint-disable no-unused-vars */
'use strict';

// const HD = require('../hd');
const common = require('../hd/common');
// const hash160 = require('bcrypto/lib/hash160');
/**
 * Base class for public key objects in descriptors
 */

class PubkeyProvider {
    /**
     * create a new PubkeyProvider
     * @constructor
     */

    constructor(options) {
        if (options)
            this.fromOptions(options);
    }
    fromOptions(options) {
        if (options.ring)
            this.index = options.index;
        if (options.ring)
            this.ring = options.ring;
    }
    isRange() {
        return false;
    }
    getSize() {
        return 0;
    }
    toString() {
        return null;
    }
    toPrivateString() {
        return null;
    }
    getPrivatekey() {
        const privKey = this.ring.getPrivateKey('base58', 'main');
        return privKey;
    }
}

class ConstPubkeyProvider extends PubkeyProvider {
    constructor(options) {
        super(options);
    }
    getPubKey() {
        return this.ring.publicKey;
    }
    isRange() {
        return false;
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
        const str = this.ring.getPrivateKey('base58', 'main');
        return str;
    }
    toNormalizedString() {
        const str = this.ring.getPublicKey('hex');
        return str;
    }
    // getPubkey() {
    //     return this.ring.getPubkey('base58');
    // }
}
const DeriveType = {
    NO: 'NO',
    UNHARDENED: 'UNHARDENED',
    HARDENED: 'HARDENED'
};

class HDPubkeyProvider extends PubkeyProvider {
    constructor(options) {
        super(options);
        this.hdkey = options.hdkey;
        this.path = options.path;
        this.type = options.type;
    }
    isRange() {
        if (this.type === DeriveType.NO) {
            return false;
        }
        return true;
    }
    isHardened() {
        if (this.type === DeriveType.HARDENED) {
            return true;
        }
        for (let i = 0; i < this.path.length; i++) {
            if (this.path[i] & common.HARDENED) {
                return true;
            }
        }
        return false;
    }
    getSize() {
        return 33;
    }
    toString() {
        let str = this.hdkey.xpubkey('main') + format(this.path);
        if (this.isRange()) {
            str += '/*';
            if (this.type === DeriveType.HARDENED) {
                str += '\'';
            }
        }
        return str;
    }
    toPrivateString() {
        if (this.ring.privateKey) {
            let str = this.hdkey.xprivkey('main') + format(this.path);
            if (this.isRange()) {
                str += '/*';
                if (this.type === DeriveType.HARDENED) {
                    str += '\'';
                }
            }
            return str;
        }
        return null;
    }
    // Derives the last xprv
    getLastxpriv() {
        if (!this.getPrivatekey())
            return null;
        let lastHardened;
        let key = this.hdkey;
        for (const index of this.path) {
            key = key.derive(index);
            if (index & common.HARDENED) {
                lastHardened = key;
            }
        }
        return lastHardened;
    }
    // toNormalizedString() {
    //     if (this.type === DeriveType.HARDENED) {
    //         return this.toString();
    //     }
    //     // step backwards until we find a non-hardened path component
    //     let pos = this.path.length - 1;
    //     while (pos >= 0) {
    //         if (this.path[pos] & common.HARDENED)
    //             break;
    //         pos--;
    //     }
    //     if (pos === -1) {
    //         return this.toString();
    //     }
    //     const originPath = this.path.slice(0, pos + 1);
    //     const endPath = this.path.slice(pos + 1);
    //     const fp = hash160.digest(this.hdkey.publicKey);
    //     const fingerPrint = fp.readUInt32BE(0, true);
    //     const originInfo = HD.KeyOriginInfo.fromOptions({
    //         path: originPath,
    //         fingerPrint
    //     });
    //     const lastxpriv = this.getLastxpriv();
    //     const xpub = lastxpriv.toPublic();
    //     const formattedInfo = originInfo.format();
    //     const originStr = `${formattedInfo.fingerPrint}${formattedInfo.path}`;
    //     const result = `[${originStr}]${xpub.toBase58('main')}${format(endPath)}}`;
    //     return result;
    // }
    // getPubkey(pos) {
    //     let parentInfo;
    //     let derivedKey = this.hdkey;
    //     if (!this.isHardened()) {
    //         for (const index of this.path) {
    //             derivedKey = derivedKey.derive(index, false);
    //         }
    //     }
    //     // let key = this.hdkey;
    //     // for (let i = 0; i < this.path.length; i++) {
    //     //     key = key.derive(this.path[i], false);
    //     // }
    //     // return key.publicKey;
    // }
}

class OriginPubkeyProvider extends PubkeyProvider {
    constructor(options) {
        super(options);
        this.originInfo = options.originInfo;
        this.provider = options.provider;
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
    /**
     * @TODO getPubkey, toPrivateString, toNormalizedString
     */
}
/**
 * Helpers
 */

function format(path) {
    let formattedpath = '';
    for (const p of path) {
        const hardened = (p & common.HARDENED) ? '\'' : '';
        formattedpath += `/${p & 0x7fffffff}${hardened}`;
    }
    return formattedpath;
}

module.exports = {
    PubkeyProvider,
    ConstPubkeyProvider,
    HDPubkeyProvider,
    OriginPubkeyProvider
};
