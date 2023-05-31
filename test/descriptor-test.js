/* eslint-disable quotes */
/* eslint-disable no-unused-vars */
'use strict';

const assert = require('bsert');
const Descriptor = require('../lib/wallet/descriptor/descriptor');
const { isHex, isCompressed } = require('../lib/wallet/descriptor/common');
const descriptors = [
    `sh(multi(2,[00000000/111'/222]xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc,xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0))#ggrsrxfy`,
    `sh(multi(2,[00000000/111'/222]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0))#tjg09x5t`,
    `wpkh([d34db33f/84h/0h/0h]0279be667ef9dcbbac55a06295Ce870b07029Bfcdb2dce28d959f2815b16f81798)#qwlqgth7`,
    `addr(mkmZxiEcEd8ZqjQWVZuC6so5dFMKEFpN2j)#02wpgw69`
];
describe('Descriptor', function () {
    describe('Checksum', function () {
        for (const desc of descriptors) {
            it('should correctly validate a descriptor with checksum', function () {
                const check = Descriptor.checkChecksum(desc, true);
                assert.equal(check.length > 0, true);
            });
        }

        it('will error with incorrect checksum ', function () {
            const desc = `sh(multi(2,[00000000/111'/222]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0))#tjq09x4t`;
            const expectedChecksum = Descriptor.createChecksum(desc.split('#')[0]);
            const actualChecksum = desc.split('#')[1];
            let error = null;
            try {
                Descriptor.checkChecksum(desc, true);
            } catch (e) {
                error = e;
            }
            assert.equal(error.message, `Expected checksum ${expectedChecksum}, found ${actualChecksum}`);
        });

        it('will error with incorrect payload', function () {
            const desc = `sh(multi(3,[00000000/111'/222]àxpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0))#tjg09x5t`;
            let error = null;
            try {
                Descriptor.checkChecksum(desc, true);
            } catch (e) {
                error = e;
            }
            assert.equal(error.message, 'Character à invalid');
        });

        it('will error with a descriptor with missing checksum when require checksum is true', function () {
            const desc = `sh(multi(2,[00000000/111'/222]xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc,xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0))`;
            let error = null;
            try {
                Descriptor.checkChecksum(desc, true);
            } catch (e) {
                error = e;
            }
            assert.equal(error.message, 'Missing checksum');
        });

        it('will error with too long checksum', function () {
            const desc = `sh(multi(2,[00000000/111'/222]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0))#tjg09x5tq`;
            let error = null;
            try {
                Descriptor.checkChecksum(desc, false);
            } catch (e) {
                error = e;
            }
            assert.equal(error.message, 'Expected 8 characters checksum, not 9 characters');
        });

        it('will error with too short checksum', function () {
            const desc = `sh(multi(2,[00000000/111'/222]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0))#tjg09x5`;
            let error = null;
            try {
                Descriptor.checkChecksum(desc, false);
            } catch (e) {
                error = e;
            }
            assert.equal(error.message, 'Expected 8 characters checksum, not 7 characters');
        });

        it('will error with too many # symbols', function () {
            const desc = `sh(multi(2,[00000000/111'/222]xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc,xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0))##ggssrxfy`;
            let error = null;
            try {
                Descriptor.checkChecksum(desc, false);
            } catch (e) {
                error = e;
            }
            assert.equal(error.message, 'Multiple # symbols');
        });
    });

    describe('Helpers', () => {
        it('should validate a hex string', () => {
            const str = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
            const check = isHex(str);
            assert.equal(check, true);
        });
        it('will error an invalid hex string', () => {
            const str = `xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc,xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0`;
            const check = isHex(str);
            assert.equal(check, false);
        });
        it('correctly check whether compressed key or not 1', () => {
            const key = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
            const serialized = Buffer.from(key, 'hex');
            const check = isCompressed(serialized);
            assert.equal(check, true);
        });
        it('correctly check whether compressed key or not 2', () => {
            const key = '04317b3fd39dd25719563f46534e6d9779695ef3b5b8886c2293fc79e0c5c3283635c386d467ce6035c9862330f33dead77527b77474012410b3a26f1e7ed33447';
            const serialized = Buffer.from(key, 'hex');
            const check = isCompressed(serialized);
            assert.equal(check, false);
        });
    });

    describe('Parsing', () => {
        it('Should parse a PK descriptor from compressed public', () => {
            const desc = `pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)`;
            const descriptor = Descriptor.fromString(desc, 'main');
            assert(descriptor.getString(), desc);
        });

        it('Should parse a PK descriptor from HD private key', () => {
            const desc = `pk(xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc)`;
            const descriptor = Descriptor.fromString(desc, 'main');
            assert.equal(typeof descriptor, 'object');
        });

        it('will error for short long fingerprint', () => {
            const desc = `pk([aaaaaaa]xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/2147483647'/0)`;
            let error = null;
            try {
                Descriptor.fromString(desc, 'main');
            } catch (e) {
                error = e;
            }
            assert.equal(error.message, `Expected 8 characters fingerprint, found 7 instead`);
        });

        it('will error for non-hex fingerprint', () => {
            const desc = `pk([aaagaaaa]xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/2147483647'/0)`;
            let error = null;
            try {
                Descriptor.fromString(desc, 'main');
            } catch (e) {
                error = e;
            }
            assert.equal(error.message, 'Fingerprint aaagaaaa is not hex');
        });

        it('will parse a sh() descriptor', () => {
            const desc = `sh(wsh(pkh(02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13)))#2wtr0ej5`;
            const descriptor = Descriptor.fromString(desc, 'main');
            assert.equal(descriptor.getString(), desc);
            assert.equal(descriptor.isRange(), false);
            assert.equal(descriptor.isSolvable(), true);
            assert.equal(descriptor.hasPrivateKeys(), false);
        });

        it('will parse a pkh() descriptor', () => {
            const desc = `pkh([d34db33f/44'/0'/0']xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/1/*)#ml40v0wf`;
            const descriptor = Descriptor.fromString(desc, 'main');
            console.log(descriptor);
            assert.equal(descriptor.getString(), desc);
        });
    });
});
