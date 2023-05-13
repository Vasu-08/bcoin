/* eslint-disable quotes */
/* eslint-disable no-unused-vars */
'use strict';

const assert = require('bsert');
const Descriptor = require('../lib/wallet/descriptor');
describe('Descriptor', function () {
    describe('Checksum', function () {
        it('should validate a descriptor checksum 1', function () {
            const desc = `sh(multi(2,[00000000/111'/222]xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc,xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0))#ggrsrxfy`;
            const check = Descriptor.checkChecksum(desc, false);
            assert.equal(check.length > 0, true);
        });

        it('should validate a descriptor checksum 2', function () {
            const desc = `sh(multi(2,[00000000/111'/222]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0))#tjg09x5t`;
            const check = Descriptor.checkChecksum(desc, false);
            assert.equal(check.length > 0, true);
        });

        it('should validate a descriptor checksum 3', function () {
            const desc = `wpkh([d34db33f/84h/0h/0h]0279be667ef9dcbbac55a06295Ce870b07029Bfcdb2dce28d959f2815b16f81798)#qwlqgth7`;
            const check = Descriptor.checkChecksum(desc, true);
            assert.equal(check.length > 0, true);
        });
        it('should validate a descriptor checksum 4', function () {
            const desc = `addr(mkmZxiEcEd8ZqjQWVZuC6so5dFMKEFpN2j)#02wpgw69`;
            const check = Descriptor.checkChecksum(desc, true);
            assert.equal(check.length > 0, true);
        });

        it('should return a descriptor with checksum for descriptor with no checksum 1', function () {
            const desc = `sh(multi(2,[00000000/111'/222]xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc,xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0))`;
            const expected = Descriptor.addChecksum(desc, false);
            const actual = `sh(multi(2,[00000000/111'/222]xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc,xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0))#ggrsrxfy`;
            assert.equal(expected, actual);
        });

        it('should return a descriptor with checksum for descriptor with no checksum 2', function () {
            const desc = `addr(mkmZxiEcEd8ZqjQWVZuC6so5dFMKEFpN2j)`;
            const expected = Descriptor.addChecksum(desc, false);
            const actual = `addr(mkmZxiEcEd8ZqjQWVZuC6so5dFMKEFpN2j)#02wpgw69`;
            assert.equal(expected, actual);
        });

        it('will error with incorrect checksum ', function () {
            const desc = `sh(multi(2,[00000000/111'/222]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0))#tjq09x4t`;
            let error = null;
            try {
                Descriptor.checkChecksum(desc, true);
            } catch (e) {
                error = e;
            }
            assert.equal(error.message, 'Provided checksum tjq09x4t does not match computed checksum');
        });

        it('will error with incorrect payload', function () {
            const desc = `sh(multi(3,[00000000/111'/222]àxpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0))#tjg09x5t`;
            let error = null;
            try {
                Descriptor.checkChecksum(desc, true);
            } catch (e) {
                error = e;
            }
            assert.equal(error.message, 'Invalid characters in payload');
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
});

