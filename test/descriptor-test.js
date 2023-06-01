/* eslint-disable quotes */
/* eslint-disable no-unused-vars */
'use strict';

const assert = require('bsert');
const DescriptorParser = require('../lib/wallet/descriptor/parser');

const checkSumTestCases = [
  {
    desc: `wpkh([d34db33f/84h/0h/0h]0279be667ef9dcbbac55a06295Ce870b07029Bfcdb2dce28d959f2815b16f81798)#qwlqgth7`,
    network: 'main',
    requireChecksum: false,
    descriptorString: `wpkh([d34db33f/84'/0'/0']0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)#n9g43y4k`,
    checksum: 'qwlqgth7',
    isRange: false,
    isSolvable: true,
    hasPrivateKeys: false
  },
  {
    desc: `sh(multi(2,[00000000/111'/222]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0))#tjq09x4t`,
    expectedChecksum: `tjg09x5t`,
    expectedError: `Expected checksum tjg09x5t, found tjq09x4t`,
    network: 'main'
  },
  {
    desc: `sh(multi(3,[00000000/111'/222]àxpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0))#tjg09x5t`,
    expectedError: `Character à invalid`,
    network: 'main'
  },
  {
    desc: `sh(multi(2,[00000000/111'/222]xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc,xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0))`,
    requireChecksum: true,
    expectedError: `Missing checksum`,
    network: 'main'
  },
  {
    desc: `sh(multi(2,[00000000/111'/222]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0))#tjg09x5tq`,
    expectedError: `Expected 8 characters checksum, not 9 characters`,
    network: 'main'
  },
  {
    desc: `sh(multi(2,[00000000/111'/222]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0))#tjg09x5`,
    expectedError: 'Expected 8 characters checksum, not 7 characters',
    network: 'main'
  },
  {
    desc: `sh(multi(2,[00000000/111'/222]xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc,xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0))##ggssrxfy`,
    expectedError: 'Multiple # symbols',
    network: 'main'
  }
];

describe('Descriptor Parsing', () => {
  for (const descriptor of checkSumTestCases) {
    const {desc, expectedError, requireChecksum, network} = descriptor;
    const require = requireChecksum || false;
    it('Parse descriptor string', () => {
      try {
        const {isRange, isSolvable, hasPrivateKeys, descriptorString} =
          descriptor;
        const parsedDescriptor = DescriptorParser.fromString(
          desc,
          network,
          require
        );
        assert.strictEqual(parsedDescriptor.isRange(), isRange);
        assert.strictEqual(parsedDescriptor.isSolvable(), isSolvable);
        assert.strictEqual(parsedDescriptor.hasPrivateKeys(), hasPrivateKeys);
        assert.strictEqual(parsedDescriptor.getString(), descriptorString);
      } catch (e) {
        assert.strictEqual(e.message, expectedError);
      }
    });
  }
});
