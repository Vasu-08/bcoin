/* eslint-disable quotes */
/* eslint-disable no-unused-vars */
'use strict';

const assert = require('bsert');
const DescriptorParser = require('../lib/wallet/descriptor/parser');
const {createChecksum} = require('../lib/wallet/descriptor/common');

const testcases = [
  {
    "input": `addr(2NBFNJTktNa7GZusGbDbGKRZTxdK9VVez3n)`,
    "descriptor": "addr(2NBFNJTktNa7GZusGbDbGKRZTxdK9VVez3n)#l98qe9z6",
    "checksum": "l98qe9z6",
    "isrange": false,
    "issolvable": false,
    "hasprivatekeys": false,
    "network": "testnet"
  },
  {
    "input": `pkh(xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/1aa)`,
    "network": "main",
    "error": "Path index is non-numeric"
  },
  {
    "input": `multi(3,L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1,5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss)`,
    "network": "main",
    "error": "Threshold greater than number of keys (3 > 2)"
  },
  {
    "input": `multi(3,03669b8afcec803a0d323e9a17f3ea8e68e8abe5a278020a929adbec52421adbd0,0260b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600,0362a74e399c39ed5593852a30147f2959b56bb827dfa3e60e464b02ccf87dc5e8,0261345b53de74a4d721ef877c255429961b7e43714171ac06168d7e08c542a8b8)`,
    "network": "main",
    "error": `At most 3 pubkeys allowed in bare multisig not 4`
  },
  {
    "input": `multi(0,L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1,5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss)`,
    "network": "main",
    "error": `Multisig threshold '0' is not valid`
  },
  {
    "input": `multi(a,L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1,5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss)`,
    "network": "main",
    "error": `Multisig threshold 'a' is not valid`
  },
  {
    "input":`sh(multi(16,KzoAz5CanayRKex3fSLQ2BwJpN7U52gZvxMyk78nDMHuqrUxuSJy,KwGNz6YCCQtYvFzMtrC6D3tKTKdBBboMrLTsjr2NYVBwapCkn7Mr,KxogYhiNfwxuswvXV66eFyKcCpm7dZ7TqHVqujHAVUjJxyivxQ9X,L2BUNduTSyZwZjwNHynQTF14mv2uz2NRq5n5sYWTb4FkkmqgEE9f,L1okJGHGn1kFjdXHKxXjwVVtmCMR2JA5QsbKCSpSb7ReQjezKeoD,KxDCNSST75HFPaW5QKpzHtAyaCQC7p9Vo3FYfi2u4dXD1vgMiboK,L5edQjFtnkcf5UWURn6UuuoFrabgDQUHdheKCziwN42aLwS3KizU,KzF8UWFcEC7BYTq8Go1xVimMkDmyNYVmXV5PV7RuDicvAocoPB8i,L3nHUboKG2w4VSJ5jYZ5CBM97oeK6YuKvfZxrefdShECcjEYKMWZ,KyjHo36dWkYhimKmVVmQTq3gERv3pnqA4xFCpvUgbGDJad7eS8WE,KwsfyHKRUTZPQtysN7M3tZ4GXTnuov5XRgjdF2XCG8faAPmFruRF,KzCUbGhN9LJhdeFfL9zQgTJMjqxdBKEekRGZX24hXdgCNCijkkap,KzgpMBwwsDLwkaC5UrmBgCYaBD2WgZ7PBoGYXR8KT7gCA9UTN5a3,KyBXTPy4T7YG4q9tcAM3LkvfRpD1ybHMvcJ2ehaWXaSqeGUxEdkP,KzJDe9iwJRPtKP2F2AoN6zBgzS7uiuAwhWCfGdNeYJ3PC1HNJ8M8,L1xbHrxynrqLKkoYc4qtoQPx6uy5qYXR5ZDYVYBSRmCV5piU3JG9))`,
    "network": "main",
    "error": "P2SH script is too large (547 > 520)"
  },
  {
    "input":`pkh([deadbeef]/1/2'/3/4']L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1)`,
    "network": "main",
    "error": "Multiple ] characters found for a single pubkey"
  },
  {
    "input":`pkh(deadbeef/1/2'/3/4']03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)`,
    "network": "main",
    "error": "Key origin start expected '[', found d instead"
  },
  {
    "input": `sh(wsh(sortedmulti(2,[e7dd1c50/48'/1'/40'/1']tpubDFh3VaUEs71ZMcVBmscSSnP4f4r6TvnLssu8yXvpj3uMfAehciMYTrgbfu4KCxXb7oSaz4kriuWRZtQVhZR2oA9toob6aELnsYLN94fXQLF/<0;1>/*,[e7dd1c50/48'/1'/20'/1']tpubDFPemvLnpMqE1BPuturDUh46KxsR8wGSQrA6HofYE7fqxpMAKCcoYWHGA46B6zKY4xcQAc1vLFTcqQ9BvsbHZ4UhzqqF5nUeeNBjNivHxPT/<0;1>/*,[aedb3d12/48'/1'/0'/1']tpubDEbuxto5Kftus28NyPddiEev2yUhzZGpkpQdCK732KBge5FJDhaMdhG1iVw3rMJ2qvABkaLR9HxobkeFkmQZ4RqQgN1KJadDjPn9ANBLo8V/<0;1>/*)))#exzcvs8g`,
    "network": "testnet",
    "error": "Path index is non-numeric"
  },
  {
    "input": `sh(wpkh(5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss))`,
    "network": "main",
    "error": "Uncompressed keys are not allowed"
  },
  {
    "input": `wsh(pk(04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235))`,
    "network": "main",
    "error": "Uncompressed keys are not allowed"
  },
  {
    "input": `wpkh(04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235)`,
    "network": "main",
    "error": "Uncompressed keys are not allowed"
  },
  {
    "input":"addr(asdf)",
    "network": "main",
    "error": "Address is not valid"
  },
  {
    "input":"sh(combo(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd))",
    "network": "main",
    "error": "Can only have combo() at top level"
  },
  {
    "input": `wsh(wpkh(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd))`,
    "network": "main",
    "error": "Can only have wpkh() at top level or inside sh()"
  },
  {
    "input": `wsh(wsh(pk(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)))`,
    "network": "main",
    "error": "Can only have wsh() at top level or inside sh()"
  },
  {
    "input": `sh(sh(pk(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)))`,
    "network": "main",
    "error": "Can only have sh() at top level"
  },
  {
    "input": `wsh(sh(pk(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)))`,
    "network": "main",
    "error": "Can only have sh() at top level"
  },
  {
    "input": `wsh(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)`,
    "network": "main",
    "error": "A function is needed within P2WSH"
  },
  {
    "input":`sh(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)`,
    "network": "main",
    "error": "A function is needed within P2SH"
  },
  {
    "input": `pkh([d34db33f/44'/0'/0']tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/1/*)`,
    "descriptor": "pkh([d34db33f/44'/0'/0']tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/1/*)#j8kcuq32",
    "checksum": "j8kcuq32",
    "isrange": true,
    "issolvable": true,
    "hasprivatekeys": false,
    "network": "testnet"
  },
  {
    "input": `pkh(tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/1'/2)`,
    "descriptor": "pkh(tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/1'/2)#hvxe7cts",
    "checksum": "hvxe7cts",
    "isrange": false,
    "issolvable": true,
    "hasprivatekeys": false,
    "network": "testnet"
  },
  {
    "input": `pk(tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B)`,
    "descriptor": "pk(tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B)#a63el85t",
    "checksum": "a63el85t",
    "isrange": false,
    "issolvable": true,
    "hasprivatekeys": false,
    "network": "testnet"
  },
  {
    "input": `sh(wsh(multi(1,03f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa8,03499fdf9e895e719cfd64e67f07d38e3226aa7b63678949e6e49b241a60e823e4,02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e)))`,
    "descriptor": "sh(wsh(multi(1,03f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa8,03499fdf9e895e719cfd64e67f07d38e3226aa7b63678949e6e49b241a60e823e4,02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e)))#ks05yr6p",
    "checksum": "ks05yr6p",
    "isrange": false,
    "issolvable": true,
    "hasprivatekeys": false,
    "network": "main"
  },
  {
    "input": `wsh(multi(2,03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7,03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb,03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a))`,
    "descriptor": "wsh(multi(2,03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7,03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb,03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a))#en3tu306",
    "checksum": "en3tu306",
    "isrange": false,
    "issolvable": true,
    "hasprivatekeys": false,
    "network": "main"
  },
  {
    "input": `sh(multi(2,022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01,03acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe))`,
    "descriptor": "sh(multi(2,022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01,03acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe))#y9zthqta",
    "checksum": "y9zthqta",
    "isrange": false,
    "issolvable": true,
    "hasprivatekeys": false,
    "network": "main"
  },
  {
    "input": `multi(1,022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4,025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc)`,
    "descriptor": "multi(1,022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4,025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc)#hzhjw406",
    "checksum": "hzhjw406",
    "isrange": false,
    "issolvable": true,
    "hasprivatekeys": false,
    "network": "main"
  },
  {
    "input": "sh(wsh(pkh(02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13)))",
    "descriptor": "sh(wsh(pkh(02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13)))#2wtr0ej5",
    "checksum": "2wtr0ej5",
    "isrange": false,
    "issolvable": true,
    "hasprivatekeys": false,
    "network": "main"
  },
  {
    "input": `combo(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)`,
    "descriptor": `combo(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)#lq9sf04s`,
    "checksum": "lq9sf04s",
    "isrange": false,
    "issolvable": true,
    "hasprivatekeys": false,
    "network": "main"
  },
  {
    "input": `wsh(multi(1,tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/1/0/*,tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/0/0/*))`,
    "descriptor": `wsh(multi(1,tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/1/0/*,tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/0/0/*))#8srnyrlv`,
    "checksum": "8srnyrlv",
    "isrange": true,
    "issolvable": true,
    "hasprivatekeys": false,
    "network": "testnet"
  },
  {
    "input":`pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)`,
    "descriptor": `pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)#gn28ywm7`,
    "checksum": "gn28ywm7",
    "isrange": false,
    "issolvable": true,
    "hasprivatekeys": false,
    "network": "main"
  },
  {
    "input": `multi(1,03f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa8,03499fdf9e895e719cfd64e67f07d38e3226aa7b63678949e6e49b241a60e823e4,02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e)`,
    "descriptor": `multi(1,03f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa8,03499fdf9e895e719cfd64e67f07d38e3226aa7b63678949e6e49b241a60e823e4,02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e)#3znta99r`,
    "checksum": "3znta99r",
    "isrange": false,
    "issolvable": true,
    "hasprivatekeys": false,
    "network": "main"
  },
  {
    "input": `wpkh([d34db33f/84h/0h/0h]0279be667ef9dcbbac55a06295Ce870b07029Bfcdb2dce28d959f2815b16f81798)#qwlqgth7`,
    "descriptor": `wpkh([d34db33f/84'/0'/0']0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)#n9g43y4k`,
    "checksum": "qwlqgth7",
    "isrange": false,
    "issolvable": true,
    "hasprivatekeys": false,
    "network": "main"
  },
  {
    "input": `pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)`,
    "descriptor": "pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)#8fhd9pwu",
    "checksum": "8fhd9pwu",
    "isrange": false,
    "issolvable": true,
    "hasprivatekeys": false,
    "network": "main"
  },
  {
    "input": `wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)`,
    "descriptor": `wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)#8zl0zxma`,
    "checksum": "8zl0zxma",
    "isrange": false,
    "issolvable": true,
    "hasprivatekeys": false,
    "network": "main"
  },
  {
    "input":`sh(wpkh(03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556))`,
    "descriptor": "sh(wpkh(03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556))#qkrrc7je",
    "checksum": "qkrrc7je",
    "isrange": false,
    "issolvable": true,
    "hasprivatekeys": false,
    "network": "main"
  },
  {
    "input": `pkh(xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/2147483648)`,
    "network": 'main',
    "error" : `Key path value 2147483648 is out of range`
  },
  {
    "input": `sh(multi(2,[00000000/111'/222]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0))#tjq09x4t`,
    "network": 'main',
    "error" : `Expected checksum tjg09x5t, found tjq09x4t`
  },
  {
    "input": `sh(multi(3,[00000000/111'/222]àxpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0))#tjg09x5t`,
    "network": 'main',
    "error" : `Invalid character à at position 30`
  },
  {
    "input": `sh(multi(2,[00000000/111'/222]xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc,xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0))`,
    "network": 'main',
    "requirechecksum": true,
    "error" : `Missing checksum`
  },
  {
    "input": `sh(multi(2,[00000000/111'/222]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0))#tjg09x5tq`,
    "network": 'main',
    "error" : `Expected 8 characters checksum, not 9 characters`
  },
  {
    "input": `sh(multi(2,[00000000/111'/222]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0))#tjg09x5`,
    "network": 'main',
    "error" : `Expected 8 characters checksum, not 7 characters`
  },
  {
    "input": `sh(multi(2,[00000000/111'/222]xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc,xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0))##ggssrxfy`,
    "network": 'main',
    "error" : `Multiple # symbols`
  }
];

describe('Descriptor Parsing', () => {
  for (const testcase of testcases) {
    const {input, error, network, requirechecksum} = testcase;
    const require = requirechecksum || false;
    it('Parse descriptor string', () => {
      try {
        const {descriptor, isrange, issolvable, hasprivatekeys, checksum} = testcase;
        const desc = DescriptorParser.fromString(input, network, require);
        assert.strictEqual(createChecksum(input.split('#')[0]), checksum);
        assert.strictEqual(desc.isRange(), isrange);
        assert.strictEqual(desc.isSolvable(), issolvable);
        assert.strictEqual(desc.hasPrivateKeys(), hasprivatekeys);
        assert.strictEqual(desc.toString(), descriptor);
      } catch (e) {
        assert.strictEqual(e.message, error);
      }
    });
  }
});
