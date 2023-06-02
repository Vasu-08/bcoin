'use strict';

const Descriptor = require('./descriptor');
const {outputTypes} = require('./common');

class PKDescriptor extends Descriptor {
  constructor(options) {
    super();
    this.name = 'pk';

    if (options) {
      this.fromOptions(options);
    }
  }

  fromOptions(options) {
    this.pubkeys = options.pubkeys;
    this.network = options.network;
    return this;
  }

  static fromOptions(options) {
    return new this().fromOptions(options);
  }

  isSingleType() {
    return true;
  }

  getOutputType() {
    return outputTypes.PUBKEY;
  }

  isSolvable() {
    return true;
  }
}

module.exports = PKDescriptor;
