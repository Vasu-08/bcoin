'use strict';

const Descriptor = require('./descriptor');

class MultisigDescriptor extends Descriptor {
  constructor(options) {
    super();
    this.name = 'multi';
    this.sorted = false;

    if (options) {
      this.fromOptions(options);
    }
  }

  fromOptions(options) {
    this.pubkeys = options.pubkeys;
    this.threshold = options.threshold;
    this.sorted = options.sorted;
    this.network = options.network;
    return this;
  }

  static fromOptions(options) {
    return new this().fromOptions(options);
  }

  isSingleType() {
    return true;
  }

  toStringExtra() {
    return this.threshold.toString();
  }
}

module.exports = MultisigDescriptor;
