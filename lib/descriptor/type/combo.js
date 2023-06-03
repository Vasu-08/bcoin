'use strict';

const Descriptor = require('../descriptor');

class ComboDescriptor extends Descriptor {
  constructor(options) {
    super();
    this.name = 'combo';

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
    return false;
  }

  isSolvable() {
    return true;
  }
}

module.exports = ComboDescriptor;
