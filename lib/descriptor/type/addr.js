'use strict';

const Descriptor = require('../descriptor');

class AddressDescriptor extends Descriptor {
  constructor(options) {
    super();
    this.name = 'addr';

    if (options) {
      this.fromOptions(options);
    }
  }

  fromOptions(options) {
    this.address = options.address;
    this.network = options.network;
    return this;
  }

  static fromOptions(options) {
    return new this().fromOptions(options);
  }

  isSingleType() {
    return true;
  }

  toPrivateString() {
    return null;
  }

  toStringExtra() {
    return this.address.toString(this.network);
  }

  getOutputType() {
    return this.address.getType();
  }

  isSolvable() {
    return false;
  }
}

module.exports = AddressDescriptor;
