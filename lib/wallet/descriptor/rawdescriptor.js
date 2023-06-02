'use strict';

const Descriptor = require('./descriptor');
const Address = require('../../primitives/address');

class RawDescriptor extends Descriptor {
  constructor(options) {
    super();
    this.name = 'raw';

    if (options) {
      this.fromOptions(options);
    }
  }

  fromOptions(options) {
    this.script = options.script;
    this.network = options.network;
  }

  static fromOptions(options) {
    return new this().fromOptions(options);
  }

  isSingleType() {
    return true;
  }

  getOutputType() {
    const address = Address.fromScript(this.script);
    return address.getType(this.network);
  }
}

module.exports = RawDescriptor;
