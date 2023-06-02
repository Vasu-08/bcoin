'use strict';

const Descriptor = require('./descriptor');

class WSHDescriptor extends Descriptor {
  constructor(options) {
    super();
    this.name = 'wsh';

    if (options) {
      this.fromOptions(options);
    }
  }

  fromOptions(options) {
    this.subdescriptors = options.subdescriptors;
    this.network = options.network;
    return this;
  }

  static fromOptions(options) {
    return new this().fromOptions(options);
  }

  isSingleType() {
    return true;
  }

  isSolvable() {
    return true;
  }
}

module.exports = WSHDescriptor;
