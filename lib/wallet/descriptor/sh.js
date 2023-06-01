'use strict';
const Descriptor = require('./descriptor');

class SHDescriptor extends Descriptor {
  constructor() {
    super();
    this.name = 'sh';
  }

  fromOptions(options) {
    this.subdescriptors = options.subdescriptors;
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

module.exports = SHDescriptor;
