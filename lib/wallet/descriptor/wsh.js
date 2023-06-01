'use strict';

const Descriptor = require('./descriptor');

class WSHDescriptor extends Descriptor {
  constructor() {
    super();
    this.name = 'wsh';
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

module.exports = WSHDescriptor;
