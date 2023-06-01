'use strict';
const Descriptor = require('./descriptor');
const outputTypes = require('./common');

class WPKHDescriptor extends Descriptor {
  constructor() {
    super();
    this.name = 'wpkh';
  }

  fromOptions(options) {
    this.pubkeys = options.pubkeys;
    return this;
  }

  static fromOptions(options) {
    return new this().fromOptions(options);
  }

  isSingleType() {
    return true;
  }

  getScriptType() {
    return outputTypes.WITNESSPUBKEYHASH;
  }

  isSolvable() {
    return true;
  }
}

module.exports = WPKHDescriptor;
