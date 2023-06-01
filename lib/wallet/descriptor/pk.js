'use strict';

const Descriptor = require('./descriptor');
const {outputTypes} = require('./common');

class PKDescriptor extends Descriptor {
  constructor() {
    super();
    this.name = 'pk';
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
    return outputTypes.PUBKEY;
  }

  isSolvable() {
    return true;
  }
}

module.exports = PKDescriptor;
