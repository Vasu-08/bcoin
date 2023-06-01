'use strict';
const Descriptor = require('./descriptor');
const {outputTypes} = require('./common');

class PKHDescriptor extends Descriptor {
  constructor() {
    super();
    this.name = 'pkh';
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
    return outputTypes.PUBKEYHASH;
  }

  isSolvable() {
    return true;
  }
}

module.exports = PKHDescriptor;
