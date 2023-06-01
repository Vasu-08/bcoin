'use strict';

const Descriptor = require('./descriptor');

class ComboDescriptor extends Descriptor {
    constructor() {
        super();
        this.name = 'combo';
    }

    fromOptions(options) {
        this.pubkeys = options.pubkeys;
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
