const mongoose = require('mongoose');
const keygen = require('keygen');
const { Schema } = mongoose;
const { SERVICE } = require('../constants.js');

const procedureSchema = new Schema({
  name: {
    type: String,
    required: true
  },
  description: String,
  arguments: {
    type: [{
      name: { type: String, required: true },
      type: { type: String, required: true },
      default: String,
      optional: Boolean,
      description: String
    }]
  },
  returns: {
    type: { type: String },
    description: String
  }
});

procedureSchema.methods.isAvailable = async function (name) {
  if(name && await this.model('Service').find({ 'procedures.name': name }))
    return false;
  return true;
};

const serviceSchema = new Schema({
  identifier: {
    type: String,
    unique: true,
    required: true,
    immutable: true
  },
  name: {
    type: String,
    required: true
  },
  repository: {
    type: {
      provider: {
        type: String,
        default: null
      },
      url: {
        type: String,
        default: null
      }
    }
  },
  meta: {
    description: {
      text: {
        type: String,
        default: null
      },
      url: {
        type: String,
        default: null
      }
    },
    license: {
      type: {
        type: String,
        default: 'MIT'
      },
      url: {
        type: String,
        default: null
      },
      text: {
        type: String,
        default: null
      }
    }
  },
  testing: {
    enabled: {
      type: Boolean,
      default: false
    },
    procedure: {
      type: String,
      default: null
    }
  },
  usage: {
    type: Number,
    default: 0
  },
  status: {
    type: Number,
    default: SERVICE.STATUS.AVAILABLE,
    validate: {
      validator: function (v) {
        return SERVICE.STATUS.AVAILABLE === v || SERVICE.STATUS.UNAVAILABLE === v || SERVICE.STATUS.QUOTA_EXPIRED === v;
      }
    }
  },
  scope: {
    type: Number,
    default: SERVICE.SCOPE.PUBLIC,
    validate: {
      validator: function (v) {
        return SERVICE.SCOPE.PUBLIC === v || SERVICE.SCOPE.PRIVATE === v;
      }
    },
    immutable: true
  },
  apiKeys: {
    type: [String],
    default: [],
  },
  procedures: [procedureSchema]
},
{
  timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' }
});

serviceSchema.static('isAvailable', async function (identifier) {
  if(identifier && await this.model('Service').exists({ identifier }))
    return false;
  return true;
});

serviceSchema.methods.generateAPIKey = function () {
  var key = keygen.url(keygen.medium);
  this.apiKeys.push(key);
  return key;
};

serviceSchema.methods.verifyAPIKey = function (key) {
  if(this.apiKeys.includes(key))
    return true;
  return false;
};

serviceSchema.methods.removeAPIKey = function (key) {
  this.apiKeys.pull(key);
  return true;
};

module.exports = mongoose.model('Service', serviceSchema);