const mongoose = require('mongoose');
const crypto = require('crypto');
const { Schema } = mongoose;

const userSchema = new Schema({
  name: String,
  username: {
    type: String,
    unique: true,
    required: true
  },
  password: {
    type: {
      hash: {
        type: String
      },
      salt: {
        type: String
      }
    },
    select: false
  },
  email: {
    type: String,
    unique: true,
    required: true
  },
  services: [
    { type: Schema.Types.ObjectId, ref: 'Service' }
  ]
},
{
  timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' }
});

userSchema.static('isAvailable', async function ({ username, email }) {
  if(username && await this.exists({ username }))
    return false;
  if(email && await this.exists({ email }))
    return false;
  return true;
});

userSchema.methods.setPassword = function (password) {
  // Creating a unique salt for a particular user 
  this.password.salt = crypto.randomBytes(16).toString('hex');
  // Hashing user's salt and password with 1000 iterations, 64 length and sha512 digest 
  this.password.hash = crypto.pbkdf2Sync(password, this.password.salt, 1000, 64, `sha512`).toString(`hex`); 
};

userSchema.methods.validatePassword = function (password) {
  var hash = crypto.pbkdf2Sync(password, this.password.salt, 1000, 64, `sha512`).toString(`hex`);
  return this.password.hash === hash;
}; 

module.exports = mongoose.model('User', userSchema);