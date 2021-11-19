const mongoose = require('mongoose');
const httpStatus = require('http-status');
const { omitBy, isNil } = require('lodash');
const bcrypt = require('bcryptjs');
const moment = require('moment-timezone');
const jwt = require('jwt-simple');
const uuidv4 = require('uuid/v4');
const APIError = require('@utils/APIError');
const { env, jwtSecret, jwtExpirationInterval } = require('@config/vars');
const LoginSession = require("@models/auth/login.session")

/**
* User Roles
*/
const roles = ['USER', 'ADMIN'];
const Genders = ['MALE', 'FEMALE', 'OTHER'];
/**
 * User Schema
 * @private
 */
const userSchema = new mongoose.Schema({
  firstName: {
    type: String,
    maxlength: 128,
    index: true,
    trim: true,
  },
  lastName: {
    type: String,
    maxlength: 128,
    index: true,
    trim: true,
  },
  email: {
    type: String,
    trim: true,
    lowercase: true,
  },
  phone: {
    type: String,
    trim: true,
    index: true,
    maxlength: 15,
  },
  dateOfBirth: {
    type: Date,
  },
  gender: {
    type: String,
    enum: Genders
  },
  password: {
    type: String,
    minlength: 6,
    maxlength: 128,
  },
  loginInfo: {
    signinCount: Number,
    failedAttempts: Number,
    lockedAt: Date,
    confirmedAt: Date,
    confirmationToken: String,
    confirmationSentAt: Date
  },
  services: { // Future use social auth
    facebook: String,
    google: String,
  },
  role: {
    type: String,
    enum: roles,
    default: 'USER',
  },
  displayPicture: { 
    type: String
  }

}, {
  timestamps: true,
});

/**
 * Add your
 * - pre-save hooks
 * - validations
 * - virtuals
 */
userSchema.pre('save', async function save(next) {
  try {
    if (!this.isModified('password')) return next();

    const rounds = env === 'test' ? 1 : 10;

    const hash = await bcrypt.hash(this.password, rounds);
    this.password = hash;

    return next();
  } catch (error) {
    return next(error);
  }
});

/**
 * Methods
 */
userSchema.method({
  transform() {
    const transformed = {};
    const fields = ['id', 'firstName', 'lastName', 'phone', 'email', 'dateOfBirth', 'gender', 'displayPicture', 'role', 'createdAt'];

    fields.forEach((field) => {
      transformed[field] = this[field];
    });

    return transformed;
  },

  async token(device, ip) {
    const payload = {
      entity: this,
      firstName: this.firstName,
      lastName: this.lastName,
      role: this.role,
      ipAddress: ip,
      type: 'USER',
      device,
      channel: 'MOBILE'
    };
    const sessionToken = await LoginSession.createSession(payload)
    const token = await jwt.encode(sessionToken, jwtSecret)
    return token
  },

  async passwordMatches(password) { 
    return bcrypt.compareSync(password, this.password);
  },
});

/**
 * Statics
 */
userSchema.statics = {

  roles,

  /**
   * Get user
   *
   * @param {ObjectId} id - The objectId of user.
   * @returns {Promise<User, APIError>}
   */
  async get(id) {
    try {
      let user;

      if (mongoose.Types.ObjectId.isValid(id)) {
        user = await this.findById(id).exec();
      }
      if (user) {
        return user;
      }

      throw new APIError({
        message: 'User does not exist',
        status: httpStatus.NOT_FOUND,
      });
    } catch (error) {
      throw error;
    }
  },

  /**
   * Find user by email and tries to generate a JWT token
   *
   * @param {ObjectId} id - The objectId of user.
   * @returns {Promise<User, APIError>}
   */
  async findAndGenerateToken(options) {
    const { email, phone, password, device, ip, refreshObject } = options;
    if (!email) throw new APIError({ message: 'A phone is required to generate a token' });
    let user;
    if(email){
      user = await this.findOne({ email }).exec();
    } else {
      user = await this.findOne({ phone }).exec();
    }
    const err = {
      status: httpStatus.UNAUTHORIZED,
      isPublic: true,
    };
    if (password && await user.passwordMatches(password)) {
      const accessToken = await user.token(device, ip);
      return { user, accessToken };
    } else if (refreshObject && refreshObject.userEmail === email) {
      if (moment(refreshObject.expires).isBefore()) {
        err.message = 'Invalid refresh token.';
      } else {
        const accessToken = await user.token(device, ip);
        return { user, accessToken };
      }
    } else {
      err.message = 'Incorrect email or refreshToken';
    }
    throw new APIError(err);
  },

  /**
   * List users in descending order of 'createdAt' timestamp.
   *
   * @param {number} skip - Number of users to be skipped.
   * @param {number} limit - Limit number of users to be returned.
   * @returns {Promise<User[]>}
   */
  list({
    page = 1, perPage = 30, name, email, role,
  }) {
    const options = omitBy({ name, email, role }, isNil);

    return this.find(options)
      .sort({ createdAt: -1 })
      .skip(perPage * (page - 1))
      .limit(perPage)
      .exec();
  },

  /**
   * Return new validation error
   * if error is a mongoose duplicate key error
   *
   * @param {Error} error
   * @returns {Error|APIError}
   */
  checkDuplicateEmail(error) {
    if (error.name === 'MongoError' && error.code === 11000) {
      return new APIError({
        message: 'Validation Error',
        errors: [{
          field: 'email',
          location: 'body',
          messages: ['"email" already exists'],
        }],
        status: httpStatus.CONFLICT,
        isPublic: true,
        stack: error.stack,
      });
    }
    return error;
  },

  async oAuthLogin({
    service, id, email, name, picture,
  }) {
    const user = await this.findOne({ $or: [{ [`services.${service}`]: id }, { email }] });
    if (user) {
      user.services[service] = id;
      if (!user.name) user.name = name;
      if (!user.picture) user.picture = picture;
      return user.save();
    }
    const password = uuidv4();
    return this.create({
      services: { [service]: id }, email, password, name, picture,
    });
  },
};

/**
 * @typedef User
 */
module.exports = mongoose.model('User', userSchema);