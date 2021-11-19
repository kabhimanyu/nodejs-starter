const JwtStrategy = require('passport-jwt').Strategy;
const BearerStrategy = require('passport-http-bearer');
const { ExtractJwt } = require('passport-jwt');
const { jwtSecret } = require('@config/vars');
const LoginSession = require('@models/auth/login.session')
const authProviders = require('@services/authProviders');
const User = require('@models/auth/user.model');

const jwtOptions = {
  secretOrKey: jwtSecret,
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken()
}

const jwtStrategy = new JwtStrategy(jwtOptions, (jwtPayload, done) => {
  LoginSession.findOne({ token: jwtPayload.token.token }, (err, session) => {
    if (err) {
      return done(err, null)
    }
    if (session) {
      return done(null, session)
    } else {
      return done(null, false)
    }
  })
})

const oAuth = (service) => async (token, done) => {
  try {
    const userData = await authProviders[service](token);
    const user = await User.oAuthLogin(userData);
    return done(null, user);
  } catch (err) {
    return done(err);
  }
};

exports.jwtOptions = jwtOptions;
exports.jwt = jwtStrategy;
exports.facebook = new BearerStrategy(oAuth('facebook'));
exports.google = new BearerStrategy(oAuth('google'));
