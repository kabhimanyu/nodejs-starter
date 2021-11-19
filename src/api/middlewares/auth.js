const httpStatus = require('http-status');
const passport = require('passport');
const User = require('@models/auth/user.model');
const APIError = require('@utils/APIError');

const ADMIN = 'admin';
const LOGGED_USER = '_loggedUser';

const loadUser = async (session) =>{
  try{
    let user;
    if(session && session.type && session.type === 'USER'){
      user = await User.findOne({_id : session.entity})
    }
    return user
  }catch(error){
    throw error
  }
}

const handleJWT = (req, res, next, roles) => async (err, session, info) => {
  const error = err || info;
  const logIn = Promise.promisify(req.logIn);

  if (!session.isActive || session.logoutTime <= new Date()) {
    return next(new APIError({
      message: 'SESSION EXPIRED',
      status: httpStatus.UNAUTHORIZED,
    }));
  }

  const apiError = new APIError({
    message: error ? error.message : 'Unauthorized',
    status: httpStatus.UNAUTHORIZED,
    stack: error ? error.stack : undefined,
  });

  try {
    if (error || !session) throw error;
    await logIn(session, { session: false });
  } catch (e) {
    return next(apiError);
  }

  if (roles === LOGGED_USER) {
    if (session.role !== 'admin' && req.params.userId !== session.entity.toString()) {
      apiError.status = httpStatus.FORBIDDEN;
      apiError.message = 'Forbidden';
      return next(apiError);
    }
  } else if (!roles.includes(session.role)) {
    apiError.status = httpStatus.FORBIDDEN;
    apiError.message = 'Forbidden';
    return next(apiError);
  } else if (err || !user) {
    return next(apiError);
  }

  req.session = session;
  req.user = await loadUser(session)
  return next();
};

exports.ADMIN = ADMIN;
exports.LOGGED_USER = LOGGED_USER;

exports.authorize = (roles = User.roles) => (req, res, next) => passport.authenticate(
  'jwt', { session: false },
  handleJWT(req, res, next, roles),
)(req, res, next);

exports.oAuth = (service) => passport.authenticate(service, { session: false });
