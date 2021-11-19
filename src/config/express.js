const express = require('express');
const morgan = require('morgan');
const bodyParser = require('body-parser');
const compress = require('compression');
const methodOverride = require('method-override');
const cors = require('cors');
const helmet = require('helmet');
const passport = require('passport');
const routes = require('@api/routes/v1');
const { logs,redis } = require('@config/vars');
const strategies = require('@config/passport');
const error = require('@api/middlewares/error');
const { expressSharp,FsAdapter } = require('express-sharp');
const Keyv = require('keyv');
const path = require('path');
const cache = new Keyv(redis);
const audit = require('express-requests-logger')
const logger = require('./logger')
/**
* Express instance
* @public
*/
const app = express();
app.use(audit({
    logger: logger, // Existing bunyan logger
    excludeURLs: ['health', 'metrics'], // Exclude paths which enclude 'health' & 'metrics'
    request: {
        maskBody: ['password'], // Mask 'password' field in incoming requests
        excludeHeaders: ['authorization'], // Exclude 'authorization' header from requests
        excludeBody: ['creditCard'], // Exclude 'creditCard' field from requests body
        maskHeaders: [''], // Mask 'header1' header in incoming requests
        maxBodyLength: 5000 // limit length to 50 chars + '...'
    },
    response: {
        maskBody: ['session_token'], // Mask 'session_token' field in response body
        excludeHeaders: ['*'], // Exclude all headers from responses,
        excludeBody: ['*'], // Exclude all body from responses
        maskHeaders: [''], // Mask 'header1' header in incoming requests
        maxBodyLength: 5000 // limit length to 50 chars + '...'
    }
}));

// request logging. dev: console | production: file
app.use(morgan(logs));
app.use('/static', expressSharp({
    cache,
    imageAdapter: new FsAdapter(path.join(__dirname, '../../public')),
 }))
// parse body params and attache them to req.body
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// gzip compression
app.use(compress());

// lets you use HTTP verbs such as PUT or DELETE
// in places where the client doesn't support it
app.use(methodOverride());

// secure apps by setting various HTTP headers
app.use(helmet());

// enable CORS - Cross Origin Resource Sharing
app.use(cors());

// enable authentication
app.use(passport.initialize());
passport.use('jwt', strategies.jwt);
passport.use('facebook', strategies.facebook);
passport.use('google', strategies.google);

// mount api v1 routes
app.use('/v1', routes);

// if error is not an instanceOf APIError, convert it.
app.use(error.converter);

// catch 404 and forward to error handler
app.use(error.notFound);

// error handler, send stacktrace only during development
app.use(error.handler);




module.exports = app;
