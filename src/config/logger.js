const { createLogger, format, transports } = require('winston');
const { combine, timestamp, label, printf } = format;
const chalk = require('chalk');
 
const logFormat = printf(({ level, message, label, timestamp }) => {
  return `${getLevelLabel(level)}: ${chalk.yellow(timestamp)} : ${JSON.stringify(message)}`;
});

const logger = createLogger({
  level: 'debug',
  colorize: true,
  timestamp: function () {
    return (new Date()).toLocaleTimeString();
  },
  prettyPrint: true,
  format: combine(
    label({ label: 'Server' }),
    timestamp(),
    logFormat
  ),
  transports: [
    //
    // - Write to all logs with level `info` and below to `combined.log`
    // - Write all logs error (and below) to `error.log`.
    //
    new transports.File({ filename: 'error.log', level: 'error' }),
    new transports.File({ filename: 'combined.log' }),
  ],
});

//
// If we're not in production then log to the `console` with the format:
// `${info.level}: ${info.message} JSON.stringify({ ...rest }) `
//
if (process.env.NODE_ENV !== 'production') {
  logger.add(new transports.Console({
    format: combine(
      label({ label: 'Server' }),
      timestamp(),
      logFormat
    ),
    level: 'info',
    colorize: true,
    timestamp: function () {
      return (new Date()).toLocaleTimeString();
    },
    prettyPrint: true
  }));
}

logger.stream = {
  write: (message) => {
    logger.info(message.trim());
  },
};

const getLevelLabel = (level) =>{
  if(level == 'error'){
    return chalk.red(level.toUpperCase())
  } else if (level == 'warning'){
    return chalk.yellow(level.toUpperCase())
  } else {
    return chalk.green(level.toUpperCase())
  }
}

module.exports = logger;
