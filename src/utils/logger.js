const config = require('../config');

const LOG_LEVELS = { error: 0, warn: 1, info: 2, debug: 3 };
const currentLevel = LOG_LEVELS[config.logging.level] ?? LOG_LEVELS.info;

function formatLog(level, message, meta = {}) {
  return JSON.stringify({
    timestamp: new Date().toISOString(),
    level,
    message,
    ...meta,
  });
}

const logger = {
  error(message, meta) {
    if (currentLevel >= LOG_LEVELS.error) {
      process.stderr.write(formatLog('error', message, meta) + '\n');
    }
  },
  warn(message, meta) {
    if (currentLevel >= LOG_LEVELS.warn) {
      process.stderr.write(formatLog('warn', message, meta) + '\n');
    }
  },
  info(message, meta) {
    if (currentLevel >= LOG_LEVELS.info) {
      process.stdout.write(formatLog('info', message, meta) + '\n');
    }
  },
  debug(message, meta) {
    if (currentLevel >= LOG_LEVELS.debug) {
      process.stdout.write(formatLog('debug', message, meta) + '\n');
    }
  },
};

module.exports = logger;
