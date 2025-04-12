const logger = require('../utils/logger');
const config = require('../config/config');

// eslint-disable-next-line no-unused-vars
const errorHandler = (err, req, res, next) => {
  let { statusCode = 500, message } = err;

  // Handle specific error types if needed (e.g., Mongoose validation errors)
  // if (err.name === 'ValidationError') { ... }

  // Don't leak sensitive error details in production
  if (config.env === 'production' && !err.isOperational) {
    statusCode = 500;
    message = 'Internal Server Error';
  }

  res.locals.errorMessage = err.message; // For potential server-side logging

  const response = {
    code: statusCode,
    message,
    ...(config.env === 'development' && { stack: err.stack }), // Include stack trace in development
  };

  if (config.env === 'development') {
    logger.error(err);
  } else {
    // Log error level based on status code in production
    if (statusCode >= 500) {
        logger.error(`[${statusCode}] ${message} - ${req.originalUrl} - ${req.method} - ${req.ip}`);
    } else {
        logger.warn(`[${statusCode}] ${message} - ${req.originalUrl} - ${req.method} - ${req.ip}`);
    }
  }

  res.status(statusCode).send(response);
};

module.exports = errorHandler;
