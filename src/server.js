const http = require('http');
const app = require('./app');
const config = require('./config/config');
const logger = require('./utils/logger');
const connectDB = require('./db/connect');

const server = http.createServer(app);

// Connect to Database
connectDB();

const startServer = () => {
  server.listen(config.port, () => {
    logger.info(`Server listening on port ${config.port}`);
    logger.info(`Environment: ${config.env}`);
  });
};

// Graceful shutdown
const exitHandler = () => {
  if (server) {
    server.close(() => {
      logger.info('Server closed');
      process.exit(0);
    });
  } else {
    process.exit(0);
  }
};

const unexpectedErrorHandler = (error) => {
  logger.error('Unhandled Error:', error);
  exitHandler();
};

process.on('uncaughtException', unexpectedErrorHandler);
process.on('unhandledRejection', (reason) => {
    logger.error('Unhandled Rejection:', reason);
    // We throw the error here so uncaughtException handler catches it
    // This ensures consistent handling and logging for both types of unhandled errors
    throw reason;
});

// Handle termination signals
process.on('SIGTERM', () => {
  logger.info('SIGTERM signal received.');
  logger.info('Closing http server.');
  exitHandler();
});

process.on('SIGINT', () => {
    logger.info('SIGINT signal received.');
    logger.info('Closing http server.');
    exitHandler();
});

// Start the server
startServer();

module.exports = server; // Export server for potential testing
