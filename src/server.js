const http = require('http');
const app = require('./app');
const config = require('./config/config');
const logger = require('./utils/logger');
const { initializeDatabase } = require('./db/connect');

const server = http.createServer(app);

// Function to start the server
const startServer = () => {
  try {
    // Initialize Supabase Client
    initializeDatabase();

    server.listen(config.port, () => {
      logger.info(`Server listening on port ${config.port}`);
      logger.info(`Environment: ${config.env}`);
    });
  } catch (error) {
    // Error during DB initialization is already logged in initializeDatabase
    // Exit process is handled there too, but we can log again if needed
    logger.error('Failed to initialize database or start server:', error);
    process.exit(1);
  }
};

// Graceful shutdown
const exitHandler = () => {
  // Optional: Add logic here to gracefully close the database pool if needed
  // const pool = getPool(); // Need to import getPool if used here
  // if (pool) { pool.end(); }
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

// Start the server by calling the function
startServer();

module.exports = server; // Export server for potential testing
