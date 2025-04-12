const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const swaggerUi = require('swagger-ui-express'); 
const config = require('./config/config');
const logger = require('./utils/logger');
const errorHandler = require('./middlewares/errorHandler');
const swaggerSpec = require('./config/swagger'); 
// const v1ApiRoutes = require('./api/v1/routes'); // Import routes once they exist

const app = express();

// Set security HTTP headers
app.use(helmet());

// Parse json request body
app.use(express.json());

// Parse urlencoded request body
app.use(express.urlencoded({ extended: true }));

// Enable CORS - configure options as needed
app.use(cors());
app.options('*', cors()); // Enable pre-flight requests for all routes

// Simple request logging middleware (can be expanded)
app.use((req, res, next) => {
  // Skip logging for swagger docs requests to reduce noise
  if (!req.originalUrl.includes('/api-docs')) {
    logger.http(`${req.method} ${req.originalUrl} - ${req.ip}`);
  }
  next();
});

// v1 API routes - Uncomment when routes are defined
// app.use('/api/v1', v1ApiRoutes);

// Serve Swagger documentation
// Only serve docs in non-production environments by default for security
if (config.env !== 'production') {
    app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec, {
        explorer: true, // Enables search bar
        // You can add custom options here, e.g., customCssUrl
    }));
    logger.info(`Swagger docs available at /api-docs`);
}

/**
 * @swagger
 * /health:
 *   get:
 *     summary: Health Check
 *     description: Returns the health status of the API.
 *     tags: [Health]
 *     responses:
 *       200:
 *         description: API is healthy.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                   example: UP
 */
app.get('/health', (req, res) => {
  res.status(200).send({ status: 'UP' });
});

// Handle 404 errors - Route not found
app.use((req, res, next) => {
    const error = new Error('Not Found');
    error.statusCode = 404;
    error.isOperational = true; // Mark as operational error
    next(error);
});

// Centralized error handler
app.use(errorHandler);

module.exports = app;
