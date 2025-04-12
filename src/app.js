const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const swaggerUi = require('swagger-ui-express'); 
const config = require('./config/config');
const logger = require('./utils/logger');
const errorHandler = require('./middlewares/errorHandler');
const swaggerSpec = require('./config/swagger'); 
const cookieParser = require('cookie-parser'); 
const authRoutes = require('./api/v1/routes/auth.routes'); 
const { authenticateToken } = require('./api/v1/middlewares/auth.middleware'); 

const app = express();

// Set security HTTP headers
app.use(helmet());

// Parse json request body
app.use(express.json());

// Parse urlencoded request body
app.use(express.urlencoded({ extended: true }));

// Parse cookies
app.use(cookieParser()); 

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

// Mount V1 Auth routes
app.use('/api/v1/auth', authRoutes);

// --- Example Protected Route --- 
app.get('/api/v1/protected', authenticateToken, (req, res) => {
    // Access user info attached by the middleware
    res.json({ message: `Welcome User ${req.user.id}! Your role is ${req.user.role}. This is protected content.` });
});

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

// Serve Swagger documentation
if (config.env !== 'production') {
    app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec, {
        explorer: true, // Enables search bar
        // You can add custom options here, e.g., customCssUrl
    }));
    logger.info(`Swagger docs available at /api-docs`);
}

module.exports = app;
