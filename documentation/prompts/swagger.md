# Prompt: Setting Up Swagger Documentation for Node.js Express Server

## Overview
Add comprehensive API documentation to our Node.js Express server using Swagger/OpenAPI. This will provide interactive documentation for all API endpoints, authentication flows, and data models.

## Implementation Requirements

### 1. Install Required Dependencies

Add the following packages to our project:
- swagger-jsdoc
- swagger-ui-express

### 2. Create Swagger Configuration

Set up a Swagger configuration file in the `/config` directory with the following specifications:

- API information (title, version, description)
- Server URLs for different environments
- Authentication schemes (JWT Bearer)
- Tags for API categorization
- Base path configuration

### 3. Set Up Swagger Middleware

Create an Express middleware that initializes and serves the Swagger documentation:
- Mount Swagger UI at `/api-docs`
- Configure security requirements
- Set up proper CORS for documentation access
- Add environment-specific configurations

### 4. Document API Routes

Add JSDoc annotations to all routes with the following information:
- Route descriptions
- Request parameters
- Request body schemas
- Response schemas
- Authentication requirements
- Example requests and responses
- Error responses

### 5. Document Authentication Flow

Create comprehensive documentation for the authentication system:
- Registration process
- Login process
- Token refresh flow
- Logout procedure
- Security schemes definition

### 6. Document Data Models

Create Swagger schema definitions for all data models:
- User model
- Token model
- Error response model
- Success response model

### 7. Secure Swagger UI in Production

Implement security measures for the Swagger UI in production:
- Basic authentication for accessing documentation
- Environment-based restrictions
- Sensitive information filtering

## Implementation Details

### Base Swagger Configuration Example

```javascript
const swaggerOptions = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'Node.js Express API with JWT Authentication',
      version: '1.0.0',
      description: 'A RESTful API built with Express and documented with Swagger',
      license: {
        name: 'MIT',
        url: 'https://spdx.org/licenses/MIT.html'
      },
      contact: {
        name: 'API Support',
        url: 'https://www.example.com/support',
        email: 'support@example.com'
      }
    },
    servers: [
      {
        url: 'http://localhost:3000/api/v1',
        description: 'Development server'
      },
      {
        url: 'https://api.example.com/api/v1',
        description: 'Production server'
      }
    ],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT'
        }
      },
      schemas: {
        // Define your schemas here
      },
      responses: {
        // Define standard responses here
      }
    }
  },
  apis: ['./src/routes/*.js', './src/models/*.js', './src/swagger/*.js']
};
```

### Route Documentation Example

For each route, include detailed JSDoc comments following this pattern:

```javascript
/**
 * @swagger
 * /auth/register:
 *   post:
 *     summary: Register a new user
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - username
 *               - email
 *               - password
 *             properties:
 *               username:
 *                 type: string
 *                 description: User's unique username
 *               email:
 *                 type: string
 *                 format: email
 *                 description: User's email address
 *               password:
 *                 type: string
 *                 format: password
 *                 description: User's password (min 8 characters)
 *             example:
 *               username: "johndoe"
 *               email: "john@example.com"
 *               password: "Password123!"
 *     responses:
 *       201:
 *         description: User registered successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                   example: success
 *                 data:
 *                   type: object
 *                   properties:
 *                     user:
 *                       $ref: '#/components/schemas/User'
 *                     accessToken:
 *                       type: string
 *                       description: JWT access token
 *       400:
 *         description: Invalid input data
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       409:
 *         description: User already exists
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
router.post('/register', authController.register);
```

### Model Documentation Example

For each model, include JSDoc annotations:

```javascript
/**
 * @swagger
 * components:
 *   schemas:
 *     User:
 *       type: object
 *       required:
 *         - username
 *         - email
 *         - password
 *       properties:
 *         id:
 *           type: string
 *           description: Auto-generated unique identifier
 *         username:
 *           type: string
 *           description: User's unique username
 *         email:
 *           type: string
 *           format: email
 *           description: User's email address
 *         role:
 *           type: string
 *           enum: [user, admin]
 *           default: user
 *           description: User's role
 *         createdAt:
 *           type: string
 *           format: date-time
 *           description: Timestamp of user creation
 *         updatedAt:
 *           type: string
 *           format: date-time
 *           description: Timestamp of last update
 *       example:
 *         id: "60d21b4667d0d8992e610c85"
 *         username: "johndoe"
 *         email: "john@example.com"
 *         role: "user"
 *         createdAt: "2023-01-01T00:00:00.000Z"
 *         updatedAt: "2023-01-01T00:00:00.000Z"
 */
```

### Common Response Schemas

Define standard response formats:

```javascript
/**
 * @swagger
 * components:
 *   schemas:
 *     Error:
 *       type: object
 *       properties:
 *         status:
 *           type: string
 *           example: fail
 *         message:
 *           type: string
 *           example: Error message details
 *     
 *     SuccessResponse:
 *       type: object
 *       properties:
 *         status:
 *           type: string
 *           example: success
 *         data:
 *           type: object
 */
```

### Swagger Setup File

Create a dedicated file to initialize Swagger:

```javascript
// src/config/swagger.js
const swaggerJsDoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');

const options = {
  // Your swagger options as defined above
};

const specs = swaggerJsDoc(options);

module.exports = { specs, swaggerUi };
```

### Integrating With Express App

Add the Swagger middleware to your Express app:

```javascript
// src/app.js
const express = require('express');
const { specs, swaggerUi } = require('./config/swagger');

const app = express();

// Other middleware and configurations...

// Swagger documentation - restricted in production
if (process.env.NODE_ENV === 'development') {
  app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(specs));
} else {
  // In production, add basic authentication
  app.use('/api-docs', (req, res, next) => {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Basic ')) {
      res.setHeader('WWW-Authenticate', 'Basic');
      return res.status(401).send('Authentication required');
    }
    
    const base64Credentials = authHeader.split(' ')[1];
    const credentials = Buffer.from(base64Credentials, 'base64').toString('utf8');
    const [username, password] = credentials.split(':');
    
    if (username === process.env.SWAGGER_USER && password === process.env.SWAGGER_PASSWORD) {
      return next();
    }
    
    res.setHeader('WWW-Authenticate', 'Basic');
    return res.status(401).send('Authentication required');
  }, swaggerUi.serve, swaggerUi.setup(specs));
}

// Routes and other app configurations...

module.exports = app;
```

## Expected Deliverables

1. Fully configured Swagger setup in the Node.js Express server
2. Complete API documentation for all endpoints
3. Interactive API testing interface at `/api-docs`
4. Proper security mechanisms for documentation access in production
5. Model documentation for all data schemas

## Best Practices

1. Keep documentation close to the code it documents
2. Use components and schemas to avoid repetition
3. Include realistic examples for requests and responses
4. Document error scenarios thoroughly
5. Group related endpoints using tags
6. Implement proper security definitions
7. Test all examples to ensure they are valid
8. Version your API documentation along with your API

## Additional Resources

- [Swagger JSDoc Documentation](https://github.com/Surnet/swagger-jsdoc/blob/master/docs/GETTING-STARTED.md)
- [OpenAPI 3.0 Specification](https://swagger.io/specification/)
- [Swagger UI Express Documentation](https://github.com/scottie1984/swagger-ui-express)