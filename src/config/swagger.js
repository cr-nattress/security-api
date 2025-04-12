const swaggerJsdoc = require('swagger-jsdoc');
const config = require('./config');

const options = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'Security API Documentation',
      version: '1.0.0',
      description:
        'API documentation for the Node.js Express Security API, demonstrating best practices.',
      license: {
        name: 'ISC', // Or your chosen license
        // url: 'https://opensource.org/licenses/ISC',
      },
      contact: {
        name: 'Your Name / Team', // Optional: Add contact info
        // url: 'https://yourwebsite.com',
        // email: 'info@email.com',
      },
    },
    servers: [
      {
        url: `http://localhost:${config.port}/api/v1`,
        description: 'Development server (V1)',
      },
      // Add other servers like staging or production if needed
      // {
      //   url: 'https://api.yourdomain.com/api/v1',
      //   description: 'Production server (V1)',
      // },
    ],
    // Define components like security schemes, schemas, etc.
    components: {
        securitySchemes: {
            bearerAuth: { // Arbitrary name for the security scheme
                type: 'http',
                scheme: 'bearer',
                bearerFormat: 'JWT', // Optional, specific format
                description: 'Input your JWT token in the format: Bearer <token>',
            },
        },
        // Define reusable schemas (models) here
        schemas: {
          // Example Schema:
          // ErrorResponse: {
          //   type: 'object',
          //   properties: {
          //     code: {
          //       type: 'integer',
          //       format: 'int32',
          //       description: 'HTTP status code',
          //       example: 400,
          //     },
          //     message: {
          //       type: 'string',
          //       description: 'Error message',
          //       example: 'Validation Failed',
          //     },
          //     stack: {
          //        type: 'string',
          //        description: 'Error stack trace (only in development)',
          //        example: 'Error: Validation Failed\n    at ...',
          //     },
          //   },
          //   required: ['code', 'message'],
          // },
        },
    },
    // Optionally define security requirements globally or per-operation
    // security: [
    //   {
    //     bearerAuth: [], // Applies bearerAuth security scheme to all operations unless overridden
    //   },
    // ],
  },
  // Path to the API docs
  // swagger-jsdoc will scan these files for JSDoc comments
  apis: ['./src/api/v1/routes/*.js', './src/models/*.js'], // Adjust paths as needed
};

const swaggerSpec = swaggerJsdoc(options);

module.exports = swaggerSpec;
