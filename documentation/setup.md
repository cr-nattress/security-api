Node.js Express Server
Project Overview
Create a modern, scalable, and maintainable Node.js Express server with the following characteristics:

Clean architecture that separates concerns
Modular design for easy maintenance and scalability
Well-structured error handling
Comprehensive logging
Environment-based configuration
Testing setup
Documentation

Project Structure
Please implement the following directory structure:
/my-express-app
├── .env.example           # Example environment variables
├── .gitignore             # Git ignore file
├── package.json           # Project dependencies and scripts
├── README.md              # Project documentation
├── /src                   # Source code
│   ├── app.js             # Express app setup (without server)
│   ├── server.js          # Server entry point
│   ├── /api               # API endpoints
│   │   ├── /v1            # Version 1 of the API
│   │   │   ├── routes.js  # Route index
│   │   │   ├── /resources # Resource-specific routes
│   │   │   │   ├── /users
│   │   │   │   │   ├── user.routes.js
│   │   │   │   │   ├── user.controller.js
│   │   │   │   │   ├── user.service.js
│   │   │   │   │   ├── user.model.js
│   │   │   │   │   └── user.validation.js
│   │   │   │   └── /other-resources
│   ├── /config            # Configuration files
│   │   ├── index.js       # Exports all configs
│   │   ├── database.js    # Database configuration
│   │   ├── logger.js      # Logger configuration
│   │   └── express.js     # Express configuration
│   ├── /middleware        # Custom middleware
│   │   ├── error.middleware.js
│   │   ├── auth.middleware.js
│   │   └── logger.middleware.js
│   ├── /utils             # Utility functions
│   │   ├── asyncHandler.js
│   │   ├── ApiError.js
│   │   └── response.js
│   └── /db                # Database setup and models
│       ├── index.js
│       └── /migrations    # Database migrations
├── /tests                 # Test files
│   ├── /unit
│   ├── /integration
│   └── /fixtures          # Test fixtures
└── /docs                  # Documentation
Implementation Requirements
Core Setup

Initialize with npm init and install Express and other essential dependencies
Set up a modular Express application with separation between the app setup and server
Implement proper environment configuration with dotenv

API Organization

Create a versioned API structure to allow for future changes
Organize routes by resource/domain
Implement the controller-service pattern:

Controllers: Handle HTTP requests and responses
Services: Contain business logic
Models: Define data structures and database interactions



Error Handling

Create a centralized error handling middleware
Implement custom error classes for different types of errors (e.g., ValidationError, AuthenticationError)
Ensure all errors return consistent response formats

Middleware

Set up essential middleware:

Body parsing
CORS configuration
Request logging
Security headers


Create custom middleware for authentication, input validation, etc.

Configuration

Implement environment-based configuration
Create a centralized config module that loads appropriate settings
Include validation for required environment variables

Logging

Implement structured logging using Winston or Pino
Log requests, responses, errors, and application events
Configure different log levels for development and production

Database Integration

Set up a database connection module (MongoDB, PostgreSQL, etc.)
Implement models with proper validation
Create database migration scripts

Testing Setup

Configure Jest or Mocha for testing
Set up unit tests for utilities and services
Create integration tests for API endpoints
Implement test fixtures and helpers

Documentation

Create a comprehensive README.md
Document API endpoints using Swagger/OpenAPI
Include setup and deployment instructions

Performance & Security

Implement rate limiting
Set up appropriate security headers
Configure compression middleware
Implement proper input validation

Additional Guidelines

Follow the principle of separation of concerns
Use dependency injection for better testability
Implement proper async/await patterns with error handling
Use ESLint and Prettier for code quality
Follow semantic versioning for your API

Deliverables

Complete Node.js Express server setup with the structure described above
Minimal working examples for each component (routes, controllers, services, etc.)
Documentation explaining the architecture and how to extend it
Sample environment configuration