JavaScript Best Practices for Node.js Applications
Code Structure and Organization
Use Modern JavaScript Features

Leverage ES6+ features like arrow functions, destructuring, template literals, and async/await
Use const for variables that won't be reassigned, and let for variables that will
Avoid var due to its function scoping (rather than block scoping)

javascript// Bad
var user = { name: 'John' };
function getData() {
  var result = api.call();
  return result;
}

// Good
const user = { name: 'John' };
const getData = async () => {
  const result = await api.call();
  return result;
};
Modular Architecture

Organize code by feature/domain rather than by technical role
Use the CommonJS (require()) or ES modules (import/export) consistently
Create small, focused modules with clear responsibilities

javascript// users/user.model.js
class User {
  constructor(data) {
    this.name = data.name;
    this.email = data.email;
  }
  
  validate() {
    // Validation logic
  }
}

module.exports = User;

// users/user.service.js
const User = require('./user.model');
const userRepository = require('./user.repository');

exports.createUser = async (userData) => {
  const user = new User(userData);
  const isValid = user.validate();
  
  if (!isValid) {
    throw new Error('Invalid user data');
  }
  
  return userRepository.save(user);
};
Error Handling
Use Async/Await with Try-Catch

Always handle promises with async/await and proper try-catch blocks
Avoid mixing callback and promise patterns

javascript// Bad
function getUserData(id) {
  return db.users.findById(id)
    .then(user => {
      return processUserData(user);
    })
    .catch(err => console.error(err));
}

// Good
async function getUserData(id) {
  try {
    const user = await db.users.findById(id);
    return await processUserData(user);
  } catch (error) {
    logger.error('Failed to get user data', { error, userId: id });
    throw new AppError('Failed to retrieve user data', 500, error);
  }
}
Create Custom Error Classes

Extend the native Error class for different types of errors
Include relevant context in errors for better debugging

javascriptclass AppError extends Error {
  constructor(message, statusCode, originalError) {
    super(message);
    this.statusCode = statusCode;
    this.originalError = originalError;
    this.timestamp = new Date().toISOString();
    this.name = this.constructor.name;
    Error.captureStackTrace(this, this.constructor);
  }
}

class ValidationError extends AppError {
  constructor(message, validationErrors, originalError) {
    super(message, 400, originalError);
    this.validationErrors = validationErrors;
  }
}
Performance Optimization
Use Asynchronous Operations Carefully

Avoid blocking the event loop with CPU-intensive tasks
Use worker threads or child processes for CPU-bound operations
Leverage Promise.all() for concurrent operations

javascript// Bad - Sequential processing
async function processItems(items) {
  const results = [];
  for (const item of items) {
    const result = await processItem(item);
    results.push(result);
  }
  return results;
}

// Good - Concurrent processing when order doesn't matter
async function processItems(items) {
  const promises = items.map(item => processItem(item));
  return Promise.all(promises);
}
Optimize Memory Usage

Be careful with large objects and arrays that can cause memory leaks
Use streams for processing large files instead of loading them into memory
Implement pagination for API responses with large data sets

javascript// Bad - Loads entire file into memory
const fs = require('fs');

function processLargeFile(filePath) {
  const content = fs.readFileSync(filePath, 'utf8');
  // Process content
}

// Good - Uses streams
const fs = require('fs');

function processLargeFile(filePath) {
  return new Promise((resolve, reject) => {
    const stream = fs.createReadStream(filePath, { encoding: 'utf8' });
    let data = '';
    
    stream.on('data', (chunk) => {
      // Process chunk
    });
    
    stream.on('end', () => resolve());
    stream.on('error', (error) => reject(error));
  });
}
Code Quality and Maintainability
Consistent Naming Conventions

Use camelCase for variables, functions, and methods
Use PascalCase for classes and constructor functions
Use UPPER_SNAKE_CASE for constants
Choose descriptive names that reveal intent

javascript// Bad
const u = getUser();
function calc_total(a, b) {
  return a + b;
}

// Good
const currentUser = getCurrentUser();
const MAXIMUM_RETRY_COUNT = 3;

function calculateOrderTotal(basePrice, taxRate) {
  return basePrice * (1 + taxRate);
}

class OrderProcessor {
  constructor(orderData) {
    this.order = orderData;
  }
}
Write Self-Documenting Code

Use clear, descriptive variable and function names
Break complex functions into smaller, well-named functions
Use comments to explain "why" not "what"

javascript// Bad
function p(d) {
  const r = d.filter(i => i.a > 0).map(i => i.a * 2);
  return r.reduce((t, v) => t + v, 0);
}

// Good
function calculateTotalPositiveValuesDoubled(items) {
  const positiveItems = items.filter(item => item.value > 0);
  const doubledValues = positiveItems.map(item => item.value * 2);
  return doubledValues.reduce((total, value) => total + value, 0);
}
Testing
Write Comprehensive Tests

Implement unit tests for all business logic functions
Create integration tests for API endpoints and database operations
Use mocks and stubs for external dependencies

javascript// user.service.test.js
const { expect } = require('chai');
const sinon = require('sinon');
const userService = require('./user.service');
const userRepository = require('./user.repository');

describe('User Service', () => {
  describe('createUser', () => {
    it('should create a valid user', async () => {
      // Setup
      const userData = { name: 'John', email: 'john@example.com' };
      const expectedUser = { id: '123', ...userData };
      const saveStub = sinon.stub(userRepository, 'save').resolves(expectedUser);
      
      // Execute
      const result = await userService.createUser(userData);
      
      // Verify
      expect(result).to.deep.equal(expectedUser);
      expect(saveStub.calledOnce).to.be.true;
      expect(saveStub.calledWith(sinon.match(userData))).to.be.true;
      
      // Cleanup
      saveStub.restore();
    });
    
    it('should throw validation error for invalid data', async () => {
      // Setup
      const invalidUserData = { name: '' };
      
      // Execute & Verify
      try {
        await userService.createUser(invalidUserData);
        expect.fail('Should have thrown an error');
      } catch (error) {
        expect(error.message).to.include('Invalid user data');
      }
    });
  });
});
Security
Input Validation

Validate all input data, especially from external sources
Use schemas for validating complex objects
Never trust user input for database queries or command execution

javascriptconst Joi = require('joi');

const userSchema = Joi.object({
  name: Joi.string().required().min(2).max(50),
  email: Joi.string().required().email(),
  age: Joi.number().integer().min(13).max(120),
  role: Joi.string().valid('user', 'admin', 'editor')
});

function validateUser(userData) {
  const { error, value } = userSchema.validate(userData);
  if (error) {
    throw new ValidationError('Invalid user data', error.details);
  }
  return value;
}
Avoid Security Vulnerabilities

Keep dependencies updated regularly
Use security linters like npm audit and automated security tools
Implement proper authentication and authorization mechanisms
Use parameterized queries for database operations to prevent SQL injection

javascript// Bad - SQL injection vulnerability
function getUserById(id) {
  const query = `SELECT * FROM users WHERE id = ${id}`;
  return db.query(query);
}

// Good - Parameterized query
function getUserById(id) {
  const query = 'SELECT * FROM users WHERE id = ?';
  return db.query(query, [id]);
}
Configuration and Environment
Use Environment Variables

Store configuration in environment variables
Never commit sensitive information to version control
Use a library like dotenv for local development

javascript// config.js
require('dotenv').config();

module.exports = {
  database: {
    url: process.env.DATABASE_URL,
    name: process.env.DATABASE_NAME,
    options: {
      useNewUrlParser: true,
      useUnifiedTopology: true
    }
  },
  server: {
    port: process.env.PORT || 3000,
    env: process.env.NODE_ENV || 'development'
  },
  auth: {
    jwtSecret: process.env.JWT_SECRET,
    jwtExpiresIn: process.env.JWT_EXPIRES_IN || '1d'
  }
};
Logging and Monitoring
Implement Structured Logging

Use a logging library like Winston or Pino
Log in structured JSON format for easier analysis
Include relevant context in logs (request IDs, user IDs, etc.)

javascriptconst winston = require('winston');

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  defaultMeta: { service: 'user-service' },
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' })
  ]
});

// Usage
logger.info('User created', { userId: user.id, email: user.email });
logger.error('Failed to process payment', { 
  orderId, 
  userId,
  error: error.message,
  stack: error.stack
});
Documentation
Document Your Code

Write JSDoc comments for functions and classes
Include examples in documentation
Keep documentation up-to-date with code changes

javascript/**
 * Calculates the total price of an order including tax and shipping.
 * 
 * @param {Object} order - The order object
 * @param {number} order.subtotal - The order subtotal amount
 * @param {number} order.taxRate - The tax rate as a decimal (e.g., 0.07 for 7%)
 * @param {number} [order.shippingCost=0] - The shipping cost
 * @returns {number} The total order price
 * 
 * @example
 * const orderTotal = calculateOrderTotal({
 *   subtotal: 100,
 *   taxRate: 0.07,
 *   shippingCost: 10
 * });
 * // Returns: 117
 */
function calculateOrderTotal(order) {
  const { subtotal, taxRate, shippingCost = 0 } = order;
  const taxAmount = subtotal * taxRate;
  return subtotal + taxAmount + shippingCost;
}
Dependency Management
Manage Dependencies Carefully

Keep dependencies up-to-date
Be cautious about adding new dependencies
Lock dependency versions in package.json
Consider using tools like npm audit and dependabot

json{
  "name": "my-node-app",
  "version": "1.0.0",
  "dependencies": {
    "express": "4.17.1",
    "mongoose": "5.12.3"
  },
  "devDependencies": {
    "jest": "26.6.3",
    "eslint": "7.24.0"
  },
  "scripts": {
    "start": "node src/server.js",
    "test": "jest",
    "lint": "eslint .",
    "audit": "npm audit"
  }
}
Conclusion
Following these best practices will help you build Node.js applications that are maintainable, performant, and secure. Remember that these guidelines are not rigid rules - adapt them to the specific needs of your project and team. The most important thing is to be consistent and deliberate in your approach to writing and organizing JavaScript code.