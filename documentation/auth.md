# Implementing JWT Authentication in Node.js

## Introduction

JSON Web Tokens (JWT) provide a compact, self-contained mechanism for securely transmitting information between parties as a JSON object. This document outlines a complete implementation of JWT-based authentication for Node.js servers, covering everything from setup to best practices.

## Table of Contents

1. [Understanding JWT](#understanding-jwt)
2. [Setting Up the Project](#setting-up-the-project)
3. [User Model and Database Setup](#user-model-and-database-setup)
4. [Registration and Login Implementation](#registration-and-login-implementation)
5. [JWT Middleware for Route Protection](#jwt-middleware-for-route-protection)
6. [Token Refresh Mechanism](#token-refresh-mechanism)
7. [Logout Implementation](#logout-implementation)
8. [Security Best Practices](#security-best-practices)
9. [Complete Implementation Example](#complete-implementation-example)
10. [Testing Your JWT Implementation](#testing-your-jwt-implementation)

## Understanding JWT

### JWT Structure

A JWT consists of three parts:
1. **Header**: Contains the token type and signing algorithm
2. **Payload**: Contains the claims (data)
3. **Signature**: Verifies the token hasn't been altered

These parts are encoded separately and concatenated with dots, resulting in a token like:
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

### JWT Authentication Flow

1. User logs in with credentials
2. Server validates credentials and creates a JWT
3. Server sends the JWT to the client
4. Client stores the JWT (usually in localStorage or an httpOnly cookie)
5. Client includes the JWT in the Authorization header for subsequent requests
6. Server validates the JWT signature and extracts user information
7. Server processes the request if the JWT is valid

## Setting Up the Project

### Required Dependencies

```bash
# Initialize a new Node.js project
npm init -y

# Install necessary packages
npm install express mongoose bcrypt jsonwebtoken dotenv
npm install nodemon --save-dev
```

### Project Structure

```
/jwt-auth-project
  /config
    - db.js
    - jwt.js
  /controllers
    - authController.js
    - userController.js
  /middleware
    - authMiddleware.js
    - errorMiddleware.js
  /models
    - User.js
    - Token.js (optional, for refresh tokens)
  /routes
    - authRoutes.js
    - userRoutes.js
  /utils
    - catchAsync.js
    - AppError.js
  - server.js
  - .env
  - package.json
```

### Environment Configuration

Create a `.env` file with the following variables:

```
PORT=3000
MONGODB_URI=mongodb://localhost:27017/jwt-auth-db
JWT_SECRET=your_jwt_secret_key_here
JWT_ACCESS_EXPIRY=15m
JWT_REFRESH_EXPIRY=7d
NODE_ENV=development
```

## User Model and Database Setup

### Database Connection (config/db.js)

```javascript
const mongoose = require('mongoose');

const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log('MongoDB connected successfully');
  } catch (error) {
    console.error('MongoDB connection error:', error);
    process.exit(1);
  }
};

module.exports = connectDB;
```

### User Model (models/User.js)

```javascript
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: [true, 'Username is required'],
    unique: true,
    trim: true,
    minlength: 3,
    maxlength: 20
  },
  email: {
    type: String,
    required: [true, 'Email is required'],
    unique: true,
    lowercase: true,
    match: [/^\S+@\S+\.\S+$/, 'Please use a valid email address']
  },
  password: {
    type: String,
    required: [true, 'Password is required'],
    minlength: 8,
    select: false // Don't include password in queries by default
  },
  role: {
    type: String,
    enum: ['user', 'admin'],
    default: 'user'
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Hash password before saving
userSchema.pre('save', async function(next) {
  // Only hash the password if it has been modified (or is new)
  if (!this.isModified('password')) return next();
  
  try {
    // Generate a salt
    const salt = await bcrypt.genSalt(10);
    // Hash the password along with the new salt
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// Method to check if password is correct
userSchema.methods.isPasswordCorrect = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

const User = mongoose.model('User', userSchema);

module.exports = User;
```

### Refresh Token Model (optional, models/Token.js)

```javascript
const mongoose = require('mongoose');

const tokenSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    required: true,
    ref: 'User'
  },
  token: {
    type: String,
    required: true
  },
  createdAt: {
    type: Date,
    default: Date.now,
    expires: 30 * 24 * 60 * 60 // 30 days
  }
});

const Token = mongoose.model('Token', tokenSchema);

module.exports = Token;
```

## Registration and Login Implementation

### JWT Configuration (config/jwt.js)

```javascript
const jwt = require('jsonwebtoken');

// Generate access token
const generateAccessToken = (userId, role) => {
  return jwt.sign(
    { id: userId, role },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_ACCESS_EXPIRY || '15m' }
  );
};

// Generate refresh token
const generateRefreshToken = (userId, role) => {
  return jwt.sign(
    { id: userId, role },
    process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_REFRESH_EXPIRY || '7d' }
  );
};

// Verify token
const verifyToken = (token) => {
  try {
    return jwt.verify(token, process.env.JWT_SECRET);
  } catch (error) {
    return null;
  }
};

module.exports = {
  generateAccessToken,
  generateRefreshToken,
  verifyToken
};
```

### Auth Controller (controllers/authController.js)

```javascript
const User = require('../models/User');
const Token = require('../models/Token');
const { generateAccessToken, generateRefreshToken } = require('../config/jwt');
const catchAsync = require('../utils/catchAsync');
const AppError = require('../utils/AppError');

// Register a new user
exports.register = catchAsync(async (req, res, next) => {
  const { username, email, password } = req.body;

  // Check if user already exists
  const existingUser = await User.findOne({ 
    $or: [{ email }, { username }]
  });

  if (existingUser) {
    return next(new AppError('User with that email or username already exists', 400));
  }

  // Create new user
  const newUser = await User.create({
    username,
    email,
    password
  });

  // Remove password from output
  newUser.password = undefined;

  // Generate tokens
  const accessToken = generateAccessToken(newUser._id, newUser.role);
  const refreshToken = generateRefreshToken(newUser._id, newUser.role);

  // Store refresh token in database
  await Token.create({
    userId: newUser._id,
    token: refreshToken
  });

  // Set refresh token as HttpOnly cookie
  res.cookie('refreshToken', refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
  });

  res.status(201).json({
    status: 'success',
    data: {
      user: newUser,
      accessToken
    }
  });
});

// Login user
exports.login = catchAsync(async (req, res, next) => {
  const { email, password } = req.body;

  // Check if email and password are provided
  if (!email || !password) {
    return next(new AppError('Please provide email and password', 400));
  }

  // Find the user
  const user = await User.findOne({ email }).select('+password');

  // Check if user exists and password is correct
  if (!user || !(await user.isPasswordCorrect(password))) {
    return next(new AppError('Incorrect email or password', 401));
  }

  // Generate tokens
  const accessToken = generateAccessToken(user._id, user.role);
  const refreshToken = generateRefreshToken(user._id, user.role);

  // Store refresh token in database
  await Token.create({
    userId: user._id,
    token: refreshToken
  });

  // Remove password from output
  user.password = undefined;

  // Set refresh token as HttpOnly cookie
  res.cookie('refreshToken', refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
  });

  res.status(200).json({
    status: 'success',
    data: {
      user,
      accessToken
    }
  });
});

// Refresh token
exports.refreshToken = catchAsync(async (req, res, next) => {
  // Get refresh token from cookie
  const refreshToken = req.cookies.refreshToken;

  if (!refreshToken) {
    return next(new AppError('Authentication required. Please log in.', 401));
  }

  // Verify token
  const decoded = jwt.verify(
    refreshToken,
    process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET
  );

  // Check if token exists in database
  const tokenDoc = await Token.findOne({ 
    userId: decoded.id,
    token: refreshToken
  });

  if (!tokenDoc) {
    return next(new AppError('Invalid token. Please log in again.', 401));
  }

  // Check if user still exists
  const user = await User.findById(decoded.id);
  if (!user) {
    return next(new AppError('The user no longer exists.', 401));
  }

  // Generate new access token
  const accessToken = generateAccessToken(user._id, user.role);

  res.status(200).json({
    status: 'success',
    data: {
      accessToken
    }
  });
});
```

## JWT Middleware for Route Protection

### Auth Middleware (middleware/authMiddleware.js)

```javascript
const jwt = require('jsonwebtoken');
const { promisify } = require('util');
const User = require('../models/User');
const AppError = require('../utils/AppError');
const catchAsync = require('../utils/catchAsync');

exports.protect = catchAsync(async (req, res, next) => {
  // 1) Get token from headers
  let token;
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith('Bearer')
  ) {
    token = req.headers.authorization.split(' ')[1];
  }

  if (!token) {
    return next(
      new AppError('You are not logged in. Please log in to get access.', 401)
    );
  }

  // 2) Verify token
  const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);

  // 3) Check if user still exists
  const currentUser = await User.findById(decoded.id);
  if (!currentUser) {
    return next(
      new AppError('The user belonging to this token no longer exists.', 401)
    );
  }

  // 4) Grant access to protected route
  req.user = currentUser;
  next();
});

// Middleware for restricting routes to specific roles
exports.restrictTo = (...roles) => {
  return (req, res, next) => {
    // roles is an array like ['admin', 'moderator']
    if (!roles.includes(req.user.role)) {
      return next(
        new AppError('You do not have permission to perform this action', 403)
      );
    }
    next();
  };
};
```

## Token Refresh Mechanism

### Token Refresh Strategy

For token refresh, we'll implement the following strategy:

1. When users log in, they receive both an access token and a refresh token
2. The refresh token is stored as an HttpOnly cookie
3. The access token is short-lived (15 minutes)
4. The refresh token is long-lived (7 days)
5. When the access token expires, the client makes a request to refresh it

### Refresh Token Route (routes/authRoutes.js)

```javascript
const express = require('express');
const authController = require('../controllers/authController');

const router = express.Router();

router.post('/register', authController.register);
router.post('/login', authController.login);
router.post('/refresh-token', authController.refreshToken);
router.post('/logout', authController.logout);

module.exports = router;
```

## Logout Implementation

### Logout Controller (in controllers/authController.js)

```javascript
// Logout user
exports.logout = catchAsync(async (req, res, next) => {
  // Get refresh token from cookie
  const refreshToken = req.cookies.refreshToken;
  
  if (refreshToken) {
    // Delete refresh token from database
    await Token.findOneAndDelete({ token: refreshToken });
    
    // Clear refresh token cookie
    res.clearCookie('refreshToken');
  }
  
  res.status(200).json({
    status: 'success',
    message: 'Logged out successfully'
  });
});
```

## Security Best Practices

### 1. Use Strong Secrets

Generate a strong, random secret for signing JWTs:

```javascript
// In a terminal, generate a random string
// node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
```

### 2. Set Proper Token Expiration

- Access tokens: Short-lived (15 minutes or less)
- Refresh tokens: Longer-lived (days to weeks)

### 3. Store Tokens Securely

- Access tokens: Client-side storage (memory preferred, localStorage if necessary)
- Refresh tokens: HttpOnly cookies or secure storage

### 4. Implement Token Blacklisting/Revocation

For critical applications, maintain a blacklist of revoked tokens:

```javascript
const mongoose = require('mongoose');

const blacklistedTokenSchema = new mongoose.Schema({
  token: {
    type: String,
    required: true,
    unique: true
  },
  createdAt: {
    type: Date,
    default: Date.now,
    expires: '1h' // Automatically remove after token would have expired
  }
});

const BlacklistedToken = mongoose.model('BlacklistedToken', blacklistedTokenSchema);

module.exports = BlacklistedToken;
```

Add this check to your auth middleware:

```javascript
// Check if token is blacklisted
const isBlacklisted = await BlacklistedToken.findOne({ token });
if (isBlacklisted) {
  return next(new AppError('Invalid token. Please log in again.', 401));
}
```

### 5. Secure Headers

Set proper security headers with Helmet:

```bash
npm install helmet
```

```javascript
const helmet = require('helmet');
app.use(helmet());
```

### 6. HTTPS Only

Always use HTTPS in production. For local development, you can use a self-signed certificate.

## Complete Implementation Example

### Server Entry Point (server.js)

```javascript
const express = require('express');
const dotenv = require('dotenv');
const helmet = require('helmet');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const connectDB = require('./config/db');
const errorMiddleware = require('./middleware/errorMiddleware');
const authRoutes = require('./routes/authRoutes');
const userRoutes = require('./routes/userRoutes');

// Load environment variables
dotenv.config();

// Connect to database
connectDB();

// Initialize Express app
const app = express();

// Middleware
app.use(express.json());
app.use(cookieParser());
app.use(helmet());
app.use(cors({
  origin: process.env.CLIENT_URL || 'http://localhost:3000',
  credentials: true
}));

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);

// Error handling
app.use(errorMiddleware);

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
```

### Error Middleware (middleware/errorMiddleware.js)

```javascript
const AppError = require('../utils/AppError');

// Error handling middleware
const errorMiddleware = (err, req, res, next) => {
  let error = { ...err };
  error.message = err.message;
  error.statusCode = err.statusCode || 500;

  // Log error for development
  console.error(err);

  // Handle MongoDB duplicate key error
  if (err.code === 11000) {
    const field = Object.keys(err.keyValue)[0];
    const value = err.keyValue[field];
    const message = `Duplicate field value: ${field}. Please use another value!`;
    error = new AppError(message, 400);
  }

  // Handle Mongoose validation error
  if (err.name === 'ValidationError') {
    const errors = Object.values(err.errors).map(val => val.message);
    const message = `Invalid input data. ${errors.join('. ')}`;
    error = new AppError(message, 400);
  }

  // Handle JWT errors
  if (err.name === 'JsonWebTokenError') {
    error = new AppError('Invalid token. Please log in again!', 401);
  }

  if (err.name === 'TokenExpiredError') {
    error = new AppError('Your token has expired! Please log in again.', 401);
  }

  // Send error response
  res.status(error.statusCode).json({
    status: error.statusCode >= 500 ? 'error' : 'fail',
    message: error.statusCode >= 500 && process.env.NODE_ENV === 'production'
      ? 'Something went wrong'
      : error.message
  });
};

module.exports = errorMiddleware;
```

### Utility Functions

```javascript
// utils/catchAsync.js
module.exports = fn => {
  return (req, res, next) => {
    fn(req, res, next).catch(next);
  };
};

// utils/AppError.js
class AppError extends Error {
  constructor(message, statusCode) {
    super(message);
    this.statusCode = statusCode;
    this.status = `${statusCode}`.startsWith('4') ? 'fail' : 'error';
    this.isOperational = true;

    Error.captureStackTrace(this, this.constructor);
  }
}

module.exports = AppError;
```

### User Routes (routes/userRoutes.js)

```javascript
const express = require('express');
const userController = require('../controllers/userController');
const authMiddleware = require('../middleware/authMiddleware');

const router = express.Router();

// Protected routes
router.use(authMiddleware.protect);

// User profile route
router.get('/me', userController.getMe);
router.patch('/me', userController.updateMe);

// Admin only routes
router.use(authMiddleware.restrictTo('admin'));
router.route('/')
  .get(userController.getAllUsers)
  .post(userController.createUser);

router.route('/:id')
  .get(userController.getUser)
  .patch(userController.updateUser)
  .delete(userController.deleteUser);

module.exports = router;
```

### User Controller (controllers/userController.js)

```javascript
const User = require('../models/User');
const catchAsync = require('../utils/catchAsync');
const AppError = require('../utils/AppError');

// Get current user
exports.getMe = catchAsync(async (req, res, next) => {
  res.status(200).json({
    status: 'success',
    data: {
      user: req.user
    }
  });
});

// Update current user
exports.updateMe = catchAsync(async (req, res, next) => {
  // 1) Check if password update is attempted
  if (req.body.password) {
    return next(
      new AppError(
        'This route is not for password updates. Please use /updatePassword.',
        400
      )
    );
  }

  // 2) Filter out fields that should not be updated
  const allowedFields = ['username', 'email'];
  const filteredBody = {};
  Object.keys(req.body).forEach(key => {
    if (allowedFields.includes(key)) {
      filteredBody[key] = req.body[key];
    }
  });

  // 3) Update user document
  const updatedUser = await User.findByIdAndUpdate(
    req.user.id,
    filteredBody,
    {
      new: true,
      runValidators: true
    }
  );

  res.status(200).json({
    status: 'success',
    data: {
      user: updatedUser
    }
  });
});

// Admin controller methods for user management
exports.getAllUsers = catchAsync(async (req, res, next) => {
  const users = await User.find();

  res.status(200).json({
    status: 'success',
    results: users.length,
    data: {
      users
    }
  });
});

exports.getUser = catchAsync(async (req, res, next) => {
  const user = await User.findById(req.params.id);

  if (!user) {
    return next(new AppError('No user found with that ID', 404));
  }

  res.status(200).json({
    status: 'success',
    data: {
      user
    }
  });
});

exports.createUser = catchAsync(async (req, res, next) => {
  return next(
    new AppError('This route is not defined. Please use /signup instead', 400)
  );
});

exports.updateUser = catchAsync(async (req, res, next) => {
  const user = await User.findByIdAndUpdate(req.params.id, req.body, {
    new: true,
    runValidators: true
  });

  if (!user) {
    return next(new AppError('No user found with that ID', 404));
  }

  res.status(200).json({
    status: 'success',
    data: {
      user
    }
  });
});

exports.deleteUser = catchAsync(async (req, res, next) => {
  const user = await User.findByIdAndDelete(req.params.id);

  if (!user) {
    return next(new AppError('No user found with that ID', 404));
  }

  res.status(204).json({
    status: 'success',
    data: null
  });
});
```

## Testing Your JWT Implementation

### API Testing with Postman/Insomnia

1. Register a new user:
   - `POST /api/auth/register` with username, email, password
   - Save the returned access token

2. Access protected route:
   - Add Authorization header: `Bearer [your_access_token]`
   - `GET /api/users/me`

3. Test token expiration:
   - Wait for the access token to expire (15 minutes)
   - Try accessing the protected route
   - Use refresh token endpoint to get a new access token
   - Try with the new token

### Unit Testing

Using Jest and Supertest:

```bash
npm install jest supertest --save-dev
```

Create a test file for auth routes:

```javascript
const request = require('supertest');
const mongoose = require('mongoose');
const app = require('../server');
const User = require('../models/User');

// Clean up test database before tests
beforeAll(async () => {
  await User.deleteMany({});
});

// Clean up and disconnect after tests
afterAll(async () => {
  await User.deleteMany({});
  await mongoose.connection.close();
});

describe('Auth API', () => {
  let accessToken;
  let refreshToken;
  
  const testUser = {
    username: 'testuser',
    email: 'test@example.com',
    password: 'Password123!'
  };

  it('should register a new user', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send(testUser);
    
    expect(res.statusCode).toEqual(201);
    expect(res.body).toHaveProperty('data');
    expect(res.body.data).toHaveProperty('accessToken');
    expect(res.body.data.user).toHaveProperty('username', testUser.username);
    
    accessToken = res.body.data.accessToken;
    refreshToken = res.headers['set-cookie'][0]
      .split(';')[0]
      .split('=')[1];
  });

  it('should log in the user', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({
        email: testUser.email,
        password: testUser.password
      });
    
    expect(res.statusCode).toEqual(200);
    expect(res.body).toHaveProperty('data');
    expect(res.body.data).toHaveProperty('accessToken');
  });

  it('should access protected route with valid token', async () => {
    const res = await request(app)
      .get('/api/users/me')
      .set('Authorization', `Bearer ${accessToken}`);
    
    expect(res.statusCode).toEqual(200);
    expect(res.body.data.user).toHaveProperty('username', testUser.username);
  });

  it('should not access protected route without token', async () => {
    const res = await request(app)
      .get('/api/users/me');
    
    expect(res.statusCode).toEqual(401);
  });

  it('should refresh access token with valid refresh token', async () => {
    const res = await request(app)
      .post('/api/auth/refresh-token')
      .set('Cookie', `refreshToken=${refreshToken}`);
    
    expect(res.statusCode).toEqual(200);
    expect(res.body.data).toHaveProperty('accessToken');
  });

  it('should log out the user', async () => {
    const res = await request(app)
      .post('/api/auth/logout')
      .set('Cookie', `refreshToken=${refreshToken}`);
    
    expect(res.statusCode).toEqual(200);
    
    // Verify refresh token is no longer valid
    const refreshRes = await request(app)
      .post('/api/auth/refresh-token')
      .set('Cookie', `refreshToken=${refreshToken}`);
    
    expect(refreshRes.statusCode).toEqual(401);
  });
});
```

## Conclusion

This document provides a comprehensive implementation of JWT-based authentication for a Node.js application. Key points to remember:

1. Keep JWT secrets secure and separate for access and refresh tokens
2. Set appropriate expiration times for tokens
3. Store refresh tokens securely (HttpOnly cookies)
4. Implement token refresh mechanism
5. Apply proper security headers and HTTPS
6. Validate and sanitize all inputs
7. Handle errors gracefully

By following these practices, you'll have a secure, robust authentication system for your Node.js application.