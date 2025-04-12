// src/api/v1/routes/auth.routes.js

const express = require('express');
const { body, validationResult } = require('express-validator');
const authController = require('../controllers/auth.controller');
const { authenticateToken } = require('../middlewares/auth.middleware'); // Only needed if protecting e.g. logout

const router = express.Router();

// Middleware to handle validation errors
const validate = (req, res, next) => {
  const errors = validationResult(req);
  if (errors.isEmpty()) {
    return next();
  }
  // Extract specific error messages for better client feedback
  const extractedErrors = [];
  errors.array().map(err => extractedErrors.push({ [err.path]: err.msg }));

  return res.status(400).json({
    errors: extractedErrors,
  });
};

// Validation rules for registration
const registerValidationRules = [
  body('email').isEmail().withMessage('Must be a valid email address').normalizeEmail(),
  body('username').isLength({ min: 3 }).withMessage('Username must be at least 3 characters long').trim().escape(),
  body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters long')
  // Optional: Add password complexity rules here if desired
  // .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$/)
  // .withMessage('Password must contain uppercase, lowercase, number, and special character'),
  // Optional: Validate 'role' if provided, ensuring it's 'user' or 'admin'
  // body('role').optional().isIn(['user', 'admin']).withMessage('Invalid role specified')
];

// Validation rules for login
const loginValidationRules = [
  body('email').isEmail().withMessage('Must be a valid email address').normalizeEmail(),
  body('password').notEmpty().withMessage('Password is required'),
];

// --- Routes ---

// POST /api/v1/auth/register
router.post(
    '/register',
    registerValidationRules,
    validate, // Apply validation middleware
    authController.register
);

// POST /api/v1/auth/login
router.post(
    '/login',
    loginValidationRules,
    validate, // Apply validation middleware
    authController.login
);

// POST /api/v1/auth/refresh
// No validation needed as it relies on the cookie
router.post('/refresh', authController.refresh);

// POST /api/v1/auth/logout
// Optionally protect this route to ensure only authenticated users can trigger their own logout
// router.post('/logout', authenticateToken, authController.logout);
// For simplicity, allowing logout without strict auth - clearing cookie is main action
router.post('/logout', authController.logout);


module.exports = router;
