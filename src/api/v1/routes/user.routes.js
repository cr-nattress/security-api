// src/api/v1/routes/user.routes.js

const express = require('express');
const { body, param, validationResult } = require('express-validator');
const userController = require('../controllers/user.controller');
const { authenticateToken, authorizeRole } = require('../middlewares/auth.middleware');

const router = express.Router();

// Middleware to handle validation errors (similar to auth.routes.js)
const validate = (req, res, next) => {
  const errors = validationResult(req);
  if (errors.isEmpty()) {
    return next();
  }
  const extractedErrors = [];
  errors.array().map(err => extractedErrors.push({ [err.path]: err.msg }));
  return res.status(400).json({ errors: extractedErrors });
};

// Validation rules for updating 'me'
const updateMeValidationRules = [
    body('username').optional().isLength({ min: 3 }).withMessage('Username must be at least 3 characters long').trim().escape(),
    body('email').optional().isEmail().withMessage('Must be a valid email address').normalizeEmail(),
    // Ensure at least one field is present (handled in controller, but could add custom validator here)
];

// Validation rules for updating any user (admin)
const updateUserValidationRules = [
    param('id').isUUID().withMessage('User ID must be a valid UUID'),
    body('username').optional().isLength({ min: 3 }).withMessage('Username must be at least 3 characters long').trim().escape(),
    body('email').optional().isEmail().withMessage('Must be a valid email address').normalizeEmail(),
    body('role').optional().isIn(['user', 'admin']).withMessage('Role must be either user or admin'),
];

// Validation for routes with user ID in params
const userIdParamValidation = [
    param('id').isUUID().withMessage('User ID must be a valid UUID'),
];


// --- Apply authentication middleware to ALL user routes ---
router.use(authenticateToken);

// --- User-specific routes ---

// GET /api/v1/users/me
router.get('/me', userController.getMe);

// PATCH /api/v1/users/me
router.patch(
    '/me',
    updateMeValidationRules,
    validate,
    userController.updateMe
);


// --- Admin-only routes ---

// Apply admin authorization middleware to subsequent routes
router.use(authorizeRole(['admin']));

// GET /api/v1/users
router.get('/', userController.getUsers);

// GET /api/v1/users/:id
router.get(
    '/:id',
    userIdParamValidation,
    validate,
    userController.getUser
);

// PATCH /api/v1/users/:id
router.patch(
    '/:id',
    updateUserValidationRules, // Includes param validation
    validate,
    userController.updateUser
);

// DELETE /api/v1/users/:id
router.delete(
    '/:id',
    userIdParamValidation,
    validate,
    userController.deleteUser
);


module.exports = router;
