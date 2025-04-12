// src/api/v1/middlewares/auth.middleware.js

const { verifyAccessToken } = require('../../../utils/jwt.utils');
const logger = require('../../../utils/logger');
const userService = require('../services/user.service'); // Needed to check if user still exists

/**
 * Middleware to verify JWT access token.
 * Attaches user payload to req.user if token is valid.
 */
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.startsWith('Bearer ') && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Access token required' }); // Unauthorized
  }

  try {
    const decoded = await verifyAccessToken(token);

    // Optional: Check if the user associated with the token still exists in the DB
    // This prevents access if a user was deleted after the token was issued.
    const userExists = await userService.findUserById(decoded.id);
    if (!userExists) {
        logger.warn(`Authentication attempt for non-existent user ID: ${decoded.id}`);
        return res.status(401).json({ message: 'User not found' }); // Unauthorized
    }

    // Attach user info (id, role) to the request object
    req.user = { id: decoded.id, role: decoded.role };
    next(); // Proceed to the next middleware or route handler
  } catch (error) {
    logger.warn(`Token authentication failed: ${error.message}`);
    // Handle specific JWT errors
    if (error.message === 'Access token expired') {
        return res.status(401).json({ message: 'Access token expired' }); // Unauthorized
    }
    return res.status(403).json({ message: 'Invalid access token' }); // Forbidden
  }
};

/**
 * Middleware factory to check if the user has one of the required roles.
 * Must be used *after* authenticateToken middleware.
 * @param {string[]} requiredRoles - Array of roles allowed to access the route.
 */
const authorizeRole = (requiredRoles) => {
  return (req, res, next) => {
    if (!req.user || !req.user.role) {
      // This should technically not happen if authenticateToken runs first
      logger.error('Authorization check failed: req.user not set');
      return res.status(403).json({ message: 'Forbidden: User role not available' });
    }

    const hasRequiredRole = requiredRoles.includes(req.user.role);

    if (!hasRequiredRole) {
      logger.warn(`Authorization failed: User ${req.user.id} (role: ${req.user.role}) attempted access to route requiring roles [${requiredRoles.join(', ')}]`);
      return res.status(403).json({ message: 'Forbidden: Insufficient permissions' });
    }

    next(); // User has the required role, proceed
  };
};


module.exports = {
  authenticateToken,
  authorizeRole,
};
