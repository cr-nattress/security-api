const jwt = require('jsonwebtoken');
const config = require('../config/config');
const logger = require('./logger');

const ACCESS_TOKEN_SECRET = config.jwt.secret;
const REFRESH_TOKEN_SECRET = config.jwt.secret; // Using the same secret for simplicity, consider a separate one for production
const ACCESS_TOKEN_EXPIRY = config.jwt.expiresIn || '15m'; // Default to 15 minutes
const REFRESH_TOKEN_EXPIRY = '7d'; // Standard 7 days for refresh tokens

/**
 * Generates a JWT Access Token.
 * @param {object} payload - Data to include in the token (e.g., { id, role }).
 * @returns {string} The generated access token.
 */
const generateAccessToken = (payload) => {
  if (!ACCESS_TOKEN_SECRET) {
    throw new Error('JWT_SECRET is not defined for access token.');
  }
  return jwt.sign(payload, ACCESS_TOKEN_SECRET, { expiresIn: ACCESS_TOKEN_EXPIRY });
};

/**
 * Generates a JWT Refresh Token.
 * @param {object} payload - Data to include in the token (e.g., { id }).
 * @returns {string} The generated refresh token.
 */
const generateRefreshToken = (payload) => {
  if (!REFRESH_TOKEN_SECRET) {
    throw new Error('JWT_SECRET is not defined for refresh token.');
  }
  return jwt.sign(payload, REFRESH_TOKEN_SECRET, { expiresIn: REFRESH_TOKEN_EXPIRY });
};

/**
 * Verifies a JWT Access Token.
 * @param {string} token - The access token to verify.
 * @returns {Promise<object>} The decoded payload if verification is successful.
 * @throws {Error} If verification fails (e.g., expired, invalid signature).
 */
const verifyAccessToken = (token) => {
  return new Promise((resolve, reject) => {
    if (!ACCESS_TOKEN_SECRET) {
      return reject(new Error('JWT_SECRET is not defined for access token verification.'));
    }
    jwt.verify(token, ACCESS_TOKEN_SECRET, (err, decoded) => {
      if (err) {
        logger.warn(`Access token verification failed: ${err.message}`);
        // Standardize error messages slightly
        if (err.name === 'TokenExpiredError') {
            return reject(new Error('Access token expired'));
        }
        return reject(new Error('Invalid access token'));
      }
      resolve(decoded);
    });
  });
};

/**
 * Verifies a JWT Refresh Token.
 * @param {string} token - The refresh token to verify.
 * @returns {Promise<object>} The decoded payload if verification is successful.
 * @throws {Error} If verification fails (e.g., expired, invalid signature).
 */
const verifyRefreshToken = (token) => {
  return new Promise((resolve, reject) => {
    if (!REFRESH_TOKEN_SECRET) {
      return reject(new Error('JWT_SECRET is not defined for refresh token verification.'));
    }
    jwt.verify(token, REFRESH_TOKEN_SECRET, (err, decoded) => {
      if (err) {
        logger.warn(`Refresh token verification failed: ${err.message}`);
        if (err.name === 'TokenExpiredError') {
            return reject(new Error('Refresh token expired'));
        }
        return reject(new Error('Invalid refresh token'));
      }
      resolve(decoded);
    });
  });
};

module.exports = {
  generateAccessToken,
  generateRefreshToken,
  verifyAccessToken,
  verifyRefreshToken,
  REFRESH_TOKEN_EXPIRY // Export expiry duration string if needed elsewhere
};
