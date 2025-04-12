const userService = require('../services/user.service');
const tokenService = require('../services/token.service');
const { comparePassword } = require('../../../utils/password.utils');
const {
  generateAccessToken,
  generateRefreshToken,
  verifyRefreshToken,
  REFRESH_TOKEN_EXPIRY
} = require('../../../utils/jwt.utils');
const logger = require('../../../utils/logger');
const config = require('../../../config/config');
const ms = require('ms');

const REFRESH_TOKEN_COOKIE = 'refreshToken';

/**
 * Handles user registration.
 * @param {object} req - Express request object.
 * @param {object} res - Express response object.
 */
const register = async (req, res) => {
  const { username, email, password, role } = req.body; // Role is optional

  try {
    // Input validation should be handled by middleware before this point
    const newUser = await userService.createUser({ username, email, password, role });

    // Respond successfully (don't send back password hash)
    // Consider what user info is appropriate to return on registration
    res.status(201).json({
      message: 'User registered successfully',
      user: {
        id: newUser.id,
        username: newUser.username,
        email: newUser.email,
        role: newUser.role,
        created_at: newUser.created_at,
      },
    });
  } catch (error) {
    logger.error('Registration error:', error);
    // Check for specific error types (e.g., duplicate user)
    if (error.message.includes('already exists')) {
        return res.status(409).json({ message: error.message }); // Conflict
    }
    res.status(500).json({ message: 'Failed to register user' });
  }
};

/**
 * Handles user login.
 * @param {object} req - Express request object.
 * @param {object} res - Express response object.
 */
const login = async (req, res) => {
  const { email, password } = req.body; // Can adapt to accept username too if needed

  try {
    // Input validation handled by middleware
    const user = await userService.findUserByEmail(email);

    if (!user) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    const isPasswordValid = await comparePassword(password, user.password);

    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    // Generate tokens
    const accessTokenPayload = { id: user.id, role: user.role };
    const refreshTokenPayload = { id: user.id }; // Keep refresh token payload minimal

    const accessToken = generateAccessToken(accessTokenPayload);
    const refreshToken = generateRefreshToken(refreshTokenPayload);

    // Store refresh token in database
    const refreshTokenExpiryDate = new Date(Date.now() + ms(REFRESH_TOKEN_EXPIRY));
    await tokenService.saveToken(user.id, refreshToken, refreshTokenExpiryDate);

    // Set refresh token in secure cookie
    res.cookie(REFRESH_TOKEN_COOKIE, refreshToken, {
      httpOnly: true, // Prevent client-side JS access
      secure: config.env === 'production', // Send only over HTTPS in production
      sameSite: 'strict', // Mitigate CSRF attacks
      maxAge: ms(REFRESH_TOKEN_EXPIRY), // Cookie expiry in milliseconds
      // path: '/api/v1/auth', // Optional: Scope cookie to auth routes
    });

    // Send access token and user info in response body
    res.status(200).json({
      message: 'Login successful',
      accessToken,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
      },
    });

  } catch (error) {
    logger.error('Login error:', error);
    res.status(500).json({ message: 'Login failed' });
  }
};

/**
 * Handles refreshing the access token using a refresh token.
 * @param {object} req - Express request object.
 * @param {object} res - Express response object.
 */
const refresh = async (req, res) => {
  const incomingRefreshToken = req.cookies[REFRESH_TOKEN_COOKIE];

  if (!incomingRefreshToken) {
    return res.status(401).json({ message: 'Refresh token not found' });
  }

  try {
    // 1. Verify the incoming refresh token
    const decoded = await verifyRefreshToken(incomingRefreshToken);

    // 2. Check if the token exists in the database (it might have been revoked/logged out)
    const storedToken = await tokenService.findToken(incomingRefreshToken);
    if (!storedToken) {
        logger.warn(`Attempted refresh with revoked/invalid token for user ID ${decoded.id}`);
        // Clear potentially invalid cookie
        res.clearCookie(REFRESH_TOKEN_COOKIE, { httpOnly: true, secure: config.env === 'production', sameSite: 'strict' });
        return res.status(403).json({ message: 'Invalid or expired refresh token' });
    }

    // 3. Check if token belongs to the user specified in the payload (redundant if findToken worked, but safe)
    if (storedToken.user_id !== decoded.id) {
        logger.error(`Refresh token user mismatch: decoded=${decoded.id}, stored=${storedToken.user_id}`);
        res.clearCookie(REFRESH_TOKEN_COOKIE, { httpOnly: true, secure: config.env === 'production', sameSite: 'strict' });
        return res.status(403).json({ message: 'Token mismatch' });
    }

    // 4. Find the user associated with the token
    const user = await userService.findUserById(decoded.id);
    if (!user) {
      logger.warn(`User not found for valid refresh token: user ID ${decoded.id}`);
      res.clearCookie(REFRESH_TOKEN_COOKIE, { httpOnly: true, secure: config.env === 'production', sameSite: 'strict' });
      return res.status(403).json({ message: 'User not found' });
    }

    // 5. Generate a new access token
    const accessTokenPayload = { id: user.id, role: user.role };
    const newAccessToken = generateAccessToken(accessTokenPayload);

    // Optional: Implement Refresh Token Rotation here if desired
    // - Generate new refresh token
    // - Store new refresh token in DB (replace or add)
    // - Remove old refresh token from DB
    // - Set new refresh token in cookie

    res.status(200).json({
      accessToken: newAccessToken,
    });

  } catch (error) {
    logger.error('Token refresh error:', error);
    // Clear cookie on verification failure
    res.clearCookie(REFRESH_TOKEN_COOKIE, { httpOnly: true, secure: config.env === 'production', sameSite: 'strict' });
    res.status(403).json({ message: error.message || 'Invalid or expired refresh token' });
  }
};

/**
 * Handles user logout.
 * @param {object} req - Express request object.
 * @param {object} res - Express response object.
 */
const logout = async (req, res) => {
  const incomingRefreshToken = req.cookies[REFRESH_TOKEN_COOKIE];

  // Clear the cookie regardless of whether the token exists in DB
  res.clearCookie(REFRESH_TOKEN_COOKIE, {
    httpOnly: true,
    secure: config.env === 'production',
    sameSite: 'strict',
  });

  if (!incomingRefreshToken) {
    // If no token, user is effectively logged out already
    return res.status(200).json({ message: 'Logout successful (no token found)' });
  }

  try {
    // Attempt to remove the token from the database
    await tokenService.removeToken(incomingRefreshToken);
    res.status(200).json({ message: 'Logout successful' });
  } catch (error) {
    // Log error but still respond successfully as cookie is cleared
    logger.error('Error removing refresh token during logout:', error);
    res.status(200).json({ message: 'Logout successful (error clearing token from DB)' });
  }
};


module.exports = {
  register,
  login,
  refresh,
  logout,
};
