const bcrypt = require('bcryptjs');

const HASH_ROUNDS = 10; // Standard number of salt rounds

/**
 * Hashes a plain text password using bcrypt.
 * @param {string} password - The plain text password.
 * @returns {Promise<string>} The hashed password.
 */
const hashPassword = async (password) => {
  if (!password) {
    throw new Error('Password cannot be empty');
  }
  const salt = await bcrypt.genSalt(HASH_ROUNDS);
  const hashedPassword = await bcrypt.hash(password, salt);
  return hashedPassword;
};

/**
 * Compares a plain text password with a stored hash.
 * @param {string} plainPassword - The plain text password to check.
 * @param {string} hashedPassword - The stored hashed password.
 * @returns {Promise<boolean>} True if the passwords match, false otherwise.
 */
const comparePassword = async (plainPassword, hashedPassword) => {
  if (!plainPassword || !hashedPassword) {
    // Avoid unnecessary bcrypt computation if inputs are invalid
    return false;
  }
  return await bcrypt.compare(plainPassword, hashedPassword);
};

module.exports = {
  hashPassword,
  comparePassword,
};
