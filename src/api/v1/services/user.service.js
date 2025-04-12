const { getSupabaseClient } = require('../../../db/connect');
const { hashPassword } = require('../../../utils/password.utils');
const logger = require('../../../utils/logger');

const TABLE_NAME = 'users'; // Make sure this matches your Supabase table name

/**
 * Creates a new user in the database after hashing their password.
 * @param {object} userData - User data.
 * @param {string} userData.username - The username.
 * @param {string} userData.email - The user's email.
 * @param {string} userData.password - The plain text password.
 * @param {string} [userData.role='user'] - The user's role (defaults if not provided, but Supabase default is preferred).
 * @returns {Promise<object|null>} The created user object (excluding password) or null if creation failed.
 */
const createUser = async (userData) => {
  const supabase = getSupabaseClient();
  const { username, email, password, role } = userData;

  try {
    // Hash the password before storing
    const hashedPassword = await hashPassword(password);

    // Prepare data for Supabase, ensuring role defaults if necessary
    const userToInsert = {
      username,
      email,
      password: hashedPassword,
      // Include role only if provided, otherwise rely on Supabase default
      ...(role && { role }),
    };

    const { data, error } = await supabase
      .from(TABLE_NAME)
      .insert([userToInsert])
      .select('id, username, email, role, created_at'); // Exclude password from selection

    if (error) {
      // Log Supabase specific errors
      logger.error(`Supabase error creating user (${email}): ${error.message}`, { code: error.code, details: error.details });
      // Handle specific errors like unique constraint violation (code 23505 in Postgres)
      if (error.code === '23505') {
        throw new Error(`User with that email or username already exists.`);
      }
      throw new Error(`Failed to create user: ${error.message}`);
    }

    return data ? data[0] : null;

  } catch (error) {
    // Log any other errors (e.g., from hashing)
    logger.error(`Error in createUser service for ${email}:`, error);
    // Re-throw the potentially more user-friendly error from above or a generic one
    throw error; 
  }
};

/**
 * Finds a user by their email.
 * @param {string} email - The user's email.
 * @returns {Promise<object|null>} The user object or null if not found.
 */
const findUserByEmail = async (email) => {
  const supabase = getSupabaseClient();
  try {
    const { data, error } = await supabase
      .from(TABLE_NAME)
      .select('*') // Select all fields for internal use (e.g., password for comparison)
      .eq('email', email)
      .maybeSingle(); // Returns null if no user, throws error only for db issues

    if (error) {
      logger.error(`Supabase error finding user by email (${email}): ${error.message}`);
      throw new Error(`Database error finding user: ${error.message}`);
    }
    return data; // Returns user object or null
  } catch (error) {
    logger.error(`Error in findUserByEmail service for ${email}:`, error);
    throw error;
  }
};

/**
 * Finds a user by their username.
 * @param {string} username - The user's username.
 * @returns {Promise<object|null>} The user object or null if not found.
 */
const findUserByUsername = async (username) => {
  const supabase = getSupabaseClient();
  try {
    const { data, error } = await supabase
      .from(TABLE_NAME)
      .select('*')
      .eq('username', username)
      .maybeSingle();

    if (error) {
      logger.error(`Supabase error finding user by username (${username}): ${error.message}`);
      throw new Error(`Database error finding user: ${error.message}`);
    }
    return data;
  } catch (error) {
    logger.error(`Error in findUserByUsername service for ${username}:`, error);
    throw error;
  }
};

/**
 * Finds a user by their ID.
 * @param {string} id - The user's ID (usually UUID).
 * @returns {Promise<object|null>} The user object or null if not found.
 */
const findUserById = async (id) => {
  const supabase = getSupabaseClient();
  try {
    const { data, error } = await supabase
      .from(TABLE_NAME)
      .select('id, username, email, role, created_at') // Exclude password hash
      .eq('id', id)
      .maybeSingle();

    if (error) {
      logger.error(`Supabase error finding user by ID (${id}): ${error.message}`);
      throw new Error(`Database error finding user: ${error.message}`);
    }
    return data;
  } catch (error) {
    logger.error(`Error in findUserById service for ${id}:`, error);
    throw error;
  }
};


module.exports = {
  createUser,
  findUserByEmail,
  findUserByUsername,
  findUserById,
  // Add other user-related database functions here
};
