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
 * Finds a user by their unique ID.
 * @param {string} userId - The ID of the user.
 * @returns {Promise<object|null>} The user object (excluding password) or null if not found.
 */
const findUserById = async (userId) => {
  const supabase = getSupabaseClient();
  try {
    const { data, error } = await supabase
      .from(TABLE_NAME)
      .select('id, username, email, role, created_at, updated_at') // Exclude password
      .eq('id', userId)
      .maybeSingle(); // Returns single object or null

    if (error) {
      logger.error(`Supabase error finding user by ID ${userId}: ${error.message}`, { code: error.code });
      throw new Error(`Database error finding user by ID: ${error.message}`);
    }
    return data;
  } catch (error) {
    logger.error(`Error in findUserById service for ID ${userId}:`, error);
    throw error;
  }
};

/**
 * Retrieves all users from the database.
 * @returns {Promise<Array<object>>} An array of user objects (excluding passwords).
 */
const getAllUsers = async () => {
  const supabase = getSupabaseClient();
  try {
    const { data, error } = await supabase
      .from(TABLE_NAME)
      .select('id, username, email, role, created_at, updated_at'); // Exclude password

    if (error) {
      logger.error(`Supabase error getting all users: ${error.message}`, { code: error.code });
      throw new Error(`Database error getting all users: ${error.message}`);
    }
    return data || []; // Return data or empty array if null
  } catch (error) {
    logger.error('Error in getAllUsers service:', error);
    throw error;
  }
};

/**
 * Updates a user's details by their ID.
 * Does not handle password updates.
 * @param {string} userId - The ID of the user to update.
 * @param {object} updateData - An object containing the fields to update (e.g., { username, email, role }).
 * @returns {Promise<object|null>} The updated user object (excluding password) or null if not found/error.
 */
const updateUserById = async (userId, updateData) => {
  const supabase = getSupabaseClient();
  const allowedUpdates = {};

  // Filter out password or other non-updatable fields
  if (updateData.username !== undefined) allowedUpdates.username = updateData.username;
  if (updateData.email !== undefined) allowedUpdates.email = updateData.email;
  if (updateData.role !== undefined) allowedUpdates.role = updateData.role; // Admins might update roles

  // Ensure updated_at is handled by the trigger, no need to set it here

  if (Object.keys(allowedUpdates).length === 0) {
    logger.warn(`No valid fields provided for user update: ${userId}`);
    return null; // Or throw an error? Returning the existing user might be better?
    // Let's refetch the user to return current state if no updates applied
    // return findUserById(userId);
  }

  try {
    const { data, error } = await supabase
      .from(TABLE_NAME)
      .update(allowedUpdates)
      .eq('id', userId)
      .select('id, username, email, role, created_at, updated_at'); // Return updated user data (excluding password)

    if (error) {
      // Check for unique constraint violation (e.g., email/username already exists)
      if (error.code === '23505') { // PostgreSQL unique violation code
          logger.warn(`Update failed for user ${userId} due to unique constraint: ${error.details}`);
          throw new Error(`Update failed: ${error.details}`); // More specific error
      }
      logger.error(`Supabase error updating user ${userId}: ${error.message}`, { code: error.code });
      throw new Error(`Database error updating user: ${error.message}`);
    }

    if (!data || data.length === 0) {
        logger.warn(`Attempted to update non-existent user: ${userId}`);
        return null; // User not found
    }

    return data[0]; // Return the updated user
  } catch (error) {
    logger.error(`Error in updateUserById service for ID ${userId}:`, error);
    throw error; // Re-throw original or new Error
  }
};

/**
 * Deletes a user by their ID.
 * @param {string} userId - The ID of the user to delete.
 * @returns {Promise<boolean>} True if deletion was successful, false otherwise.
 */
const deleteUserById = async (userId) => {
  const supabase = getSupabaseClient();
  try {
    // Supabase delete doesn't typically return the count or data easily without specific select
    // We check the error status
    const { error } = await supabase
      .from(TABLE_NAME)
      .delete()
      .eq('id', userId);

    if (error) {
      logger.error(`Supabase error deleting user ${userId}: ${error.message}`, { code: error.code });
      throw new Error(`Database error deleting user: ${error.message}`);
    }

    // Since Supabase delete doesn't throw an error if the row doesn't exist,
    // we assume success if no error occurred. A prior check (e.g., findUserById)
    // might be needed in the controller if strict confirmation of existence is required.
    return true;

  } catch (error) {
    logger.error(`Error in deleteUserById service for ID ${userId}:`, error);
    return false; // Return false on failure
  }
};

module.exports = {
  createUser,
  findUserByEmail,
  findUserByUsername,
  findUserById,
  getAllUsers,
  updateUserById,
  deleteUserById
};
