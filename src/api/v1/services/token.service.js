const { getSupabaseClient } = require('../../../db/connect');
const logger = require('../../../utils/logger');

const TABLE_NAME = 'refresh_tokens'; // Make sure this matches your Supabase table name

/**
 * Saves a new refresh token to the database.
 * @param {string} userId - The ID of the user the token belongs to.
 * @param {string} token - The refresh token string.
 * @param {Date} expiresAt - The expiry date and time for the token.
 * @returns {Promise<object|null>} The saved token object or null on failure.
 */
const saveToken = async (userId, token, expiresAt) => {
  const supabase = getSupabaseClient();
  try {
    const { data, error } = await supabase
      .from(TABLE_NAME)
      .insert([{
        user_id: userId,
        token: token,
        expires_at: expiresAt.toISOString(), // Ensure correct format for TIMESTAMPTZ
      }])
      .select();

    if (error) {
      logger.error(`Supabase error saving token for user ${userId}: ${error.message}`, { code: error.code });
      throw new Error(`Failed to save refresh token: ${error.message}`);
    }
    return data ? data[0] : null;
  } catch (error) {
    logger.error(`Error in saveToken service for user ${userId}:`, error);
    throw error;
  }
};

/**
 * Finds a refresh token by its string value.
 * @param {string} token - The refresh token string.
 * @returns {Promise<object|null>} The token object including user_id or null if not found.
 */
const findToken = async (token) => {
  const supabase = getSupabaseClient();
  try {
    const { data, error } = await supabase
      .from(TABLE_NAME)
      .select('*')
      .eq('token', token)
      .maybeSingle();

    if (error) {
      logger.error(`Supabase error finding token: ${error.message}`);
      throw new Error(`Database error finding token: ${error.message}`);
    }
    return data; // Returns token object or null
  } catch (error) {
    logger.error('Error in findToken service:', error);
    throw error;
  }
};

/**
 * Removes a specific refresh token from the database.
 * @param {string} token - The refresh token string to remove.
 * @returns {Promise<boolean>} True if deletion was successful (or token didn't exist), false otherwise.
 */
const removeToken = async (token) => {
  const supabase = getSupabaseClient();
  try {
    const { error } = await supabase
      .from(TABLE_NAME)
      .delete()
      .eq('token', token);

    if (error) {
      logger.error(`Supabase error removing token: ${error.message}`);
      throw new Error(`Failed to remove refresh token: ${error.message}`);
    }
    return true; // Deletion successful or token didn't exist
  } catch (error) {
    logger.error('Error in removeToken service:', error);
    throw error;
  }
};

/**
 * Removes all refresh tokens associated with a specific user ID.
 * @param {string} userId - The ID of the user whose tokens should be removed.
 * @returns {Promise<boolean>} True if deletion was successful, false otherwise.
 */
const removeTokensByUserId = async (userId) => {
  const supabase = getSupabaseClient();
  try {
    const { error } = await supabase
      .from(TABLE_NAME)
      .delete()
      .eq('user_id', userId);

    if (error) {
      logger.error(`Supabase error removing tokens for user ${userId}: ${error.message}`);
      throw new Error(`Failed to remove refresh tokens for user: ${error.message}`);
    }
    return true;
  } catch (error) {
    logger.error(`Error in removeTokensByUserId service for user ${userId}:`, error);
    throw error;
  }
};


module.exports = {
  saveToken,
  findToken,
  removeToken,
  removeTokensByUserId,
};
