const { createClient } = require('@supabase/supabase-js');
const config = require('../config/config');
const logger = require('../utils/logger');

let supabase;

const initializeDatabase = () => {
  try {
    if (!config.supabase.url || !config.supabase.anonKey) {
      throw new Error('Supabase URL or Anon Key is missing in configuration.');
    }

    supabase = createClient(config.supabase.url, config.supabase.anonKey);
    logger.info('Supabase client initialized successfully.');

    // Optional: Test connection by making a simple request, e.g., listing tables
    // This requires async handling if you want to test before returning.
    // Example (add async to initializeDatabase if using await here):
    // const { data, error } = await supabase.rpc('get_tables'); // Adjust based on Supabase setup
    // if (error) throw error;
    // logger.info('Supabase connection test successful.');

    return supabase; // Return the client instance

  } catch (error) {
    logger.error('Supabase initialization error:', error);
    process.exit(1); // Exit process with failure
  }
};

// Function to get the Supabase client instance
const getSupabaseClient = () => {
  if (!supabase) {
    logger.error('Supabase client requested before initialization.');
    // Ensure initializeDatabase is called at application startup
    throw new Error('Supabase client has not been initialized. Call initializeDatabase during application startup.');
  }
  return supabase;
};

module.exports = { initializeDatabase, getSupabaseClient }; // Export initialization function and getter
