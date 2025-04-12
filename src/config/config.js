const dotenv = require('dotenv');
const path = require('path');

// Load environment variables from .env file
dotenv.config({ path: path.resolve(__dirname, '../../.env') });

const config = {
  env: process.env.NODE_ENV || 'development',
  port: process.env.PORT || 3000,
  supabase: {
    url: process.env.SUPABASE_URL,
    anonKey: process.env.SUPABASE_ANON_KEY,
  },
  jwt: {
    secret: process.env.JWT_SECRET,
    expiresIn: process.env.JWT_EXPIRES_IN || '1h',
  },
  logLevel: process.env.LOG_LEVEL || 'info',
};

// Validate essential configuration
if (!config.jwt.secret) {
  console.error('FATAL ERROR: JWT_SECRET is not defined.');
  process.exit(1);
}

if (!config.supabase.url) {
    console.error('FATAL ERROR: SUPABASE_URL is not defined.');
    process.exit(1);
}

if (!config.supabase.anonKey) {
    console.error('FATAL ERROR: SUPABASE_ANON_KEY is not defined.');
    process.exit(1);
}

module.exports = config;
