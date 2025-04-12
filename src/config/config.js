const dotenv = require('dotenv');
const path = require('path');

// Load environment variables from .env file
dotenv.config({ path: path.resolve(__dirname, '../../.env') });

const config = {
  env: process.env.NODE_ENV || 'development',
  port: process.env.PORT || 3000,
  mongoose: {
    url: process.env.MONGODB_URI,
    options: {
      // Add Mongoose connection options if needed
      // useNewUrlParser: true, // Deprecated but keep for reference
      // useUnifiedTopology: true, // Deprecated but keep for reference
    },
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

if (!config.mongoose.url) {
    console.error('FATAL ERROR: MONGODB_URI is not defined.');
    process.exit(1);
}


module.exports = config;
