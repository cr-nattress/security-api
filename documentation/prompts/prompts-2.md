Prompt 2: Database Configuration and Models
Building on our Node.js Express server, implement the database layer with the following:

1. Create a database connection module in /db/index.js that connects to MongoDB using mongoose.

2. Implement the user model with:
   - Username (required, unique)
   - Email (required, unique, validated)
   - Password (required, hashed using bcrypt)
   - Role (enum: ['user', 'admin'], default: 'user')
   - Created/Updated timestamps

3. If implementing refresh tokens, create a token model with:
   - User ID reference
   - Token string
   - Expiry date
   - Created timestamp

4. Set up proper pre-save hooks for password hashing.

5. Create model methods for password comparison.

Ensure all models follow best practices for data validation, indexing, and security. Include appropriate error handling for database operations.
