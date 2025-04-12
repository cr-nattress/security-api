Prompt 3: Authentication Implementation
Implement JWT authentication for our Node.js server with these requirements:

1. Create authentication controller with:
   - Register endpoint
   - Login endpoint
   - Refresh token endpoint
   - Logout endpoint

2. Implement JWT middleware for:
   - Token verification
   - Role-based access control

3. Set up JWT configuration:
   - Generate access tokens (short-lived, 15min)
   - Generate refresh tokens (longer-lived, 7 days)
   - Verify tokens

4. Implement secure cookie handling for refresh tokens.

5. Set up proper error handling for authentication failures.

The implementation should follow security best practices including:
- No storing of raw passwords
- Proper token expiration
- HttpOnly cookies for refresh tokens
- CSRF protection
- Proper validation of all inputs

Use async/await pattern and ensure all error cases are properly handled.
