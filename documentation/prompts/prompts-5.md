Prompt 5: Security Enhancements
Enhance the security of our Node.js server with the following implementations:

1. Implement Helmet.js configuration with:
   - Content Security Policy (CSP)
   - XSS Protection
   - Prevent MIME type sniffing
   - HTTP Strict Transport Security (HSTS)

2. Set up CORS with proper configuration:
   - Restricted origins list for production
   - Methods and headers control
   - Credentials handling

3. Implement rate limiting for:
   - API endpoints (general)
   - Authentication endpoints (more strict)

4. Add input validation and sanitization for all routes using express-validator.

5. Set up proper logging for security events:
   - Authentication attempts
   - Authorization failures
   - Rate limit triggers
   - Suspicious activity patterns

Each security measure should have appropriate configuration for both development and production environments.