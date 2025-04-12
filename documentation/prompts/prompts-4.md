Prompt 4: User Routes and Controllers
Add user management functionality to our Node.js server:

1. Create user routes:
   - GET /api/v1/users/me (get current user profile)
   - PATCH /api/v1/users/me (update current user)
   - GET /api/v1/users (admin: get all users)
   - GET /api/v1/users/:id (admin: get user by ID)
   - PATCH /api/v1/users/:id (admin: update user)
   - DELETE /api/v1/users/:id (admin: delete user)

2. Implement user controller with:
   - Methods for each route
   - Proper input validation
   - Error handling
   - Authorization checks

3. Apply authentication middleware to all routes.

4. Implement role-based access control for admin routes.

5. Ensure proper filtering of sensitive information (no passwords) in responses.

Follow REST best practices with consistent response formats and proper HTTP status codes.
