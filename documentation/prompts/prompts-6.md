Prompt 6: Testing Setup
Set up a comprehensive testing framework for our Node.js server:

1. Install testing dependencies:
   - Jest
   - Supertest
   - MongoDB memory server

2. Create test directory structure:
   /tests
     /unit
     /integration
     /fixtures
     setup.js

3. Implement test setup:
   - Database connection handling
   - Test environment variables
   - Global test hooks

4. Create authentication tests:
   - Registration flow
   - Login flow
   - Token refresh
   - Protected routes
   - Role-based access

5. Create user API tests:
   - User profile operations
   - Admin operations
   - Error cases

Include appropriate test fixtures and utilities for repeatable tests. Configure proper cleanup between tests to ensure isolation.
