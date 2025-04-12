// src/api/v1/controllers/user.controller.js

const userService = require('../services/user.service');
const logger = require('../../../utils/logger');

/**
 * Get the profile of the currently authenticated user.
 */
const getMe = async (req, res) => {
    // req.user is attached by the authenticateToken middleware
    const userId = req.user.id;
    try {
        // User service already fetches without password
        const user = await userService.findUserById(userId);
        if (!user) {
            // Should not happen if token is valid and user exists check passed in middleware
            logger.error(`User ${userId} not found in getMe despite valid token.`);
            return res.status(404).json({ message: 'User not found' });
        }
        res.status(200).json(user);
    } catch (error) {
        logger.error(`Error fetching profile for user ${userId}:`, error);
        res.status(500).json({ message: 'Failed to fetch user profile' });
    }
};

/**
 * Update the profile of the currently authenticated user.
 */
const updateMe = async (req, res) => {
    const userId = req.user.id;
    const { username, email } = req.body; // Only allow updating username/email for self

    // Basic validation: ensure at least one field is provided
    if (username === undefined && email === undefined) {
        return res.status(400).json({ message: 'No update fields provided (allowed: username, email)' });
    }

    const updateData = {};
    if (username !== undefined) updateData.username = username;
    if (email !== undefined) updateData.email = email;

    try {
        const updatedUser = await userService.updateUserById(userId, updateData);
        if (!updatedUser) {
             // Could be not found or unique constraint violation handled by service
            return res.status(404).json({ message: 'User not found or update failed' });
        }
        res.status(200).json(updatedUser);
    } catch (error) {
        logger.error(`Error updating profile for user ${userId}:`, error);
         // Check for specific errors thrown by the service (like unique constraint)
        if (error.message.includes('Update failed:')) {
             return res.status(409).json({ message: error.message }); // Conflict
        }
        res.status(500).json({ message: 'Failed to update user profile' });
    }
};

// --- Admin Only Routes ---

/**
 * Get all users (Admin only).
 */
const getUsers = async (req, res) => {
    try {
        const users = await userService.getAllUsers();
        res.status(200).json(users);
    } catch (error) {
        logger.error('Error fetching all users (admin):', error);
        res.status(500).json({ message: 'Failed to fetch users' });
    }
};

/**
 * Get a specific user by ID (Admin only).
 */
const getUser = async (req, res) => {
    const { id } = req.params;
    try {
        const user = await userService.findUserById(id);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        res.status(200).json(user);
    } catch (error) {
        logger.error(`Error fetching user ${id} (admin):`, error);
        res.status(500).json({ message: 'Failed to fetch user' });
    }
};

/**
 * Update a user by ID (Admin only).
 */
const updateUser = async (req, res) => {
    const { id } = req.params;
    const { username, email, role } = req.body; // Admins can update username, email, role

    // Basic validation
    if (username === undefined && email === undefined && role === undefined) {
        return res.status(400).json({ message: 'No update fields provided (allowed: username, email, role)' });
    }
    // Add more specific validation if needed (e.g., role is valid)

    const updateData = {};
    if (username !== undefined) updateData.username = username;
    if (email !== undefined) updateData.email = email;
    if (role !== undefined) updateData.role = role;

    try {
        const updatedUser = await userService.updateUserById(id, updateData);
        if (!updatedUser) {
            // Could be not found or unique constraint violation handled by service
            return res.status(404).json({ message: 'User not found or update failed' });
        }
        res.status(200).json(updatedUser);
    } catch (error) {
        logger.error(`Error updating user ${id} (admin):`, error);
        // Check for specific errors thrown by the service
        if (error.message.includes('Update failed:')) {
             return res.status(409).json({ message: error.message }); // Conflict
        }
        res.status(500).json({ message: 'Failed to update user' });
    }
};

/**
 * Delete a user by ID (Admin only).
 */
const deleteUser = async (req, res) => {
    const { id } = req.params;

    // Optional: Prevent admin from deleting themselves?
    // if (id === req.user.id) {
    //     return res.status(400).json({ message: "Cannot delete your own account via this endpoint." });
    // }

    try {
        // Check if user exists first for a clearer 404
        const userExists = await userService.findUserById(id);
        if (!userExists) {
             return res.status(404).json({ message: 'User not found' });
        }

        const success = await userService.deleteUserById(id);
        if (!success) {
             // Should not happen if existence check passed and service handles errors, but good failsafe
            return res.status(500).json({ message: 'Failed to delete user' });
        }
        // Standard practice for DELETE is often 204 No Content on success
        res.status(204).send();
    } catch (error) {
        logger.error(`Error deleting user ${id} (admin):`, error);
        res.status(500).json({ message: 'Failed to delete user' });
    }
};


module.exports = {
    getMe,
    updateMe,
    getUsers,
    getUser,
    updateUser,
    deleteUser,
};
