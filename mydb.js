
// db.js
require('dotenv').config();
const mongoose = require('mongoose');
const User = require('./models/User'); // Import the User model

const connectDB = async () => {
  try {
    const uri = 'mongodb+srv://aarronrahul:aot-tech%21%40%23123@passkey.j0cps.mongodb.net/?retryWrites=true&w=majority&appName=passkey';

    await mongoose.connect(uri, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });

    console.log('MongoDB Atlas connected successfully');
  } catch (error) {
    console.error('Error connecting to MongoDB Atlas:', error.message);
    process.exit(1); // Exit process with failure
  }
};



// Get user by email
async function getUserByEmail(email) {
    try {
        return await User.findOne({ email });
    } catch (error) {
        console.error('Error fetching user by email:', error);
        return null;
    }
}

// Create a new user
async function createUser(userId, email, passKey) {
    try {
        const user = new User({
            _id: userId,
            email,
            passKey,
        });
        await user.save();
        console.log('User created successfully');
        return user;
    } catch (error) {
        console.error('Error creating user:', error);
        throw error;
    }
}

// Update user counter
async function updateUserCounter(userId, newCounter) {
    try {
        const user = await User.findById(userId);
        if (!user) {
            throw new Error('User not found');
        }
        user.passKey.counter = newCounter;
        await user.save();
        console.log('User counter updated successfully');
    } catch (error) {
        console.error('Error updating user counter:', error);
        throw error;
    }
}

// Get user by ID
async function getUserById(userId) {
    try {
        return await User.findById(userId);
    } catch (error) {
        console.error('Error fetching user by ID:', error);
        return null;
    }
}

module.exports = {
    getUserByEmail,
    createUser,
    updateUserCounter,
    getUserById,
    connectDB
};

