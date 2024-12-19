const mongoose = require('mongoose');
const User = require('./models/User'); // Import the User model

// Function to connect to MongoDB Atlas
const connectDB = async () => {
  try {
    await mongoose.connect('mongodb+srv://aarronrahul:aot-tech%21%40%23123@passkey.j0cps.mongodb.net/?retryWrites=true&w=majority&appName=passkey', {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log('MongoDB connected successfully');
  } catch (err) {
    console.error('MongoDB connection failed:', err.message);
    process.exit(1); // Exit process with failure
  }
};

// Database functions
async function getUserByEmail(email) {
  return await User.findOne({ email });
}

async function getUserById(id) {
  return await User.findById(id);
}

const createUser = async (id, email, passKey) => {
  try {
    const user = new User({
      _id: id, // Ensure the ID is passed as a string
      email,
      passKey,
    });
    await user.save();
    return user;
  } catch (error) {
    throw new Error(`Failed to create user: ${error.message}`);
  }
};

async function updateUserCounter(id, counter) {
  const user = await User.findById(id);
  if (user) {
    user.passKey.counter = counter;
    await user.save();
  }
}

// Export connection and functions
module.exports = {
  connectDB,
  getUserByEmail,
  getUserById,
  createUser,
  updateUserCounter,
};
