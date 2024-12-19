const mongoose = require('mongoose');

const passKeySchema = new mongoose.Schema({
    id: String,
    publicKey: Buffer,
    counter: Number,
    deviceType: String,
    backedUp: Boolean,
    transport: [String],
});

const userSchema = new mongoose.Schema({
    _id: String, // Explicitly define _id as a String
    email: { type: String, required: true, unique: true },
    passKey: passKeySchema,
});

module.exports = mongoose.model('User', userSchema);

