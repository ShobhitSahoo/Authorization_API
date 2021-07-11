const mongoose = require('mongoose');
const validator = require('validator');

const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: [true, 'Please specify your name.']
    },
    email : {
        type: String,
        required: [true, 'Please specify your email address.'],
        unique: true,
        lowercase: true,
        validate: [validator.isEmail, 'Please provide a valid email address.']
    },
    photo: String,
    password: {
        type: String,
        required: [true, 'Please provide a password'],
        minlength: 8
    },
    passwordConfirm: {
        type: String,
        required: [true, 'Please confirm your password'],
        minlength: 8,
    }
});

const User = mongoose.model('User', userSchema);
module.exports = User;

// module.exports = mongoose.models.User || mongoose.model('User', userSchema);