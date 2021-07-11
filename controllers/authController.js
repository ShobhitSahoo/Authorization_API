const jwt = require('jsonwebtoken');
const { promisify } = require('util');

const User = require('./../models/userModel');
const catchAsync = require('./../utils/catchAsync');
const AppError = require('./../Utils/appError');

const signToken = id => {
    return jwt.sign({ id: id }, process.env.JWT_SECRET, {expiresIn: process.env.JWT_EXPIRES_IN});
};

exports.signup = catchAsync(async (req, res, next) => {

    const newUser = await User.create({
        name: req.body.name,
        email: req.body.email,
        password: req.body.password,
        passwordConfirm: req.body.passwordConfirm
    });

    const token = signToken(newUser._id);

    res.status(201).json({
        status: 'success',
        token,
        data: {
            user: newUser
        }
    });
});

exports.login = catchAsync( async (req, res, next) => {
    const {email, password} = req.body;
    
    // 1) If email and password provided
    if(!email || !password) {
        return next(new AppError('Please provide an email address and password', 400));
    }

    // 2) Check if user exists and password is correct or not
    const user = await User.findOne({ email }).select('+password');

    if(!user || !(await user.correctPassword(password, user.password)) ) {
        return next(new AppError('Incorrect email or password provided', 401));
    }

    // 3) If user exists and password is correct, then send token to client
    const token = signToken(user._id);

    res.status(200).json({
        status: 'success',
        token
    });
});

exports.protect = catchAsync( async (req, res, next) => {
    let token;
    // 1) Get the token and check if its there
    if(req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    }

    if(!token) {
        return next(new AppError('You are not allowed to access this page. Please login.', 401));
    }

    // 2) Verification token
    try {
        const decodedToken = await promisify(jwt.verify)(token, process.env.JWT_SECRET);
    } catch (err) {
        new AppError('Invalid token. Please login again.', 401);
    }

    // 3) Check if user still exists
    const freshUser = await User.findById(decodedToken.id);
    if(!freshUser) 
        return next(new AppError('The user belonging to this token no longer exists.', 401));

    // 4) Check if user changed password after JWT was issued
    if (freshUser.passwordChangedAt(decodedToken.iat))
        return next(new AppError('User recently changed password! Please log in again', 401));

    // Access granted to the protected route
    req.user = freshUser;
    next();
});