const jwt = require('jsonwebtoken');
const { promisify } = require('util');
const crypto = require('crypto');

const User = require('./../models/userModel');
const catchAsync = require('./../utils/catchAsync');
const AppError = require('./../Utils/appError');
const sendEmail = require('./../utils/email');

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

    let decodedToken;
    // 2) Verification token
    try {
        decodedToken = await promisify(jwt.verify)(token, process.env.JWT_SECRET);
    } catch (err) {
        new AppError('Invalid token. Please login again.', 401);
    }

    // 3) Check if user still exists
    const freshUser = await User.findById(decodedToken.id);
    if(!freshUser) 
        return next(new AppError('The user belonging to this token no longer exists.', 401));

    // 4) Check if user changed password after JWT was issued
    if (freshUser.changedPasswordAfter(decodedToken.iat))
        return next(new AppError('User recently changed password! Please log in again', 401));

    // Access granted to the protected route
    req.user = freshUser;
    next();
});

exports.restrictTo = (...roles) => {
    return (req, res, next) => {
        
        if(!roles.includes(req.user.role)) {
            return next(new AppError('You do not have permission to access this route.', 403));
        }

        next();
    }
};

exports.forgotPassword = catchAsync( async (req, res, next) => {

    // 1) Get the user requested
    const user = await User.findOne({ email: req.body.email });
    if(!user) {
        return next(new AppError('There is no user with the provided email.', 404));
    }

    // 2) Generate the password reset token
    const resetToken = user.createPasswordResetToken();
    await user.save({ validateBeforeSave: false });

    // 3) Send the token to user's mail
    const resetURL = `${req.protocol}://${req.get('host')}/api/v1/users/resetPassword/${resetToken}`;

    const message = `Forgot your password? Submit a patch request with new password to: \n${resetURL}. \nIf you didnt forgot your password, please ignore this mail.`;

    try {
        await sendEmail({
            email: user.email,
            subject: 'Your password reset token. Valid for 15 mins.', 
            message: message
        });
    
        res.status(200).json({
            status: 'success',
            message: 'Token has been sent to your mail'
        });
    } catch (err) {
        user.passwordResetToken = undefined;
        user.passwordResetExpires = undefined;

        await user.save({ validateBeforeSave: false });
        console.log(err);
        return next(new AppError('There was an error sending the reset token. Please try again later.', 500));
    }
});

exports.resetPassword = catchAsync( async (req, res, next) => {

    // 1) Get user based on token
    const hashedToken = crypto.createHash('sha256').update(req.params.token).digest('hex');

    const user = await User.findOne({ 
        passwordResetToken: hashedToken, 
        passwordResetExpires: { $gt: Date.now() }
    });

    // 2) If token is valid i.e., not expired and user exists, set the new password
    if (!user)
        return next(new AppError('Token is not valid or expired', 400));

    user.password = req.body.password;
    user.passwordConfirm = req.body.passwordConfirm;
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;

    await user.save();

    // 3) Update changedPasswordAt property for the user


    // 4) Log the user in, send JWT
    const token = signToken(user._id);

    res.status(200).json({
        status: 'success',
        token
    });

});