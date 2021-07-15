const jwt = require('jsonwebtoken');
const { promisify } = require('util');
const crypto = require('crypto');

const User = require('./../models/userModel');
const catchAsync = require('./../utils/catchAsync');
const AppError = require('./../utils/appError');
const Email = require('./../utils/email');

const signToken = id => {
    return jwt.sign({ id: id }, process.env.JWT_SECRET, {expiresIn: process.env.JWT_EXPIRES_IN});
};

const createSendToken = (user, statusCode, res) => {
    const token = signToken(user._id);

    const cookieOptions = {
        expires: new Date(Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000),
        //secure: true,     // Since in development we dont have HTTPS
        httpOnly: true
    };

    res.cookie('jwt', token, cookieOptions);

    user.password = undefined;

    res.status(statusCode).json({
        status: 'success',
        token,
        data: {
            user
        }
    });
};

exports.signup = catchAsync(async (req, res, next) => {

    const newUser = await User.create({
        name: req.body.name,
        email: req.body.email,
        password: req.body.password,
        passwordConfirm: req.body.passwordConfirm
    });

    const url = `https://documenter.getpostman.com/view/11750601/TzmBDDwB`;     // API docs link goes here
    await new Email(newUser, url).sendWelcome();

    createSendToken(newUser, 201, res);

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
    createSendToken(user, 200, res);

});

exports.protect = catchAsync( async (req, res, next) => {
    // 1) Get the token and check if its there
    const auth = req.headers.authorization;
    let token;
    if(auth && auth.startsWith('Bearer')) {
        token = auth.split(' ')[1];
    } else if (req.cookies.jwt) {
        token = req.cookies.jwt;
    }

    if(!token) {
        return next(new AppError('You are not allowed to access this page. Please login.', 401));
    }

    // 2) Verification token
    const decodedToken = await promisify(jwt.verify)(token, process.env.JWT_SECRET);

    // 3) Check if user still exists
    const freshUser = await User.findById(decodedToken.id);
    if(!freshUser) 
        return next(new AppError('The user belonging to this token no longer exists.', 401));

    // 4) Check if user changed password after JWT was issued
    if (freshUser.changedPasswordAfter(decodedToken.iat))
        return next(new AppError('User recently changed password! Please log in again', 401));

    // Access granted to the protected route
    req.user = freshUser;
    res.locals.user = freshUser;
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
    try {
        const resetURL = `${req.protocol}://${req.get('host')}/api/v1/users/resetPassword/${resetToken}`;
        await new Email(user, resetURL).sendPasswordReset();
    
        res.status(200).json({
            status: 'success',
            message: 'Token has been sent to your mail'
        });
    } catch (err) {
        user.passwordResetToken = undefined;
        user.passwordResetExpires = undefined;

        await user.save({ validateBeforeSave: false });
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

    // 3) Log the user in, send JWT
    createSendToken(user, 200, res);

});

exports.updatePassword = catchAsync( async ( req, res, next ) => {
    
    // 1) Get the user from the password provided.
    const user = await User.findById(req.user.id).select('+password');

    // 2) Check if provided password is correct or not.
    if (!(await user.correctPassword(req.body.passwordCurrent, user.password))) 
        return next(new AppError('Your current password is incorrect.', 401));

    // 3) If correct, update the current password.
    user.password = req.body.password;
    user.passwordConfirm = req.body.passwordConfirm;
    // Using save() because middlewares are defined on save.
    await user.save();

    // 4) Log the user in and send JWT
    createSendToken(user, 200, res);

});