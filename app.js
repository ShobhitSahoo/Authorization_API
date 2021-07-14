const express = require('express');
const dotenv = require('dotenv');
const mongoose = require('mongoose');
const bodyparser = require("body-parser");
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const mongoSanitizer = require('express-mongo-sanitize');
const xss = require('xss-clean');

const app = express();

app.use(helmet());
const limiter = rateLimit({
    max: 100,
    windowMs: 60 * 60 * 1000,
    message: 'Too many request from this IP. Please try again in an hour'
});

app.use('/api', limiter);

const userRouter = require('./Routes/userRoutes');

process.on('uncaughtException', err => {
    console.log('UNCAUGHT EXCEPTION! 💥 Shutting Down....');
    console.log(err.name, err.message, err.stack);
    process.exit(1);
});

app.use(bodyparser.json());

// To prevent NoSQL injections like { "$gt": "" }
app.use(mongoSanitizer());

// Prevent HTML injection in DB
app.use(xss());

dotenv.config({path: './config.env'})

const DB = process.env.DATABASE.replace('<PASSWORD>', process.env.DATABASE_PASSWORD);

mongoose.connect(DB, {
    useNewUrlParser: true,
    useCreateIndex: true,
    useFindAndModify: false,
    useUnifiedTopology: true        // Added due a warning in terminal
}).then(() => console.log('DB connection successful!'));

const port = process.env.PORT || 3000
const server = app.listen(port, () => console.log(`App listening on port ${port}!`));

app.use('/api/v1/users', userRouter);

process.on('unhandledRejection', err => {
    console.log('UNHANDLED REJECTION 🤯 Shutting Down....');
    console.log(err.name, err.message);
    server.close(() => {
        process.exit(1);
    });
}); 