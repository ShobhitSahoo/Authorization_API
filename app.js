const express = require('express');
const dotenv = require('dotenv');
const mongoose = require('mongoose');
const bodyparser = require("body-parser");

const app = express();

const userRouter = require('./Routes/userRoutes');

process.on('uncaughtException', err => {
    console.log('UNCAUGHT EXCEPTION! 💥 Shutting Down....');
    console.log(err.name, err.message, err.stack);
    process.exit(1);
});

app.use(bodyparser.json());

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