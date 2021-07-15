const nodemailer = require('nodemailer');
const pug = require('pug');
const htmlToText = require('html-to-text');
const nodemailerSendgrid = require('nodemailer-sendgrid');

module.exports = class Email {
    constructor(user, url) {
        this.to = user.email;
        this.firstName = user.name.split(' ')[0];
        this.url = url;
        this.from = process.env.EMAIL_FROM
    }

    newTransport() {
        if(process.env.NODE_ENV === 'production') {
            return nodemailer.createTransport(
                nodemailerSendgrid({
                  apiKey: process.env.SENDGRID_PASSWORD
                }))
        }

        return nodemailer.createTransport({
            host: process.env.EMAIL_HOST,
            port: process.env.EMAIL_PORT,
            auth: {
                user: process.env.EMAIL_USERNAME,
                pass: process.env.EMAIL_PASSWORD
            }
        });
    }

    // Send the actual email
    async send( template, subject ) {
        // 1) Render the template
        const html = pug.renderFile(`${__dirname}/../views/${template}.pug`, {
            firstName: this.firstName,
            url: this.url,
            subject
        });

        // 2) Define the email options
        const mailOptions = {
            from: this.from,
            to: this.to,
            subject: subject,
            html,
            text: htmlToText.fromString(html)
        };

        // 3) Create the transport and send email
        await this.newTransport().sendMail(mailOptions);
    }

    async sendWelcome() {
        await this.send('welcome', 'Thanks for registering with this API!');
    }

    async sendPasswordReset() {
        await this.send('passwordReset', 'Your password reset token (Valid for 15 mins)');
    }
}

