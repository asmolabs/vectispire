const nodemailer = require('nodemailer');

async function test() {
    console.log('Testing SMTP connection...');
    // Replace these with your settings if you want to test manually
    const transporter = nodemailer.createTransport({
        host: process.argv[2] || 'localhost',
        port: parseInt(process.argv[3] || '1025', 10),
        secure: false,
        tls: { rejectUnauthorized: false }
    });

    try {
        await transporter.verify();
        console.log('SMTP server is ready to take our messages');
    } catch (error) {
        console.error('SMTP verification failed:', error.message);
    }
}

test();
