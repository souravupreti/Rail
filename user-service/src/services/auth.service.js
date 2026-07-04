const { PrismaClient } = require('@prisma/client');
const { generateAndStoreOtp, verifyOtp: verifyOtpUtil } = require('../utils/otp'); // fixed naming collision
const bcrypt = require('bcrypt');
const notificationProducer = require('../kalfta/producer/notification.producer'); // fixed: wrong path

const prisma = new PrismaClient();

const sendOtp = async ({ firstName, lastName, email, password }) => {
    const existingUser = await prisma.user.findUnique({  // fixed: prisme → prisma
        where: { email },
    });

    if (existingUser) {
        throw new Error('User already exists with this email.');
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const meta = { firstName, lastName, email, password: hashedPassword };

    const { otp, otpSessionId } = await generateAndStoreOtp(email, meta);

    await notificationProducer.sendOtpEmail(             // fixed: senOtpEmail → sendOtpEmail
        email,
        otp,
        Math.floor(process.env.OTP_TTL / 60)
    );

    console.log(`OTP sent to ${email}`);
    return { otpSessionId };  // fixed: otpSesssionId (3 s's) → otpSessionId
};


const verifyOtp = async ({ otp, otpSessionId }) => {
    const verification = await verifyOtpUtil({ otp, otpSessionId });
    if (!verification) {
        throw new Error('Invalid or expired OTP');
    }
    
    const { meta, email } = verification;
    const user = await prisma.user.create({
        data: {
            firstName: meta.firstName,
            lastName: meta.lastName,
            email: email,
            password: meta.password, // meta has password, not hashedPassword
            emailVerified: true
        }
    });

    return user;
};




module.exports = { sendOtp, verifyOtp }; // fixed: verifyOtp added to exports