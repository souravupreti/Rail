const { PrismaClient } = require('@prisma/client');
const { generateAndStoreOtp, verifyOtp: verifyOtpUtil } = require('../utils/otp'); // fixed naming collision
const bcrypt = require('bcrypt');
const notificationProducer = require('../kalfta/producer/notification.producer'); // fixed: wrong path
const { generateAccessToken, generateRefreshToken, verifyRefreshToken } = require('../utils/auth');
const { redis } = require('../config/redis');
const { OAuth2Client } = require('google-auth-library');

const prisma = new PrismaClient();
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

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


const login = async ({ email, password, deviceId }) => {
    const existingUser = await prisma.user.findUnique({
        where: { email }
    });
    if (!existingUser) {
        throw new Error("User not found");
    }

    const doesPasswordMatch = await bcrypt.compare(password, existingUser.password);
    if (!doesPasswordMatch) {
        throw new Error("Invalid password");
    }

    const accessToken = generateAccessToken(existingUser.id);
    const { token: refreshToken, jti } = generateRefreshToken(existingUser.id);

    const ttlSeconds = parseInt(process.env.REFRESH_TOKEN_TTL_SEC) || 604800;

    await redis.set(`refresh:${existingUser.id}:${deviceId}`, jti, 'EX', ttlSeconds);

    const { password: _password, ...safeUser } = existingUser;
    await redis.set(`user:${existingUser.id}`, JSON.stringify(safeUser), 'EX', ttlSeconds);

    return { accessToken, refreshToken, user: safeUser };
};


const rotateRefreshToken = async ({ refreshToken, deviceId }) => {
    const payload = verifyRefreshToken(refreshToken);
    if (!payload) {
        throw new Error("Invalid refresh token");
    }
    const { userId, jti } = payload;
    const storedJti = await redis.get(`refresh:${userId}:${deviceId}`);
    if (storedJti !== jti) {
        await redis.del(`refresh:${userId}:${deviceId}`);
        throw new Error("Invalid refresh token");
    }
    const accessToken = generateAccessToken(userId);
    const { token: newRefreshToken, jti: newJti } = generateRefreshToken(userId);
    const ttlSeconds = parseInt(process.env.REFRESH_TOKEN_TTL_SEC) || 604800;
    await redis.set(`refresh:${userId}:${deviceId}`, newJti, 'EX', ttlSeconds);

    const existingUser = await prisma.user.findUnique({ where: { id: userId } });
    if (!existingUser) {
        throw new Error("User not found");
    }
    const { password: _password, ...safeUser } = existingUser;

    await redis.set(`user:${userId}`, JSON.stringify(safeUser), 'EX', ttlSeconds);
    return { accessToken, refreshToken: newRefreshToken, user: safeUser };
};



const verifyGoogleIdToken = async ({ idToken, deviceId }) => {
    const ticket = await googleClient.verifyIdToken({
        idToken,
        audience: process.env.GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
    if (!payload.sub || !payload.email) {
        throw new Error("Invalid Google ID token");
    }

    const googleUser = {
        provider: "google",
        providerId: payload.sub,
        email: payload.email,
        firstName: payload.given_name || "",
        lastName: payload.family_name || "",
        emailVerified: payload.email_verified || false
    };

    const user = await prisma.$transaction(async (tx) => {
        let googleAuth = await tx.authProvider.findUnique({
            where: {
                provider_providerId: {
                    provider: googleUser.provider,
                    providerId: googleUser.providerId
                }
            },
            include: { user: true }
        });
        if (googleAuth) {
            return googleAuth.user;
        }

        let existingUser = await tx.user.findUnique({
            where: { email: googleUser.email }
        });

        if (existingUser) {
            await tx.authProvider.create({
                data: {
                    provider: googleUser.provider,
                    providerId: googleUser.providerId,
                    userId: existingUser.id
                }
            });
            return existingUser;
        }

        return await tx.user.create({
            data: {
                email: googleUser.email,
                firstName: googleUser.firstName,
                lastName: googleUser.lastName,
                emailVerified: googleUser.emailVerified,
                authProviders: {
                    create: {
                        provider: googleUser.provider,
                        providerId: googleUser.providerId
                    }
                }
            }
        });
    });

    const accessToken = generateAccessToken(user.id);
    const { token: refreshToken, jti } = generateRefreshToken(user.id);
    const ttlSeconds = parseInt(process.env.REFRESH_TOKEN_TTL_SEC) || 604800;
    await redis.set(`refresh:${user.id}:${deviceId}`, jti, 'EX', ttlSeconds);
    const { password: _password, ...safeUser } = user;
    await redis.set(`user:${user.id}`, JSON.stringify(safeUser), 'EX', ttlSeconds);
    
    return { accessToken, refreshToken, user: safeUser };
};




module.exports = { sendOtp, verifyOtp, login, rotateRefreshToken, verifyGoogleIdToken };