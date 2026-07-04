const otpGenerator = require('otp-generator');
const crypto = require('crypto');
const { redis } = require('../config/redis');

function hashOtp(otp, email) {
    return crypto
        .createHmac('sha256', process.env.HMAC_SECRET)
        .update(email + ':' + otp)
        .digest('hex');
}

async function generateAndStoreOtp(email, meta) {
    const rateKey = `otp_rate_limit:${email}`;
    const sentCount = parseInt(await redis.get(rateKey)) || 0; // fixed: pareInt → parseInt

    if (sentCount >= parseInt(process.env.OTP_RATE_LIMIT)) {
        throw new Error('OTP rate limit exceeded. Please try again later.');
    }

    const otp = otpGenerator.generate(6, {
        upperCaseAlphabets: false,
        specialChars: false,
        lowerCaseAlphabets: false,
        digits: true,
    });

    const otpSessionId = crypto.randomUUID();
    const hashed = hashOtp(otp, email);

    await redis.set(
        `otp:session:${otpSessionId}`,
        JSON.stringify({ hashedOtp: hashed, meta, email }),
        'EX',
        process.env.OTP_TTL  // fixed: bare OTP_TTL → process.env.OTP_TTL
    );

    await redis.incr(rateKey);          // fixed: redis.inc → redis.incr
    await redis.expire(rateKey, 3600);

    return { otp, otpSessionId };
}



const verifyOtp = async ({ otp, otpSessionId }) => {
    const sessionKey = `otp:session:${otpSessionId}`;
    const raw = await redis.get(sessionKey);
    if (!raw) return null;

    const { hashedOtp: storedOtp, meta, email } = JSON.parse(raw);
    const attemptsKey = `otp:attempts:${email}`;

    const attempts = await redis.incr(attemptsKey);
    const attemptsCount = parseInt(await redis.get(attemptsKey) || 0);
    if (attemptsCount >= process.env.ATTEMPT_MAX) {
        throw new Error('Too many attempts to verify OTP');
    }

    const hashedOtp = hashOtp(otp, email);

    // Timing safe comparison (must check length to avoid timingSafeEqual crashes)
    const bufHashed = Buffer.from(hashedOtp, 'hex');
    const bufStored = Buffer.from(storedOtp, 'hex');
    const isMatch = (bufHashed.length === bufStored.length) && crypto.timingSafeEqual(bufHashed, bufStored);

    if (isMatch) {
        await redis.del(sessionKey, attemptsKey, `otp_rate_limit:${email}`);
        return { meta, email };
    } else {
        await redis.incr(attemptsKey);
        await redis.expire(attemptsKey, parseInt(process.env.OTP_TTL) || 300);
        return null;
    }
}

module.exports = { generateAndStoreOtp, verifyOtp };   // fixed: was missing entirely