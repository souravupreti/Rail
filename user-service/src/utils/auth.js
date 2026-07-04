const jwt = require("jsonwebtoken");
const crypto = require("crypto");

const generateAccessToken = (userId) => {
    return jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: process.env.ACCESS_TOKEN_TTL });
};

const generateRefreshToken = (userId) => {
    const jti = crypto.randomUUID();
    const token = jwt.sign({ userId, jti }, process.env.JWT_SECRET, { expiresIn: process.env.REFRESH_TOKEN_TTL });
    return { token, jti };
};

module.exports = { generateAccessToken, generateRefreshToken };