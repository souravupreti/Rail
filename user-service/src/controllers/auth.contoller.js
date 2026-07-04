const authService = require('../services/auth.service');
const getDeviceFingerprint = require('../utils/device');
const cookieOptions = (maxAgeMs) => ({
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: maxAgeMs,
});

exports.sendOtp = async (req, res, next) => {
    try {
        const { firstName, lastName, email, password, confirmPassword } = req.body;

        if (!firstName || !lastName || !email || !password || !confirmPassword) {
            return res.status(400).json({ message: 'All fields are required' });
        }

        if (password !== confirmPassword) {
            return res.status(400).json({ message: 'Password and Confirm Password do not match' });
        }

        const { otpSessionId } = await authService.sendOtp({ firstName, lastName, email, password }); // fixed: 3-s typo

        const otpTtl = (parseInt(process.env.OTP_TTL) || 300) * 1000;
        res.cookie('otpSessionId', otpSessionId, cookieOptions(otpTtl)) // fixed: cookieOptions now defined
            .status(200)
            .json({
                success: true,          // fixed: "sucess" typo
                message: 'OTP sent successfully',
            });
    } catch (error) {
        res.status(500).json({ message: 'Internal server error' });
    }
};


exports.verifyOtp = async (req, res) => {
    try {
        const { otp } = req.body;
        const otpSessionId = req.cookies.otpSessionId;

        if (!otp || !otpSessionId) {
            return res.status(400).json({ message: 'OTP and OTP session ID are required' });
        }

        const user = await authService.verifyOtp({ otp, otpSessionId });

        res.clearCookie('otpSessionId');
        res.status(200).json({
            success: true,
            message: 'OTP verified successfully and user registered',
            data: {
                id: user.id,
                firstName: user.firstName,
                lastName: user.lastName,
                email: user.email,
                emailVerified: user.emailVerified
            }
        });
    } catch (error) {
        if (error.message.includes('Invalid') || error.message.includes('expired') || error.message.includes('attempts')) {
            return res.status(400).json({ success: false, message: error.message });
        }
        res.status(500).json({ message: 'Internal server error' });
    }
};



exports.login = async (req, res, next) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ message: 'All fields are required' });
        }
        const deviceId = getDeviceFingerprint(req);
        const { accessToken, refreshToken, user } = await authService.login({ email, password, deviceId });

        const accessTokenMaxAge = (parseInt(process.env.ACCESS_TOKEN_TTL_SEC) || 900) * 1000;
        const refreshTokenMaxAge = (parseInt(process.env.REFRESH_TOKEN_TTL_SEC) || 604800) * 1000;

        res.cookie("accessToken", accessToken, cookieOptions(accessTokenMaxAge));
        res.cookie("refreshToken", refreshToken, cookieOptions(refreshTokenMaxAge))
            .status(200).json({
                success: true,
                message: "Logged in successfully",
                loggedInUser: user
            })
    } catch (error) {
        if (error.message.includes('not found') || error.message.includes('Invalid password') || error.message.includes('mismatch')) {
            return res.status(401).json({ success: false, message: error.message });
        }
        next(error);
    }
};



exports.rotateRefreshToken = async (req, res, next) => {

    try {

        const { refreshToken } = req.cookies;
        if (!refreshToken) {
            return res.status(401).json({ success: false, message: 'Refresh token not found' });
        }
        const deviceId = getDeviceFingerprint(req);
        const { accessToken, refreshToken: newRefreshToken, user } = await authService.rotateRefreshToken({ refreshToken, deviceId });

        const accessTokenMaxAge = (parseInt(process.env.ACCESS_TOKEN_TTL_SEC) || 900) * 1000;
        const refreshTokenMaxAge = (parseInt(process.env.REFRESH_TOKEN_TTL_SEC) || 604800) * 1000;

        res.cookie("accessToken", accessToken, cookieOptions(accessTokenMaxAge));
        res.cookie("refreshToken", newRefreshToken, cookieOptions(refreshTokenMaxAge))
            .status(200).json({
                success: true,
                message: "Refresh token rotated successfully",
                loggedInUser: user
            })
    } catch (error) {
        if (error.message.includes('not found') || error.message.includes('Invalid password') || error.message.includes('mismatch')) {
            return res.status(401).json({ success: false, message: error.message });
        }
        next(error);
    }
}


exports.verifyGoogleIdToken = async (req, res, next) => {
    try {
        const { idToken } = req.body;
        if (!idToken) {
            return res.status(400).json({ success: false, message: 'ID token not found' });
        }
        const deviceId = getDeviceFingerprint(req);
        const { accessToken, refreshToken, user } = await authService.verifyGoogleIdToken({ idToken, deviceId });

        const accessTokenMaxAge = (parseInt(process.env.ACCESS_TOKEN_TTL_SEC) || 900) * 1000;
        const refreshTokenMaxAge = (parseInt(process.env.REFRESH_TOKEN_TTL_SEC) || 604800) * 1000;

        res.cookie("accessToken", accessToken, cookieOptions(accessTokenMaxAge));
        res.cookie("refreshToken", refreshToken, cookieOptions(refreshTokenMaxAge))
        res.status(200).json({
            success: true,
            message: "Google ID token verified successfully",
            loggedInUser: user
        })
    } catch (error) {
        if (error.message.includes('not found') || error.message.includes('Invalid password') || error.message.includes('mismatch')) {
            return res.status(401).json({ success: false, message: error.message });
        }
        next(error);
    }
}