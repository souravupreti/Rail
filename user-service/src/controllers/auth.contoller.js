const authService = require('../services/auth.service');

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

        res.cookie('otpSessionId', otpSessionId, cookieOptions(process.env.OTP_TTL * 1000)) // fixed: cookieOptions now defined
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