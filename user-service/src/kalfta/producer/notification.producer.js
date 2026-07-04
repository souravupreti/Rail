// Notification producer — logs OTP to console (real email sender can replace this later)

const sendOtpEmail = async (email, otp, ttlMinutes) => {
    try {
        // TODO: Replace with actual email/SMS provider (e.g. Nodemailer, Twilio, AWS SES)
        console.log('=========================================');
        console.log(`OTP for ${email}: ${otp}`);
        console.log(`This OTP is valid for ${ttlMinutes} minute(s).`);
        console.log('=========================================');
    } catch (error) {
        console.error('Failed to send OTP notification:', error.message);
        throw error;
    }
};

module.exports = { sendOtpEmail }; // fixed: was using ES module "export", wrong fn name