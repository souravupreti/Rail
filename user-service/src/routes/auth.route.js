const express = require('express');
const router = express.Router();
const { sendOtp, verifyOtp, login, rotateRefreshToken, verifyGoogleIdToken } = require('../controllers/auth.contoller'); // matches actual filename on disk

router.post('/send-otp', sendOtp);
router.post('/verify-otp', verifyOtp)
router.post('/login', login);
router.post('/refresh', rotateRefreshToken);
router.post('/google-auth', verifyGoogleIdToken);

module.exports = router;