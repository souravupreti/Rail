const express = require('express');
const router = express.Router();
const { sendOtp, verifyOtp, login, rotateRefreshToken } = require('../controllers/auth.contoller'); // matches actual filename on disk

router.post('/send-otp', sendOtp);
router.post('/verify-otp', verifyOtp)
router.post('/login', login);
router.post('/refresh', rotateRefreshToken);

module.exports = router;