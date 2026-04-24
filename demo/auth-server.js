"use strict";
// Demo file: intentionally contains both good practices and security issues
// for demonstration of the Auth Flow Analyzer extension.
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const express_session_1 = __importDefault(require("express-session"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const bcrypt_1 = __importDefault(require("bcrypt"));
const server_1 = require("@simplewebauthn/server");
const app = (0, express_1.default)();
// ---- BAD: Hardcoded session secret ----
app.use((0, express_session_1.default)({
    secret: 'mysupersecret123', // VULNERABILITY: hardcoded secret
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true }, // Missing: secure, sameSite
}));
// ---- JWT Authentication ----
const JWT_SECRET = process.env.JWT_SECRET || 'fallback-secret'; // Warn: weak fallback
router.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const user = await db.findUserByEmail(email);
    if (!user) {
        // BAD: User enumeration via specific error
        return res.status(401).json({ error: 'User not found' });
    }
    const valid = await bcrypt_1.default.compare(password, user.passwordHash);
    if (!valid) {
        return res.status(401).json({ error: 'Wrong password' }); // BAD: reveals reason
    }
    // BAD: JWT with no expiration
    const token = jsonwebtoken_1.default.sign({ sub: user.id, role: user.role }, JWT_SECRET);
    // BAD: Cookie missing 'secure' and 'sameSite'
    res.cookie('token', token, { httpOnly: true });
    res.json({ token });
});
router.get('/profile', (req, res) => {
    const authHeader = req.headers.authorization;
    // BAD: No Bearer scheme check
    const token = authHeader?.split(' ')[1];
    // BAD: using decode instead of verify
    const decoded = jsonwebtoken_1.default.decode(token);
    res.json({ user: decoded });
});
// ---- WebAuthn Registration ----
const rpId = 'localhost'; // Acceptable for development only
const rpName = 'Demo App';
router.post('/passkey/register/options', async (req, res) => {
    const { userId, userName } = req.body;
    const options = await (0, server_1.generateRegistrationOptions)({
        rpID: rpId,
        rpName,
        userID: userId,
        userName,
        attestationType: 'none',
        userVerification: 'discouraged', // WARN: weak user verification
    });
    // Store challenge in session for verification
    req.session.registrationChallenge = options.challenge;
    res.json(options);
});
router.post('/passkey/register/verify', async (req, res) => {
    const expectedChallenge = req.session.registrationChallenge;
    if (!expectedChallenge) {
        return res.status(400).json({ error: 'No challenge found' });
    }
    const verification = await (0, server_1.verifyRegistrationResponse)({
        response: req.body,
        expectedChallenge,
        expectedOrigin: `https://${rpId}`, // GOOD: expectedOrigin set
        expectedRPID: rpId,
    });
    if (verification.verified) {
        delete req.session.registrationChallenge;
        await db.saveCredential(req.body.userId, verification.registrationInfo);
        res.json({ verified: true });
    }
    else {
        res.status(400).json({ verified: false });
    }
});
// ---- WebAuthn Authentication ----
router.post('/passkey/auth/options', async (req, res) => {
    const { userId } = req.body;
    const credentials = await db.getUserCredentials(userId);
    const options = await (0, server_1.generateAuthenticationOptions)({
        rpID: rpId,
        userVerification: 'preferred',
        allowCredentials: credentials.map(c => ({
            id: c.credentialId,
            type: 'public-key',
            transports: c.transports,
        })),
    });
    req.session.authChallenge = options.challenge;
    res.json(options);
});
router.post('/passkey/auth/verify', async (req, res) => {
    const expectedChallenge = req.session.authChallenge;
    const credential = await db.getCredential(req.body.id);
    // NOTE: Missing origin check in verify options — vulnerability!
    const verification = await (0, server_1.verifyAuthenticationResponse)({
        response: req.body,
        expectedChallenge,
        expectedRPID: rpId,
        authenticator: {
            credentialID: credential.id,
            credentialPublicKey: credential.publicKey,
            counter: credential.counter,
        },
    });
    if (verification.verified) {
        delete req.session.authChallenge;
        await db.updateCounter(credential.id, verification.authenticationInfo.newCounter);
        req.session.userId = credential.userId;
        res.json({ verified: true });
    }
});
// BAD: SQL injection risk in auth query (example)
router.get('/user', async (req, res) => {
    const username = req.query.username;
    // BAD: Direct string interpolation in query
    const result = await db.query(`SELECT * FROM users WHERE username = '${username}'`);
    res.json(result);
});
app.listen(3000);
//# sourceMappingURL=auth-server.js.map