import * as crypto from 'crypto';
import {
  JWTSimulationRequest,
  JWTSimulationResult,
  JWTVerifyRequest,
  JWTVerifyResult,
  JWTHeader,
  JWTPayload,
  SimulationLog,
} from '../types';

function base64url(input: string | Buffer): string {
  const buf = typeof input === 'string' ? Buffer.from(input, 'utf-8') : input;
  return buf.toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

function base64urlDecode(input: string): Buffer {
  const padded = input + '='.repeat((4 - (input.length % 4)) % 4);
  return Buffer.from(padded.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

const HMAC_MAP: Record<string, string> = {
  HS256: 'sha256',
  HS384: 'sha384',
  HS512: 'sha512',
};

export class JWTSimulator {
  simulate(request: JWTSimulationRequest): JWTSimulationResult {
    const logs: SimulationLog[] = [];
    const warnings: string[] = [];
    const now = Math.floor(Date.now() / 1000);

    // Build header
    const header: JWTHeader = { alg: request.algorithm, typ: 'JWT' };

    // Build payload with defaults
    const payload: JWTPayload = {
      iat: now,
      ...request.payload,
    };

    logs.push(this.log('info', 'Starting JWT generation', { algorithm: request.algorithm }));

    // Security checks
    if (!payload.exp) {
      warnings.push('Token has no expiration (exp claim). Non-expiring tokens are a security risk — always set expiresIn.');
      logs.push(this.log('warning', 'No expiration claim (exp) set. Tokens should expire.'));
    } else {
      const expDate = new Date(payload.exp * 1000).toISOString();
      logs.push(this.log('info', `Token expires at: ${expDate}`));
    }

    if (!payload.iss) {
      warnings.push('Missing issuer (iss) claim. Always identify who issued the token.');
    }

    if (!payload.sub) {
      warnings.push('Missing subject (sub) claim. The "sub" identifies the principal that is the subject of the JWT.');
    }

    if (request.secret.length < 32) {
      warnings.push(`Secret is only ${request.secret.length} characters. NIST recommends at least 256 bits (32 bytes) for HS256.`);
      logs.push(this.log('warning', 'Secret key is shorter than recommended 32 bytes'));
    }

    // Encode header and payload
    const headerEncoded = base64url(JSON.stringify(header));
    const payloadEncoded = base64url(JSON.stringify(payload));
    const signingInput = `${headerEncoded}.${payloadEncoded}`;

    logs.push(this.log('info', 'Header encoded (base64url)', { encoded: headerEncoded }));
    logs.push(this.log('info', 'Payload encoded (base64url)', { encoded: payloadEncoded }));

    // Sign
    const hashAlgorithm = HMAC_MAP[request.algorithm];
    const hmac = crypto.createHmac(hashAlgorithm, request.secret);
    hmac.update(signingInput);
    const signature = hmac.digest('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');

    const token = `${signingInput}.${signature}`;

    logs.push(this.log('success', 'HMAC signature computed', { algorithm: hashAlgorithm }));
    logs.push(this.log('success', 'JWT generated successfully', { tokenLength: token.length }));

    return {
      header,
      payload,
      headerEncoded,
      payloadEncoded,
      signature,
      token,
      logs,
      securityWarnings: warnings,
    };
  }

  verify(request: JWTVerifyRequest): JWTVerifyResult {
    const logs: SimulationLog[] = [];

    logs.push(this.log('info', 'Starting JWT verification'));

    const parts = request.token.split('.');
    if (parts.length !== 3) {
      logs.push(this.log('error', 'Invalid JWT format: expected 3 parts (header.payload.signature)'));
      return { valid: false, error: 'Malformed JWT: expected exactly 3 parts', logs };
    }

    const [headerEncoded, payloadEncoded, signature] = parts;

    // Decode header
    let header: JWTHeader;
    try {
      header = JSON.parse(base64urlDecode(headerEncoded).toString('utf-8'));
      logs.push(this.log('info', 'Header decoded', header));
    } catch {
      logs.push(this.log('error', 'Failed to decode JWT header'));
      return { valid: false, error: 'Invalid base64url encoding in header', logs };
    }

    // Algorithm check
    if (!request.expectedAlgorithms || request.expectedAlgorithms.length === 0) {
      logs.push(this.log('warning', 'No expected algorithms specified — accepting any algorithm is dangerous'));
    } else if (!request.expectedAlgorithms.includes(header.alg)) {
      logs.push(this.log('error', `Algorithm mismatch: token uses "${header.alg}", expected one of [${request.expectedAlgorithms.join(', ')}]`));
      return { valid: false, error: `Algorithm "${header.alg}" is not in the expected list`, logs };
    }

    // Algorithm none check
    if (header.alg === 'none' || header.alg === 'NONE') {
      logs.push(this.log('error', 'CRITICAL: Token uses "none" algorithm — this allows forgery!'));
      return { valid: false, error: 'Rejected: "none" algorithm is not allowed', logs };
    }

    // Decode payload
    let payload: JWTPayload;
    try {
      payload = JSON.parse(base64urlDecode(payloadEncoded).toString('utf-8'));
      logs.push(this.log('info', 'Payload decoded', payload));
    } catch {
      logs.push(this.log('error', 'Failed to decode JWT payload'));
      return { valid: false, error: 'Invalid base64url encoding in payload', logs };
    }

    // Verify signature
    const hashAlgorithm = HMAC_MAP[header.alg];
    if (!hashAlgorithm) {
      logs.push(this.log('error', `Unsupported algorithm: ${header.alg}`));
      return { valid: false, error: `Unsupported algorithm: ${header.alg}`, logs };
    }

    const signingInput = `${headerEncoded}.${payloadEncoded}`;
    const expectedSig = crypto.createHmac(hashAlgorithm, request.secret)
      .update(signingInput)
      .digest('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');

    // Timing-safe comparison
    let sigValid: boolean;
    try {
      sigValid = crypto.timingSafeEqual(
        Buffer.from(signature, 'utf-8'),
        Buffer.from(expectedSig, 'utf-8')
      );
    } catch {
      sigValid = false;
    }

    if (!sigValid) {
      logs.push(this.log('error', 'Signature verification FAILED — token may be tampered'));
      return { valid: false, error: 'Invalid signature', logs };
    }

    logs.push(this.log('success', 'Signature verified successfully using timing-safe comparison'));

    // Check expiry
    const now = Math.floor(Date.now() / 1000);
    let expired = false;
    let expiresAt: string | undefined;

    if (payload.exp !== undefined) {
      expired = now > payload.exp;
      expiresAt = new Date(payload.exp * 1000).toISOString();
      if (expired) {
        logs.push(this.log('error', `Token expired at ${expiresAt}`));
        return { valid: false, error: `Token expired at ${expiresAt}`, header, payload, logs, expired: true, expiresAt };
      } else {
        const remaining = payload.exp - now;
        logs.push(this.log('success', `Token valid. Expires in ${remaining}s at ${expiresAt}`));
      }
    } else {
      logs.push(this.log('warning', 'Token has no expiry (exp claim) — it never expires'));
    }

    // Check nbf
    if (payload.nbf !== undefined && now < payload.nbf) {
      const nbfDate = new Date(payload.nbf * 1000).toISOString();
      logs.push(this.log('error', `Token not yet valid (nbf: ${nbfDate})`));
      return { valid: false, error: `Token not yet valid until ${nbfDate}`, logs };
    }

    logs.push(this.log('success', 'JWT verification complete — token is valid'));

    return { valid: true, header, payload, logs, expired: false, expiresAt };
  }

  private log(level: SimulationLog['level'], message: string, data?: unknown): SimulationLog {
    return {
      timestamp: new Date().toISOString(),
      level,
      message,
      data,
    };
  }
}
