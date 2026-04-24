import { JWTSimulator } from '../simulator/jwtSimulator';

describe('JWTSimulator', () => {
  let sim: JWTSimulator;

  beforeEach(() => { sim = new JWTSimulator(); });

  describe('simulate()', () => {
    it('returns a valid 3-part JWT', () => {
      const result = sim.simulate({ algorithm: 'HS256', secret: 'test-secret-32-bytes-long-enough!', payload: { sub: 'user1' } });
      expect(result.token.split('.')).toHaveLength(3);
    });

    it('encodes header with correct alg', () => {
      const result = sim.simulate({ algorithm: 'HS256', secret: 'secret', payload: {} });
      expect(result.header.alg).toBe('HS256');
      expect(result.header.typ).toBe('JWT');
    });

    it('includes iat in payload', () => {
      const before = Math.floor(Date.now() / 1000);
      const result = sim.simulate({ algorithm: 'HS256', secret: 'secret', payload: {} });
      expect(result.payload.iat).toBeGreaterThanOrEqual(before);
    });

    it('includes exp when provided', () => {
      const now = Math.floor(Date.now() / 1000);
      const result = sim.simulate({ algorithm: 'HS256', secret: 'secret', payload: { exp: now + 3600, sub: 'u1' } });
      expect(result.payload.exp).toBe(now + 3600);
      expect(result.securityWarnings.some(w => w.includes('expiration'))).toBe(false);
    });

    it('warns when no exp claim', () => {
      const result = sim.simulate({ algorithm: 'HS256', secret: 'secret', payload: {} });
      expect(result.securityWarnings.some(w => w.includes('expiration'))).toBe(true);
    });

    it('warns when secret shorter than 32 bytes', () => {
      const result = sim.simulate({ algorithm: 'HS256', secret: 'short', payload: {} });
      expect(result.securityWarnings.some(w => w.includes('Secret'))).toBe(true);
    });

    it('no secret-length warning when secret is 32+ bytes', () => {
      const result = sim.simulate({ algorithm: 'HS256', secret: 'a'.repeat(32), payload: {} });
      expect(result.securityWarnings.some(w => w.includes('Secret'))).toBe(false);
    });

    it('supports HS384', () => {
      const result = sim.simulate({ algorithm: 'HS384', secret: 'secret', payload: {} });
      expect(result.header.alg).toBe('HS384');
      expect(result.token.split('.')).toHaveLength(3);
    });

    it('supports HS512', () => {
      const result = sim.simulate({ algorithm: 'HS512', secret: 'secret', payload: {} });
      expect(result.header.alg).toBe('HS512');
    });

    it('warns missing iss and sub', () => {
      const result = sim.simulate({ algorithm: 'HS256', secret: 'secret', payload: {} });
      expect(result.securityWarnings.some(w => w.includes('issuer'))).toBe(true);
      expect(result.securityWarnings.some(w => w.includes('subject'))).toBe(true);
    });

    it('produces logs with info and success entries', () => {
      const result = sim.simulate({ algorithm: 'HS256', secret: 'secret', payload: {} });
      expect(result.logs.some(l => l.level === 'info')).toBe(true);
      expect(result.logs.some(l => l.level === 'success')).toBe(true);
    });
  });

  describe('verify()', () => {
    it('verifies a token it generated', () => {
      const secret = 'verify-test-secret-long-enough!!';
      const now = Math.floor(Date.now() / 1000);
      const { token } = sim.simulate({ algorithm: 'HS256', secret, payload: { sub: 'u1', exp: now + 3600 } });
      const result = sim.verify({ token, secret, expectedAlgorithms: ['HS256'] });
      expect(result.valid).toBe(true);
      expect(result.expired).toBe(false);
    });

    it('rejects tampered token', () => {
      const secret = 'my-secret';
      const { token } = sim.simulate({ algorithm: 'HS256', secret, payload: { sub: 'user' } });
      const parts = token.split('.');
      parts[1] = Buffer.from(JSON.stringify({ sub: 'admin', iat: 0 })).toString('base64').replace(/=/g, '');
      const tampered = parts.join('.');
      const result = sim.verify({ token: tampered, secret, expectedAlgorithms: ['HS256'] });
      expect(result.valid).toBe(false);
    });

    it('rejects wrong secret', () => {
      const { token } = sim.simulate({ algorithm: 'HS256', secret: 'correct-secret', payload: {} });
      const result = sim.verify({ token, secret: 'wrong-secret', expectedAlgorithms: ['HS256'] });
      expect(result.valid).toBe(false);
    });

    it('rejects malformed token', () => {
      const result = sim.verify({ token: 'not.a.valid.jwt.extra', secret: 'secret', expectedAlgorithms: ['HS256'] });
      expect(result.valid).toBe(false);
      expect(result.error).toMatch(/Malformed/i);
    });

    it('rejects algorithm mismatch', () => {
      const secret = 'secret';
      const { token } = sim.simulate({ algorithm: 'HS256', secret, payload: {} });
      const result = sim.verify({ token, secret, expectedAlgorithms: ['HS512'] });
      expect(result.valid).toBe(false);
    });

    it('rejects expired token', () => {
      const secret = 'secret';
      const past = Math.floor(Date.now() / 1000) - 3600;
      const { token } = sim.simulate({ algorithm: 'HS256', secret, payload: { exp: past } });
      const result = sim.verify({ token, secret, expectedAlgorithms: ['HS256'] });
      expect(result.valid).toBe(false);
      expect(result.expired).toBe(true);
    });

    it('rejects nbf in future', () => {
      const secret = 'secret';
      const future = Math.floor(Date.now() / 1000) + 9999;
      const { token } = sim.simulate({ algorithm: 'HS256', secret, payload: { nbf: future } });
      const result = sim.verify({ token, secret, expectedAlgorithms: ['HS256'] });
      expect(result.valid).toBe(false);
      expect(result.error).toMatch(/not yet valid/i);
    });

    it('warns when no expectedAlgorithms provided', () => {
      const secret = 'secret';
      const { token } = sim.simulate({ algorithm: 'HS256', secret, payload: {} });
      const result = sim.verify({ token, secret, expectedAlgorithms: [] });
      expect(result.logs.some(l => l.level === 'warning' && l.message.includes('algorithm'))).toBe(true);
    });
  });
});
