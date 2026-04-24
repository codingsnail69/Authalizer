import { LIBRARY_PATTERNS, VULNERABILITY_PATTERNS } from '../analyzer/patternMatchers';

describe('LIBRARY_PATTERNS', () => {
  const findPattern = (name: string) => LIBRARY_PATTERNS.find(p => p.name === name)!;

  describe('jsonwebtoken', () => {
    const p = findPattern('jsonwebtoken');
    it('detects require import', () => {
      expect(p.importPatterns.some(r => r.test("const jwt = require('jsonwebtoken')"))).toBe(true);
    });
    it('detects ES import', () => {
      expect(p.importPatterns.some(r => r.test("import jwt from 'jsonwebtoken'"))).toBe(true);
    });
    it('detects jwt.sign usage', () => {
      expect(p.usagePatterns.some(r => r.test('jwt.sign(payload, secret)'))).toBe(true);
    });
    it('detects jwt.verify usage', () => {
      expect(p.usagePatterns.some(r => r.test('jwt.verify(token, secret)'))).toBe(true);
    });
    it('has flowType jwt', () => {
      expect(p.flowType).toBe('jwt');
    });
  });

  describe('@simplewebauthn/server', () => {
    const p = findPattern('@simplewebauthn/server');
    it('has flowType webauthn', () => {
      expect(p.flowType).toBe('webauthn');
    });
    it('detects generateRegistrationOptions', () => {
      expect(p.usagePatterns.some(r => r.test('await generateRegistrationOptions(opts)'))).toBe(true);
    });
    it('detects verifyRegistrationResponse', () => {
      expect(p.usagePatterns.some(r => r.test('await verifyRegistrationResponse(resp)'))).toBe(true);
    });
  });

  describe('passport', () => {
    const p = findPattern('passport');
    it('detects passport.authenticate', () => {
      expect(p.usagePatterns.some(r => r.test("passport.authenticate('local')"))).toBe(true);
    });
    it('has flowType oauth2', () => {
      expect(p.flowType).toBe('oauth2');
    });
  });

  describe('express-session', () => {
    const p = findPattern('express-session');
    it('has flowType session', () => {
      expect(p.flowType).toBe('session');
    });
    it('detects session() usage', () => {
      expect(p.usagePatterns.some(r => r.test('app.use(session({ secret: "s" }))'))).toBe(true);
    });
  });

  it('all patterns have importPatterns and usagePatterns', () => {
    LIBRARY_PATTERNS.forEach(p => {
      expect(p.importPatterns.length).toBeGreaterThan(0);
      expect(p.usagePatterns.length).toBeGreaterThan(0);
    });
  });

  it('all patterns have required fields', () => {
    LIBRARY_PATTERNS.forEach(p => {
      expect(p.name).toBeTruthy();
      expect(p.displayName).toBeTruthy();
      expect(p.description).toBeTruthy();
      expect(['library', 'framework', 'protocol', 'standard']).toContain(p.type);
      expect(['jwt', 'oauth2', 'session', 'webauthn', 'apikey', 'basic', 'unknown']).toContain(p.flowType);
    });
  });
});

describe('VULNERABILITY_PATTERNS', () => {
  const findVuln = (id: string) => VULNERABILITY_PATTERNS.find(p => p.id === id)!;

  describe('HARDCODED_SECRET', () => {
    const p = findVuln('HARDCODED_SECRET');
    it('detects hardcoded secret', () => {
      expect(p.pattern.test('const secret = "my-super-secret123"')).toBe(true);
    });
    it('detects hardcoded password', () => {
      const r = new RegExp(p.pattern.source, p.pattern.flags);
      expect(r.test("password: 'hardcoded-password'")).toBe(true);
    });
    it('has severity critical', () => {
      expect(p.severity).toBe('critical');
    });
    it('has excludePatterns that cover process.env', () => {
      const excluded = p.excludePatterns!.some(r => r.test('process.env.SECRET'));
      expect(excluded).toBe(true);
    });
  });

  describe('JWT_NONE_ALGORITHM', () => {
    const p = findVuln('JWT_NONE_ALGORITHM');
    it('detects none algorithm in array', () => {
      const r = new RegExp(p.pattern.source, p.pattern.flags);
      expect(r.test('algorithms: ["HS256", "none"]')).toBe(true);
    });
    it('has severity critical', () => {
      expect(p.severity).toBe('critical');
    });
  });

  describe('JWT_DECODE_NO_VERIFY', () => {
    const p = findVuln('JWT_DECODE_NO_VERIFY');
    it('detects jwt.decode call', () => {
      const r = new RegExp(p.pattern.source, p.pattern.flags);
      expect(r.test('const data = jwt.decode(token)')).toBe(true);
    });
    it('has severity high', () => {
      expect(p.severity).toBe('high');
    });
  });

  describe('WEAK_PASSWORD_HASH', () => {
    const p = findVuln('WEAK_PASSWORD_HASH');
    it('detects md5 hash', () => {
      const r = new RegExp(p.pattern.source, p.pattern.flags);
      expect(r.test("crypto.createHash('md5')")).toBe(true);
    });
    it('detects sha1 hash', () => {
      const r = new RegExp(p.pattern.source, p.pattern.flags);
      expect(r.test("crypto.createHash('sha1')")).toBe(true);
    });
    it('has severity high', () => {
      expect(p.severity).toBe('high');
    });
  });

  it('all vulnerability patterns have required fields', () => {
    VULNERABILITY_PATTERNS.forEach(p => {
      expect(p.id).toBeTruthy();
      expect(p.title).toBeTruthy();
      expect(p.description).toBeTruthy();
      expect(p.recommendation).toBeTruthy();
      expect(['critical', 'high', 'medium', 'low', 'info']).toContain(p.severity);
      expect(p.pattern).toBeInstanceOf(RegExp);
    });
  });

  it('no duplicate IDs', () => {
    const ids = VULNERABILITY_PATTERNS.map(p => p.id);
    const unique = new Set(ids);
    expect(unique.size).toBe(ids.length);
  });
});
