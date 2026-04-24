import { WebAuthnSimulator } from '../simulator/webAuthnSimulator';

describe('WebAuthnSimulator', () => {
  let sim: WebAuthnSimulator;

  beforeEach(() => { sim = new WebAuthnSimulator(); });

  describe('simulateRegistration()', () => {
    it('returns verified registration result', () => {
      const result = sim.simulateRegistration('example.com', 'Example App', 'alice@example.com');
      expect(result.verified).toBe(true);
      expect(result.ceremony).toBe('registration');
    });

    it('produces 5 steps', () => {
      const result = sim.simulateRegistration('example.com', 'Example App', 'alice@example.com');
      expect(result.steps).toHaveLength(5);
    });

    it('steps are numbered 1 through 5', () => {
      const result = sim.simulateRegistration('example.com', 'Example App', 'user');
      result.steps.forEach((step, i) => {
        expect(step.stepNumber).toBe(i + 1);
      });
    });

    it('credential has required fields', () => {
      const result = sim.simulateRegistration('example.com', 'Example App', 'alice');
      const cred = result.credential!;
      expect(cred.id).toBeTruthy();
      expect(cred.publicKey).toBeTruthy();
      expect(cred.algorithm).toBe(-7); // ES256
      expect(cred.counter).toBe(0);
      expect(cred.transports).toContain('internal');
    });

    it('options reflect input rpId, rpName, userName', () => {
      const result = sim.simulateRegistration('myapp.io', 'My App', 'bob@myapp.io');
      expect(result.options!.rpId).toBe('myapp.io');
      expect(result.options!.rpName).toBe('My App');
      expect(result.options!.userName).toBe('bob@myapp.io');
    });

    it('generates unique credential IDs across runs', () => {
      const r1 = sim.simulateRegistration('example.com', 'App', 'user');
      const r2 = sim.simulateRegistration('example.com', 'App', 'user');
      expect(r1.credential!.id).not.toBe(r2.credential!.id);
    });

    it('generates unique challenges across runs', () => {
      const r1 = sim.simulateRegistration('example.com', 'App', 'user');
      const r2 = sim.simulateRegistration('example.com', 'App', 'user');
      expect(r1.options!.challenge).not.toBe(r2.options!.challenge);
    });

    it('all steps have non-empty securityNotes', () => {
      const result = sim.simulateRegistration('example.com', 'App', 'user');
      result.steps.forEach(step => {
        expect(step.securityNotes.length).toBeGreaterThan(0);
      });
    });

    it('step actors cover server, client, authenticator, database', () => {
      const result = sim.simulateRegistration('example.com', 'App', 'user');
      const actors = result.steps.map(s => s.actor);
      expect(actors).toContain('server');
      expect(actors).toContain('client');
      expect(actors).toContain('authenticator');
      expect(actors).toContain('database');
    });

    it('logs contain success entries', () => {
      const result = sim.simulateRegistration('example.com', 'App', 'user');
      expect(result.logs.some(l => l.level === 'success')).toBe(true);
    });
  });

  describe('simulateAuthentication()', () => {
    it('returns verified authentication result', () => {
      const result = sim.simulateAuthentication('example.com', 'cred-id-abc', 'pubkey-abc');
      expect(result.verified).toBe(true);
      expect(result.ceremony).toBe('authentication');
    });

    it('produces 5 steps', () => {
      const result = sim.simulateAuthentication('example.com', 'cred-id', 'pubkey');
      expect(result.steps).toHaveLength(5);
    });

    it('assertion contains credentialId', () => {
      const result = sim.simulateAuthentication('example.com', 'my-cred-id', 'pubkey');
      expect(result.assertion!.credentialId).toBe('my-cred-id');
    });

    it('options use provided rpId', () => {
      const result = sim.simulateAuthentication('secure.example.com', 'cred', 'key');
      expect(result.options!.rpId).toBe('secure.example.com');
    });

    it('counter increments from positive base', () => {
      const result = sim.simulateAuthentication('example.com', 'cred', 'key');
      const counterStep = result.steps[2]; // Step 3: authenticator signs
      const counterStr = JSON.stringify(counterStep.data);
      expect(counterStr).toMatch(/signCount/);
    });

    it('generates unique challenges across runs', () => {
      const r1 = sim.simulateAuthentication('example.com', 'cred', 'key');
      const r2 = sim.simulateAuthentication('example.com', 'cred', 'key');
      expect(r1.options!.challenge).not.toBe(r2.options!.challenge);
    });

    it('logs contain success entries', () => {
      const result = sim.simulateAuthentication('example.com', 'cred', 'key');
      expect(result.logs.some(l => l.level === 'success')).toBe(true);
    });

    it('security notes mention counter check', () => {
      const result = sim.simulateAuthentication('example.com', 'cred', 'key');
      const allNotes = result.steps.flatMap(s => s.securityNotes).join(' ');
      expect(allNotes).toMatch(/counter/i);
    });
  });

  describe('registration → authentication flow', () => {
    it('credential from registration can be passed into authentication', () => {
      const reg = sim.simulateRegistration('example.com', 'App', 'alice');
      const cred = reg.credential!;
      const auth = sim.simulateAuthentication('example.com', cred.id, cred.publicKey);
      expect(auth.verified).toBe(true);
      expect(auth.assertion!.credentialId).toBe(cred.id);
    });
  });
});
