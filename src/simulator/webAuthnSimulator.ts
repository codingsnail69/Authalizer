import * as crypto from 'crypto';
import {
  WebAuthnRegistrationResult,
  WebAuthnAuthenticationResult,
  WebAuthnSimulationStep,
  WebAuthnCredential,
  SimulationLog,
} from '../types';

export class WebAuthnSimulator {
  simulateRegistration(
    rpId: string,
    rpName: string,
    userName: string
  ): WebAuthnRegistrationResult {
    const logs: SimulationLog[] = [];
    const steps: WebAuthnSimulationStep[] = [];

    const userId = crypto.randomBytes(16).toString('hex');
    const challenge = crypto.randomBytes(32).toString('base64url');

    // Step 1: Server creates registration options
    const options = {
      rpId,
      rpName,
      userId,
      userName,
      userDisplayName: userName,
      challenge,
      timeout: 60000,
      attestation: 'none' as const,
      userVerification: 'preferred' as const,
    };

    steps.push({
      stepNumber: 1,
      title: 'Server Generates Registration Options',
      description: 'The server creates PublicKeyCredentialCreationOptions with a fresh cryptographic challenge.',
      actor: 'server',
      data: {
        rp: { id: rpId, name: rpName },
        user: { id: userId, name: userName, displayName: userName },
        challenge: `${challenge.substring(0, 20)}... (32 random bytes)`,
        pubKeyCredParams: [
          { type: 'public-key', alg: -7, label: 'ES256 (EC P-256)' },
          { type: 'public-key', alg: -257, label: 'RS256 (RSA)' },
        ],
        timeout: '60000ms',
        attestation: 'none',
        userVerification: 'preferred',
      },
      securityNotes: [
        'Challenge is 32 bytes from crypto.randomBytes() — cryptographically secure',
        'Challenge must be stored server-side in the session for verification',
        'Challenge is single-use: delete it after verification regardless of outcome',
        'rpId must match the domain of the relying party — prevents phishing',
      ],
    });

    logs.push(this.log('info', 'Registration options generated', { challenge: challenge.substring(0, 20) + '...' }));
    logs.push(this.log('info', `Challenge stored in session for user: ${userName}`));

    // Step 2: Authenticator creates credential
    const keyPair = crypto.generateKeyPairSync('ec', {
      namedCurve: 'P-256',
    });
    const publicKeyDer = keyPair.publicKey.export({ type: 'spki', format: 'der' });
    const publicKeyBase64 = publicKeyDer.toString('base64url');
    const credentialId = crypto.randomBytes(32).toString('base64url');
    const aaguid = '00000000-0000-0000-0000-000000000000'; // Software authenticator

    steps.push({
      stepNumber: 2,
      title: 'Browser Calls navigator.credentials.create()',
      description: 'The browser presents the authenticator (Touch ID, Face ID, security key, etc.) to the user for consent.',
      actor: 'client',
      data: {
        action: 'navigator.credentials.create(options)',
        userAction: 'User verifies identity (biometric, PIN, touch)',
        authenticatorType: 'Platform (built-in) or Roaming (USB/NFC security key)',
      },
      securityNotes: [
        'Private key is generated inside the authenticator — it NEVER leaves the device',
        'The credential is scoped to the rpId — a credential for example.com cannot be used on evil.com',
        'User verification (PIN/biometric) is enforced before signing',
      ],
    });

    logs.push(this.log('info', 'navigator.credentials.create() called in browser'));
    logs.push(this.log('success', 'Authenticator created EC P-256 key pair'));
    logs.push(this.log('info', 'User verified via platform authenticator'));

    // Step 3: Authenticator response
    const clientDataJSON = Buffer.from(JSON.stringify({
      type: 'webauthn.create',
      challenge: challenge,
      origin: `https://${rpId}`,
      crossOrigin: false,
    })).toString('base64url');

    // Simulated authenticator data (simplified)
    const rpIdHash = crypto.createHash('sha256').update(rpId).digest('hex');
    const authenticatorData = {
      rpIdHash: rpIdHash.substring(0, 16) + '...',
      flags: 'UP|UV|AT (User Present, User Verified, Attested Credential)',
      counter: 0,
      aaguid,
      credentialId: credentialId.substring(0, 20) + '...',
      credentialPublicKey: 'COSE-encoded EC P-256 public key',
    };

    steps.push({
      stepNumber: 3,
      title: 'Authenticator Returns Attestation Object',
      description: 'The authenticator returns clientDataJSON and the attestation object containing the new public key.',
      actor: 'authenticator',
      data: {
        credentialId: credentialId.substring(0, 24) + '...',
        clientDataJSON: {
          type: 'webauthn.create',
          challenge: challenge.substring(0, 16) + '...',
          origin: `https://${rpId}`,
          crossOrigin: false,
        },
        authenticatorData,
        attestationFormat: 'none',
      },
      securityNotes: [
        'clientDataJSON binds this response to the specific origin and challenge',
        'The rpIdHash in authenticatorData ensures the credential is bound to this domain',
        'Counter starts at 0 for new credentials',
        '"none" format means no hardware attestation — acceptable for consumer apps',
      ],
    });

    logs.push(this.log('info', 'Attestation object received from authenticator'));

    // Step 4: Server verifies
    steps.push({
      stepNumber: 4,
      title: 'Server Verifies Registration Response',
      description: 'Server calls verifyRegistrationResponse() performing comprehensive validation.',
      actor: 'server',
      data: {
        checks: [
          '✓ clientDataJSON.type === "webauthn.create"',
          `✓ clientDataJSON.challenge matches stored challenge (${challenge.substring(0, 16)}...)`,
          `✓ clientDataJSON.origin === "https://${rpId}"`,
          `✓ authenticatorData.rpIdHash matches SHA-256("${rpId}")`,
          '✓ Flags: User Present (UP) bit is set',
          '✓ Credential ID is unique (not already registered)',
          '✓ Public key format is valid COSE',
        ],
      },
      securityNotes: [
        'Challenge is consumed — delete it from session after this point',
        'If any check fails, reject the registration entirely',
        'Credential ID uniqueness prevents duplicate registrations',
      ],
    });

    logs.push(this.log('info', 'Verifying challenge match'));
    logs.push(this.log('info', 'Verifying origin binding'));
    logs.push(this.log('info', 'Verifying rpId hash'));
    logs.push(this.log('success', 'All verification checks passed'));

    // Step 5: Store credential
    const credential: WebAuthnCredential = {
      id: credentialId,
      rawId: credentialId,
      publicKey: publicKeyBase64.substring(0, 40) + '... (EC P-256 SPKI)',
      algorithm: -7, // ES256
      counter: 0,
      transports: ['internal'],
      aaguid,
    };

    steps.push({
      stepNumber: 5,
      title: 'Credential Stored in Database',
      description: 'Server stores the credential ID and public key associated with the user account.',
      actor: 'database',
      data: {
        userId,
        credentialId: credentialId.substring(0, 24) + '...',
        publicKey: '(EC P-256 SPKI — stored as base64 or hex)',
        counter: 0,
        transports: ['internal'],
        createdAt: new Date().toISOString(),
        aaguid,
      },
      securityNotes: [
        'Store the full credential ID and public key — they are needed for authentication',
        'The counter must be updated on each successful authentication',
        'Never store the private key — it never leaves the authenticator',
        'Store aaguid to identify authenticator make/model for enterprise policies',
      ],
    });

    logs.push(this.log('success', `Credential registered for user "${userName}" on rpId "${rpId}"`));
    logs.push(this.log('success', 'Registration ceremony complete — user can now sign in with passkey'));

    return {
      ceremony: 'registration',
      steps,
      credential,
      options,
      logs,
      verified: true,
    };
  }

  simulateAuthentication(
    rpId: string,
    credentialId: string,
    publicKey: string
  ): WebAuthnAuthenticationResult {
    const logs: SimulationLog[] = [];
    const steps: WebAuthnSimulationStep[] = [];
    const challenge = crypto.randomBytes(32).toString('base64url');
    const prevCounter = Math.floor(Math.random() * 100) + 1;

    // Step 1: Server generates authentication options
    const options = {
      rpId,
      challenge,
      timeout: 60000,
      userVerification: 'preferred' as const,
      allowCredentials: [{ id: credentialId, type: 'public-key' as const, transports: ['internal' as const] }],
    };

    steps.push({
      stepNumber: 1,
      title: 'Server Generates Authentication Options',
      description: 'Server calls generateAuthenticationOptions() with the user\'s registered credential IDs.',
      actor: 'server',
      data: {
        challenge: `${challenge.substring(0, 20)}... (32 random bytes)`,
        rpId,
        allowCredentials: [
          { id: credentialId.substring(0, 16) + '...', type: 'public-key', transports: ['internal'] }
        ],
        userVerification: 'preferred',
        timeout: '60000ms',
      },
      securityNotes: [
        'Fresh challenge generated for each authentication attempt',
        'allowCredentials limits which credentials can respond — prevents credential stuffing',
        'Challenge stored server-side in session — must be deleted after use',
      ],
    });

    logs.push(this.log('info', 'Authentication options generated'));
    logs.push(this.log('info', `Challenge: ${challenge.substring(0, 20)}...`));

    // Step 2: Browser and authenticator
    steps.push({
      stepNumber: 2,
      title: 'Browser Calls navigator.credentials.get()',
      description: 'Browser selects the matching credential from allowCredentials and prompts user for consent.',
      actor: 'client',
      data: {
        action: 'navigator.credentials.get(options)',
        credentialSelected: credentialId.substring(0, 16) + '...',
        userAction: 'User verifies identity (Touch ID / Face ID / PIN)',
      },
      securityNotes: [
        'The credential is bound to the rpId — only https://rpId can use this credential',
        'Browser verifies it\'s communicating with the legitimate origin before proceeding',
        'This is what makes passkeys phishing-resistant — the origin binding is enforced by the OS/browser',
      ],
    });

    logs.push(this.log('info', 'navigator.credentials.get() called'));
    logs.push(this.log('success', 'User verified via platform authenticator'));

    // Step 3: Authenticator signs
    const clientDataJSON = {
      type: 'webauthn.get',
      challenge: challenge,
      origin: `https://${rpId}`,
      crossOrigin: false,
    };
    const newCounter = prevCounter + 1;
    const simulatedSignature = crypto.randomBytes(64).toString('base64url');

    steps.push({
      stepNumber: 3,
      title: 'Authenticator Signs the Challenge',
      description: 'The authenticator uses the private key to sign: SHA256(authenticatorData || SHA256(clientDataJSON)).',
      actor: 'authenticator',
      data: {
        credentialId: credentialId.substring(0, 16) + '...',
        clientDataJSON,
        authenticatorData: {
          rpIdHash: 'SHA-256("' + rpId + '") — matches registration',
          flags: 'UP|UV (User Present, User Verified)',
          signCount: newCounter,
        },
        signature: simulatedSignature.substring(0, 32) + '... (EC P-256 DER signature)',
      },
      securityNotes: [
        'Signature covers: authenticatorData + SHA-256(clientDataJSON)',
        'The challenge is embedded in clientDataJSON — signature is only valid for this challenge',
        'signCount increased from ' + prevCounter + ' to ' + newCounter + ' — prevents replay',
        'Private key never leaves the authenticator during this process',
      ],
    });

    logs.push(this.log('info', 'Challenge signed with EC P-256 private key'));
    logs.push(this.log('info', `Counter incremented: ${prevCounter} → ${newCounter}`));

    // Step 4: Server verifies
    steps.push({
      stepNumber: 4,
      title: 'Server Verifies Authentication Response',
      description: 'Server calls verifyAuthenticationResponse() performing all security checks.',
      actor: 'server',
      data: {
        checks: [
          '✓ clientDataJSON.type === "webauthn.get"',
          `✓ clientDataJSON.challenge matches stored challenge`,
          `✓ clientDataJSON.origin === "https://${rpId}"`,
          `✓ authenticatorData.rpIdHash matches SHA-256("${rpId}")`,
          '✓ Flags: User Present (UP) bit is set',
          `✓ signCount (${newCounter}) > stored counter (${prevCounter}) — no replay`,
          `✓ Signature valid against stored public key for credential`,
        ],
      },
      securityNotes: [
        'Counter check: if newCounter ≤ storedCounter, REJECT — possible cloned authenticator',
        'Signature verification uses the stored PUBLIC key — no secret transmitted',
        'After verification, update stored counter to ' + newCounter,
        'Any failing check must reject the authentication',
      ],
    });

    logs.push(this.log('info', 'Verifying challenge'));
    logs.push(this.log('info', 'Verifying origin and rpId'));
    logs.push(this.log('info', `Counter check: ${newCounter} > ${prevCounter} ✓`));
    logs.push(this.log('info', 'Verifying EC P-256 signature against stored public key'));
    logs.push(this.log('success', 'Authentication response verified successfully'));

    // Step 5: Session
    steps.push({
      stepNumber: 5,
      title: 'Session Created / Token Issued',
      description: 'Authentication succeeds. Server updates the credential counter and establishes a session.',
      actor: 'server',
      data: {
        counterUpdated: `${prevCounter} → ${newCounter}`,
        sessionCreated: true,
        sessionExpiry: '24h (configure per your security policy)',
        tokenType: 'Session cookie or JWT',
      },
      securityNotes: [
        'Update counter in database BEFORE issuing session to prevent race conditions',
        'Use short-lived sessions for high-security scenarios',
        'Consider re-authentication for sensitive operations even within an active session',
      ],
    });

    logs.push(this.log('success', `Counter updated to ${newCounter}`));
    logs.push(this.log('success', 'Session established — authentication complete'));

    return {
      ceremony: 'authentication',
      steps,
      options,
      assertion: {
        credentialId,
        signature: simulatedSignature.substring(0, 32) + '...',
        authenticatorData: `rpIdHash|flags|counter(${newCounter})`,
        clientDataJSON: Buffer.from(JSON.stringify(clientDataJSON)).toString('base64url').substring(0, 30) + '...',
      },
      logs,
      verified: true,
    };
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
