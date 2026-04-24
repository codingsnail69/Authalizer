import * as path from 'path';
import { Vulnerability } from '../types';

interface FileInfo {
  filePath: string;
  content: string;
}

export class WebAuthnAnalyzer {
  async analyzeFiles(files: FileInfo[]): Promise<Vulnerability[]> {
    const vulns: Vulnerability[] = [];

    for (const file of files) {
      if (this.hasWebAuthnCode(file.content)) {
        vulns.push(...this.analyzeWebAuthnCode(file.filePath, file.content));
      }
    }

    return vulns;
  }

  private hasWebAuthnCode(content: string): boolean {
    return (
      // JS/TS camelCase (SimpleWebAuthn, fido2-lib)
      /generateRegistrationOptions|verifyRegistrationResponse|generateAuthenticationOptions|verifyAuthenticationResponse/.test(content) ||
      /navigator\.credentials\.(create|get)/.test(content) ||
      /startRegistration|startAuthentication/.test(content) ||
      /attestationOptions|assertionOptions|attestationResult|assertionResult/.test(content) ||
      /new\s+Fido2Lib/.test(content) ||
      // Python snake_case (py_webauthn, python-fido2)
      /generate_registration_options|verify_registration_response/.test(content) ||
      /generate_authentication_options|verify_authentication_response/.test(content) ||
      /register_begin|register_complete|authenticate_begin|authenticate_complete/.test(content) ||
      /from\s+webauthn/.test(content) ||
      /from\s+fido2/.test(content)
    );
  }

  private analyzeWebAuthnCode(filePath: string, content: string): Vulnerability[] {
    const vulns: Vulnerability[] = [];
    const basename = path.basename(filePath);

    vulns.push(...this.checkChallengeGeneration(filePath, basename, content));
    vulns.push(...this.checkOriginValidation(filePath, basename, content));
    vulns.push(...this.checkRpIdValidation(filePath, basename, content));
    vulns.push(...this.checkCounterValidation(filePath, basename, content));
    vulns.push(...this.checkAttestationFormat(filePath, basename, content));
    vulns.push(...this.checkUserVerification(filePath, basename, content));
    vulns.push(...this.checkCredentialStorage(filePath, basename, content));

    return vulns;
  }

  private checkChallengeGeneration(filePath: string, basename: string, content: string): Vulnerability[] {
    const vulns: Vulnerability[] = [];

    // Check if challenge is generated with Math.random()
    const mathRandomChallenge = /challenge\s*[:=]\s*(?:Buffer\.from\s*\(\s*)?Math\.random/g;
    let match: RegExpExecArray | null;
    while ((match = mathRandomChallenge.exec(content)) !== null) {
      vulns.push(this.makeVuln(
        `WA_CHALLENGE_MATH_RANDOM-${basename}-${this.lineOf(content, match.index)}`,
        'critical',
        'WebAuthn Challenge Generated With Math.random()',
        'Math.random() is not cryptographically secure. An attacker who can observe or predict the challenge can forge authenticator responses.',
        'Use crypto.randomBytes(32) or let the SimpleWebAuthn library generate the challenge automatically (it uses crypto.getRandomValues internally).',
        filePath, content, match.index,
        'A02:2021 – Cryptographic Failures', 'CWE-338'
      ));
    }

    // Check for hardcoded/static challenges
    const staticChallenge = /challenge\s*[:=]\s*['"`][a-zA-Z0-9+/=]{4,64}['"`]/g;
    while ((match = staticChallenge.exec(content)) !== null) {
      vulns.push(this.makeVuln(
        `WA_STATIC_CHALLENGE-${basename}-${this.lineOf(content, match.index)}`,
        'critical',
        'WebAuthn Challenge Is Static or Hardcoded',
        'A static challenge allows replay attacks — the same authenticator response can be reused indefinitely.',
        'Generate a fresh cryptographically random challenge (min 16 bytes) for every authentication ceremony.',
        filePath, content, match.index,
        'A02:2021 – Cryptographic Failures', 'CWE-330'
      ));
    }

    return vulns;
  }

  private checkOriginValidation(filePath: string, basename: string, content: string): Vulnerability[] {
    const vulns: Vulnerability[] = [];

    // JS verify calls (camelCase) and Python verify calls (snake_case)
    const verifyCallsPattern = /(?:verify(?:Registration|Authentication)Response|verify_(?:registration|authentication)_response)\s*\(\s*([^)]{0,400})\)/gs;
    let match: RegExpExecArray | null;
    while ((match = verifyCallsPattern.exec(content)) !== null) {
      const callBody = match[1];
      // JS uses expectedOrigin, Python uses expected_origin
      if (!callBody.includes('expectedOrigin') && !callBody.includes('expected_origin') && !callBody.includes('origin')) {
        vulns.push(this.makeVuln(
          `WA_NO_ORIGIN-${basename}-${this.lineOf(content, match.index)}`,
          'high',
          'WebAuthn Verification Missing Origin Check',
          'Without validating the expected origin, a malicious site can proxy a legitimate WebAuthn ceremony and authenticate users without their intent.',
          'JS: set expectedOrigin: "https://your-domain.com". Python (py_webauthn): set expected_rp_id and expected_origin in verify_registration_response() / verify_authentication_response().',
          filePath, content, match.index,
          'A07:2021 – Identification and Authentication Failures', 'CWE-346'
        ));
      }
    }

    // Check for wildcard or overly permissive origin
    const wildcardOrigin = /(?:expectedOrigin|expected_origin)\s*[=:]\s*(?:\[|\s*)['"]\s*\*\s*['"]/g;
    while ((match = wildcardOrigin.exec(content)) !== null) {
      vulns.push(this.makeVuln(
        `WA_WILDCARD_ORIGIN-${basename}-${this.lineOf(content, match.index)}`,
        'critical',
        'WebAuthn Accepts Wildcard Origin',
        'A wildcard origin allows any site to perform WebAuthn authentication in your context, completely bypassing origin binding.',
        'Specify the exact expected origin: "https://example.com". For multi-origin apps, use an array of exact origins.',
        filePath, content, match.index,
        'A07:2021 – Identification and Authentication Failures', 'CWE-346'
      ));
    }

    return vulns;
  }

  private checkRpIdValidation(filePath: string, basename: string, content: string): Vulnerability[] {
    const vulns: Vulnerability[] = [];

    // JS: rpID / Python: rp_id
    const localhostRpId = /(?:rpID|rp_id)\s*[=:]\s*['"]localhost['"]/gi;
    let match: RegExpExecArray | null;
    while ((match = localhostRpId.exec(content)) !== null) {
      if (!filePath.includes('test') && !filePath.includes('spec') && !filePath.includes('dev')) {
        vulns.push(this.makeVuln(
          `WA_LOCALHOST_RPID-${basename}-${this.lineOf(content, match.index)}`,
          'info',
          'WebAuthn rpID Set to "localhost"',
          '"localhost" as rpId is only valid for local development. If deployed to production with this setting, WebAuthn will fail.',
          'Set rpId to your production domain: rpID: process.env.RP_ID || "example.com". Use environment variables to switch between development and production.',
          filePath, content, match.index,
          'A05:2021 – Security Misconfiguration', 'CWE-942'
        ));
      }
    }

    return vulns;
  }

  private checkCounterValidation(filePath: string, basename: string, content: string): Vulnerability[] {
    const vulns: Vulnerability[] = [];

    // Check if counter validation is explicitly disabled
    const counterDisabled = /requireUserVerification\s*:\s*false|counter\s*:\s*0(?!\d)/g;
    let match: RegExpExecArray | null;
    while ((match = counterDisabled.exec(content)) !== null) {
      // Only flag counter: 0 if it's in a verification context
      const context = content.substring(Math.max(0, match.index - 300), match.index + 100);
      if (/verify(?:Registration|Authentication)|assertionResult/.test(context)) {
        vulns.push(this.makeVuln(
          `WA_COUNTER_CHECK-${basename}-${this.lineOf(content, match.index)}`,
          'medium',
          'WebAuthn Authenticator Counter May Not Be Validated',
          'The authenticator counter should always increase. If a response has a counter ≤ stored counter, it indicates a cloned authenticator or replay attack.',
          'Check the counter returned by verifyAuthenticationResponse. If newCounter <= storedCounter and storedCounter != 0, reject the authentication.',
          filePath, content, match.index,
          'A07:2021 – Identification and Authentication Failures', 'CWE-384'
        ));
      }
    }

    return vulns;
  }

  private checkAttestationFormat(filePath: string, basename: string, content: string): Vulnerability[] {
    const vulns: Vulnerability[] = [];

    // Warn about trusting 'none' attestation for high-security scenarios
    const noneAttestation = /attestationType\s*:\s*['"]none['"]/gi;
    let match: RegExpExecArray | null;
    while ((match = noneAttestation.exec(content)) !== null) {
      vulns.push(this.makeVuln(
        `WA_NONE_ATTESTATION-${basename}-${this.lineOf(content, match.index)}`,
        'info',
        'WebAuthn Using "none" Attestation Type',
        '"none" attestation means you cannot verify the make/model of the authenticator. For consumer apps this is acceptable, but high-security applications should use "indirect" or "direct".',
        'For consumer-facing apps, "none" is fine. For enterprise or high-security scenarios, use "direct" or "indirect" attestation and verify against a trusted FIDO MDS.',
        filePath, content, match.index,
        'A05:2021 – Security Misconfiguration', 'CWE-295'
      ));
    }

    return vulns;
  }

  private checkUserVerification(filePath: string, basename: string, content: string): Vulnerability[] {
    const vulns: Vulnerability[] = [];

    // JS: userVerification / Python: user_verification or UserVerificationRequirement.DISCOURAGED
    const discouragedUV = /(?:userVerification|user_verification)\s*[=:]\s*(?:['"]discouraged['"]|UserVerificationRequirement\.DISCOURAGED)/gi;
    let match: RegExpExecArray | null;
    while ((match = discouragedUV.exec(content)) !== null) {
      vulns.push(this.makeVuln(
        `WA_UV_DISCOURAGED-${basename}-${this.lineOf(content, match.index)}`,
        'low',
        'WebAuthn User Verification Set to "discouraged"',
        'With userVerification: "discouraged", the authenticator does not verify the user\'s PIN or biometric. This reduces security for high-value operations.',
        'Use userVerification: "required" for sensitive operations (financial transactions, admin access) and "preferred" for general authentication.',
        filePath, content, match.index,
        'A07:2021 – Identification and Authentication Failures', 'CWE-308'
      ));
    }

    return vulns;
  }

  private checkCredentialStorage(filePath: string, basename: string, content: string): Vulnerability[] {
    const vulns: Vulnerability[] = [];

    // Check for storing entire credential object in localStorage
    const localStorageCred = /localStorage\.setItem\s*\([^)]*(?:credential|passkey|webauthn)/gi;
    let match: RegExpExecArray | null;
    while ((match = localStorageCred.exec(content)) !== null) {
      vulns.push(this.makeVuln(
        `WA_LOCALSTORAGE_CRED-${basename}-${this.lineOf(content, match.index)}`,
        'high',
        'WebAuthn Credential Data Stored in localStorage',
        'Storing credential data in localStorage exposes it to XSS attacks. Credential IDs can be used to enumerate registered devices.',
        'Credential private keys never leave the authenticator. Credential IDs (public identifiers) should be stored server-side, linked to the user account.',
        filePath, content, match.index,
        'A02:2021 – Cryptographic Failures', 'CWE-312'
      ));
    }

    return vulns;
  }

  private makeVuln(
    id: string,
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info',
    title: string,
    description: string,
    recommendation: string,
    filePath: string,
    content: string,
    matchIndex: number,
    owasp?: string,
    cwe?: string
  ): Vulnerability {
    const lineNumber = this.lineOf(content, matchIndex);
    const lines = content.split('\n');
    return {
      id,
      severity,
      title,
      description,
      recommendation,
      codeRef: {
        file: filePath,
        line: lineNumber,
        column: 0,
        snippet: lines[lineNumber - 1]?.trim().substring(0, 120) ?? '',
      },
      owasp,
      cwe,
    };
  }

  private lineOf(content: string, index: number): number {
    return content.substring(0, index).split('\n').length;
  }
}
