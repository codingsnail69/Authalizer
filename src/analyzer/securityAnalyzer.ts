import * as path from 'path';
import { Vulnerability, CodeReference } from '../types';
import { VULNERABILITY_PATTERNS } from './patternMatchers';

export class SecurityAnalyzer {
  async analyzeFile(filePath: string, content: string): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    const lines = content.split('\n');

    for (const pattern of VULNERABILITY_PATTERNS) {
      const regex = new RegExp(pattern.pattern.source, pattern.pattern.flags.includes('g') ? pattern.pattern.flags : pattern.pattern.flags + 'g');

      let match: RegExpExecArray | null;
      while ((match = regex.exec(content)) !== null) {
        // Check if the match is excluded
        if (pattern.excludePatterns?.some(ex => ex.test(match![0]))) {
          continue;
        }

        // Check surrounding context for exclusions
        const matchStart = Math.max(0, match.index - 100);
        const context = content.substring(matchStart, match.index + match[0].length + 50);
        if (pattern.excludePatterns?.some(ex => ex.test(context))) {
          continue;
        }

        // Run custom check function if provided
        if (pattern.checkFn && !pattern.checkFn(content, match)) {
          continue;
        }

        // Skip if inside a comment
        const lineNumber = content.substring(0, match.index).split('\n').length;
        const lineContent = lines[lineNumber - 1] ?? '';
        if (this.isInsideComment(lineContent, match[0])) {
          continue;
        }

        const codeRef: CodeReference = {
          file: filePath,
          line: lineNumber,
          column: match.index - content.lastIndexOf('\n', match.index) - 1,
          snippet: lineContent.trim().substring(0, 120),
        };

        vulnerabilities.push({
          id: `${pattern.id}-${path.basename(filePath)}-${lineNumber}`,
          severity: pattern.severity,
          title: pattern.title,
          description: pattern.description,
          recommendation: pattern.recommendation,
          codeRef,
          owasp: pattern.owasp,
          cwe: pattern.cwe,
          references: pattern.references,
        });
      }
    }

    // Additional heuristic checks
    vulnerabilities.push(...this.checkMisconfiguredHeaders(filePath, content));
    vulnerabilities.push(...this.checkDebugModeAuthBypass(filePath, content));
    vulnerabilities.push(...this.checkInsecurePasswordStorage(filePath, content));

    return vulnerabilities;
  }

  private isInsideComment(line: string, match: string): boolean {
    const lineBeforeMatch = line.substring(0, line.indexOf(match));
    return lineBeforeMatch.includes('//') || lineBeforeMatch.includes('* ');
  }

  private checkMisconfiguredHeaders(filePath: string, content: string): Vulnerability[] {
    const vulns: Vulnerability[] = [];

    // Check for Authorization header parsing without validation
    const authHeaderPattern = /req\.headers\.authorization/g;
    let match: RegExpExecArray | null;
    while ((match = authHeaderPattern.exec(content)) !== null) {
      const context = content.substring(match.index, match.index + 300);
      const hasValidation = /split\s*\(\s*['"]\s+['"]\s*\)/.test(context) ||
        /startsWith\s*\(\s*['"]Bearer/.test(context);

      if (!hasValidation) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        vulns.push({
          id: `HEADER_NO_VALIDATION-${path.basename(filePath)}-${lineNumber}`,
          severity: 'low',
          title: 'Authorization Header Used Without Type Validation',
          description: 'The Authorization header is accessed without validating that it starts with "Bearer ". This may lead to unexpected behavior if other auth schemes are sent.',
          recommendation: 'Always check the auth scheme: if (!header.startsWith("Bearer ")) { return res.status(401).json({ error: "Unauthorized" }); }',
          codeRef: {
            file: filePath,
            line: lineNumber,
            column: 0,
            snippet: content.split('\n')[lineNumber - 1]?.trim() ?? '',
          },
          owasp: 'A07:2021 – Identification and Authentication Failures',
          cwe: 'CWE-284',
        });
      }
    }

    return vulns;
  }

  private checkDebugModeAuthBypass(filePath: string, content: string): Vulnerability[] {
    const vulns: Vulnerability[] = [];
    // Look for auth bypasses conditioned on NODE_ENV
    const bypassPattern = /(?:NODE_ENV\s*!==?\s*['"]production['"]|process\.env\.DEBUG)\s*(?:&&|\|\|)?[^;{]*(?:return|next\s*\(|skip)/gi;
    let match: RegExpExecArray | null;
    while ((match = bypassPattern.exec(content)) !== null) {
      const lineNumber = content.substring(0, match.index).split('\n').length;
      vulns.push({
        id: `DEBUG_AUTH_BYPASS-${path.basename(filePath)}-${lineNumber}`,
        severity: 'high',
        title: 'Authentication Bypass in Non-Production Mode',
        description: 'Authentication logic appears to be bypassed when NODE_ENV is not "production". This can be exploited if environment variables are misconfigured in production.',
        recommendation: 'Remove environment-based authentication bypasses. Use feature flags or test accounts instead.',
        codeRef: {
          file: filePath,
          line: lineNumber,
          column: 0,
          snippet: content.split('\n')[lineNumber - 1]?.trim() ?? '',
        },
        owasp: 'A05:2021 – Security Misconfiguration',
        cwe: 'CWE-489',
      });
    }
    return vulns;
  }

  private checkInsecurePasswordStorage(filePath: string, content: string): Vulnerability[] {
    const vulns: Vulnerability[] = [];
    // Detect storing password directly on user object to database
    const storePattern = /(?:user|User)\.(password|passwd)\s*=\s*(?:req\.body|password|passwd)(?!\s*(?:hash|hashed|bcrypt|argon))/gi;
    let match: RegExpExecArray | null;
    while ((match = storePattern.exec(content)) !== null) {
      const context = content.substring(Math.max(0, match.index - 200), match.index + 200);
      const hasHashing = /bcrypt|argon2|scrypt|pbkdf2/.test(context);
      if (!hasHashing) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        vulns.push({
          id: `PLAINTEXT_PASSWORD_STORE-${path.basename(filePath)}-${lineNumber}`,
          severity: 'critical',
          title: 'Password May Be Stored Without Hashing',
          description: 'A password field is being assigned a value without evidence of hashing. Storing plaintext passwords results in complete compromise of all user accounts on a database breach.',
          recommendation: 'Always hash passwords before storage: const hash = await bcrypt.hash(password, 12); user.password = hash;',
          codeRef: {
            file: filePath,
            line: lineNumber,
            column: 0,
            snippet: content.split('\n')[lineNumber - 1]?.trim() ?? '',
          },
          owasp: 'A02:2021 – Cryptographic Failures',
          cwe: 'CWE-256',
        });
      }
    }
    return vulns;
  }
}
