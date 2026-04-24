import * as path from 'path';
import { CodeReference } from '../types';

export type PasswordSecurityLevel = 'secure' | 'acceptable' | 'weak' | 'insecure' | 'none';

export interface PasswordFinding {
  algorithm: string;
  displayName: string;
  securityLevel: PasswordSecurityLevel;
  parameters: Record<string, string | number>;
  codeRef: CodeReference;
  issues: PasswordIssue[];
  recommendation: string;
}

export interface PasswordIssue {
  severity: 'critical' | 'high' | 'medium' | 'low';
  message: string;
}

export interface PasswordAnalysisReport {
  findings: PasswordFinding[];
  hasPasswordHandling: boolean;
  hasLoginRoutes: boolean;
  noHashingButHasAuth: boolean;
  overallRating: PasswordSecurityLevel;
  summary: string;
}

// ---- Detection patterns ----

interface AlgorithmDetector {
  name: string;
  displayName: string;
  pattern: RegExp;
  extractParams: (match: string, fileContent: string, matchIndex: number) => Record<string, unknown>;
  assess: (params: Record<string, unknown>) => { level: PasswordSecurityLevel; issues: PasswordIssue[]; recommendation: string };
}

const DETECTORS: AlgorithmDetector[] = [
  // ---- bcrypt (JS) ----
  {
    name: 'bcrypt',
    displayName: 'bcrypt',
    pattern: /bcrypt\.(?:hash|hashSync)\s*\(\s*\w+\s*,\s*(\d+|\w+)/g,
    extractParams(match, content, idx) {
      const roundsMatch = /bcrypt\.(?:hash|hashSync)\s*\([^,]+,\s*(\d+)/.exec(match);
      if (roundsMatch) return { rounds: parseInt(roundsMatch[1]) };
      // Try to resolve variable
      const varName = /bcrypt\.(?:hash|hashSync)\s*\([^,]+,\s*(\w+)/.exec(match)?.[1];
      if (varName) {
        const varPattern = new RegExp(`(?:const|let|var)\\s+${varName}\\s*=\\s*(\\d+)`);
        const varMatch = varPattern.exec(content);
        if (varMatch) return { rounds: parseInt(varMatch[1]), resolved: 'from variable' };
      }
      return { rounds: '?' };
    },
    assess(params) {
      const rounds = typeof params.rounds === 'number' ? params.rounds : null;
      if (rounds === null) return {
        level: 'acceptable',
        issues: [{ severity: 'low', message: 'bcrypt rounds value is a variable — verify it is ≥ 12 at runtime.' }],
        recommendation: 'Confirm the rounds variable is set to at least 12 in production config.',
      };
      const issues: PasswordIssue[] = [];
      if (rounds < 8) issues.push({ severity: 'critical', message: `bcrypt rounds=${rounds} is critically low — trivially brute-forceable.` });
      else if (rounds < 10) issues.push({ severity: 'high', message: `bcrypt rounds=${rounds} is below recommended minimum of 10.` });
      else if (rounds < 12) issues.push({ severity: 'medium', message: `bcrypt rounds=${rounds} — OWASP recommends ≥ 12 for new systems.` });
      const level: PasswordSecurityLevel = rounds >= 12 ? 'secure' : rounds >= 10 ? 'acceptable' : rounds >= 8 ? 'weak' : 'insecure';
      return {
        level,
        issues,
        recommendation: rounds >= 12
          ? 'bcrypt configuration looks good.'
          : `Increase rounds to at least 12: bcrypt.hash(password, 12).`,
      };
    },
  },

  // ---- bcrypt gensalt (JS) ----
  {
    name: 'bcrypt',
    displayName: 'bcrypt',
    pattern: /bcrypt\.genSalt\s*\(\s*(\d+|\w+)/g,
    extractParams(match) {
      const m = /genSalt\s*\(\s*(\d+)/.exec(match);
      return m ? { rounds: parseInt(m[1]) } : { rounds: '?' };
    },
    assess(params) {
      const rounds = typeof params.rounds === 'number' ? params.rounds : null;
      if (rounds === null) return { level: 'acceptable', issues: [], recommendation: 'Verify rounds variable is ≥ 12.' };
      const issues: PasswordIssue[] = [];
      if (rounds < 12) issues.push({ severity: rounds < 10 ? 'high' : 'medium', message: `bcrypt.genSalt(${rounds}) — use ≥ 12 rounds.` });
      return {
        level: rounds >= 12 ? 'secure' : rounds >= 10 ? 'acceptable' : 'weak',
        issues,
        recommendation: rounds >= 12 ? 'Good.' : `Use bcrypt.genSalt(12) or higher.`,
      };
    },
  },

  // ---- bcrypt (Python) ----
  {
    name: 'bcrypt-python',
    displayName: 'bcrypt (Python)',
    pattern: /bcrypt\.gensalt\s*\(\s*(?:rounds\s*=\s*)?(\d+|\w+)/g,
    extractParams(match) {
      const m = /gensalt\s*\(\s*(?:rounds\s*=\s*)?(\d+)/.exec(match);
      return m ? { rounds: parseInt(m[1]) } : { rounds: '?' };
    },
    assess(params) {
      const rounds = typeof params.rounds === 'number' ? params.rounds : null;
      if (rounds === null) return { level: 'acceptable', issues: [], recommendation: 'Verify rounds ≥ 12.' };
      const issues: PasswordIssue[] = [];
      if (rounds < 12) issues.push({ severity: rounds < 10 ? 'high' : 'medium', message: `bcrypt.gensalt(rounds=${rounds}) — use ≥ 12.` });
      return {
        level: rounds >= 12 ? 'secure' : rounds >= 10 ? 'acceptable' : 'weak',
        issues,
        recommendation: rounds >= 12 ? 'Good.' : `bcrypt.gensalt(rounds=12)`,
      };
    },
  },

  // ---- argon2 (JS) ----
  {
    name: 'argon2',
    displayName: 'Argon2',
    pattern: /argon2\.hash\s*\([^)]{0,300}\)/gs,
    extractParams(match) {
      const params: Record<string, string | number> = {};
      const mem = /memoryCost\s*:\s*(\d+)/.exec(match);
      const time = /timeCost\s*:\s*(\d+)/.exec(match);
      const parallel = /parallelism\s*:\s*(\d+)/.exec(match);
      const typeMatch = /type\s*:\s*argon2\.(\w+)/.exec(match);
      if (mem) params.memoryCost = parseInt(mem[1]);
      if (time) params.timeCost = parseInt(time[1]);
      if (parallel) params.parallelism = parseInt(parallel[1]);
      params.type = typeMatch ? typeMatch[1] : 'argon2d (default — use argon2id)';
      return params;
    },
    assess(params) {
      const issues: PasswordIssue[] = [];
      const mem = typeof params.memoryCost === 'number' ? params.memoryCost : 65536;
      const time = typeof params.timeCost === 'number' ? params.timeCost : 3;
      if (!String(params.type).includes('id')) issues.push({ severity: 'medium', message: 'Use argon2id (most secure variant). Set type: argon2.argon2id.' });
      if (mem < 19456) issues.push({ severity: 'high', message: `memoryCost=${mem} KB is very low — OWASP minimum is 19456 KB for argon2id.` });
      else if (mem < 65536) issues.push({ severity: 'medium', message: `memoryCost=${mem} KB — OWASP recommends ≥ 65536 KB (64 MB).` });
      if (time < 3) issues.push({ severity: 'medium', message: `timeCost=${time} — use ≥ 3 iterations.` });
      const level: PasswordSecurityLevel = issues.some(i => i.severity === 'high') ? 'weak'
        : issues.some(i => i.severity === 'medium') ? 'acceptable' : 'secure';
      return {
        level,
        issues,
        recommendation: level === 'secure' ? 'Argon2 configuration looks good.'
          : 'Use: argon2.hash(password, { type: argon2.argon2id, memoryCost: 65536, timeCost: 3, parallelism: 4 })',
      };
    },
  },

  // ---- argon2-cffi (Python) ----
  {
    name: 'argon2-python',
    displayName: 'Argon2 (Python / argon2-cffi)',
    pattern: /PasswordHasher\s*\([^)]{0,300}\)/gs,
    extractParams(match) {
      const params: Record<string, string | number> = {};
      const mem = /memory_cost\s*=\s*(\d+)/.exec(match);
      const time = /time_cost\s*=\s*(\d+)/.exec(match);
      const parallel = /parallelism\s*=\s*(\d+)/.exec(match);
      if (mem) params.memory_cost = parseInt(mem[1]);
      if (time) params.time_cost = parseInt(time[1]);
      if (parallel) params.parallelism = parseInt(parallel[1]);
      return params;
    },
    assess(params) {
      const issues: PasswordIssue[] = [];
      const mem = typeof params.memory_cost === 'number' ? params.memory_cost : 65536;
      const time = typeof params.time_cost === 'number' ? params.time_cost : 3;
      if (mem < 19456) issues.push({ severity: 'high', message: `memory_cost=${mem} KB is too low.` });
      else if (mem < 65536) issues.push({ severity: 'medium', message: `memory_cost=${mem} KB — OWASP recommends ≥ 65536 KB.` });
      if (time < 3) issues.push({ severity: 'medium', message: `time_cost=${time} — use ≥ 3.` });
      const level: PasswordSecurityLevel = issues.some(i => i.severity === 'high') ? 'weak'
        : issues.some(i => i.severity === 'medium') ? 'acceptable' : 'secure';
      return {
        level,
        issues,
        recommendation: level === 'secure' ? 'Good.'
          : 'Use: PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)',
      };
    },
  },

  // ---- scrypt (Node.js built-in) ----
  {
    name: 'scrypt',
    displayName: 'scrypt (Node.js crypto)',
    pattern: /crypto\.scrypt(?:Sync)?\s*\([^)]{0,300}\)/gs,
    extractParams(match) {
      const params: Record<string, string | number> = {};
      const N = /N\s*:\s*(\d+)/.exec(match) || /cost\s*:\s*(\d+)/.exec(match);
      const r = /r\s*:\s*(\d+)/.exec(match) || /blockSize\s*:\s*(\d+)/.exec(match);
      const p = /p\s*:\s*(\d+)/.exec(match) || /parallelization\s*:\s*(\d+)/.exec(match);
      if (N) params.N = parseInt(N[1]);
      if (r) params.r = parseInt(r[1]);
      if (p) params.p = parseInt(p[1]);
      return params;
    },
    assess(params) {
      const issues: PasswordIssue[] = [];
      const N = typeof params.N === 'number' ? params.N : 16384;
      if (N < 16384) issues.push({ severity: 'high', message: `scrypt N=${N} is below the minimum recommended value of 16384.` });
      const level: PasswordSecurityLevel = issues.length ? 'weak' : 'secure';
      return {
        level,
        issues,
        recommendation: level === 'secure' ? 'Good.' : 'Use N ≥ 16384, r=8, p=1 minimum.',
      };
    },
  },

  // ---- PBKDF2 (Node.js) ----
  {
    name: 'pbkdf2',
    displayName: 'PBKDF2 (Node.js crypto)',
    pattern: /crypto\.pbkdf2(?:Sync)?\s*\([^)]{0,300}\)/gs,
    extractParams(match) {
      // pbkdf2(password, salt, iterations, keylen, digest, callback)
      const args = match.replace(/crypto\.pbkdf2(?:Sync)?\s*\(/, '').split(',');
      const iterations = args[2] ? parseInt(args[2].trim()) : NaN;
      const digest = args[4] ? args[4].trim().replace(/['")\s]/g, '') : 'unknown';
      return { iterations: isNaN(iterations) ? '?' : iterations, digest };
    },
    assess(params) {
      const issues: PasswordIssue[] = [];
      const iters = typeof params.iterations === 'number' ? params.iterations : null;
      const digest = String(params.digest).toLowerCase();
      if (digest.includes('sha1') || digest.includes('md5')) {
        issues.push({ severity: 'critical', message: `PBKDF2 using ${digest} — use sha256 or sha512.` });
      }
      if (iters !== null && iters < 100000) {
        issues.push({ severity: iters < 10000 ? 'critical' : 'high', message: `PBKDF2 iterations=${iters} — OWASP recommends 600,000 for SHA-256.` });
      } else if (iters !== null && iters < 600000) {
        issues.push({ severity: 'medium', message: `PBKDF2 iterations=${iters} — OWASP 2023 recommends 600,000 for SHA-256.` });
      }
      const level: PasswordSecurityLevel = issues.some(i => i.severity === 'critical') ? 'insecure'
        : issues.some(i => i.severity === 'high') ? 'weak'
        : issues.some(i => i.severity === 'medium') ? 'acceptable' : 'secure';
      return {
        level, issues,
        recommendation: level === 'secure' ? 'Good.'
          : 'Use: crypto.pbkdf2(password, salt, 600000, 64, "sha256", callback)',
      };
    },
  },

  // ---- werkzeug (Python/Flask) ----
  {
    name: 'werkzeug',
    displayName: 'Werkzeug (Flask)',
    pattern: /generate_password_hash\s*\([^)]{0,200}\)/g,
    extractParams(match) {
      const method = /method\s*=\s*['"]([^'"]+)['"]/.exec(match);
      const salt = /salt_length\s*=\s*(\d+)/.exec(match);
      return {
        method: method ? method[1] : 'pbkdf2:sha256 (default)',
        salt_length: salt ? parseInt(salt[1]) : 16,
      };
    },
    assess(params) {
      const issues: PasswordIssue[] = [];
      const method = String(params.method).toLowerCase();
      if (method.includes('md5') || method.includes('sha1') || method === 'plain') {
        issues.push({ severity: 'critical', message: `Werkzeug using insecure method "${params.method}".` });
      } else if (method.includes('pbkdf2:sha1')) {
        issues.push({ severity: 'high', message: 'Use pbkdf2:sha256 instead of pbkdf2:sha1.' });
      }
      const level: PasswordSecurityLevel = issues.some(i => i.severity === 'critical') ? 'insecure'
        : issues.some(i => i.severity === 'high') ? 'weak' : 'acceptable';
      return {
        level, issues,
        recommendation: level !== 'insecure' && level !== 'weak'
          ? 'Werkzeug default (pbkdf2:sha256) is acceptable. Consider migrating to bcrypt or Argon2 for stronger security.'
          : 'Use generate_password_hash(password, method="pbkdf2:sha256", salt_length=16).',
      };
    },
  },

  // ---- passlib CryptContext ----
  {
    name: 'passlib',
    displayName: 'passlib CryptContext',
    pattern: /CryptContext\s*\([^)]{0,300}\)/gs,
    extractParams(match) {
      const schemes = /schemes\s*=\s*\[([^\]]+)\]/.exec(match);
      const deprecated = /deprecated\s*=\s*['"]([^'"]+)['"]/.exec(match);
      return {
        schemes: schemes ? schemes[1].replace(/['"\s]/g, '') : 'unknown',
        deprecated: deprecated ? deprecated[1] : 'auto',
      };
    },
    assess(params) {
      const issues: PasswordIssue[] = [];
      const schemes = String(params.schemes).toLowerCase();
      if (schemes.includes('md5') || schemes.includes('sha1_crypt')) {
        issues.push({ severity: 'high', message: `passlib scheme includes weak algorithm: ${params.schemes}` });
      }
      const hasStrong = schemes.includes('bcrypt') || schemes.includes('argon2') || schemes.includes('scrypt');
      if (!hasStrong) issues.push({ severity: 'medium', message: 'No strong algorithm (bcrypt/argon2/scrypt) in CryptContext schemes.' });
      const level: PasswordSecurityLevel = issues.some(i => i.severity === 'high') ? 'weak'
        : issues.some(i => i.severity === 'medium') ? 'acceptable' : 'secure';
      return {
        level, issues,
        recommendation: level === 'secure' ? 'Good.' : "Use CryptContext(schemes=['argon2', 'bcrypt'], deprecated='auto').",
      };
    },
  },

  // ---- MD5 direct hash (insecure) ----
  {
    name: 'md5',
    displayName: 'MD5',
    pattern: /(?:createHash\s*\(\s*['"]md5['"]|hashlib\.md5\s*\()/g,
    extractParams: () => ({}),
    assess() {
      return {
        level: 'insecure' as const,
        issues: [{ severity: 'critical' as const, message: 'MD5 is cryptographically broken and must never be used for passwords.' }],
        recommendation: 'Replace with bcrypt, Argon2id, or scrypt immediately.',
      };
    },
  },

  // ---- SHA-1 direct hash (insecure) ----
  {
    name: 'sha1',
    displayName: 'SHA-1',
    pattern: /(?:createHash\s*\(\s*['"]sha1['"]|hashlib\.sha1\s*\()/g,
    extractParams: () => ({}),
    assess() {
      return {
        level: 'insecure' as const,
        issues: [{ severity: 'critical' as const, message: 'SHA-1 is broken and must never be used for password hashing.' }],
        recommendation: 'Replace with bcrypt, Argon2id, or scrypt immediately.',
      };
    },
  },

  // ---- SHA-256/512 direct (weak for passwords) ----
  {
    name: 'sha256',
    displayName: 'SHA-256/512 (direct)',
    pattern: /(?:createHash\s*\(\s*['"]sha(?:256|512)['"]|hashlib\.sha(?:256|512)\s*\()/g,
    extractParams(match, content, idx) {
      // Check if it's inside a loop or has a large iteration count nearby (PBKDF2-like)
      const context = content.substring(Math.max(0, idx - 200), idx + 200);
      const hasIterations = /for\s*\(|while\s*\(|iterations|rounds/.test(context);
      return { stretched: hasIterations };
    },
    assess(params) {
      const issues: PasswordIssue[] = [];
      if (!params.stretched) {
        issues.push({ severity: 'high', message: 'Direct SHA-256/512 without key stretching is not suitable for passwords — it is too fast for brute-force resistance.' });
      }
      return {
        level: params.stretched ? 'weak' : 'insecure',
        issues,
        recommendation: 'Use bcrypt, Argon2id, or scrypt. SHA-256/512 is appropriate for general hashing but not password storage.',
      };
    },
  },

  // ---- Spring Security BCryptPasswordEncoder (Java) ----
  {
    name: 'spring-bcrypt',
    displayName: 'BCryptPasswordEncoder (Spring)',
    pattern: /new\s+BCryptPasswordEncoder\s*\(\s*(\d+|\w+)?\s*\)/g,
    extractParams(match) {
      const m = /BCryptPasswordEncoder\s*\(\s*(\d+)/.exec(match);
      return m ? { strength: parseInt(m[1]) } : { strength: '(default=10)' };
    },
    assess(params) {
      const strength = typeof params.strength === 'number' ? params.strength : null;
      if (strength === null) return {
        level: 'acceptable',
        issues: [{ severity: 'low', message: 'BCryptPasswordEncoder uses default strength 10. OWASP recommends ≥ 12 for new systems.' }],
        recommendation: 'Use new BCryptPasswordEncoder(12) or higher for better resistance to offline attacks.',
      };
      const issues: PasswordIssue[] = [];
      if (strength < 10) issues.push({ severity: 'high', message: `BCryptPasswordEncoder(${strength}) is too weak — use ≥ 12.` });
      else if (strength < 12) issues.push({ severity: 'medium', message: `BCryptPasswordEncoder(${strength}) — OWASP recommends ≥ 12 for new systems.` });
      return {
        level: strength >= 12 ? 'secure' : strength >= 10 ? 'acceptable' : 'weak',
        issues,
        recommendation: strength >= 12 ? 'Good.' : 'Use new BCryptPasswordEncoder(12) or higher.',
      };
    },
  },

  // ---- Spring Security Argon2PasswordEncoder (Java) ----
  {
    name: 'spring-argon2',
    displayName: 'Argon2PasswordEncoder (Spring)',
    pattern: /Argon2PasswordEncoder\.withSecureDefaults\s*\(\s*\)|new\s+Argon2PasswordEncoder\s*\([^)]{0,200}\)/g,
    extractParams(match) {
      if (match.includes('withSecureDefaults')) return { config: 'secure-defaults' };
      const mem = /(\d+)\s*,\s*\d+\s*,\s*\d+\s*,\s*\d+\s*,\s*\d+/.exec(match);
      return mem ? { saltLength: parseInt(mem[1]) } : { config: 'custom' };
    },
    assess(params) {
      if (params.config === 'secure-defaults') {
        return { level: 'secure', issues: [], recommendation: 'withSecureDefaults() applies OWASP-compliant Argon2 parameters.' };
      }
      return {
        level: 'acceptable',
        issues: [{ severity: 'low', message: 'Verify custom Argon2 parameters meet OWASP recommendations.' }],
        recommendation: 'Prefer Argon2PasswordEncoder.withSecureDefaults() or verify memoryCost ≥ 19456 KB and iterations ≥ 2.',
      };
    },
  },

  // ---- Spring Security SCryptPasswordEncoder (Java) ----
  {
    name: 'spring-scrypt',
    displayName: 'SCryptPasswordEncoder (Spring)',
    pattern: /SCryptPasswordEncoder\.defaultsForSpringSecurity_v\d+\s*\(\s*\)|new\s+SCryptPasswordEncoder\s*\([^)]{0,200}\)/g,
    extractParams(match) {
      return { config: match.includes('defaultsFor') ? 'secure-defaults' : 'custom' };
    },
    assess(params) {
      return {
        level: params.config === 'secure-defaults' ? 'secure' : 'acceptable',
        issues: params.config === 'secure-defaults' ? [] : [{ severity: 'low', message: 'Verify custom SCrypt parameters are adequate (cpuCost ≥ 16384).' }],
        recommendation: params.config === 'secure-defaults' ? 'Good.' : 'Use SCryptPasswordEncoder.defaultsForSpringSecurity_v5_8() for OWASP-compliant defaults.',
      };
    },
  },

  // ---- Spring Security PBKDF2PasswordEncoder (Java) ----
  {
    name: 'spring-pbkdf2',
    displayName: 'PBKDF2PasswordEncoder (Spring)',
    pattern: /PBKDF2PasswordEncoder\.defaultsForSpringSecurity_v\d+\s*\(\s*\)|new\s+PBKDF2PasswordEncoder\s*\([^)]{0,300}\)/g,
    extractParams(match) {
      if (match.includes('defaultsFor')) return { config: 'secure-defaults' };
      const iter = /,\s*(\d+)\s*,\s*\d+/.exec(match);
      return iter ? { iterations: parseInt(iter[1]) } : { config: 'custom' };
    },
    assess(params) {
      if (params.config === 'secure-defaults') return { level: 'secure', issues: [], recommendation: 'Good.' };
      const iters = typeof params.iterations === 'number' ? params.iterations : null;
      const issues: PasswordIssue[] = [];
      if (iters !== null && iters < 600000) {
        issues.push({ severity: iters < 100000 ? 'high' : 'medium', message: `PBKDF2 iterations=${iters} — OWASP 2023 recommends 600,000.` });
      }
      return {
        level: iters !== null && iters >= 600000 ? 'secure' : iters !== null && iters >= 100000 ? 'acceptable' : 'weak',
        issues,
        recommendation: 'Use PBKDF2PasswordEncoder.defaultsForSpringSecurity_v5_8() or set iterations ≥ 600,000 with SHA-256.',
      };
    },
  },

  // ---- Java MessageDigest MD5 (insecure) ----
  {
    name: 'java-md5',
    displayName: 'MD5 (Java MessageDigest)',
    pattern: /MessageDigest\.getInstance\s*\(\s*"MD5"\s*\)/g,
    extractParams: () => ({}),
    assess() {
      return {
        level: 'insecure' as const,
        issues: [{ severity: 'critical' as const, message: 'MD5 is cryptographically broken and must never be used for passwords or security-sensitive hashing.' }],
        recommendation: 'For passwords use BCryptPasswordEncoder, Argon2PasswordEncoder. For integrity use SHA-256 minimum.',
      };
    },
  },

  // ---- Java MessageDigest SHA-1 (insecure) ----
  {
    name: 'java-sha1',
    displayName: 'SHA-1 (Java MessageDigest)',
    pattern: /MessageDigest\.getInstance\s*\(\s*"SHA-?1"\s*\)/g,
    extractParams: () => ({}),
    assess() {
      return {
        level: 'insecure' as const,
        issues: [{ severity: 'critical' as const, message: 'SHA-1 is broken and must never be used for password hashing.' }],
        recommendation: 'Replace with BCryptPasswordEncoder or Argon2PasswordEncoder for passwords.',
      };
    },
  },

  // ---- Java MessageDigest SHA-256/512 (weak for passwords) ----
  {
    name: 'java-sha256',
    displayName: 'SHA-256/512 (Java MessageDigest)',
    pattern: /MessageDigest\.getInstance\s*\(\s*"SHA-(?:256|512)"\s*\)/g,
    extractParams: () => ({}),
    assess() {
      return {
        level: 'insecure' as const,
        issues: [{ severity: 'high' as const, message: 'Direct SHA-256/512 without key-stretching is not suitable for password hashing — it is far too fast.' }],
        recommendation: 'Use BCryptPasswordEncoder, Argon2PasswordEncoder, or SCryptPasswordEncoder for passwords.',
      };
    },
  },
];

const LOGIN_ROUTE_PATTERN = /(?:(?:router|app)\.(post|get)\s*\(\s*['"][^'"]*(?:login|signin|auth|token)[^'"]*['"])|@(?:app|blueprint|bp|router)\.(route|post)\s*\(\s*['"][^'"]*(?:login|signin|auth|token)[^'"]*['"]|@(?:Post|Get|Request)Mapping\s*\(\s*(?:value\s*=\s*)?["'][^"']*(?:login|signin|auth|token)[^"']*["']/gi;

export class PasswordAnalyzer {
  analyzeFiles(files: Array<{ filePath: string; content: string }>): PasswordAnalysisReport {
    const findings: PasswordFinding[] = [];
    let hasLoginRoutes = false;

    for (const file of files) {
      const { content, filePath } = file;
      if (!hasLoginRoutes) {
        hasLoginRoutes = LOGIN_ROUTE_PATTERN.test(content);
        LOGIN_ROUTE_PATTERN.lastIndex = 0;
      }
      findings.push(...this.analyzeFileContent(filePath, content));
    }

    const uniqueFindings = this.deduplicateFindings(findings);
    const hasPasswordHandling = uniqueFindings.length > 0;
    const noHashingButHasAuth = !hasPasswordHandling && hasLoginRoutes;

    const overallRating = this.computeOverallRating(uniqueFindings, noHashingButHasAuth);
    const summary = this.buildSummary(uniqueFindings, noHashingButHasAuth);

    return { findings: uniqueFindings, hasPasswordHandling, hasLoginRoutes, noHashingButHasAuth, overallRating, summary };
  }

  private analyzeFileContent(filePath: string, content: string): PasswordFinding[] {
    const findings: PasswordFinding[] = [];
    const lines = content.split('\n');

    for (const detector of DETECTORS) {
      const regex = new RegExp(detector.pattern.source, detector.pattern.flags.includes('g') ? detector.pattern.flags : detector.pattern.flags + 'g');
      let match: RegExpExecArray | null;

      while ((match = regex.exec(content)) !== null) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        const snippet = lines[lineNumber - 1]?.trim().substring(0, 120) ?? match[0];

        const params = detector.extractParams(match[0], content, match.index);
        const { level, issues, recommendation } = detector.assess(params);

        const paramStr = Object.entries(params)
          .filter(([, v]) => v !== undefined && v !== '' && typeof v !== 'boolean')
          .reduce<Record<string, string | number>>((acc, [k, v]) => { acc[k] = v as string | number; return acc; }, {});

        findings.push({
          algorithm: detector.name,
          displayName: detector.displayName,
          securityLevel: level,
          parameters: paramStr,
          codeRef: { file: filePath, line: lineNumber, column: 0, snippet },
          issues,
          recommendation,
        });
      }
    }

    return findings;
  }

  private deduplicateFindings(findings: PasswordFinding[]): PasswordFinding[] {
    const seen = new Set<string>();
    return findings.filter(f => {
      const key = `${f.algorithm}-${f.codeRef.file}-${f.codeRef.line}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }

  private computeOverallRating(findings: PasswordFinding[], noHashingButHasAuth: boolean): PasswordSecurityLevel {
    if (noHashingButHasAuth) return 'insecure';
    if (findings.length === 0) return 'none';
    const order: PasswordSecurityLevel[] = ['insecure', 'weak', 'acceptable', 'secure', 'none'];
    return findings.reduce<PasswordSecurityLevel>((worst, f) => {
      return order.indexOf(f.securityLevel) < order.indexOf(worst) ? f.securityLevel : worst;
    }, 'secure');
  }

  private buildSummary(findings: PasswordFinding[], noHashingButHasAuth: boolean): string {
    if (noHashingButHasAuth) return 'Login routes detected but no password hashing found — passwords may be stored in plain text.';
    if (findings.length === 0) return 'No password hashing detected in the codebase.';
    const algs = [...new Set(findings.map(f => f.displayName))].join(', ');
    const hasIssues = findings.some(f => f.issues.length > 0);
    return `${findings.length} password hashing instance(s) found using: ${algs}. ${hasIssues ? 'Security issues detected.' : 'No critical issues.'}`;
  }
}
