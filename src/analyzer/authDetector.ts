import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';
import {
  AnalysisResult,
  AuthFlow,
  AuthStep,
  DetectedTechnology,
  AnalysisSummary,
  Vulnerability,
  ActorType,
  StepType,
  AuthFlowType,
} from '../types';
import { LIBRARY_PATTERNS, AUTH_ROUTE_PATTERNS, MIDDLEWARE_PATTERNS, LibraryPattern } from './patternMatchers';
import { SecurityAnalyzer } from './securityAnalyzer';
import { WebAuthnAnalyzer } from './webAuthnAnalyzer';
import { PasswordAnalyzer } from './passwordAnalyzer';

interface FileAnalysis {
  filePath: string;
  content: string;
  detectedLibraries: LibraryPattern[];
  routes: RouteInfo[];
  middlewares: string[];
  authOperations: AuthOperation[];
}

interface RouteInfo {
  method: string;
  path: string;
  line: number;
  snippet: string;
}

interface AuthOperation {
  type: string;
  line: number;
  snippet: string;
  library?: string;
}

export class AuthDetector {
  private securityAnalyzer: SecurityAnalyzer;
  private webAuthnAnalyzer: WebAuthnAnalyzer;
  private passwordAnalyzer: PasswordAnalyzer;
  private config: vscode.WorkspaceConfiguration;

  constructor() {
    this.securityAnalyzer = new SecurityAnalyzer();
    this.webAuthnAnalyzer = new WebAuthnAnalyzer();
    this.passwordAnalyzer = new PasswordAnalyzer();
    this.config = vscode.workspace.getConfiguration('authAnalyzer');
  }

  async analyzeWorkspace(
    progress?: vscode.Progress<{ message?: string; increment?: number }>
  ): Promise<AnalysisResult> {
    const startTime = Date.now();
    const excludePatterns = this.config.get<string[]>('excludePatterns') ?? [
      '**/node_modules/**',
      '**/dist/**',
      '**/build/**',
      '**/.next/**',
    ];

    progress?.report({ message: 'Finding JavaScript/TypeScript files...', increment: 5 });

    const files = await this.findSourceFiles(excludePatterns);
    const allVulnerabilities: Vulnerability[] = [];
    const allTechnologies = new Map<string, DetectedTechnology>();
    const fileAnalyses: FileAnalysis[] = [];

    const increment = files.length > 0 ? 60 / files.length : 60;

    for (const file of files) {
      progress?.report({ message: `Analyzing ${path.basename(file)}...`, increment });
      const analysis = await this.analyzeFile(file);
      if (analysis) {
        fileAnalyses.push(analysis);

        for (const lib of analysis.detectedLibraries) {
          if (!allTechnologies.has(lib.name)) {
            allTechnologies.set(lib.name, {
              name: lib.name,
              displayName: lib.displayName,
              description: lib.description,
              type: lib.type,
              files: [],
              docsUrl: lib.docsUrl,
            });
          }
          allTechnologies.get(lib.name)!.files.push(file);
        }

        const fileVulns = await this.securityAnalyzer.analyzeFile(file, analysis.content);
        allVulnerabilities.push(...fileVulns);
      }
    }

    progress?.report({ message: 'Building authentication flows...', increment: 15 });
    const flows = this.buildFlows(fileAnalyses);

    progress?.report({ message: 'Running WebAuthn analysis...', increment: 10 });
    const webAuthnVulns = await this.webAuthnAnalyzer.analyzeFiles(fileAnalyses.map(f => ({
      filePath: f.filePath,
      content: f.content,
    })));
    allVulnerabilities.push(...webAuthnVulns);

    const dedupedVulns = this.deduplicateVulnerabilities(allVulnerabilities);

    progress?.report({ message: 'Analyzing password security...', increment: 5 });
    const passwordAnalysis = this.passwordAnalyzer.analyzeFiles(
      fileAnalyses.map(f => ({ filePath: f.filePath, content: f.content }))
    );

    progress?.report({ message: 'Finalizing results...', increment: 5 });

    const technologies = Array.from(allTechnologies.values());
    const summary = this.buildSummary(flows, dedupedVulns, technologies, files.length, Date.now() - startTime);

    return {
      flows,
      vulnerabilities: dedupedVulns,
      technologies,
      summary,
      passwordAnalysis,
      timestamp: Date.now(),
    };
  }

  async analyzeCurrentFile(): Promise<AnalysisResult> {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
      return this.emptyResult();
    }

    const filePath = editor.document.uri.fsPath;
    const content = editor.document.getText();

    const analysis = await this.analyzeFileContent(filePath, content);
    if (!analysis) {
      return this.emptyResult();
    }

    const vulnerabilities = await this.securityAnalyzer.analyzeFile(filePath, content);
    const technologies: DetectedTechnology[] = analysis.detectedLibraries.map(lib => ({
      name: lib.name,
      displayName: lib.displayName,
      description: lib.description,
      type: lib.type,
      files: [filePath],
      docsUrl: lib.docsUrl,
    }));

    const flows = this.buildFlows([analysis]);
    const summary = this.buildSummary(flows, vulnerabilities, technologies, 1, 0);
    const passwordAnalysis = this.passwordAnalyzer.analyzeFiles([{ filePath, content }]);

    return { flows, vulnerabilities, technologies, summary, passwordAnalysis, timestamp: Date.now() };
  }

  private async findSourceFiles(excludePatterns: string[]): Promise<string[]> {
    const includePattern = '**/*.{js,ts,jsx,tsx,mjs,cjs,py,java,kt,groovy}';
    const excludeGlob = `{${excludePatterns.join(',')}}`;

    const uris = await vscode.workspace.findFiles(includePattern, excludeGlob, 500);
    return uris.map(u => u.fsPath);
  }

  private async analyzeFile(filePath: string): Promise<FileAnalysis | null> {
    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      return this.analyzeFileContent(filePath, content);
    } catch {
      return null;
    }
  }

  private analyzeFileContent(filePath: string, content: string): FileAnalysis | null {
    const detectedLibraries = this.detectLibraries(content);
    const routes = this.detectRoutes(content);
    const middlewares = this.detectMiddlewares(content);
    const authOperations = this.detectAuthOperations(content, detectedLibraries);

    const hasAuthContent =
      detectedLibraries.length > 0 ||
      routes.length > 0 ||
      middlewares.length > 0 ||
      authOperations.length > 0;

    if (!hasAuthContent) return null;

    return { filePath, content, detectedLibraries, routes, middlewares, authOperations };
  }

  private detectLibraries(content: string): LibraryPattern[] {
    return LIBRARY_PATTERNS.filter(lib =>
      lib.importPatterns.some(p => {
        // Reset stateful regex before testing
        p.lastIndex = 0;
        return p.test(content);
      })
    );
  }

  private detectRoutes(content: string): RouteInfo[] {
    const routes: RouteInfo[] = [];
    const lines = content.split('\n');

    for (const pattern of AUTH_ROUTE_PATTERNS) {
      const globalPattern = new RegExp(pattern.source, pattern.flags.includes('g') ? pattern.flags : pattern.flags + 'g');
      let match: RegExpExecArray | null;
      while ((match = globalPattern.exec(content)) !== null) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        const snippet = lines[lineNumber - 1]?.trim() ?? match[0];
        const methodMatch = /\.(get|post|put|delete|patch)\s*\(\s*['"]([^'"]+)['"]/.exec(match[0]);

        if (methodMatch) {
          routes.push({
            method: methodMatch[1].toUpperCase(),
            path: methodMatch[2],
            line: lineNumber,
            snippet: snippet.substring(0, 100),
          });
        }
      }
    }

    return routes;
  }

  private detectMiddlewares(content: string): string[] {
    const middlewares: string[] = [];
    for (const pattern of MIDDLEWARE_PATTERNS) {
      const globalPattern = new RegExp(pattern.source, 'g');
      let match: RegExpExecArray | null;
      while ((match = globalPattern.exec(content)) !== null) {
        middlewares.push(match[0].trim().substring(0, 80));
      }
    }
    return middlewares;
  }

  private detectAuthOperations(content: string, libraries: LibraryPattern[]): AuthOperation[] {
    const operations: AuthOperation[] = [];
    const lines = content.split('\n');

    for (const lib of libraries) {
      for (const pattern of lib.usagePatterns) {
        const globalPattern = new RegExp(pattern.source, 'g');
        let match: RegExpExecArray | null;
        while ((match = globalPattern.exec(content)) !== null) {
          const lineNumber = content.substring(0, match.index).split('\n').length;
          operations.push({
            type: this.classifyOperation(match[0], lib.flowType),
            line: lineNumber,
            snippet: lines[lineNumber - 1]?.trim().substring(0, 100) ?? match[0],
            library: lib.name,
          });
        }
      }
    }

    return operations;
  }

  private classifyOperation(snippet: string, flowType: string): string {
    // JS/TS JWT
    if (/\.sign\s*\(|SignJWT/.test(snippet)) return 'token-issuance';
    if (/\.verify\s*\(|jwtVerify/.test(snippet)) return 'token-validation';
    if (/\.decode\s*\(/.test(snippet)) return 'token-decode';
    // JS/TS WebAuthn
    if (/generateRegistrationOptions|attestationOptions/.test(snippet)) return 'webauthn-reg-options';
    if (/verifyRegistrationResponse|attestationResult/.test(snippet)) return 'webauthn-reg-verify';
    if (/generateAuthenticationOptions|assertionOptions/.test(snippet)) return 'webauthn-auth-options';
    if (/verifyAuthenticationResponse|assertionResult/.test(snippet)) return 'webauthn-auth-verify';
    // JS/TS password + session
    if (/bcrypt\.hash|argon2\.hash/.test(snippet)) return 'password-hash';
    if (/bcrypt\.compare|argon2\.verify/.test(snippet)) return 'password-verify';
    if (/passport\.authenticate/.test(snippet)) return 'oauth-authenticate';
    if (/req\.session\.\w+\s*=/.test(snippet)) return 'session-create';
    if (/session\.destroy/.test(snippet)) return 'session-destroy';
    // Python JWT (PyJWT / python-jose)
    if (/jwt\.encode\s*\(/.test(snippet)) return 'token-issuance';
    if (/jwt\.decode\s*\(/.test(snippet)) return 'token-validation';
    // Python WebAuthn (py_webauthn)
    if (/generate_registration_options/.test(snippet)) return 'webauthn-reg-options';
    if (/verify_registration_response/.test(snippet)) return 'webauthn-reg-verify';
    if (/generate_authentication_options/.test(snippet)) return 'webauthn-auth-options';
    if (/verify_authentication_response/.test(snippet)) return 'webauthn-auth-verify';
    // Python FIDO2 (python-fido2)
    if (/register_begin/.test(snippet)) return 'webauthn-reg-options';
    if (/register_complete/.test(snippet)) return 'webauthn-reg-verify';
    if (/authenticate_begin/.test(snippet)) return 'webauthn-auth-options';
    if (/authenticate_complete/.test(snippet)) return 'webauthn-auth-verify';
    // Python password hashing
    if (/bcrypt\.hashpw|\.hash\s*\(/.test(snippet)) return 'password-hash';
    if (/bcrypt\.checkpw|\.verify\s*\(|check_password/.test(snippet)) return 'password-verify';
    // Python session / Flask-Login
    if (/login_user\s*\(/.test(snippet)) return 'session-create';
    if (/logout_user\s*\(/.test(snippet)) return 'session-destroy';
    if (/session\[/.test(snippet)) return 'session-create';
    // Python Django
    if (/authenticate\s*\(/.test(snippet)) return 'middleware';
    if (/create_access_token|create_refresh_token/.test(snippet)) return 'token-issuance';
    if (/get_jwt_identity|verify_jwt_in_request/.test(snippet)) return 'token-validation';
    // Java JJWT
    if (/Jwts\.builder|\.signWith/.test(snippet)) return 'token-issuance';
    if (/\.parseClaimsJws|\.parseClaimsJwt|Jwts\.parser/.test(snippet)) return 'token-validation';
    // Java Auth0 JWT
    if (/JWT\.create|\.sign\s*\(Algorithm/.test(snippet)) return 'token-issuance';
    if (/JWT\.require|\.verify\s*\(/.test(snippet)) return 'token-validation';
    // Java WebAuthn
    if (/startRegistration|finishRegistration/.test(snippet)) return 'webauthn-reg-options';
    if (/startAssertion|finishAssertion/.test(snippet)) return 'webauthn-auth-options';
    // Java Spring Security
    if (/SecurityContextHolder|\.authenticated\(\)/.test(snippet)) return 'middleware';
    if (/\.formLogin|UsernamePasswordAuthenticationFilter/.test(snippet)) return 'credential-input';
    if (/passwordEncoder\.encode/.test(snippet)) return 'password-hash';
    if (/passwordEncoder\.matches/.test(snippet)) return 'password-verify';
    // Java Apache Shiro
    if (/subject\.login/.test(snippet)) return 'credential-input';
    if (/subject\.isAuthenticated/.test(snippet)) return 'middleware';
    return `${flowType}-operation`;
  }

  private buildFlows(fileAnalyses: FileAnalysis[]): AuthFlow[] {
    const flows: AuthFlow[] = [];

    // Group file analyses by auth type
    const byType = new Map<string, FileAnalysis[]>();
    for (const analysis of fileAnalyses) {
      for (const lib of analysis.detectedLibraries) {
        const key = lib.flowType;
        if (!byType.has(key)) byType.set(key, []);
        byType.get(key)!.push(analysis);
      }
    }

    // JWT flow
    if (byType.has('jwt')) {
      const jwtFiles = byType.get('jwt')!;
      flows.push(this.buildJWTFlow(jwtFiles));
    }

    // OAuth2 flow
    if (byType.has('oauth2')) {
      const oauthFiles = byType.get('oauth2')!;
      flows.push(this.buildOAuthFlow(oauthFiles));
    }

    // Session flow
    if (byType.has('session')) {
      const sessionFiles = byType.get('session')!;
      flows.push(this.buildSessionFlow(sessionFiles));
    }

    // WebAuthn flow
    if (byType.has('webauthn')) {
      const webauthnFiles = byType.get('webauthn')!;
      flows.push(...this.buildWebAuthnFlows(webauthnFiles));
    }

    // Python Django flow
    const djangoFiles = fileAnalyses.filter(f =>
      f.detectedLibraries.some(l => l.name === 'django-auth' || l.name === 'djangorestframework-simplejwt')
    );
    if (djangoFiles.length > 0 && !byType.has('session') && !byType.has('jwt')) {
      if (djangoFiles.some(f => f.detectedLibraries.some(l => l.name === 'djangorestframework-simplejwt'))) {
        flows.push(this.buildDjangoJWTFlow(djangoFiles));
      } else {
        flows.push(this.buildDjangoSessionFlow(djangoFiles));
      }
    }

    // Python FastAPI flow
    const fastapiFiles = fileAnalyses.filter(f =>
      f.detectedLibraries.some(l => l.name === 'fastapi-security')
    );
    if (fastapiFiles.length > 0 && !byType.has('oauth2') && !byType.has('jwt')) {
      flows.push(this.buildFastAPIFlow(fastapiFiles));
    }

    // Python Flask flow
    const flaskFiles = fileAnalyses.filter(f =>
      f.detectedLibraries.some(l => l.name === 'flask-login' || l.name === 'flask-jwt-extended')
    );
    if (flaskFiles.length > 0 && !byType.has('session') && !byType.has('jwt')) {
      flows.push(this.buildFlaskFlow(flaskFiles));
    }

    // Java Spring Security flow
    const springFiles = fileAnalyses.filter(f =>
      f.detectedLibraries.some(l => l.name === 'spring-security' || l.name === 'spring-security-oauth2')
    );
    if (springFiles.length > 0 && !byType.has('session') && !byType.has('oauth2')) {
      const hasOAuth = springFiles.some(f => f.detectedLibraries.some(l => l.name === 'spring-security-oauth2'));
      flows.push(hasOAuth ? this.buildSpringOAuth2Flow(springFiles) : this.buildSpringSecurityFlow(springFiles));
    }

    // Java JWT flow (JJWT / Auth0 / Nimbus)
    const javaJwtFiles = fileAnalyses.filter(f =>
      f.detectedLibraries.some(l => ['jjwt', 'java-jwt', 'nimbus-jose-jwt'].includes(l.name))
    );
    if (javaJwtFiles.length > 0 && !byType.has('jwt') && springFiles.length === 0) {
      flows.push(this.buildJavaJWTFlow(javaJwtFiles));
    }

    // Java Apache Shiro flow
    const shiroFiles = fileAnalyses.filter(f =>
      f.detectedLibraries.some(l => l.name === 'apache-shiro')
    );
    if (shiroFiles.length > 0 && !byType.has('session') && springFiles.length === 0) {
      flows.push(this.buildShiroFlow(shiroFiles));
    }

    // If no specific flows found but there are auth routes
    if (flows.length === 0) {
      const allWithRoutes = fileAnalyses.filter(f => f.routes.length > 0);
      if (allWithRoutes.length > 0) {
        flows.push(this.buildGenericAuthFlow(allWithRoutes));
      }
    }

    return flows;
  }

  private buildJWTFlow(analyses: FileAnalysis[]): AuthFlow {
    const files = analyses.map(a => a.filePath);
    const steps: AuthStep[] = [
      this.makeStep('jwt-1', 'Client Sends Credentials', 'User submits username and password via login form or API call.', 'credential-input', 'client', 'server', files[0]),
      this.makeStep('jwt-2', 'Validate Credentials', 'Server looks up user in database and verifies password hash using bcrypt/Argon2.', 'middleware', 'server', 'database', files[0]),
      this.makeStep('jwt-3', 'Issue JWT Access Token', 'On success, server signs a JWT containing user claims (sub, role, exp) with a secret or private key.', 'token-issuance', 'server', 'client', files[0]),
      this.makeStep('jwt-4', 'Client Stores Token', 'Client stores the token in memory, localStorage, or an httpOnly cookie.', 'session-creation', 'client', 'client', files[0]),
      this.makeStep('jwt-5', 'Authenticated Request', 'Client includes the JWT in the Authorization: Bearer <token> header for subsequent requests.', 'middleware', 'client', 'server', files[0]),
      this.makeStep('jwt-6', 'Verify JWT Signature', 'Server middleware validates the JWT signature, checks expiry, and extracts claims from the payload.', 'token-validation', 'server', 'server', files[0]),
      this.makeStep('jwt-7', 'Access Protected Resource', 'Server grants or denies access based on the validated token claims (roles, permissions).', 'authorization', 'server', 'client', files[0]),
    ];

    // Enrich steps with code references from actual analysis
    for (const analysis of analyses) {
      for (const op of analysis.authOperations) {
        if (op.type === 'token-issuance') {
          const step = steps.find(s => s.id === 'jwt-3');
          if (step) step.codeRef = { file: analysis.filePath, line: op.line, column: 0, snippet: op.snippet };
        }
        if (op.type === 'token-validation') {
          const step = steps.find(s => s.id === 'jwt-6');
          if (step) step.codeRef = { file: analysis.filePath, line: op.line, column: 0, snippet: op.snippet };
        }
      }
    }

    return {
      id: 'jwt-flow',
      name: 'JWT Authentication Flow',
      type: 'jwt',
      steps,
      files,
      vulnerabilities: [],
      description: 'Stateless token-based authentication using JSON Web Tokens. The server issues a signed token that the client presents on subsequent requests.',
      metadata: { algorithm: 'HS256/RS256', storage: 'Client-side', stateless: 'true' },
    };
  }

  private buildOAuthFlow(analyses: FileAnalysis[]): AuthFlow {
    const files = analyses.map(a => a.filePath);
    const steps: AuthStep[] = [
      this.makeStep('oauth-1', 'User Initiates Login', 'User clicks "Login with Provider" button. Application redirects to Identity Provider with client_id, redirect_uri, scope, and state.', 'credential-input', 'client', 'identityProvider', files[0]),
      this.makeStep('oauth-2', 'User Authenticates at IdP', 'User authenticates with the Identity Provider (Google, GitHub, etc.) and grants requested permissions.', 'credential-input', 'identityProvider', 'identityProvider', files[0]),
      this.makeStep('oauth-3', 'Authorization Code Returned', 'IdP redirects back to redirect_uri with an authorization code and the original state parameter.', 'callback', 'identityProvider', 'server', files[0]),
      this.makeStep('oauth-4', 'State Validation', 'Server validates the state parameter to prevent CSRF attacks against the OAuth flow.', 'middleware', 'server', 'server', files[0]),
      this.makeStep('oauth-5', 'Exchange Code for Tokens', 'Server makes a back-channel POST to IdP token endpoint with code, client_id, client_secret, and redirect_uri.', 'token-issuance', 'server', 'identityProvider', files[0]),
      this.makeStep('oauth-6', 'Receive Access + ID Tokens', 'IdP returns access_token, refresh_token, and optionally an OIDC id_token (JWT with user info).', 'token-validation', 'identityProvider', 'server', files[0]),
      this.makeStep('oauth-7', 'Create User Session', 'Server creates or updates local user record and establishes a session or issues its own application JWT.', 'session-creation', 'server', 'client', files[0]),
    ];

    return {
      id: 'oauth2-flow',
      name: 'OAuth 2.0 Authorization Code Flow',
      type: 'oauth2',
      steps,
      files,
      vulnerabilities: [],
      description: 'Delegated authorization using OAuth 2.0 Authorization Code flow with PKCE. Users authenticate with a trusted Identity Provider.',
      metadata: { grantType: 'authorization_code', pkce: 'recommended', library: 'Passport.js / NextAuth' },
    };
  }

  private buildSessionFlow(analyses: FileAnalysis[]): AuthFlow {
    const files = analyses.map(a => a.filePath);
    const steps: AuthStep[] = [
      this.makeStep('session-1', 'Submit Credentials', 'User submits username and password via login form (POST /login).', 'credential-input', 'client', 'server', files[0]),
      this.makeStep('session-2', 'Verify Password', 'Server queries database for user and verifies password against stored hash using bcrypt.compare().', 'middleware', 'server', 'database', files[0]),
      this.makeStep('session-3', 'Create Session', 'On success, server creates a session record: req.session.userId = user.id. Session is stored server-side (memory, Redis, DB).', 'session-creation', 'server', 'server', files[0]),
      this.makeStep('session-4', 'Set Session Cookie', 'Server sends Set-Cookie header with a signed session ID. Cookie should have httpOnly, secure, and sameSite flags.', 'token-issuance', 'server', 'client', files[0]),
      this.makeStep('session-5', 'Authenticated Request', 'Browser automatically includes session cookie in subsequent requests.', 'middleware', 'client', 'server', files[0]),
      this.makeStep('session-6', 'Session Lookup', 'Session middleware reads cookie, looks up session in store, and populates req.session.', 'token-validation', 'server', 'database', files[0]),
      this.makeStep('session-7', 'Authorization Check', 'Route handler checks req.session.userId (or role) to authorize the request.', 'authorization', 'server', 'client', files[0]),
    ];

    return {
      id: 'session-flow',
      name: 'Session-Based Authentication Flow',
      type: 'session',
      steps,
      files,
      vulnerabilities: [],
      description: 'Traditional server-side session authentication. The server maintains session state and identifies clients via a signed cookie containing the session ID.',
      metadata: { storage: 'Server-side', stateful: 'true', cookie: 'Session ID' },
    };
  }

  private buildWebAuthnFlows(analyses: FileAnalysis[]): AuthFlow[] {
    const files = analyses.map(a => a.filePath);
    return [
      {
        id: 'webauthn-registration',
        name: 'WebAuthn Registration Ceremony',
        type: 'webauthn',
        steps: [
          this.makeStep('wa-reg-1', 'User Initiates Registration', 'User triggers passkey registration (e.g., "Add Passkey" button). Client sends user info to server.', 'credential-input', 'client', 'server', files[0]),
          this.makeStep('wa-reg-2', 'Server Generates Options', 'Server calls generateRegistrationOptions(). Creates a random cryptographic challenge (≥16 bytes), sets rpId, user info, and authenticator requirements.', 'challenge-generation', 'server', 'client', files[0]),
          this.makeStep('wa-reg-3', 'Challenge Stored Server-Side', 'Server stores the challenge in session/cache. The challenge is single-use and expires (typically 60s).', 'session-creation', 'server', 'database', files[0]),
          this.makeStep('wa-reg-4', 'Authenticator Creates Credential', 'Browser calls navigator.credentials.create() with options. Authenticator (platform/roaming) generates an EC P-256 or RS256 key pair. Private key never leaves device.', 'authenticator-response', 'client', 'authenticator', files[0]),
          this.makeStep('wa-reg-5', 'Credential Response Sent', 'Browser sends attestation object and clientDataJSON to server. Contains public key, credential ID, and authenticator data.', 'callback', 'client', 'server', files[0]),
          this.makeStep('wa-reg-6', 'Server Verifies Response', 'Server calls verifyRegistrationResponse(). Validates: challenge matches, origin matches, rpId hash matches, attestation format, counter.', 'token-validation', 'server', 'server', files[0]),
          this.makeStep('wa-reg-7', 'Credential Stored', 'On success, server stores credential (credentialID, publicKey, counter, transports) associated with the user in the database.', 'session-creation', 'server', 'database', files[0]),
        ],
        files,
        vulnerabilities: [],
        description: 'WebAuthn/FIDO2 credential registration ceremony. Creates a public-key credential backed by a platform authenticator or security key.',
        metadata: { ceremony: 'registration', standard: 'WebAuthn Level 2', keyType: 'EC P-256 / RS256' },
      },
      {
        id: 'webauthn-authentication',
        name: 'WebAuthn Authentication Ceremony',
        type: 'webauthn',
        steps: [
          this.makeStep('wa-auth-1', 'User Initiates Sign-In', 'User clicks "Sign in with Passkey". Client requests authentication options from server.', 'credential-input', 'client', 'server', files[0]),
          this.makeStep('wa-auth-2', 'Server Generates Challenge', 'Server calls generateAuthenticationOptions(). Creates fresh random challenge and lists allowedCredentials for the user.', 'challenge-generation', 'server', 'client', files[0]),
          this.makeStep('wa-auth-3', 'Challenge Stored', 'Server stores challenge in session. Challenge is bound to this specific authentication attempt.', 'session-creation', 'server', 'database', files[0]),
          this.makeStep('wa-auth-4', 'Authenticator Signs Challenge', 'Browser calls navigator.credentials.get(). Authenticator uses stored private key to sign the challenge + authenticatorData + clientDataHash.', 'authenticator-response', 'client', 'authenticator', files[0]),
          this.makeStep('wa-auth-5', 'Assertion Sent to Server', 'Browser sends the assertion: signature, authenticatorData, clientDataJSON, and credentialId.', 'callback', 'client', 'server', files[0]),
          this.makeStep('wa-auth-6', 'Server Verifies Assertion', 'Server calls verifyAuthenticationResponse(). Validates: challenge, origin, rpId, signature against stored public key, and counter > stored counter (replay prevention).', 'token-validation', 'server', 'server', files[0]),
          this.makeStep('wa-auth-7', 'Counter Updated & Session Created', 'Server updates the credential counter to prevent replay attacks. Creates user session or issues JWT.', 'session-creation', 'server', 'client', files[0]),
        ],
        files,
        vulnerabilities: [],
        description: 'WebAuthn/FIDO2 authentication ceremony. Proves possession of the private key registered during enrollment without transmitting any secret.',
        metadata: { ceremony: 'authentication', replayPrevention: 'counter', phishingResistant: 'true' },
      },
    ];
  }

  private buildDjangoSessionFlow(analyses: FileAnalysis[]): AuthFlow {
    const files = analyses.map(a => a.filePath);
    return {
      id: 'django-session-flow',
      name: 'Django Session Authentication Flow',
      type: 'session',
      steps: [
        this.makeStep('dj-1', 'POST /login/', 'User submits credentials via Django login form. CSRF token required in POST body.', 'credential-input', 'client', 'server', files[0]),
        this.makeStep('dj-2', 'authenticate()', 'Django authenticate() checks username/password against AUTH_USER_MODEL using check_password() (PBKDF2).', 'middleware', 'server', 'database', files[0]),
        this.makeStep('dj-3', 'login(request, user)', 'Django login() rotates the session ID (prevents fixation) and stores user._id in the session.', 'session-creation', 'server', 'database', files[0]),
        this.makeStep('dj-4', 'Set-Cookie: sessionid', 'Django sends a signed session cookie. Controlled by SESSION_COOKIE_SECURE, SESSION_COOKIE_HTTPONLY, SESSION_COOKIE_SAMESITE.', 'token-issuance', 'server', 'client', files[0]),
        this.makeStep('dj-5', 'Subsequent Request + Cookie', 'Browser sends session cookie automatically. @login_required or LoginRequiredMixin validates the session.', 'token-validation', 'server', 'database', files[0]),
        this.makeStep('dj-6', 'request.user available', 'SessionMiddleware populates request.user. Views check request.user.is_authenticated for authorization.', 'authorization', 'server', 'client', files[0]),
      ],
      files,
      vulnerabilities: [],
      description: 'Django built-in session authentication. Credentials validated via authenticate(), session managed by SessionMiddleware with signed cookies.',
      metadata: { framework: 'Django', hashAlgo: 'PBKDF2-SHA256', sessionStore: 'Database / Cache' },
    };
  }

  private buildDjangoJWTFlow(analyses: FileAnalysis[]): AuthFlow {
    const files = analyses.map(a => a.filePath);
    return {
      id: 'django-jwt-flow',
      name: 'Django REST Framework + Simple JWT Flow',
      type: 'jwt',
      steps: [
        this.makeStep('djjwt-1', 'POST /api/token/', 'Client sends username and password to TokenObtainPairView.', 'credential-input', 'client', 'server', files[0]),
        this.makeStep('djjwt-2', 'Validate Credentials', 'Django authenticate() checks credentials against AUTH_USER_MODEL.', 'middleware', 'server', 'database', files[0]),
        this.makeStep('djjwt-3', 'Issue Access + Refresh Tokens', 'Simple JWT generates a short-lived access token (default 5min) and long-lived refresh token (default 1 day).', 'token-issuance', 'server', 'client', files[0]),
        this.makeStep('djjwt-4', 'Store Tokens Client-Side', 'Client stores tokens in memory or httpOnly cookies (avoid localStorage for refresh tokens).', 'session-creation', 'client', 'client', files[0]),
        this.makeStep('djjwt-5', 'Authorization: Bearer <token>', 'Client attaches access token to requests. JWTAuthentication middleware validates the token.', 'token-validation', 'server', 'server', files[0]),
        this.makeStep('djjwt-6', 'POST /api/token/refresh/', 'When access token expires, client exchanges refresh token for a new access token.', 'token-issuance', 'client', 'server', files[0]),
      ],
      files,
      vulnerabilities: [],
      description: 'Django REST Framework with Simple JWT. Provides short-lived access tokens and refresh token rotation.',
      metadata: { framework: 'Django REST Framework', library: 'djangorestframework-simplejwt', algorithm: 'HS256' },
    };
  }

  private buildFastAPIFlow(analyses: FileAnalysis[]): AuthFlow {
    const files = analyses.map(a => a.filePath);
    return {
      id: 'fastapi-oauth2-flow',
      name: 'FastAPI OAuth2 + JWT Flow',
      type: 'jwt',
      steps: [
        this.makeStep('fapi-1', 'POST /token (form data)', 'Client sends username + password as OAuth2PasswordRequestForm. FastAPI validates via Depends().', 'credential-input', 'client', 'server', files[0]),
        this.makeStep('fapi-2', 'Authenticate User', 'Server queries database and verifies password hash with passlib CryptContext.', 'middleware', 'server', 'database', files[0]),
        this.makeStep('fapi-3', 'Create Access Token', 'python-jose jwt.encode() signs payload with SECRET_KEY. Response: { access_token, token_type: "bearer" }.', 'token-issuance', 'server', 'client', files[0]),
        this.makeStep('fapi-4', 'Bearer Token in Requests', 'Client sends Authorization: Bearer <token>. OAuth2PasswordBearer extracts it automatically.', 'middleware', 'client', 'server', files[0]),
        this.makeStep('fapi-5', 'Decode & Validate Token', 'get_current_user dependency decodes JWT via jose.jwt.decode(), validates expiry and claims.', 'token-validation', 'server', 'server', files[0]),
        this.makeStep('fapi-6', 'Inject User into Route', 'Validated user object injected via Depends(get_current_user). Route accesses current_user directly.', 'authorization', 'server', 'client', files[0]),
      ],
      files,
      vulnerabilities: [],
      description: 'FastAPI with OAuth2 Password Bearer flow and JWT tokens. Dependency injection handles token extraction and validation automatically.',
      metadata: { framework: 'FastAPI', library: 'python-jose + passlib', pattern: 'OAuth2PasswordBearer' },
    };
  }

  private buildFlaskFlow(analyses: FileAnalysis[]): AuthFlow {
    const files = analyses.map(a => a.filePath);
    const hasJWT = analyses.some(a => a.detectedLibraries.some(l => l.name === 'flask-jwt-extended'));
    return {
      id: 'flask-auth-flow',
      name: hasJWT ? 'Flask + JWT Extended Flow' : 'Flask-Login Session Flow',
      type: hasJWT ? 'jwt' : 'session',
      steps: hasJWT ? [
        this.makeStep('fjwt-1', 'POST /login', 'Client sends credentials to Flask login route.', 'credential-input', 'client', 'server', files[0]),
        this.makeStep('fjwt-2', 'Verify Password', 'Flask route checks password hash (bcrypt/passlib). Flask-Login user_loader fetches user.', 'middleware', 'server', 'database', files[0]),
        this.makeStep('fjwt-3', 'create_access_token()', 'Flask-JWT-Extended creates signed JWT with identity and additional claims.', 'token-issuance', 'server', 'client', files[0]),
        this.makeStep('fjwt-4', '@jwt_required()', 'Decorator on protected routes validates the JWT in the Authorization header or cookie.', 'token-validation', 'server', 'server', files[0]),
        this.makeStep('fjwt-5', 'get_jwt_identity()', 'Extracts the identity claim from the validated token for use in the route handler.', 'authorization', 'server', 'client', files[0]),
      ] : [
        this.makeStep('fl-1', 'POST /login', 'User submits credentials. Flask-Login handles the authentication flow.', 'credential-input', 'client', 'server', files[0]),
        this.makeStep('fl-2', 'user_loader + check password', 'Flask-Login calls user_loader callback. Route verifies password hash.', 'middleware', 'server', 'database', files[0]),
        this.makeStep('fl-3', 'login_user(user)', 'Flask-Login creates a signed session cookie using itsdangerous + Flask SECRET_KEY.', 'session-creation', 'server', 'client', files[0]),
        this.makeStep('fl-4', '@login_required', 'Decorator validates session cookie on protected routes. Sets current_user.', 'token-validation', 'server', 'server', files[0]),
        this.makeStep('fl-5', 'current_user available', 'Flask-Login\'s current_user proxy provides the authenticated user in routes.', 'authorization', 'server', 'client', files[0]),
      ],
      files,
      vulnerabilities: [],
      description: hasJWT
        ? 'Flask with JWT Extended for stateless API authentication.'
        : 'Flask-Login session-based authentication with server-side sessions signed by Flask\'s SECRET_KEY.',
      metadata: { framework: 'Flask', library: hasJWT ? 'flask-jwt-extended' : 'flask-login' },
    };
  }

  private buildSpringSecurityFlow(analyses: FileAnalysis[]): AuthFlow {
    const files = analyses.map(a => a.filePath);
    return {
      id: 'spring-security-flow',
      name: 'Spring Security Session Flow',
      type: 'session',
      steps: [
        this.makeStep('ss-1', 'POST /login', 'Client submits credentials. Spring\'s UsernamePasswordAuthenticationFilter intercepts the request.', 'credential-input', 'client', 'server', files[0]),
        this.makeStep('ss-2', 'AuthenticationManager.authenticate()', 'DaoAuthenticationProvider loads UserDetails from UserDetailsService and verifies password via PasswordEncoder.', 'middleware', 'server', 'database', files[0]),
        this.makeStep('ss-3', 'SecurityContext Updated', 'On success, the Authentication object is stored in SecurityContextHolder. Session fixation protection rotates the session ID.', 'session-creation', 'server', 'server', files[0]),
        this.makeStep('ss-4', 'JSESSIONID Cookie Issued', 'Spring sends Set-Cookie: JSESSIONID=<id>; HttpOnly; Secure. Controlled by HttpSessionSecurityContextRepository.', 'token-issuance', 'server', 'client', files[0]),
        this.makeStep('ss-5', 'Authenticated Request', 'Browser sends JSESSIONID cookie. SessionManagementFilter restores SecurityContext from the session.', 'token-validation', 'server', 'database', files[0]),
        this.makeStep('ss-6', '@PreAuthorize / hasRole()', 'Method security annotations or .authorizeHttpRequests() rules enforce authorization on the restored Authentication.', 'authorization', 'server', 'client', files[0]),
      ],
      files,
      vulnerabilities: [],
      description: 'Spring Security form-based session authentication with DaoAuthenticationProvider and BCryptPasswordEncoder.',
      metadata: { framework: 'Spring Security', sessionStore: 'HttpSession', hashAlgo: 'BCrypt' },
    };
  }

  private buildSpringOAuth2Flow(analyses: FileAnalysis[]): AuthFlow {
    const files = analyses.map(a => a.filePath);
    return {
      id: 'spring-oauth2-flow',
      name: 'Spring Security OAuth2 Resource Server',
      type: 'oauth2',
      steps: [
        this.makeStep('sso-1', 'Client Obtains JWT from IdP', 'Client authenticates with an Authorization Server (Keycloak, Okta, Auth0) and receives a signed JWT access token.', 'credential-input', 'client', 'identityProvider', files[0]),
        this.makeStep('sso-2', 'Bearer Token in Request', 'Client sends Authorization: Bearer <jwt> in API calls to the Spring resource server.', 'middleware', 'client', 'server', files[0]),
        this.makeStep('sso-3', 'JwtAuthenticationConverter', 'Spring\'s BearerTokenAuthenticationFilter extracts the token. NimbusJwtDecoder validates signature against JWKS endpoint.', 'token-validation', 'server', 'identityProvider', files[0]),
        this.makeStep('sso-4', 'SecurityContext Populated', 'Validated JWT claims are converted to GrantedAuthorities. Authentication is stored in SecurityContextHolder.', 'session-creation', 'server', 'server', files[0]),
        this.makeStep('sso-5', '@PreAuthorize Enforcement', 'Method-level @PreAuthorize("hasAuthority(\'SCOPE_read\')") enforces fine-grained access control.', 'authorization', 'server', 'client', files[0]),
      ],
      files,
      vulnerabilities: [],
      description: 'Spring Security OAuth2 Resource Server validating JWT access tokens issued by an external Authorization Server.',
      metadata: { framework: 'Spring Security OAuth2', tokenValidation: 'JWKS', library: 'Nimbus JOSE+JWT' },
    };
  }

  private buildJavaJWTFlow(analyses: FileAnalysis[]): AuthFlow {
    const files = analyses.map(a => a.filePath);
    const hasJJWT = analyses.some(a => a.detectedLibraries.some(l => l.name === 'jjwt'));
    return {
      id: 'java-jwt-flow',
      name: hasJJWT ? 'JJWT Authentication Flow' : 'Java JWT Authentication Flow',
      type: 'jwt',
      steps: [
        this.makeStep('jjwt-1', 'POST /auth/login', 'Client sends credentials. Server authenticates against the database using a PasswordEncoder.', 'credential-input', 'client', 'server', files[0]),
        this.makeStep('jjwt-2', 'Verify Password Hash', 'BCryptPasswordEncoder.matches() compares submitted password against the stored BCrypt hash.', 'middleware', 'server', 'database', files[0]),
        this.makeStep('jjwt-3', 'Build & Sign JWT', hasJJWT
          ? 'Jwts.builder().subject(userId).expiration(exp).signWith(secretKey).compact() creates the signed token.'
          : 'JWT.create().withSubject(userId).withExpiresAt(exp).sign(Algorithm.HMAC256(secret)) creates the signed token.', 'token-issuance', 'server', 'client', files[0]),
        this.makeStep('jjwt-4', 'Client Stores Token', 'Client stores the JWT in memory or an httpOnly cookie for subsequent requests.', 'session-creation', 'client', 'client', files[0]),
        this.makeStep('jjwt-5', 'Authorization: Bearer <token>', 'Client attaches the JWT to the Authorization header. A filter intercepts and validates it.', 'middleware', 'client', 'server', files[0]),
        this.makeStep('jjwt-6', 'Parse & Validate JWT', hasJJWT
          ? 'Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token) validates signature and expiry.'
          : 'JWT.require(Algorithm.HMAC256(secret)).verify(token) validates signature and claims.', 'token-validation', 'server', 'server', files[0]),
        this.makeStep('jjwt-7', 'Set Authentication in SecurityContext', 'Validated claims are used to construct a UsernamePasswordAuthenticationToken stored in SecurityContextHolder.', 'authorization', 'server', 'client', files[0]),
      ],
      files,
      vulnerabilities: [],
      description: `Java JWT-based stateless authentication using ${hasJJWT ? 'JJWT (jwtk/jjwt)' : 'Auth0 Java JWT'}.`,
      metadata: { framework: 'Java', library: hasJJWT ? 'JJWT' : 'Auth0 Java JWT', algorithm: 'HS256 / RS256' },
    };
  }

  private buildShiroFlow(analyses: FileAnalysis[]): AuthFlow {
    const files = analyses.map(a => a.filePath);
    return {
      id: 'shiro-session-flow',
      name: 'Apache Shiro Authentication Flow',
      type: 'session',
      steps: [
        this.makeStep('shiro-1', 'Submit Credentials', 'User submits credentials. Application creates a UsernamePasswordToken.', 'credential-input', 'client', 'server', files[0]),
        this.makeStep('shiro-2', 'Subject.login(token)', 'SecurityUtils.getSubject().login(token) delegates to the configured Realm for credential verification.', 'middleware', 'server', 'database', files[0]),
        this.makeStep('shiro-3', 'Realm Verifies Credentials', 'AuthenticatingRealm compares submitted credentials against stored hashed credentials using CredentialsMatcher.', 'middleware', 'server', 'database', files[0]),
        this.makeStep('shiro-4', 'Session Created', 'On success, Shiro creates a server-side session. Session ID is sent as a cookie (JSESSIONID or Shiro\'s own cookie).', 'session-creation', 'server', 'client', files[0]),
        this.makeStep('shiro-5', 'Subject.isAuthenticated()', 'Subsequent requests use the session cookie. subject.isAuthenticated() or @RequiresAuthentication validates the session.', 'authorization', 'server', 'client', files[0]),
      ],
      files,
      vulnerabilities: [],
      description: 'Apache Shiro session-based authentication with Realm-based credential verification.',
      metadata: { framework: 'Apache Shiro', sessionStore: 'Server-side', pattern: 'Subject/Realm' },
    };
  }

  private buildGenericAuthFlow(analyses: FileAnalysis[]): AuthFlow {
    const files = analyses.map(a => a.filePath);
    const allRoutes = analyses.flatMap(a => a.routes);
    const steps: AuthStep[] = allRoutes.slice(0, 8).map((route, i) =>
      this.makeStep(
        `gen-${i}`,
        `${route.method} ${route.path}`,
        `Authentication endpoint detected at ${route.method} ${route.path}`,
        this.guessStepType(route.path),
        'client',
        'server',
        files[0],
        route.line
      )
    );

    return {
      id: 'generic-auth-flow',
      name: 'Custom Authentication Flow',
      type: 'unknown',
      steps: steps.length > 0 ? steps : [
        this.makeStep('gen-0', 'Authentication Logic Detected', 'Authentication-related code was found but could not be mapped to a known pattern.', 'middleware', 'client', 'server', files[0]),
      ],
      files,
      vulnerabilities: [],
      description: 'Custom authentication flow detected. Could not automatically categorize the authentication mechanism.',
      metadata: {},
    };
  }

  private makeStep(
    id: string,
    name: string,
    description: string,
    type: StepType,
    from: ActorType,
    to: ActorType,
    file?: string,
    line?: number
  ): AuthStep {
    return {
      id,
      name,
      description,
      type,
      from,
      to,
      codeRef: file ? { file, line: line ?? 1, column: 0, snippet: '' } : undefined,
      inputs: [],
      outputs: [],
    };
  }

  private guessStepType(routePath: string): StepType {
    if (/login|signin/.test(routePath)) return 'credential-input';
    if (/register|signup/.test(routePath)) return 'session-creation';
    if (/logout|signout/.test(routePath)) return 'redirect';
    if (/callback|redirect/.test(routePath)) return 'callback';
    if (/token|refresh/.test(routePath)) return 'token-issuance';
    if (/verify|validate/.test(routePath)) return 'token-validation';
    return 'middleware';
  }

  private deduplicateVulnerabilities(vulns: Vulnerability[]): Vulnerability[] {
    const seen = new Set<string>();
    return vulns.filter(v => {
      const key = `${v.id}-${v.codeRef?.file}-${v.codeRef?.line}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }

  private buildSummary(
    flows: AuthFlow[],
    vulns: Vulnerability[],
    technologies: DetectedTechnology[],
    filesAnalyzed: number,
    analysisTime: number
  ): AnalysisSummary {
    const techNames = technologies.map(t => t.displayName);
    return {
      totalFlows: flows.length,
      criticalVulnerabilities: vulns.filter(v => v.severity === 'critical').length,
      highVulnerabilities: vulns.filter(v => v.severity === 'high').length,
      mediumVulnerabilities: vulns.filter(v => v.severity === 'medium').length,
      lowVulnerabilities: vulns.filter(v => v.severity === 'low').length,
      infoVulnerabilities: vulns.filter(v => v.severity === 'info').length,
      technologies: techNames,
      hasWebAuthn: flows.some(f => f.type === 'webauthn'),
      hasJWT: flows.some(f => f.type === 'jwt'),
      hasOAuth: flows.some(f => f.type === 'oauth2'),
      hasSessionAuth: flows.some(f => f.type === 'session'),
      hasApiKey: technologies.some(t => t.name.includes('apikey')),
      filesAnalyzed,
      analysisTime,
    };
  }

  private emptyResult(): AnalysisResult {
    return {
      flows: [],
      vulnerabilities: [],
      technologies: [],
      summary: {
        totalFlows: 0,
        criticalVulnerabilities: 0,
        highVulnerabilities: 0,
        mediumVulnerabilities: 0,
        lowVulnerabilities: 0,
        infoVulnerabilities: 0,
        technologies: [],
        hasWebAuthn: false,
        hasJWT: false,
        hasOAuth: false,
        hasSessionAuth: false,
        hasApiKey: false,
        filesAnalyzed: 0,
        analysisTime: 0,
      },
      timestamp: Date.now(),
    };
  }
}
