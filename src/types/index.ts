export type AuthFlowType = 'jwt' | 'oauth2' | 'session' | 'webauthn' | 'apikey' | 'basic' | 'unknown';

export type StepType =
  | 'credential-input'
  | 'challenge-generation'
  | 'authenticator-response'
  | 'token-issuance'
  | 'token-validation'
  | 'session-creation'
  | 'middleware'
  | 'redirect'
  | 'callback'
  | 'error-handling'
  | 'password-hash'
  | 'authorization';

export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type ActorType = 'client' | 'server' | 'database' | 'authenticator' | 'identityProvider';

export interface CodeReference {
  file: string;
  line: number;
  column: number;
  snippet: string;
  endLine?: number;
}

export interface AuthStep {
  id: string;
  name: string;
  description: string;
  type: StepType;
  from: ActorType;
  to: ActorType;
  codeRef?: CodeReference;
  inputs: string[];
  outputs: string[];
  metadata?: Record<string, string>;
}

export interface AuthFlow {
  id: string;
  name: string;
  type: AuthFlowType;
  steps: AuthStep[];
  files: string[];
  vulnerabilities: Vulnerability[];
  description: string;
  metadata: Record<string, string>;
}

export interface Vulnerability {
  id: string;
  severity: SeverityLevel;
  title: string;
  description: string;
  recommendation: string;
  codeRef?: CodeReference;
  owasp?: string;
  cwe?: string;
  references?: string[];
}

export interface DetectedTechnology {
  name: string;
  displayName: string;
  version?: string;
  type: 'library' | 'framework' | 'protocol' | 'standard';
  files: string[];
  description: string;
  docsUrl?: string;
}

export interface AnalysisSummary {
  totalFlows: number;
  criticalVulnerabilities: number;
  highVulnerabilities: number;
  mediumVulnerabilities: number;
  lowVulnerabilities: number;
  infoVulnerabilities: number;
  technologies: string[];
  hasWebAuthn: boolean;
  hasJWT: boolean;
  hasOAuth: boolean;
  hasSessionAuth: boolean;
  hasApiKey: boolean;
  filesAnalyzed: number;
  analysisTime: number;
}

export interface AnalysisResult {
  flows: AuthFlow[];
  vulnerabilities: Vulnerability[];
  technologies: DetectedTechnology[];
  summary: AnalysisSummary;
  passwordAnalysis?: import('../analyzer/passwordAnalyzer').PasswordAnalysisReport;
  timestamp: number;
}

// ---- Simulation types ----

export interface SimulationLog {
  timestamp: string;
  level: 'info' | 'warning' | 'error' | 'success' | 'data';
  message: string;
  data?: unknown;
}

export interface JWTHeader {
  alg: string;
  typ: string;
  kid?: string;
}

export interface JWTPayload {
  sub?: string;
  iss?: string;
  aud?: string | string[];
  exp?: number;
  nbf?: number;
  iat?: number;
  jti?: string;
  [key: string]: unknown;
}

export interface JWTSimulationRequest {
  algorithm: 'HS256' | 'HS384' | 'HS512';
  secret: string;
  payload: JWTPayload;
}

export interface JWTSimulationResult {
  header: JWTHeader;
  payload: JWTPayload;
  headerEncoded: string;
  payloadEncoded: string;
  signature: string;
  token: string;
  logs: SimulationLog[];
  securityWarnings: string[];
}

export interface JWTVerifyRequest {
  token: string;
  secret: string;
  expectedAlgorithms: string[];
}

export interface JWTVerifyResult {
  valid: boolean;
  header?: JWTHeader;
  payload?: JWTPayload;
  error?: string;
  logs: SimulationLog[];
  expired?: boolean;
  expiresAt?: string;
}

export interface WebAuthnRegistrationOptions {
  rpId: string;
  rpName: string;
  userId: string;
  userName: string;
  userDisplayName: string;
  challenge: string;
  timeout: number;
  attestation: 'none' | 'indirect' | 'direct' | 'enterprise';
  userVerification: 'required' | 'preferred' | 'discouraged';
}

export interface WebAuthnCredential {
  id: string;
  rawId: string;
  publicKey: string;
  algorithm: number;
  counter: number;
  transports: string[];
  aaguid: string;
}

export interface WebAuthnRegistrationResult {
  ceremony: 'registration';
  steps: WebAuthnSimulationStep[];
  credential?: WebAuthnCredential;
  options?: WebAuthnRegistrationOptions;
  logs: SimulationLog[];
  verified: boolean;
}

export interface WebAuthnAuthenticationOptions {
  rpId: string;
  challenge: string;
  timeout: number;
  userVerification: 'required' | 'preferred' | 'discouraged';
  allowCredentials: Array<{ id: string; type: 'public-key'; transports?: string[] }>;
}

export interface WebAuthnAuthenticationResult {
  ceremony: 'authentication';
  steps: WebAuthnSimulationStep[];
  options?: WebAuthnAuthenticationOptions;
  assertion?: {
    credentialId: string;
    signature: string;
    authenticatorData: string;
    clientDataJSON: string;
  };
  logs: SimulationLog[];
  verified: boolean;
}

export interface WebAuthnSimulationStep {
  stepNumber: number;
  title: string;
  description: string;
  actor: ActorType;
  data: Record<string, unknown>;
  securityNotes: string[];
}

// ---- Webview message types ----

export type ExtensionMessage =
  | { type: 'analysisResult'; data: AnalysisResult }
  | { type: 'jwtSimulationResult'; data: JWTSimulationResult }
  | { type: 'jwtVerifyResult'; data: JWTVerifyResult }
  | { type: 'webAuthnRegistrationResult'; data: WebAuthnRegistrationResult }
  | { type: 'webAuthnAuthenticationResult'; data: WebAuthnAuthenticationResult }
  | { type: 'analysisProgress'; data: { message: string; percent: number } }
  | { type: 'navigate'; data: { tab: string; flowIndex?: number; severity?: string; techName?: string } }
  | { type: 'error'; data: { message: string } };

export type WebviewMessage =
  | { type: 'analyzeWorkspace' }
  | { type: 'openFile'; data: { file: string; line: number } }
  | { type: 'simulateJWT'; data: JWTSimulationRequest }
  | { type: 'verifyJWT'; data: JWTVerifyRequest }
  | { type: 'simulateWebAuthnRegistration'; data: { rpId: string; rpName: string; userName: string } }
  | { type: 'simulateWebAuthnAuthentication'; data: { rpId: string; credentialId: string; publicKey: string } }
  | { type: 'ready' };
