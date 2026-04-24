import * as vscode from 'vscode';
import { DashboardPanel } from './webview/DashboardPanel';
import { DiagnosticsProvider, AuthOverviewProvider, AuthActionsProvider, AuthTreeItem } from './providers/diagnosticsProvider';
import { AuthDetector } from './analyzer/authDetector';
import { AnalysisResult } from './types';

let diagnosticsProvider: DiagnosticsProvider;
let overviewProvider: AuthOverviewProvider;
let lastAnalysis: AnalysisResult | undefined;

export function activate(context: vscode.ExtensionContext): void {
  diagnosticsProvider = new DiagnosticsProvider();
  overviewProvider = new AuthOverviewProvider();
  const detector = new AuthDetector();

  // Register sidebar tree views
  vscode.window.registerTreeDataProvider('authAnalyzer.overview', overviewProvider);

  const actionsProvider = new AuthActionsProvider();
  vscode.window.registerTreeDataProvider('authAnalyzer.actions', actionsProvider);

  // ---- Commands ----

  context.subscriptions.push(
    vscode.commands.registerCommand('authAnalyzer.showDashboard', () => {
      DashboardPanel.createOrShow(context.extensionUri);
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('authAnalyzer.analyzeWorkspace', async () => {
      const panel = DashboardPanel.createOrShow(context.extensionUri);

      await vscode.window.withProgress(
        { location: vscode.ProgressLocation.Notification, title: 'Authalyzer', cancellable: false},
        async (progress) => {
          progress.report({ message: 'Scanning workspace...', increment: 0 });
          try {
            const result = await detector.analyzeWorkspace({
              report: ({ message, increment }) => progress.report({ message, increment }),
            });
            lastAnalysis = result;
            diagnosticsProvider.updateDiagnostics(result.vulnerabilities);
            updateSidebar(result);
            panel.triggerAnalysis();

            const totalVulns = result.summary.criticalVulnerabilities + result.summary.highVulnerabilities;
            if (totalVulns > 0) {
              vscode.window.showWarningMessage(
                `Auth Analyzer found ${result.summary.criticalVulnerabilities} critical and ${result.summary.highVulnerabilities} high severity issues.`,
                'View Report'
              ).then(selection => {
                if (selection === 'View Report') {
                  DashboardPanel.createOrShow(context.extensionUri);
                }
              });
            } else {
              vscode.window.showInformationMessage(
                `Auth analysis complete. ${result.summary.totalFlows} flows detected, no critical/high issues found.`
              );
            }
          } catch (err) {
            vscode.window.showErrorMessage(`Analysis failed: ${err}`);
          }
        }
      );
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('authAnalyzer.analyzeFile', async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) {
        vscode.window.showWarningMessage('No active editor. Open a JavaScript/TypeScript file first.');
        return;
      }

      const panel = DashboardPanel.createOrShow(context.extensionUri);

      await vscode.window.withProgress(
        { location: vscode.ProgressLocation.Window, title: 'Analyzing file security...' },
        async () => {
          try {
            const result = await detector.analyzeCurrentFile();
            lastAnalysis = result;
            diagnosticsProvider.updateDiagnostics(result.vulnerabilities);
            await panel.triggerAnalysis();

            if (result.vulnerabilities.length === 0) {
              vscode.window.showInformationMessage('No auth security issues found in this file.');
            } else {
              vscode.window.showWarningMessage(
                `Found ${result.vulnerabilities.length} auth security issue(s) in ${editor.document.fileName.split('/').pop()}.`
              );
            }
          } catch (err) {
            vscode.window.showErrorMessage(`File analysis failed: ${err}`);
          }
        }
      );
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('authAnalyzer.explainFlow', async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) {
        vscode.window.showWarningMessage('No active editor.');
        return;
      }

      const selection = editor.selection;
      const selectedText = editor.document.getText(selection).trim();
      const lineText = editor.document.lineAt(selection.active.line).text.trim();
      const context = selectedText || lineText;

      if (!context) {
        vscode.window.showInformationMessage('Place your cursor on auth-related code to explain it.');
        return;
      }

      const explanation = explainAuthCode(context);
      vscode.window.showInformationMessage(explanation, { modal: false });
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('authAnalyzer.openSimulation', () => {
      const panel = DashboardPanel.createOrShow(context.extensionUri);
      void panel;
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('authAnalyzer.clearDiagnostics', () => {
      diagnosticsProvider.clearDiagnostics();
      vscode.window.showInformationMessage('Auth Analyzer diagnostics cleared.');
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand(
      'authAnalyzer.navigateTo',
      (target: { tab: string; flowIndex?: number; severity?: string; techName?: string }) => {
        const panel = DashboardPanel.createOrShow(context.extensionUri, target);
        void panel;
      }
    )
  );

  // ---- Auto-analyze on save (if configured) ----
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument(async (doc) => {
      const config = vscode.workspace.getConfiguration('authAnalyzer');
      if (!config.get<boolean>('autoAnalyzeOnSave', false)) return;

      const lang = doc.languageId;
      if (!['typescript', 'javascript', 'typescriptreact', 'javascriptreact'].includes(lang)) return;

      const { SecurityAnalyzer } = await import('./analyzer/securityAnalyzer');
      const analyzer = new SecurityAnalyzer();
      const vulns = await analyzer.analyzeFile(doc.uri.fsPath, doc.getText());
      diagnosticsProvider.updateDiagnostics(vulns);
    })
  );

  // ---- Register disposables ----
  context.subscriptions.push(diagnosticsProvider);
}

export function deactivate(): void {
  diagnosticsProvider?.dispose();
}

function updateSidebar(result: AnalysisResult): void {
  const items: AuthTreeItem[] = [];

  // Summary
  const summaryItem = new AuthTreeItem(
    'Analysis Summary',
    vscode.TreeItemCollapsibleState.Expanded,
    {
      iconPath: new vscode.ThemeIcon('info'),
      children: [
        new AuthTreeItem(`Flows: ${result.summary.totalFlows}`, vscode.TreeItemCollapsibleState.None, {
          iconPath: new vscode.ThemeIcon('git-branch'),
          tooltip: 'Open Auth Flows tab',
          command: { command: 'authAnalyzer.navigateTo', title: 'Go to Flows', arguments: [{ tab: 'flows' }] },
        }),
        new AuthTreeItem(
          `Critical: ${result.summary.criticalVulnerabilities}`,
          vscode.TreeItemCollapsibleState.None,
          {
            iconPath: new vscode.ThemeIcon(result.summary.criticalVulnerabilities > 0 ? 'error' : 'pass'),
            tooltip: 'Show critical vulnerabilities',
            command: { command: 'authAnalyzer.navigateTo', title: 'Go to Critical', arguments: [{ tab: 'security', severity: 'critical' }] },
          }
        ),
        new AuthTreeItem(
          `High: ${result.summary.highVulnerabilities}`,
          vscode.TreeItemCollapsibleState.None,
          {
            iconPath: new vscode.ThemeIcon(result.summary.highVulnerabilities > 0 ? 'warning' : 'pass'),
            tooltip: 'Show high severity vulnerabilities',
            command: { command: 'authAnalyzer.navigateTo', title: 'Go to High', arguments: [{ tab: 'security', severity: 'high' }] },
          }
        ),
        new AuthTreeItem(`Files: ${result.summary.filesAnalyzed}`, vscode.TreeItemCollapsibleState.None, {
          iconPath: new vscode.ThemeIcon('files'),
          tooltip: 'Open Technologies tab',
          command: { command: 'authAnalyzer.navigateTo', title: 'Go to Technologies', arguments: [{ tab: 'technologies' }] },
        }),
      ],
    }
  );
  items.push(summaryItem);

  // Technologies
  if (result.technologies.length > 0) {
    const techItem = new AuthTreeItem(
      'Technologies',
      vscode.TreeItemCollapsibleState.Collapsed,
      {
        iconPath: new vscode.ThemeIcon('package'),
        children: result.technologies.map(
          t => new AuthTreeItem(t.displayName, vscode.TreeItemCollapsibleState.None, {
            description: t.type,
            iconPath: new vscode.ThemeIcon('library'),
            tooltip: `View ${t.displayName} details and security guidance`,
            command: {
              command: 'authAnalyzer.navigateTo',
              title: 'View Technology',
              arguments: [{ tab: 'technologies', techName: t.name }],
            },
          })
        ),
      }
    );
    items.push(techItem);
  }

  // Flows
  if (result.flows.length > 0) {
    const flowsItem = new AuthTreeItem(
      'Auth Flows',
      vscode.TreeItemCollapsibleState.Collapsed,
      {
        iconPath: new vscode.ThemeIcon('arrow-swap'),
        children: result.flows.map(
          (f, i) => new AuthTreeItem(f.name, vscode.TreeItemCollapsibleState.None, {
            description: f.type,
            iconPath: new vscode.ThemeIcon('shield'),
            tooltip: `View ${f.name} flow diagram`,
            command: {
              command: 'authAnalyzer.navigateTo',
              title: 'Show Flow',
              arguments: [{ tab: 'flows', flowIndex: i }],
            },
          })
        ),
      }
    );
    items.push(flowsItem);
  }

  overviewProvider.refresh(items);
}

function explainAuthCode(code: string): string {
  if (/jwt\.sign/i.test(code)) {
    return 'jwt.sign(payload, secret, options) — Creates a JSON Web Token. The payload is base64url-encoded and signed with HMAC or RSA. Always set expiresIn and verify the algorithm.';
  }
  if (/jwt\.verify/i.test(code)) {
    return 'jwt.verify(token, secret, options) — Verifies the JWT signature and expiry. Always specify the expected algorithm to prevent algorithm confusion attacks.';
  }
  if (/jwt\.decode/i.test(code)) {
    return '⚠️ jwt.decode() — Only decodes without verifying the signature! Never trust decoded data for authorization. Use jwt.verify() instead.';
  }
  if (/generateRegistrationOptions|generateAuthenticationOptions/i.test(code)) {
    return 'WebAuthn options generation — Creates a cryptographic challenge for the authenticator. The challenge must be random, single-use, and stored server-side.';
  }
  if (/verifyRegistrationResponse|verifyAuthenticationResponse/i.test(code)) {
    return 'WebAuthn response verification — Validates the authenticator\'s response. Checks challenge, origin, rpId, signature, and counter. Never skip any of these checks.';
  }
  if (/bcrypt\.hash|argon2\.hash/i.test(code)) {
    return 'Password hashing — Hashes the password with a salt using bcrypt/Argon2. The cost factor determines computational cost. Use bcrypt cost ≥12 or Argon2id with at least 64MB memory.';
  }
  if (/bcrypt\.compare|argon2\.verify/i.test(code)) {
    return 'Password verification — Timing-safe comparison of the provided password against the stored hash. Never compare passwords with === or string equality.';
  }
  if (/passport\.authenticate/i.test(code)) {
    return 'Passport.js authentication middleware — Authenticates a request using the specified strategy (local, OAuth2, JWT, etc.). The strategy must be configured with passport.use() first.';
  }
  if (/req\.session/i.test(code)) {
    return 'Session access — Reads or writes user data to the server-side session. Ensure the session middleware is configured with a secure secret and appropriate cookie settings.';
  }
  if (/navigator\.credentials/i.test(code)) {
    return 'Web Credentials API — Browser API for creating/getting passkeys and security keys. navigator.credentials.create() for registration, .get() for authentication.';
  }
  // Python patterns
  if (/jwt\.encode/i.test(code)) {
    return 'PyJWT jwt.encode(payload, key, algorithm) — Creates a signed JWT. Always set "exp" in payload and use a strong key. Avoid algorithm="none".';
  }
  if (/jwt\.decode/i.test(code)) {
    return 'PyJWT jwt.decode(token, key, algorithms) — Decodes and verifies a JWT. Always pass algorithms=["HS256"] explicitly to prevent algorithm confusion. Do not pass options={"verify_signature": False} in production.';
  }
  if (/django\.contrib\.auth|authenticate\s*\(|login\s*\(\s*request/i.test(code)) {
    return 'Django auth — authenticate() checks credentials against the user model; login(request, user) starts a session and rotates the session ID to prevent fixation.';
  }
  if (/@login_required/i.test(code)) {
    return 'Django/Flask-Login @login_required — Decorator that redirects unauthenticated users to the login page. Equivalent to checking request.user.is_authenticated manually.';
  }
  if (/create_access_token|create_refresh_token/i.test(code)) {
    return 'Flask-JWT-Extended — create_access_token() signs a short-lived JWT. Always pair with a refresh token and set expiry via JWT_ACCESS_TOKEN_EXPIRES in your Flask config.';
  }
  if (/OAuth2PasswordBearer|Depends\s*\(\s*get_current_user/i.test(code)) {
    return 'FastAPI OAuth2 — OAuth2PasswordBearer extracts the Bearer token from the Authorization header. Wrap in Depends() so FastAPI injects the current user into route handlers automatically.';
  }
  if (/bcrypt\.hashpw|bcrypt\.checkpw|CryptContext|passlib/i.test(code)) {
    return 'Python password hashing — bcrypt.hashpw(password, gensalt(rounds=12)) or passlib CryptContext. Always use a cost factor ≥12 and never compare hashes with ==.';
  }
  if (/generate_registration_options|verify_registration_response|generate_authentication_options|verify_authentication_response/i.test(code)) {
    return 'py_webauthn — WebAuthn server-side ceremony helpers. generate_*_options() creates a server challenge; verify_*_response() validates the authenticator response. Always check expected_origin and expected_rp_id.';
  }
  if (/register_begin|register_complete|authenticate_begin|authenticate_complete/i.test(code)) {
    return 'python-fido2 (Yubico) — FIDO2/WebAuthn library. register_begin/complete handles the registration ceremony; authenticate_begin/complete handles authentication. Counter validation is built-in.';
  }
  return `Auth-related code detected. Use "Analyze Security of This File" for a full security assessment of this code.`;
}
