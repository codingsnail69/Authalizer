import * as vscode from 'vscode';
import { AuthDetector } from '../analyzer/authDetector';
import { JWTSimulator } from '../simulator/jwtSimulator';
import { WebAuthnSimulator } from '../simulator/webAuthnSimulator';
import { ExtensionMessage, WebviewMessage } from '../types';
import { getWebviewContent, generateNonce } from './getWebviewContent';

export class DashboardPanel {
  public static currentPanel: DashboardPanel | undefined;
  private static readonly viewType = 'authFlowAnalyzer.dashboard';

  private readonly panel: vscode.WebviewPanel;
  private readonly detector: AuthDetector;
  private readonly jwtSimulator: JWTSimulator;
  private readonly webAuthnSimulator: WebAuthnSimulator;
  private disposables: vscode.Disposable[] = [];

  private constructor(panel: vscode.WebviewPanel) {
    this.panel = panel;
    this.detector = new AuthDetector();
    this.jwtSimulator = new JWTSimulator();
    this.webAuthnSimulator = new WebAuthnSimulator();

    this.panel.onDidDispose(() => this.dispose(), null, this.disposables);
    this.panel.webview.onDidReceiveMessage(
      (msg: WebviewMessage) => this.handleMessage(msg),
      null,
      this.disposables
    );

    this.updateContent();
  }

  static createOrShow(extensionUri: vscode.Uri, navigate?: { tab: string; flowIndex?: number; severity?: string; techName?: string }): DashboardPanel {
    const column = vscode.window.activeTextEditor
      ? vscode.window.activeTextEditor.viewColumn
      : undefined;

    if (DashboardPanel.currentPanel) {
      DashboardPanel.currentPanel.panel.reveal(column);
      if (navigate) DashboardPanel.currentPanel.navigateTo(navigate);
      return DashboardPanel.currentPanel;
    }

    const panel = vscode.window.createWebviewPanel(
      DashboardPanel.viewType,
      'Authalyzer',
      column ?? vscode.ViewColumn.One,
      {
        enableScripts: true,
        retainContextWhenHidden: true,
        localResourceRoots: [extensionUri],
      }
    );

    DashboardPanel.currentPanel = new DashboardPanel(panel);
    if (navigate) DashboardPanel.currentPanel.pendingNavigation = navigate;
    return DashboardPanel.currentPanel;
  }

  private pendingNavigation?: { tab: string; flowIndex?: number; severity?: string; techName?: string };

  navigateTo(target: { tab: string; flowIndex?: number; severity?: string; techName?: string }): void {
    this.sendMessage({ type: 'navigate', data: target });
  }

  async triggerAnalysis(): Promise<void> {
    await this.runWorkspaceAnalysis();
  }

  private updateContent(): void {
    const nonce = generateNonce();
    this.panel.webview.html = getWebviewContent(this.panel.webview, nonce);
  }

  private async handleMessage(msg: WebviewMessage): Promise<void> {
    switch (msg.type) {
      case 'ready':
        if (this.pendingNavigation) {
          await this.runWorkspaceAnalysis();
        }
        break;

      case 'analyzeWorkspace':
        await this.runWorkspaceAnalysis();
        break;

      case 'openFile':
        await this.openFile(msg.data.file, msg.data.line);
        break;

      case 'simulateJWT':
        try {
          const result = this.jwtSimulator.simulate(msg.data);
          this.sendMessage({ type: 'jwtSimulationResult', data: result });
        } catch (err) {
          this.sendMessage({ type: 'error', data: { message: String(err) } });
        }
        break;

      case 'verifyJWT':
        try {
          const result = this.jwtSimulator.verify(msg.data);
          this.sendMessage({ type: 'jwtVerifyResult', data: result });
        } catch (err) {
          this.sendMessage({ type: 'error', data: { message: String(err) } });
        }
        break;

      case 'simulateWebAuthnRegistration':
        try {
          const result = this.webAuthnSimulator.simulateRegistration(
            msg.data.rpId,
            msg.data.rpName,
            msg.data.userName
          );
          this.sendMessage({ type: 'webAuthnRegistrationResult', data: result });
        } catch (err) {
          this.sendMessage({ type: 'error', data: { message: String(err) } });
        }
        break;

      case 'simulateWebAuthnAuthentication':
        try {
          const result = this.webAuthnSimulator.simulateAuthentication(
            msg.data.rpId,
            msg.data.credentialId,
            msg.data.publicKey
          );
          this.sendMessage({ type: 'webAuthnAuthenticationResult', data: result });
        } catch (err) {
          this.sendMessage({ type: 'error', data: { message: String(err) } });
        }
        break;
    }
  }

  private async runWorkspaceAnalysis(): Promise<void> {
    try {
      await vscode.window.withProgress(
        {
          location: vscode.ProgressLocation.Notification,
          title: 'Authalyzer',
          cancellable: false,
        },
        async (progress) => {
          progress.report({ message: 'Scanning workspace...', increment: 0 });

          const vsProgress = {
            report: (value: { message?: string; increment?: number }) => {
              progress.report(value);
              this.sendMessage({
                type: 'analysisProgress',
                data: { message: value.message ?? '', percent: value.increment ?? 0 },
              });
            },
          };

          const result = await this.detector.analyzeWorkspace(vsProgress);
          this.sendMessage({ type: 'analysisResult', data: result });
          if (this.pendingNavigation) {
            this.navigateTo(this.pendingNavigation);
            this.pendingNavigation = undefined;
          }

          progress.report({ message: 'Analysis complete!', increment: 100 });
        }
      );
    } catch (err) {
      vscode.window.showErrorMessage(`Auth analysis failed: ${err}`);
      this.sendMessage({ type: 'error', data: { message: String(err) } });
    }
  }

  private highlightDecoration = vscode.window.createTextEditorDecorationType({
    isWholeLine: true,
    backgroundColor: new vscode.ThemeColor('diffEditor.insertedLineBackground'),
    borderWidth: '0 0 0 3px',
    borderStyle: 'solid',
    borderColor: new vscode.ThemeColor('editorWarning.foreground'),
  });

  private async openFile(filePath: string, line: number): Promise<void> {
    try {
      const doc = await vscode.workspace.openTextDocument(filePath);
      const editor = await vscode.window.showTextDocument(doc, vscode.ViewColumn.Beside);
      const zeroLine = Math.max(0, line - 1);
      const range = new vscode.Range(zeroLine, 0, zeroLine, Number.MAX_SAFE_INTEGER);

      // Place cursor and scroll to the line
      editor.selection = new vscode.Selection(range.start, range.start);
      editor.revealRange(range, vscode.TextEditorRevealType.InCenter);

      // Highlight the vulnerability line
      editor.setDecorations(this.highlightDecoration, [range]);

      // Clear highlight after 4 seconds
      setTimeout(() => {
        editor.setDecorations(this.highlightDecoration, []);
      }, 4000);
    } catch {
      vscode.window.showErrorMessage(`Could not open file: ${filePath}`);
    }
  }

  private sendMessage(msg: ExtensionMessage): void {
    this.panel.webview.postMessage(msg);
  }

  dispose(): void {
    DashboardPanel.currentPanel = undefined;
    this.panel.dispose();
    this.highlightDecoration.dispose();
    for (const d of this.disposables) d.dispose();
    this.disposables = [];
  }
}
