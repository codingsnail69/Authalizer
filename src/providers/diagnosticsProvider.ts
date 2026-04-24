import * as vscode from 'vscode';
import { Vulnerability, SeverityLevel } from '../types';

const SEVERITY_MAP: Record<SeverityLevel, vscode.DiagnosticSeverity> = {
  critical: vscode.DiagnosticSeverity.Error,
  high: vscode.DiagnosticSeverity.Error,
  medium: vscode.DiagnosticSeverity.Warning,
  low: vscode.DiagnosticSeverity.Information,
  info: vscode.DiagnosticSeverity.Hint,
};

export class DiagnosticsProvider {
  private diagnosticCollection: vscode.DiagnosticCollection;

  constructor() {
    this.diagnosticCollection = vscode.languages.createDiagnosticCollection('authAnalyzer');
  }

  updateDiagnostics(vulnerabilities: Vulnerability[]): void {
    const config = vscode.workspace.getConfiguration('authAnalyzer');
    if (!config.get<boolean>('enableDiagnostics', true)) {
      return;
    }

    const minimumSeverity = config.get<SeverityLevel>('minimumSeverity', 'low');
    const filtered = vulnerabilities.filter(v => this.meetsSeverityThreshold(v.severity, minimumSeverity));

    // Group by file
    const byFile = new Map<string, Vulnerability[]>();
    for (const vuln of filtered) {
      if (!vuln.codeRef) continue;
      const file = vuln.codeRef.file;
      if (!byFile.has(file)) byFile.set(file, []);
      byFile.get(file)!.push(vuln);
    }

    this.diagnosticCollection.clear();

    for (const [filePath, vulns] of byFile) {
      const uri = vscode.Uri.file(filePath);
      const diagnostics = vulns.map(v => this.createDiagnostic(v));
      this.diagnosticCollection.set(uri, diagnostics);
    }
  }

  clearDiagnostics(): void {
    this.diagnosticCollection.clear();
  }

  dispose(): void {
    this.diagnosticCollection.dispose();
  }

  private createDiagnostic(vuln: Vulnerability): vscode.Diagnostic {
    const line = Math.max(0, (vuln.codeRef?.line ?? 1) - 1);
    const col = vuln.codeRef?.column ?? 0;

    const range = new vscode.Range(
      new vscode.Position(line, col),
      new vscode.Position(line, col + 100)
    );

    const severity = SEVERITY_MAP[vuln.severity];
    const diagnostic = new vscode.Diagnostic(
      range,
      `[${vuln.severity.toUpperCase()}] ${vuln.title}: ${vuln.description}`,
      severity
    );

    diagnostic.source = 'Authalyzer';
    diagnostic.code = {
      value: vuln.id,
      target: vscode.Uri.parse(`https://owasp.org/www-project-top-ten/`),
    };

    if (vuln.owasp) {
      diagnostic.tags = [];
    }

    // Add related info with recommendation
    diagnostic.relatedInformation = [
      new vscode.DiagnosticRelatedInformation(
        new vscode.Location(vscode.Uri.file(vuln.codeRef?.file ?? ''), range),
        `Recommendation: ${vuln.recommendation}`
      ),
    ];

    return diagnostic;
  }

  private meetsSeverityThreshold(severity: SeverityLevel, threshold: SeverityLevel): boolean {
    const ORDER: SeverityLevel[] = ['info', 'low', 'medium', 'high', 'critical'];
    return ORDER.indexOf(severity) >= ORDER.indexOf(threshold);
  }
}

export class AuthOverviewProvider implements vscode.TreeDataProvider<AuthTreeItem> {
  private _onDidChangeTreeData = new vscode.EventEmitter<AuthTreeItem | undefined>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  private items: AuthTreeItem[] = [];

  refresh(items: AuthTreeItem[]): void {
    this.items = items;
    this._onDidChangeTreeData.fire(undefined);
  }

  getTreeItem(element: AuthTreeItem): vscode.TreeItem {
    return element;
  }

  getChildren(element?: AuthTreeItem): AuthTreeItem[] {
    if (!element) return this.items;
    return element.children ?? [];
  }
}

export class AuthTreeItem extends vscode.TreeItem {
  children?: AuthTreeItem[];

  constructor(
    label: string,
    collapsibleState: vscode.TreeItemCollapsibleState,
    options?: {
      description?: string;
      iconPath?: vscode.ThemeIcon;
      children?: AuthTreeItem[];
      command?: vscode.Command;
      contextValue?: string;
      tooltip?: string;
    }
  ) {
    super(label, collapsibleState);
    this.description = options?.description;
    this.iconPath = options?.iconPath;
    this.children = options?.children;
    this.command = options?.command;
    this.contextValue = options?.contextValue;
    this.tooltip = options?.tooltip;
  }
}

export class AuthActionsProvider implements vscode.TreeDataProvider<AuthTreeItem> {
  readonly onDidChangeTreeData = new vscode.EventEmitter<AuthTreeItem | undefined>().event;

  getTreeItem(element: AuthTreeItem): vscode.TreeItem {
    return element;
  }

  getChildren(): AuthTreeItem[] {
    return [
      new AuthTreeItem('Analyze Workspace', vscode.TreeItemCollapsibleState.None, {
        iconPath: new vscode.ThemeIcon('search'),
        tooltip: 'Scan all files for auth vulnerabilities and flows',
        command: { command: 'authAnalyzer.analyzeWorkspace', title: 'Analyze Workspace' },
      }),
      new AuthTreeItem('Analyze Current File', vscode.TreeItemCollapsibleState.None, {
        iconPath: new vscode.ThemeIcon('file-code'),
        tooltip: 'Analyze the currently open file',
        command: { command: 'authAnalyzer.analyzeFile', title: 'Analyze File' },
      }),
      new AuthTreeItem('Open Dashboard', vscode.TreeItemCollapsibleState.None, {
        iconPath: new vscode.ThemeIcon('shield'),
        tooltip: 'Open the Authalyzer dashboard',
        command: { command: 'authAnalyzer.showDashboard', title: 'Open Dashboard' },
      }),
      new AuthTreeItem('Clear Diagnostics', vscode.TreeItemCollapsibleState.None, {
        iconPath: new vscode.ThemeIcon('clear-all'),
        tooltip: 'Remove all inline security diagnostics',
        command: { command: 'authAnalyzer.clearDiagnostics', title: 'Clear Diagnostics' },
      }),
    ];
  }
}
