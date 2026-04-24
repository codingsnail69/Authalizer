import * as vscode from 'vscode';

export function getWebviewContent(webview: vscode.Webview, nonce: string): string {
  const csp = [
    `default-src 'none'`,
    `style-src ${webview.cspSource} 'unsafe-inline'`,
    `script-src 'nonce-${nonce}'`,
    `img-src ${webview.cspSource} data:`,
    `font-src ${webview.cspSource}`,
  ].join('; ');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta http-equiv="Content-Security-Policy" content="${csp}"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Authalyzer</title>
  <style nonce="${nonce}">
    :root {
      --radius: 6px;
      --gap: 12px;
      --color-critical: #ef4444;
      --color-high: #f97316;
      --color-medium: #eab308;
      --color-low: #3b82f6;
      --color-info: #8b5cf6;
      --color-success: #22c55e;
    }
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: var(--vscode-font-family);
      font-size: var(--vscode-font-size);
      color: var(--vscode-foreground);
      background: var(--vscode-editor-background);
      line-height: 1.5;
      overflow-x: hidden;
    }
    /* ---- Header ---- */
    .header {
      display: flex;
      align-items: center;
      gap: var(--gap);
      padding: 14px 20px;
      background: var(--vscode-editorGroupHeader-tabsBackground);
      border-bottom: 1px solid var(--vscode-panel-border);
      position: sticky;
      top: 0;
      z-index: 100;
    }
    .header-logo { font-size: 1.4rem; }
    .header-title { font-size: 1rem; font-weight: 700; flex: 1; }
    .header-subtitle { font-size: 0.75rem; opacity: 0.6; }
    .btn {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 6px 14px;
      border: 1px solid var(--vscode-button-border, transparent);
      border-radius: var(--radius);
      cursor: pointer;
      font-size: 0.8rem;
      font-family: inherit;
      transition: opacity 0.15s;
    }
    .btn:hover { opacity: 0.85; }
    .btn-primary {
      background: linear-gradient(135deg, #4f46e5 0%, #6d5fd4 100%);
      color: #fff;
      border-color: #4338ca;
      box-shadow: 0 1px 6px rgba(79,70,229,0.35);
      transition: box-shadow 0.15s, opacity 0.15s;
    }
    .btn-primary:hover {
      opacity: 1;
      box-shadow: 0 2px 10px rgba(79,70,229,0.55);
      background: linear-gradient(135deg, #4338ca 0%, #5b4fd4 100%);
    }
    .btn-secondary {
      background: var(--vscode-button-secondaryBackground);
      color: var(--vscode-button-secondaryForeground);
    }
    /* ---- Tabs ---- */
    .tabs-bar {
      display: flex;
      gap: 2px;
      padding: 0 20px;
      background: var(--vscode-editorGroupHeader-tabsBackground);
      border-bottom: 1px solid var(--vscode-panel-border);
      overflow-x: auto;
    }
    .tab {
      padding: 10px 16px;
      cursor: pointer;
      font-size: 0.82rem;
      border-bottom: 2px solid transparent;
      white-space: nowrap;
      opacity: 0.65;
      transition: opacity 0.15s, border-color 0.15s;
      background: none;
      border-top: none;
      border-left: none;
      border-right: none;
      color: var(--vscode-foreground);
      font-family: inherit;
    }
    .tab.active {
      border-bottom-color: var(--vscode-focusBorder);
      opacity: 1;
      font-weight: 600;
    }
    .tab-panel { display: none; padding: 20px; }
    .tab-panel.active { display: block; }
    /* ---- Summary Cards ---- */
    .summary-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
      gap: var(--gap);
      margin-bottom: 20px;
    }
    .summary-card {
      background: var(--vscode-editorWidget-background);
      border: 1px solid var(--vscode-panel-border);
      border-radius: var(--radius);
      padding: 14px;
      text-align: center;
    }
    .summary-card .value {
      font-size: 1.8rem;
      font-weight: 800;
      line-height: 1;
      margin-bottom: 4px;
    }
    .summary-card .label { font-size: 0.72rem; opacity: 0.65; text-transform: uppercase; letter-spacing: 0.05em; }
    .critical { color: var(--color-critical); }
    .high { color: var(--color-high); }
    .medium { color: var(--color-medium); }
    .low-color { color: var(--color-low); }
    .success { color: var(--color-success); }
    /* ---- Badges ---- */
    .badge {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 100px;
      font-size: 0.7rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    .badge-critical { background: rgba(239,68,68,0.15); color: var(--color-critical); }
    .badge-high { background: rgba(249,115,22,0.15); color: var(--color-high); }
    .badge-medium { background: rgba(234,179,8,0.15); color: var(--color-medium); }
    .badge-low { background: rgba(59,130,246,0.15); color: var(--color-low); }
    .badge-info { background: rgba(139,92,246,0.15); color: var(--color-info); }
    .badge-webauthn { background: rgba(34,197,94,0.15); color: var(--color-success); }
    .badge-jwt { background: rgba(249,115,22,0.15); color: var(--color-high); }
    .badge-oauth2 { background: rgba(59,130,246,0.15); color: var(--color-low); }
    .badge-session { background: rgba(139,92,246,0.15); color: var(--color-info); }
    /* ---- Flow Diagram ---- */
    .flow-selector { display: flex; gap: var(--gap); align-items: center; margin-bottom: 16px; flex-wrap: wrap; }
    .flow-selector select {
      background: var(--vscode-dropdown-background);
      color: var(--vscode-dropdown-foreground);
      border: 1px solid var(--vscode-dropdown-border);
      border-radius: var(--radius);
      padding: 6px 10px;
      font-family: inherit;
      font-size: 0.85rem;
      min-width: 220px;
    }
    .diagram-container {
      background: var(--vscode-editorWidget-background);
      border: 1px solid var(--vscode-panel-border);
      border-radius: var(--radius);
      overflow: auto;
      min-height: 300px;
      position: relative;
    }
    .diagram-container svg { display: block; }
    .empty-state {
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      padding: 60px 20px;
      opacity: 0.5;
      gap: 10px;
      text-align: center;
    }
    .empty-state .icon { font-size: 3rem; }
    /* ---- Vulnerability Table ---- */
    .vuln-filters { display: flex; gap: var(--gap); margin-bottom: 16px; flex-wrap: wrap; align-items: center; }
    .vuln-filters select, .vuln-filters input {
      background: var(--vscode-dropdown-background);
      color: var(--vscode-dropdown-foreground);
      border: 1px solid var(--vscode-dropdown-border);
      border-radius: var(--radius);
      padding: 6px 10px;
      font-family: inherit;
      font-size: 0.82rem;
    }
    .vuln-filters input { flex: 1; min-width: 200px; }
    .vuln-list { display: flex; flex-direction: column; gap: 10px; }
    .vuln-card {
      background: var(--vscode-editorWidget-background);
      border: 1px solid var(--vscode-panel-border);
      border-radius: var(--radius);
      overflow: hidden;
      cursor: pointer;
      transition: border-color 0.15s;
    }
    .vuln-card:hover { border-color: var(--vscode-focusBorder); }
    .vuln-card-header {
      display: flex;
      align-items: center;
      gap: 10px;
      padding: 12px 16px;
      cursor: pointer;
      transition: background 0.12s;
    }
    .vuln-card-header:hover { background: var(--vscode-list-hoverBackground); }
    .vuln-card-header .title { font-weight: 600; flex: 1; }
    .vuln-card-loc {
      font-family: var(--vscode-editor-font-family, monospace);
      font-size: 0.72rem;
      opacity: 0.55;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      max-width: 200px;
    }
    .vuln-expand-btn {
      background: none;
      border: none;
      cursor: pointer;
      color: var(--vscode-foreground);
      opacity: 0.4;
      font-size: 0.75rem;
      padding: 2px 4px;
      border-radius: 3px;
      flex-shrink: 0;
      transition: opacity 0.12s;
      line-height: 1;
    }
    .vuln-expand-btn:hover { opacity: 0.9; background: var(--vscode-toolbar-hoverBackground); }
    .vuln-card-body { padding: 0 16px 14px; border-top: 1px solid var(--vscode-panel-border); }
    /* ---- Password Security ---- */
    .pw-section { margin-bottom: 20px; }
    .pw-overall {
      display: flex;
      align-items: center;
      gap: 14px;
      padding: 14px 18px;
      border-radius: var(--radius);
      border: 1px solid var(--vscode-panel-border);
      background: var(--vscode-editorWidget-background);
      margin-bottom: 14px;
    }
    .pw-rating-icon { font-size: 1.8rem; line-height: 1; }
    .pw-overall-label { font-size: 0.75rem; opacity: 0.6; text-transform: uppercase; letter-spacing: 0.05em; }
    .pw-overall-value { font-size: 1rem; font-weight: 700; }
    .pw-overall-summary { font-size: 0.8rem; opacity: 0.75; flex: 1; }
    .pw-findings { display: flex; flex-direction: column; gap: 10px; }
    .pw-finding {
      border: 1px solid var(--vscode-panel-border);
      border-radius: var(--radius);
      overflow: hidden;
    }
    .pw-finding-header {
      display: flex;
      align-items: center;
      gap: 10px;
      padding: 10px 14px;
      cursor: pointer;
      transition: background 0.12s;
    }
    .pw-finding-header:hover { background: var(--vscode-list-hoverBackground); }
    .pw-alg-badge {
      font-size: 0.75rem;
      font-weight: 700;
      padding: 2px 8px;
      border-radius: 4px;
      font-family: var(--vscode-editor-font-family, monospace);
      flex-shrink: 0;
    }
    .pw-level-secure   { background: rgba(34,197,94,0.15);  color: #22c55e; }
    .pw-level-acceptable { background: rgba(59,130,246,0.15); color: #3b82f6; }
    .pw-level-weak     { background: rgba(234,179,8,0.15);  color: #eab308; }
    .pw-level-insecure { background: rgba(239,68,68,0.15);  color: #ef4444; }
    .pw-level-none     { background: rgba(107,114,128,0.15); color: #6b7280; }
    .pw-finding-params {
      font-family: var(--vscode-editor-font-family, monospace);
      font-size: 0.72rem;
      opacity: 0.55;
      flex: 1;
    }
    .pw-finding-loc { font-size: 0.72rem; opacity: 0.5; font-family: var(--vscode-editor-font-family, monospace); white-space: nowrap; }
    .pw-finding-body { padding: 10px 14px; border-top: 1px solid var(--vscode-panel-border); display: none; }
    .pw-finding-body.open { display: block; }
    .pw-issue {
      display: flex;
      gap: 8px;
      font-size: 0.8rem;
      padding: 5px 0;
      border-bottom: 1px solid var(--vscode-panel-border);
    }
    .pw-issue:last-of-type { border-bottom: none; margin-bottom: 8px; }
    .pw-rec {
      font-size: 0.8rem;
      padding: 8px 12px;
      background: rgba(34,197,94,0.08);
      border-left: 3px solid var(--color-success);
      border-radius: 0 var(--radius) var(--radius) 0;
      margin-top: 8px;
    }
    .vuln-card-body p { font-size: 0.82rem; opacity: 0.8; margin-bottom: 8px; margin-top: 10px; }
    .vuln-card-body .recommendation {
      font-size: 0.8rem;
      padding: 8px 12px;
      background: rgba(34,197,94,0.08);
      border-left: 3px solid var(--color-success);
      border-radius: 0 var(--radius) var(--radius) 0;
      margin-bottom: 8px;
    }
    .code-ref {
      font-family: var(--vscode-editor-font-family, monospace);
      font-size: 0.75rem;
      padding: 6px 10px;
      background: var(--vscode-textCodeBlock-background);
      border-radius: var(--radius);
      overflow-x: auto;
      cursor: pointer;
      transition: opacity 0.15s;
    }
    .code-ref:hover { opacity: 0.8; }
    .meta-tags { display: flex; gap: 6px; flex-wrap: wrap; margin-top: 8px; }
    .meta-tag {
      font-size: 0.68rem;
      padding: 2px 6px;
      border-radius: 4px;
      background: var(--vscode-badge-background);
      color: var(--vscode-badge-foreground);
    }
    /* ---- Technologies ---- */
    .tech-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); gap: var(--gap); }
    .tech-card {
      background: var(--vscode-editorWidget-background);
      border: 1px solid var(--vscode-panel-border);
      border-radius: var(--radius);
      padding: 16px;
      cursor: pointer;
      transition: border-color 0.15s, box-shadow 0.15s;
    }
    .tech-card:hover { border-color: var(--vscode-focusBorder); }
    .tech-card.highlighted {
      border-color: var(--vscode-focusBorder);
      box-shadow: 0 0 0 2px var(--vscode-focusBorder);
    }
    .tech-card .tech-name { font-weight: 700; margin-bottom: 4px; }
    .tech-card .tech-desc { font-size: 0.78rem; opacity: 0.7; margin-bottom: 10px; }
    .tech-files { font-size: 0.72rem; opacity: 0.55; margin-bottom: 8px; }
    .tech-expand-btn {
      font-size: 0.72rem;
      color: var(--vscode-textLink-foreground);
      background: none; border: none; padding: 0;
      cursor: pointer; font-family: inherit;
    }
    .tech-detail {
      display: none;
      margin-top: 12px;
      padding-top: 12px;
      border-top: 1px solid var(--vscode-panel-border);
    }
    .tech-detail.open { display: block; }
    .tech-detail-section { margin-bottom: 10px; }
    .tech-detail-section-title { font-size: 0.72rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; opacity: 0.6; margin-bottom: 5px; }
    .tech-detail-overview { font-size: 0.8rem; line-height: 1.5; margin-bottom: 10px; }
    .tech-detail ul { margin: 0; padding-left: 16px; }
    .tech-detail li { font-size: 0.78rem; line-height: 1.55; opacity: 0.85; }
    /* ---- Simulation ---- */
    .sim-tabs { display: flex; gap: 2px; margin-bottom: 16px; border-bottom: 1px solid var(--vscode-panel-border); }
    .sim-tab {
      padding: 8px 16px;
      cursor: pointer;
      font-size: 0.82rem;
      border-bottom: 2px solid transparent;
      background: none;
      border-top: none; border-left: none; border-right: none;
      color: var(--vscode-foreground);
      font-family: inherit;
      opacity: 0.65;
    }
    .sim-tab.active { border-bottom-color: var(--vscode-focusBorder); opacity: 1; font-weight: 600; }
    .sim-panel { display: none; }
    .sim-panel.active { display: block; }
    .form-grid { display: grid; gap: 12px; max-width: 600px; }
    .form-row { display: grid; gap: 4px; }
    .form-row label { font-size: 0.8rem; font-weight: 600; opacity: 0.8; }
    .form-row input, .form-row select, .form-row textarea {
      background: var(--vscode-input-background);
      color: var(--vscode-input-foreground);
      border: 1px solid var(--vscode-input-border);
      border-radius: var(--radius);
      padding: 7px 10px;
      font-family: var(--vscode-editor-font-family, monospace);
      font-size: 0.82rem;
      width: 100%;
    }
    .form-row textarea { resize: vertical; min-height: 80px; }
    .jwt-result {
      margin-top: 20px;
      display: flex;
      flex-direction: column;
      gap: var(--gap);
    }
    .jwt-parts { display: grid; gap: 8px; }
    .jwt-part {
      border-radius: var(--radius);
      overflow: hidden;
      border: 1px solid var(--vscode-panel-border);
    }
    .jwt-part-header {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 8px 12px;
      font-size: 0.78rem;
      font-weight: 700;
      border-bottom: 1px solid var(--vscode-panel-border);
    }
    .jwt-part-header .dot { width: 10px; height: 10px; border-radius: 50%; }
    .dot-header { background: #ef4444; }
    .dot-payload { background: #8b5cf6; }
    .dot-signature { background: #22c55e; }
    .jwt-part-content {
      padding: 10px 12px;
      font-family: var(--vscode-editor-font-family, monospace);
      font-size: 0.78rem;
      overflow-x: auto;
      white-space: pre;
    }
    .jwt-token-display {
      font-family: var(--vscode-editor-font-family, monospace);
      font-size: 0.75rem;
      word-break: break-all;
      padding: 12px;
      background: var(--vscode-textCodeBlock-background);
      border-radius: var(--radius);
      border: 1px solid var(--vscode-panel-border);
    }
    .jwt-token-display .part-header { color: #ef4444; }
    .jwt-token-display .part-payload { color: #8b5cf6; }
    .jwt-token-display .part-sig { color: #22c55e; }
    .warnings-list { display: flex; flex-direction: column; gap: 6px; }
    .warning-item {
      display: flex;
      gap: 8px;
      padding: 8px 12px;
      background: rgba(234,179,8,0.08);
      border-left: 3px solid var(--color-medium);
      border-radius: 0 var(--radius) var(--radius) 0;
      font-size: 0.8rem;
    }
    .sim-logs {
      max-height: 200px;
      overflow-y: auto;
      background: var(--vscode-terminal-background, #1e1e1e);
      border-radius: var(--radius);
      padding: 10px;
      font-family: var(--vscode-editor-font-family, monospace);
      font-size: 0.75rem;
    }
    .log-entry { display: flex; gap: 8px; margin-bottom: 3px; }
    .log-time { opacity: 0.4; white-space: nowrap; }
    .log-info { color: #60a5fa; }
    .log-warning { color: #fbbf24; }
    .log-error { color: #f87171; }
    .log-success { color: #4ade80; }
    .log-data { color: #a78bfa; }
    /* WebAuthn steps */
    .wa-steps { display: flex; flex-direction: column; gap: 12px; max-width: 800px; }
    .wa-step {
      border: 1px solid var(--vscode-panel-border);
      border-radius: var(--radius);
      overflow: hidden;
    }
    .wa-step-header {
      display: flex;
      align-items: center;
      gap: 12px;
      padding: 12px 16px;
      background: var(--vscode-editorGroupHeader-tabsBackground);
      cursor: pointer;
    }
    .step-number {
      width: 28px;
      height: 28px;
      border-radius: 50%;
      background: linear-gradient(135deg, #4f46e5, #818cf8);
      color: #fff;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 0.75rem;
      font-weight: 700;
      flex-shrink: 0;
    }
    .step-title { font-weight: 600; flex: 1; }
    .step-actor {
      font-size: 0.72rem;
      padding: 2px 8px;
      border-radius: 100px;
      background: var(--vscode-badge-background);
      color: var(--vscode-badge-foreground);
    }
    .wa-step-body { padding: 14px 16px; display: none; }
    .wa-step-body.open { display: block; }
    .wa-step-desc { font-size: 0.82rem; opacity: 0.85; margin-bottom: 12px; }
    .data-viewer {
      background: var(--vscode-textCodeBlock-background);
      border-radius: var(--radius);
      padding: 10px 12px;
      font-family: var(--vscode-editor-font-family, monospace);
      font-size: 0.75rem;
      overflow-x: auto;
      white-space: pre;
      margin-bottom: 10px;
    }
    .security-notes { display: flex; flex-direction: column; gap: 5px; }
    .security-note {
      display: flex;
      gap: 8px;
      font-size: 0.78rem;
      padding: 5px 0;
      border-bottom: 1px solid var(--vscode-panel-border);
    }
    .security-note:last-child { border-bottom: none; }
    .note-icon { flex-shrink: 0; opacity: 0.6; }
    /* Loading */
    .loading {
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 12px;
      padding: 40px;
      font-size: 0.85rem;
      opacity: 0.7;
    }
    .spinner {
      width: 18px;
      height: 18px;
      border: 2px solid var(--vscode-foreground);
      border-top-color: transparent;
      border-radius: 50%;
      animation: spin 0.7s linear infinite;
    }
    @keyframes spin { to { transform: rotate(360deg); } }
    .section-title {
      font-size: 0.85rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      opacity: 0.6;
      margin-bottom: 10px;
    }
    .divider { height: 1px; background: var(--vscode-panel-border); margin: 20px 0; }
  </style>
</head>
<body>

<div class="header">
  <span class="header-logo">🔐</span>
  <div style="flex:1">
    <div class="header-title">Authalyzer</div>
    <div class="header-subtitle">Passkey &amp; Authentication Security</div>
  </div>
  <button class="btn btn-primary" id="analyzeBtn">⚡ Analyze Workspace</button>
</div>

<div class="tabs-bar">
  <button class="tab active" data-tab="overview">Overview</button>
  <button class="tab" data-tab="flows">Auth Flows</button>
  <button class="tab" data-tab="security">Security Report</button>
  <button class="tab" data-tab="simulation">Simulation</button>
  <button class="tab" data-tab="technologies">Technologies</button>
</div>

<!-- OVERVIEW TAB -->
<div class="tab-panel active" id="tab-overview">
  <div id="overview-loading" class="loading" style="display:none">
    <div class="spinner"></div>
    <span id="loading-text">Scanning workspace...</span>
  </div>
  <div id="overview-empty" class="empty-state">
    <div class="icon">🔍</div>
    <strong>No analysis yet</strong>
    <span>Click "Analyze Workspace" to scan your project for authentication flows and security issues.</span>
    <button class="btn btn-primary" id="emptyAnalyzeBtn" style="margin-top:10px">Analyze Workspace</button>
  </div>
  <div id="overview-content" style="display:none">
    <div class="summary-grid" id="summary-cards"></div>
    <div class="section-title">Detected Auth Technologies</div>
    <div id="tech-badges" style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:20px"></div>
    <div class="divider"></div>
    <div class="section-title">Top Issues</div>
    <div id="top-issues"></div>
  </div>
</div>

<!-- FLOWS TAB -->
<div class="tab-panel" id="tab-flows">
  <div id="flows-empty" class="empty-state">
    <div class="icon">🗺️</div>
    <strong>No flows detected</strong>
    <span>Run an analysis to see authentication flow diagrams.</span>
  </div>
  <div id="flows-content" style="display:none">
    <div class="flow-selector">
      <label for="flowSelect" style="font-size:0.82rem;font-weight:600">Flow:</label>
      <select id="flowSelect"></select>
      <div id="flow-type-badge"></div>
    </div>
    <div id="flow-description" style="font-size:0.82rem;opacity:0.75;margin-bottom:14px"></div>
    <div class="diagram-container" id="diagram-container">
      <div class="empty-state">Select a flow to view the diagram</div>
    </div>
    <div style="margin-top:16px">
      <div class="section-title">Flow Steps</div>
      <div id="flow-steps-list"></div>
    </div>
  </div>
</div>

<!-- SECURITY TAB -->
<div class="tab-panel" id="tab-security">
  <div id="security-empty" class="empty-state">
    <div class="icon">🛡️</div>
    <strong>No security analysis yet</strong>
    <span>Run an analysis to see security vulnerabilities.</span>
  </div>
  <div id="security-content" style="display:none">
    <div id="pw-section" class="pw-section"></div>
    <div class="vuln-filters">
      <select id="severityFilter">
        <option value="">All Severities</option>
        <option value="critical">Critical</option>
        <option value="high">High</option>
        <option value="medium">Medium</option>
        <option value="low">Low</option>
        <option value="info">Info</option>
      </select>
      <input type="text" id="vulnSearch" placeholder="Search vulnerabilities..." />
      <span id="vuln-count" style="font-size:0.8rem;opacity:0.6"></span>
    </div>
    <div class="vuln-list" id="vuln-list"></div>
  </div>
</div>

<!-- SIMULATION TAB -->
<div class="tab-panel" id="tab-simulation">
  <div class="sim-tabs">
    <button class="sim-tab active" data-simtab="jwt">JWT Simulation</button>
    <button class="sim-tab" data-simtab="webauthn-reg">WebAuthn Registration</button>
    <button class="sim-tab" data-simtab="webauthn-auth">WebAuthn Authentication</button>
  </div>

  <!-- JWT -->
  <div class="sim-panel active" id="simtab-jwt">
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;align-items:start;max-width:900px" class="jwt-layout">
      <div>
        <div class="section-title">Generate Token</div>
        <div class="form-grid">
          <div class="form-row">
            <label>Algorithm</label>
            <select id="jwt-alg">
              <option value="HS256">HS256 (HMAC SHA-256)</option>
              <option value="HS384">HS384 (HMAC SHA-384)</option>
              <option value="HS512">HS512 (HMAC SHA-512)</option>
            </select>
          </div>
          <div class="form-row">
            <label>Secret Key</label>
            <input type="password" id="jwt-secret" value="super-secret-key-change-me" placeholder="HMAC secret"/>
          </div>
          <div class="form-row">
            <label>Subject (sub)</label>
            <input id="jwt-sub" value="user-123" placeholder="user-123"/>
          </div>
          <div class="form-row">
            <label>Issuer (iss)</label>
            <input id="jwt-iss" value="https://auth.example.com" placeholder="https://auth.example.com"/>
          </div>
          <div class="form-row">
            <label>Audience (aud)</label>
            <input id="jwt-aud" value="https://api.example.com" placeholder="Leave blank to omit"/>
          </div>
          <div class="form-row">
            <label>Expires In (seconds, 0 = no expiry)</label>
            <input type="number" id="jwt-exp" value="3600" min="0"/>
          </div>
          <div class="form-row">
            <label>Custom Claims (JSON)</label>
            <textarea id="jwt-custom">{"role": "user", "email": "alice@example.com"}</textarea>
          </div>
          <button class="btn btn-primary" id="generateJwtBtn">Generate JWT</button>
        </div>

        <div class="divider"></div>
        <div class="section-title">Verify Token</div>
        <div class="form-grid">
          <div class="form-row">
            <label>Token to Verify</label>
            <textarea id="jwt-verify-token" placeholder="Paste a JWT here..." style="min-height:80px;font-size:0.72rem"></textarea>
          </div>
          <div class="form-row">
            <label>Secret Key</label>
            <input type="password" id="jwt-verify-secret" placeholder="HMAC secret"/>
          </div>
          <div class="form-row">
            <label>Expected Algorithms (comma-separated)</label>
            <input id="jwt-verify-algs" value="HS256,HS384,HS512" placeholder="HS256"/>
          </div>
          <button class="btn btn-secondary" id="verifyJwtBtn">Verify JWT</button>
        </div>
      </div>

      <div>
        <div id="jwt-result-area">
          <div class="empty-state" style="padding:40px 10px">
            <div class="icon">🔑</div>
            <span>Generate or verify a JWT to see the result</span>
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- WebAuthn Registration -->
  <div class="sim-panel" id="simtab-webauthn-reg">
    <div style="max-width:800px">
      <div class="section-title">Simulate Registration Ceremony</div>
      <p style="font-size:0.82rem;opacity:0.75;margin-bottom:16px">
        Walk through the WebAuthn/FIDO2 passkey registration process step-by-step, with security notes at each stage.
      </p>
      <div class="form-grid" style="max-width:500px;margin-bottom:20px">
        <div class="form-row">
          <label>Relying Party ID (rpId)</label>
          <input id="wa-reg-rpid" value="example.com" placeholder="example.com"/>
        </div>
        <div class="form-row">
          <label>Relying Party Name</label>
          <input id="wa-reg-rpname" value="Example App" placeholder="My Application"/>
        </div>
        <div class="form-row">
          <label>Username</label>
          <input id="wa-reg-user" value="alice@example.com" placeholder="alice@example.com"/>
        </div>
        <button class="btn btn-primary" id="waRegBtn">▶ Run Registration Ceremony</button>
      </div>
      <div id="wa-reg-result"></div>
    </div>
  </div>

  <!-- WebAuthn Authentication -->
  <div class="sim-panel" id="simtab-webauthn-auth">
    <div style="max-width:800px">
      <div class="section-title">Simulate Authentication Ceremony</div>
      <p style="font-size:0.82rem;opacity:0.75;margin-bottom:16px">
        Walk through the WebAuthn/FIDO2 passkey authentication process with a previously registered credential.
      </p>
      <div class="form-grid" style="max-width:500px;margin-bottom:20px">
        <div class="form-row">
          <label>Relying Party ID (rpId)</label>
          <input id="wa-auth-rpid" value="example.com" placeholder="example.com"/>
        </div>
        <div class="form-row">
          <label>Credential ID (from registration)</label>
          <input id="wa-auth-credid" placeholder="Base64url credential ID (auto-filled after registration)"/>
        </div>
        <div class="form-row">
          <label>Public Key (from registration)</label>
          <input id="wa-auth-pubkey" placeholder="Base64url public key (auto-filled after registration)"/>
        </div>
        <button class="btn btn-primary" id="waAuthBtn">▶ Run Authentication Ceremony</button>
        <p style="font-size:0.75rem;opacity:0.6">Tip: Run the Registration ceremony first to auto-fill credential details.</p>
      </div>
      <div id="wa-auth-result"></div>
    </div>
  </div>
</div>

<!-- TECHNOLOGIES TAB -->
<div class="tab-panel" id="tab-technologies">
  <div id="tech-empty" class="empty-state">
    <div class="icon">📦</div>
    <strong>No technologies detected</strong>
    <span>Run an analysis to detect authentication libraries.</span>
  </div>
  <div id="tech-content" style="display:none">
    <div class="tech-grid" id="tech-grid"></div>
  </div>
</div>

<script nonce="${nonce}">
  const vscode = acquireVsCodeApi();
  let currentAnalysis = null;
  let lastRegisteredCredential = null;

  // ---- Tab switching ----
  function switchTab(name) {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
    const btn = document.querySelector('.tab[data-tab="' + name + '"]');
    const panel = document.getElementById('tab-' + name);
    if (btn) btn.classList.add('active');
    if (panel) panel.classList.add('active');
  }

  document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => switchTab(tab.dataset.tab));
  });

  document.querySelectorAll('.sim-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.sim-tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.sim-panel').forEach(p => p.classList.remove('active'));
      tab.classList.add('active');
      document.getElementById('simtab-' + tab.dataset.simtab).classList.add('active');
    });
  });

  // ---- Messages from extension ----
  window.addEventListener('message', event => {
    const msg = event.data;
    switch (msg.type) {
      case 'analysisResult':
        currentAnalysis = msg.data;
        renderAnalysis(msg.data);
        break;
      case 'analysisProgress':
        updateProgress(msg.data.message, msg.data.percent);
        break;
      case 'jwtSimulationResult':
        renderJWTResult(msg.data);
        break;
      case 'jwtVerifyResult':
        renderJWTVerify(msg.data);
        break;
      case 'webAuthnRegistrationResult':
        renderWebAuthnSteps(msg.data, 'wa-reg-result', msg.data.credential);
        break;
      case 'webAuthnAuthenticationResult':
        renderWebAuthnSteps(msg.data, 'wa-auth-result', null);
        break;
      case 'error':
        showError(msg.data.message);
        break;
      case 'navigate': {
        const { tab, flowIndex, severity, techName } = msg.data;
        switchTab(tab);
        if (tab === 'flows' && flowIndex !== undefined) {
          const select = document.getElementById('flowSelect');
          if (select && select.options.length > flowIndex) {
            select.value = String(flowIndex);
            select.dispatchEvent(new Event('change'));
          }
        }
        if (tab === 'security' && severity) {
          const search = document.getElementById('vulnSearch');
          if (search) { search.value = severity; search.dispatchEvent(new Event('input')); }
        }
        if (tab === 'technologies' && techName) {
          requestAnimationFrame(() => highlightTech(techName));
        }
        break;
      }
    }
  });

  // Notify extension we're ready
  vscode.postMessage({ type: 'ready' });

  // ---- Actions ----
  function analyzeWorkspace() {
    showLoading(true);
    vscode.postMessage({ type: 'analyzeWorkspace' });
  }

  document.getElementById('analyzeBtn').addEventListener('click', analyzeWorkspace);
  document.getElementById('emptyAnalyzeBtn').addEventListener('click', analyzeWorkspace);
  document.getElementById('generateJwtBtn').addEventListener('click', generateJWT);
  document.getElementById('verifyJwtBtn').addEventListener('click', verifyJWT);
  document.getElementById('waRegBtn').addEventListener('click', simulateWebAuthnReg);
  document.getElementById('waAuthBtn').addEventListener('click', simulateWebAuthnAuth);

  function updateProgress(message, percent) {
    document.getElementById('loading-text').textContent = message;
  }

  function showLoading(show) {
    document.getElementById('overview-loading').style.display = show ? 'flex' : 'none';
    document.getElementById('overview-empty').style.display = 'none';
    document.getElementById('overview-content').style.display = 'none';
  }

  // ---- Render analysis ----
  function renderAnalysis(data) {
    document.getElementById('overview-loading').style.display = 'none';
    document.getElementById('overview-empty').style.display = 'none';
    document.getElementById('overview-content').style.display = 'block';

    renderSummary(data.summary);
    renderTechBadges(data.technologies);
    renderTopIssues(data.vulnerabilities.slice(0, 5));
    renderFlows(data.flows);
    renderVulnerabilities(data.vulnerabilities, data.passwordAnalysis);
    renderTechnologies(data.technologies);
  }

  function renderSummary(summary) {
    const totalVulns = summary.criticalVulnerabilities + summary.highVulnerabilities +
      summary.mediumVulnerabilities + summary.lowVulnerabilities;
    const cards = [
      { value: summary.totalFlows, label: 'Auth Flows', class: 'success' },
      { value: summary.criticalVulnerabilities, label: 'Critical', class: 'critical' },
      { value: summary.highVulnerabilities, label: 'High', class: 'high' },
      { value: summary.mediumVulnerabilities, label: 'Medium', class: 'medium' },
      { value: summary.lowVulnerabilities + summary.infoVulnerabilities, label: 'Low/Info', class: 'low-color' },
      { value: summary.filesAnalyzed, label: 'Files Scanned', class: '' },
    ];
    document.getElementById('summary-cards').innerHTML = cards.map(c =>
      \`<div class="summary-card">
        <div class="value \${c.class}">\${c.value}</div>
        <div class="label">\${c.label}</div>
      </div>\`
    ).join('');
  }

  function renderTechBadges(techs) {
    const el = document.getElementById('tech-badges');
    if (!techs.length) { el.innerHTML = '<span style="opacity:0.5;font-size:0.8rem">No known auth libraries detected</span>'; return; }
    el.innerHTML = techs.map(t => {
      const type = t.type === 'library' || t.type === 'framework' ? t.name.split('/').pop() : t.type;
      const cls = getFlowBadgeClass(t);
      return \`<span class="badge \${cls}" title="\${t.description}">\${t.displayName}</span>\`;
    }).join('');
  }

  function getFlowBadgeClass(tech) {
    const name = tech.name.toLowerCase();
    if (name.includes('webauthn') || name.includes('fido') || name.includes('simplewebauthn')) return 'badge-webauthn';
    if (name.includes('jwt') || name.includes('jsonwebtoken') || name.includes('jose')) return 'badge-jwt';
    if (name.includes('oauth') || name.includes('passport') || name.includes('next-auth')) return 'badge-oauth2';
    if (name.includes('session')) return 'badge-session';
    return 'badge-info';
  }

  function renderTopIssues(vulns) {
    const el = document.getElementById('top-issues');
    if (!vulns.length) {
      el.innerHTML = '<div style="opacity:0.5;font-size:0.82rem">No issues found — great security posture!</div>';
      return;
    }
    el.innerHTML = vulns.map(v => \`
      <div class="vuln-card" data-vuln-id="\${escHtml(v.id)}" style="cursor:pointer">
        <div class="vuln-card-header">
          <span class="badge badge-\${v.severity}">\${v.severity}</span>
          <span class="title">\${escHtml(v.title)}</span>
        </div>
      </div>
    \`).join('');
    el.querySelectorAll('.vuln-card[data-vuln-id]').forEach(card => {
      card.addEventListener('click', () => showVulnDetail(card.dataset.vulnId));
    });
  }

  // ---- Flows ----
  function renderFlows(flows) {
    const emptyEl = document.getElementById('flows-empty');
    const contentEl = document.getElementById('flows-content');

    if (!flows || !flows.length) {
      emptyEl.style.display = 'flex';
      contentEl.style.display = 'none';
      return;
    }

    emptyEl.style.display = 'none';
    contentEl.style.display = 'block';

    const select = document.getElementById('flowSelect');
    select.innerHTML = flows.map((f, i) =>
      \`<option value="\${i}">\${escHtml(f.name)}</option>\`
    ).join('');

    select.addEventListener('change', () => renderFlow(flows[parseInt(select.value)]));
    renderFlow(flows[0]);
  }

  function renderFlow(flow) {
    document.getElementById('flow-description').textContent = flow.description;
    const badgeEl = document.getElementById('flow-type-badge');
    badgeEl.innerHTML = \`<span class="badge badge-\${flow.type}">\${flow.type.toUpperCase()}</span>\`;

    renderSequenceDiagram(flow);
    renderFlowStepsList(flow.steps);
  }

  function renderSequenceDiagram(flow) {
    const container = document.getElementById('diagram-container');
    const actors = getActorsForFlow(flow);
    const steps = flow.steps;

    const ACTOR_W = 130;
    const ACTOR_H = 44;
    const STEP_H = 70;
    const PAD = 40;
    const TOTAL_W = actors.length * (ACTOR_W + 30) + PAD * 2;
    const TOTAL_H = steps.length * STEP_H + ACTOR_H * 2 + PAD * 2;

    const actorX = actors.map((_, i) => PAD + i * (ACTOR_W + 30) + ACTOR_W / 2);

    let svg = \`<svg width="\${TOTAL_W}" height="\${TOTAL_H}" xmlns="http://www.w3.org/2000/svg" style="min-width:\${TOTAL_W}px">\`;

    // Defs: arrowhead marker
    svg += \`<defs>
      <marker id="arr" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
        <path d="M0,0 L0,6 L8,3 z" fill="var(--vscode-foreground)" opacity="0.7"/>
      </marker>
      <marker id="arr-dashed" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
        <path d="M0,0 L0,6 L8,3 z" fill="var(--vscode-foreground)" opacity="0.4"/>
      </marker>
    </defs>\`;

    // Actor boxes (top)
    actors.forEach((actor, i) => {
      const x = actorX[i] - ACTOR_W / 2;
      const color = actorColor(actor.id);
      svg += \`<rect x="\${x}" y="\${PAD}" width="\${ACTOR_W}" height="\${ACTOR_H}" rx="6" fill="\${color}" opacity="0.9"/>
        <text x="\${actorX[i]}" y="\${PAD + ACTOR_H / 2 + 1}" text-anchor="middle" dominant-baseline="middle"
          font-family="var(--vscode-font-family)" font-size="11" font-weight="600" fill="#fff">\${actor.label}</text>\`;
    });

    // Lifelines
    actors.forEach((_, i) => {
      svg += \`<line x1="\${actorX[i]}" y1="\${PAD + ACTOR_H}" x2="\${actorX[i]}" y2="\${TOTAL_H - PAD - ACTOR_H}"
        stroke="var(--vscode-foreground)" stroke-opacity="0.15" stroke-width="1" stroke-dasharray="5,4"/>\`;
    });

    // Steps / messages
    steps.forEach((step, i) => {
      const y = PAD + ACTOR_H + 20 + i * STEP_H;
      const fromIdx = actors.findIndex(a => a.id === step.from);
      const toIdx = actors.findIndex(a => a.id === step.to);
      const fromX = fromIdx >= 0 ? actorX[fromIdx] : actorX[0];
      const toX = toIdx >= 0 ? actorX[toIdx] : actorX[actors.length - 1];

      const isSelf = fromX === toX;
      const color = stepColor(step.type);

      if (isSelf) {
        // Self-loop arrow
        const lx = fromX + 20;
        svg += \`<path d="M\${fromX},\${y} Q\${lx + 40},\${y - 10} \${lx + 40},\${y + 15} Q\${lx + 40},\${y + 35} \${fromX},\${y + 30}"
          stroke="\${color}" stroke-width="1.5" fill="none" stroke-opacity="0.8" marker-end="url(#arr)"/>\`;
      } else {
        const dir = toX > fromX ? -4 : 4;
        svg += \`<line x1="\${fromX}" y1="\${y}" x2="\${toX + dir}" y2="\${y}"
          stroke="\${color}" stroke-width="1.5" stroke-opacity="0.8" marker-end="url(#arr)"/>\`;
      }

      // Step label
      const midX = isSelf ? fromX + 50 : (fromX + toX) / 2;
      const labelY = isSelf ? y + 15 : y - 8;
      const truncated = step.name.length > 30 ? step.name.substring(0, 28) + '…' : step.name;
      svg += \`<rect x="\${midX - 70}" y="\${labelY - 11}" width="140" height="18" rx="3"
        fill="var(--vscode-editor-background)" opacity="0.85"/>
        <text x="\${midX}" y="\${labelY + 2}" text-anchor="middle"
          font-family="var(--vscode-font-family)" font-size="10" fill="\${color}" font-weight="600"
          class="step-label">\${escHtml(truncated)}</text>\`;

      // Step number
      svg += \`<circle cx="\${fromX}" cy="\${y}" r="9" fill="\${color}" opacity="0.9"/>
        <text x="\${fromX}" y="\${y + 1}" text-anchor="middle" dominant-baseline="middle"
          font-family="var(--vscode-font-family)" font-size="9" font-weight="700" fill="#fff">\${i + 1}</text>\`;
    });

    // Actor boxes (bottom)
    actors.forEach((actor, i) => {
      const x = actorX[i] - ACTOR_W / 2;
      const color = actorColor(actor.id);
      svg += \`<rect x="\${x}" y="\${TOTAL_H - PAD - ACTOR_H}" width="\${ACTOR_W}" height="\${ACTOR_H}" rx="6" fill="\${color}" opacity="0.7"/>
        <text x="\${actorX[i]}" y="\${TOTAL_H - PAD - ACTOR_H / 2 + 1}" text-anchor="middle" dominant-baseline="middle"
          font-family="var(--vscode-font-family)" font-size="11" font-weight="600" fill="#fff">\${actor.label}</text>\`;
    });

    svg += '</svg>';
    container.innerHTML = svg;
  }

  function getActorsForFlow(flow) {
    const actorMap = {
      client: { id: 'client', label: '👤 Client' },
      server: { id: 'server', label: '🖥 Server' },
      database: { id: 'database', label: '🗄 Database' },
      authenticator: { id: 'authenticator', label: '🔑 Authenticator' },
      identityProvider: { id: 'identityProvider', label: '🌐 Identity Provider' },
    };

    const seen = new Set();
    const result = [];
    for (const step of flow.steps) {
      if (!seen.has(step.from)) { seen.add(step.from); result.push(actorMap[step.from] || { id: step.from, label: step.from }); }
      if (!seen.has(step.to)) { seen.add(step.to); result.push(actorMap[step.to] || { id: step.to, label: step.to }); }
    }
    return result.length ? result : [actorMap.client, actorMap.server];
  }

  function actorColor(id) {
    const colors = {
      client: '#3b82f6',
      server: '#8b5cf6',
      database: '#22c55e',
      authenticator: '#f97316',
      identityProvider: '#06b6d4',
    };
    return colors[id] || '#6b7280';
  }

  function stepColor(type) {
    const colors = {
      'credential-input': '#3b82f6',
      'challenge-generation': '#8b5cf6',
      'authenticator-response': '#f97316',
      'token-issuance': '#22c55e',
      'token-validation': '#ef4444',
      'session-creation': '#06b6d4',
      'middleware': '#6b7280',
      'redirect': '#eab308',
      'callback': '#ec4899',
      'error-handling': '#ef4444',
      'password-hash': '#84cc16',
      'authorization': '#f59e0b',
    };
    return colors[type] || '#6b7280';
  }

  function renderFlowStepsList(steps) {
    const el = document.getElementById('flow-steps-list');
    el.innerHTML = steps.map((step, i) => \`
      <div style="display:flex;gap:12px;align-items:flex-start;padding:10px 0;border-bottom:1px solid var(--vscode-panel-border)">
        <div style="width:24px;height:24px;border-radius:50%;background:\${stepColor(step.type)};display:flex;align-items:center;justify-content:center;font-size:0.7rem;font-weight:700;color:#fff;flex-shrink:0;margin-top:2px">\${i + 1}</div>
        <div>
          <div style="font-weight:600;font-size:0.85rem">\${escHtml(step.name)}</div>
          <div style="font-size:0.78rem;opacity:0.75;margin-top:2px">\${escHtml(step.description)}</div>
          \${step.codeRef && step.codeRef.snippet ? \`<div class="code-ref" data-file="\${escHtml(step.codeRef.file)}" data-line="\${step.codeRef.line}" style="margin-top:6px;cursor:pointer" title="Click to open file">\${escHtml(step.codeRef.snippet)} — \${escHtml(step.codeRef.file.split('/').pop())}:\${step.codeRef.line}</div>\` : ''}
        </div>
      </div>
    \`).join('');
    el.querySelectorAll('.code-ref[data-file]').forEach(ref => {
      ref.addEventListener('click', () => openFile(ref.dataset.file, parseInt(ref.dataset.line)));
    });
  }

  // ---- Vulnerabilities ----
  function renderVulnerabilities(vulns, passwordAnalysis) {
    const emptyEl = document.getElementById('security-empty');
    const contentEl = document.getElementById('security-content');

    const hasVulns = !!(vulns && vulns.length);
    const hasPw = !!(passwordAnalysis && (passwordAnalysis.hasPasswordHandling || passwordAnalysis.noHashingButHasAuth));

    if (!hasVulns && !hasPw) {
      emptyEl.style.display = 'flex';
      contentEl.style.display = 'none';
      return;
    }

    emptyEl.style.display = 'none';
    contentEl.style.display = 'block';

    renderPasswordSecurity(passwordAnalysis);

    const filtersEl = document.querySelector('.vuln-filters');
    if (!hasVulns) {
      if (filtersEl) filtersEl.style.display = 'none';
      document.getElementById('vuln-list').innerHTML = '';
      document.getElementById('vuln-count').textContent = '';
      return;
    }
    if (filtersEl) filtersEl.style.display = '';

    function applyFilters() {
      const sev = document.getElementById('severityFilter').value;
      const q = document.getElementById('vulnSearch').value.toLowerCase();
      const filtered = vulns.filter(v =>
        (!sev || v.severity === sev) &&
        (!q || v.title.toLowerCase().includes(q) || v.description.toLowerCase().includes(q))
      );
      document.getElementById('vuln-count').textContent = \`\${filtered.length} of \${vulns.length} issues\`;
      renderVulnCards(filtered);
    }

    document.getElementById('severityFilter').addEventListener('change', applyFilters);
    document.getElementById('vulnSearch').addEventListener('input', applyFilters);

    applyFilters();
  }

  function renderVulnCards(vulns) {
    const list = document.getElementById('vuln-list');
    if (!vulns.length) {
      list.innerHTML = '<div class="empty-state" style="padding:30px"><div class="icon">✅</div><strong>No matching issues</strong></div>';
      return;
    }

    const sorted = [...vulns].sort((a, b) => {
      const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
      return (order[a.severity] ?? 5) - (order[b.severity] ?? 5);
    });

    // Store refs in a map keyed by index — avoids embedding paths in HTML attributes
    const refMap = {};
    list.innerHTML = sorted.map((v, i) => {
      const hasRef = !!(v.codeRef && v.codeRef.file);
      if (hasRef) refMap[i] = { file: v.codeRef.file, line: v.codeRef.line, snippet: v.codeRef.snippet };
      const fileName = hasRef ? v.codeRef.file.split('/').pop() : '';
      return \`
      <div class="vuln-card" data-idx="\${i}">
        <div class="vuln-card-header" \${hasRef ? 'title="Click to open in editor"' : ''}>
          <span class="badge badge-\${v.severity}">\${v.severity}</span>
          <span class="title">\${escHtml(v.title)}</span>
          \${hasRef ? \`<span class="vuln-card-loc">📄 \${escHtml(fileName)}:\${v.codeRef.line}</span>\` : ''}
          <button class="vuln-expand-btn" title="Show details" aria-label="Expand">▼</button>
        </div>
        <div class="vuln-card-body" style="display:none">
          <p>\${escHtml(v.description)}</p>
          <div class="recommendation">💡 <strong>Fix:</strong> \${escHtml(v.recommendation)}</div>
          \${hasRef ? \`<div class="code-ref" data-idx="\${i}" title="Open in editor">
            📄 \${escHtml(fileName)}:\${v.codeRef.line}&nbsp;&nbsp;\${escHtml((v.codeRef.snippet || '').substring(0, 80))}
          </div>\` : ''}
          \${v.owasp || v.cwe ? \`<div class="meta-tags" style="margin-top:8px">
            \${v.owasp ? \`<span class="meta-tag">\${escHtml(v.owasp)}</span>\` : ''}
            \${v.cwe ? \`<span class="meta-tag">\${escHtml(v.cwe)}</span>\` : ''}
          </div>\` : ''}
        </div>
      </div>\`;
    }).join('');

    // Attach listeners after HTML is in the DOM
    list.querySelectorAll('.vuln-card').forEach(card => {
      const idx = parseInt(card.dataset.idx);
      const ref = refMap[idx];

      const header = card.querySelector('.vuln-card-header');
      const expandBtn = card.querySelector('.vuln-expand-btn');
      const body = card.querySelector('.vuln-card-body');
      const codeRefEl = card.querySelector('.code-ref');

      // Header click → navigate to file
      header.addEventListener('click', () => {
        if (ref) openFile(ref.file, ref.line);
      });

      // Expand button → toggle details only, don't navigate
      expandBtn.addEventListener('click', e => {
        e.stopPropagation();
        const open = body.style.display !== 'none';
        body.style.display = open ? 'none' : 'block';
        expandBtn.textContent = open ? '▼' : '▲';
      });

      // Code ref inside body → also navigates
      if (codeRefEl && ref) {
        codeRefEl.addEventListener('click', e => {
          e.stopPropagation();
          openFile(ref.file, ref.line);
        });
      }
    });
  }

  function renderPasswordSecurity(pa) {
    const el = document.getElementById('pw-section');
    if (!el) return;
    if (!pa || (!pa.hasPasswordHandling && !pa.noHashingButHasAuth)) {
      el.style.display = 'none';
      el.innerHTML = '';
      return;
    }
    el.style.display = 'block';

    const levelIcon = { secure: '🟢', acceptable: '🔵', weak: '🟡', insecure: '🔴', none: '⚪' };
    const icon = levelIcon[pa.overallRating] || '⚪';

    let html = \`
      <div class="section-title">Password Security</div>
      <div class="pw-overall">
        <span class="pw-rating-icon">\${icon}</span>
        <div>
          <div class="pw-overall-label">Overall Rating</div>
          <div class="pw-overall-value pw-level-\${escHtml(pa.overallRating)}">\${escHtml(pa.overallRating.toUpperCase())}</div>
        </div>
        <span class="pw-overall-summary">\${escHtml(pa.summary)}</span>
      </div>\`;

    if (pa.noHashingButHasAuth) {
      html += \`<div class="pw-overall" style="border-left:3px solid var(--color-critical);background:rgba(239,68,68,0.05);margin-bottom:10px">
        <span class="pw-rating-icon">⚠️</span>
        <div>
          <div class="pw-overall-value" style="color:var(--color-critical)">No Password Hashing Detected</div>
          <div style="font-size:0.8rem;opacity:0.75;margin-top:2px">Login routes found but no hashing library detected — passwords may be stored in plain text.</div>
        </div>
      </div>\`;
    }

    if (pa.findings && pa.findings.length > 0) {
      html += '<div class="pw-findings">';
      pa.findings.forEach((f, i) => {
        const params = Object.entries(f.parameters || {}).map(([k, v]) => escHtml(String(k) + '=' + String(v))).join(', ');
        const fileName = f.codeRef ? f.codeRef.file.split('/').pop() : '';
        const issuesHtml = (f.issues || []).map(issue =>
          \`<div class="pw-issue"><span>\${issue.severity === 'critical' || issue.severity === 'high' ? '⚠️' : 'ℹ️'}</span><span>\${escHtml(issue.message)}</span></div>\`
        ).join('');
        html += \`
          <div class="pw-finding" data-pw-idx="\${i}">
            <div class="pw-finding-header">
              <span class="pw-alg-badge pw-level-\${escHtml(f.securityLevel)}">\${escHtml(f.displayName)}</span>
              \${params ? \`<span class="pw-finding-params">\${params}</span>\` : ''}
              \${fileName ? \`<span class="pw-finding-loc">📄 \${escHtml(fileName)}:\${f.codeRef.line}</span>\` : ''}
              <button class="vuln-expand-btn" title="Show details">▼</button>
            </div>
            <div class="pw-finding-body">
              \${issuesHtml}
              <div class="pw-rec">💡 \${escHtml(f.recommendation)}</div>
              \${f.codeRef ? \`<div class="code-ref pw-code-ref" data-pw-file="\${escAttr(f.codeRef.file)}" data-pw-line="\${f.codeRef.line}" style="margin-top:8px" title="Open in editor">📄 \${escHtml(fileName)}:\${f.codeRef.line}&nbsp;&nbsp;\${escHtml((f.codeRef.snippet || '').substring(0, 80))}</div>\` : ''}
            </div>
          </div>\`;
      });
      html += '</div>';
    }

    html += '<div class="divider"></div>';
    el.innerHTML = html;

    el.querySelectorAll('.pw-finding').forEach(card => {
      const header = card.querySelector('.pw-finding-header');
      const body = card.querySelector('.pw-finding-body');
      const btn = header.querySelector('.vuln-expand-btn');
      const codeRef = card.querySelector('.pw-code-ref');

      header.addEventListener('click', () => {
        const isOpen = body.classList.contains('open');
        body.classList.toggle('open', !isOpen);
        if (btn) btn.textContent = isOpen ? '▼' : '▲';
      });

      if (codeRef) {
        codeRef.addEventListener('click', e => {
          e.stopPropagation();
          openFile(codeRef.dataset.pwFile, parseInt(codeRef.dataset.pwLine));
        });
      }
    });
  }

  function showVulnDetail(id) {
    document.querySelectorAll('.tab')[2].click();
    if (!currentAnalysis) return;
    const v = currentAnalysis.vulnerabilities.find(x => x.id === id);
    if (!v) return;
    const sev = document.getElementById('severityFilter');
    sev.value = v.severity;
    sev.dispatchEvent(new Event('change'));
  }

  // ---- Technologies ----
  function highlightTech(name) {
    const card = document.querySelector('.tech-card[data-name="' + name + '"]');
    if (!card) return;
    document.querySelectorAll('.tech-card.highlighted').forEach(c => c.classList.remove('highlighted'));
    card.classList.add('highlighted');
    card.scrollIntoView({ behavior: 'smooth', block: 'center' });
    const detail = card.querySelector('.tech-detail');
    if (detail && !detail.classList.contains('open')) {
      detail.classList.add('open');
      const btn = card.querySelector('.tech-expand-btn');
      if (btn) btn.textContent = '▲ Hide details';
    }
  }

  const TECH_EXPLANATIONS = {
    'express-session': {
      overview: 'Server-side session middleware for Express. Stores session data on the server; sends only a session ID cookie to the client.',
      security: ['Use a strong randomly-generated secret (≥32 bytes)', 'Set cookie.secure=true in production (HTTPS only)', 'Set cookie.httpOnly=true to block JS access', 'Set cookie.sameSite="strict" to prevent CSRF', 'Use a persistent store (Redis, DB) — MemoryStore leaks in production'],
      bestPractices: ['Regenerate session ID after login to prevent session fixation', 'Set a short maxAge and implement sliding expiry', 'Store minimal data in session; keep sensitive data server-side only'],
    },
    'passport': {
      overview: 'Authentication middleware for Node.js with a unified strategy API. Delegates auth logic to swappable strategies.',
      security: ['Always validate user existence in the verify callback before calling done(null, user)', 'Use timing-safe comparison for password checks', 'Log failed authentication attempts for anomaly detection'],
      bestPractices: ['Pair with express-session or JWT — Passport itself is stateless', 'Use passport.authenticate() as Express middleware, not manually', 'Serialize only the user ID to the session, not the full object'],
    },
    'passport-jwt': {
      overview: 'Passport strategy for authenticating with JSON Web Tokens. Extracts the token and verifies it against the secret or public key.',
      security: ['Always specify algorithms — prevents "alg:none" attacks', 'Validate issuer and audience claims', 'Use RS256/ES256 in multi-service environments instead of HS256'],
      bestPractices: ['Extract token from Authorization header, not query params', 'Check jti claim against a revocation list for sensitive operations'],
    },
    'passport-local': {
      overview: 'Passport strategy for username/password (local) authentication.',
      security: ['Hash passwords with bcrypt, Argon2, or scrypt — never store plaintext', 'Use timing-safe comparison (bcrypt.compare, argon2.verify)', 'Rate-limit login attempts to prevent brute force'],
      bestPractices: ['Return the same error for unknown user and wrong password to prevent user enumeration', 'Add CSRF protection to the login form'],
    },
    'passport-oauth2': {
      overview: 'Passport strategy for OAuth 2.0 authorization code flow.',
      security: ['Validate the state parameter to prevent CSRF', 'Store tokens securely — never in localStorage', 'Validate the token issuer and audience after exchange'],
      bestPractices: ['Request only the scopes you need (principle of least privilege)', 'Implement token refresh and expiry handling', 'Use PKCE for public clients (SPAs, mobile apps)'],
    },
    'bcrypt': {
      overview: 'Password hashing library using the bcrypt algorithm with automatic salt generation.',
      security: ['Use cost factor ≥12 (default 10 is outdated for modern hardware)', 'Never compare hashes with === — always use bcrypt.compare()', 'bcrypt truncates passwords at 72 bytes — pre-hash with SHA-512 for very long passwords'],
      bestPractices: ['Increase cost factor as hardware improves; re-hash on next login', 'Store only the hash returned by bcrypt.hash(), never the plaintext'],
    },
    'argon2': {
      overview: 'Password hashing using Argon2 — winner of the 2015 Password Hashing Competition. Argon2id variant recommended.',
      security: ['Use Argon2id (not Argon2i or Argon2d) for general password hashing', 'Set memory ≥64MB, iterations ≥3, parallelism ≥4', 'Never compare hashes with string equality — use argon2.verify()'],
      bestPractices: ['Argon2 is preferred over bcrypt for new projects due to memory hardness', 'Tune parameters so hashing takes ~100–300ms on your server'],
    },
    'jsonwebtoken': {
      overview: 'Node.js library for signing and verifying JSON Web Tokens (JWTs) per RFC 7519.',
      security: ['Always pass algorithms to verify() — prevents algorithm confusion attacks', 'Set expiresIn — tokens without expiry are permanent credentials', 'Use a secret ≥256 bits for HS256; prefer RS256/ES256 for distributed systems', 'Never use decode() for auth decisions — always verify()'],
      bestPractices: ['Implement refresh token rotation to limit exposure from token theft', 'Include only necessary claims — JWTs are base64 not encrypted', 'Use short access token TTL (15m) with longer refresh token TTL'],
    },
    'jwks-rsa': {
      overview: 'Retrieves RSA signing keys from a JWKS endpoint for JWT verification.',
      security: ['Cache keys with a short TTL to prevent DoS via JWKS endpoint hammering', 'Validate the kid header before fetching — prevents key confusion', 'Pin the JWKS URI in config, never derive it from the token'],
      bestPractices: ['Pair with passport-jwt or jsonwebtoken for full verification pipeline'],
    },
    'express-rate-limit': {
      overview: 'Rate limiting middleware for Express to protect endpoints from brute-force and DoS attacks.',
      security: ['Apply strict limits to /login, /register, /reset-password endpoints', 'Use a shared store (Redis) in multi-instance deployments — in-memory limits are per-process', 'Set trust proxy carefully — attackers can spoof X-Forwarded-For'],
      bestPractices: ['Return 429 with Retry-After header', 'Combine with account lockout for credential-stuffing defense'],
    },
    'helmet': {
      overview: 'Sets security-related HTTP response headers in Express apps.',
      security: ['contentSecurityPolicy is disabled by default in helmet v4+ — enable and tune it', 'hsts forces HTTPS — ensure your deployment supports HTTPS before enabling'],
      bestPractices: ['Configure CSP to restrict script sources — prevents XSS escalation', 'Enable helmet as early middleware so all routes are covered'],
    },
    'csurf': {
      overview: 'CSRF token middleware for Express (deprecated). Generates and validates synchronizer tokens.',
      security: ['csurf is deprecated/archived — migrate to csrf-csrf or double-submit cookies', 'Pair with same-site cookies — SameSite=Strict eliminates most CSRF in modern browsers'],
      bestPractices: ['Include CSRF token in every state-mutating form and AJAX request', 'Validate on all POST/PUT/PATCH/DELETE routes'],
    },
    '@simplewebauthn/server': {
      overview: 'Server-side WebAuthn/FIDO2 library for Node.js implementing the W3C WebAuthn spec.',
      security: ['Store and validate the credential counter on each authentication — detects cloned authenticators', 'Verify expectedOrigin and expectedRPID — origin mismatch = phishing attempt', 'Challenges must be random, server-generated, and single-use'],
      bestPractices: ['Allow both roaming (FIDO2 keys) and platform authenticators (Touch ID)', 'Implement fallback authentication for lost authenticator recovery', 'Store publicKey and credentialID per user, not globally'],
    },
    'PyJWT': {
      overview: 'Python library for encoding and decoding JSON Web Tokens per RFC 7519.',
      security: ['Always pass algorithms= to decode() — prevents algorithm confusion (alg:none attack)', 'Set options={"require": ["exp", "iss"]} to enforce required claims', 'Never pass options={"verify_signature": False} in production'],
      bestPractices: ['Use RS256 in microservice environments', 'Keep access token TTL short (15m); use refresh tokens for session continuity'],
    },
    'flask-jwt-extended': {
      overview: 'JWT authentication extension for Flask with access/refresh token management.',
      security: ['Set JWT_SECRET_KEY to a strong random value — not hardcoded', 'Set JWT_ACCESS_TOKEN_EXPIRES and JWT_REFRESH_TOKEN_EXPIRES', 'Implement token revocation list (blocklist) for logout'],
      bestPractices: ['Use @jwt_required(fresh=True) for sensitive operations to require re-auth', 'Store refresh tokens server-side and rotate on each use'],
    },
    'django-auth': {
      overview: "Django's built-in authentication system — handles users, passwords, sessions, and permissions.",
      security: ['Always call login(request, user) after authenticate() to rotate session ID', 'Django uses PBKDF2-SHA256 by default; consider Argon2 via django[argon2]', 'Enable SESSION_COOKIE_SECURE and CSRF_COOKIE_SECURE in production'],
      bestPractices: ["Use Django's built-in password validators in AUTH_PASSWORD_VALIDATORS", 'Use django-axes or similar for login rate limiting'],
    },
    'fastapi-security': {
      overview: "FastAPI's built-in security utilities — OAuth2PasswordBearer, HTTP Basic, API keys, and Depends injection.",
      security: ['OAuth2PasswordBearer only extracts the token — you must verify it in get_current_user()', 'Never skip token expiry validation in the verification function', 'Use HTTPS in production — Bearer tokens are credentials'],
      bestPractices: ["Use Depends(get_current_user) consistently — don't mix manual header extraction", 'Return HTTP 401 with WWW-Authenticate header for unauthenticated requests'],
    },
    'passlib': {
      overview: 'Python password hashing library supporting bcrypt, Argon2, scrypt, and more via CryptContext.',
      security: ['Use CryptContext with schemes=["argon2"] or ["bcrypt"] and deprecated="auto"', 'deprecated="auto" automatically upgrades weak hashes on next login'],
      bestPractices: ['Set rounds ≥12 for bcrypt; use Argon2 default params for argon2', 'Call pwd_context.hash() + pwd_context.verify() — never manual hash comparison'],
    },
    'py_webauthn': {
      overview: 'Python WebAuthn server library implementing W3C WebAuthn Level 2.',
      security: ['Validate expected_origin and expected_rp_id — mismatches indicate phishing', 'Store and check credential sign_count on every authentication', 'Challenges must be cryptographically random and invalidated after use'],
      bestPractices: ['Use verify_registration_response() and verify_authentication_response() — never skip steps', 'Support multiple credentials per user for key recovery'],
    },
    'python-fido2': {
      overview: "Yubico's python-fido2 library for FIDO2/WebAuthn server and client implementations.",
      security: ['Verify origin and rp_id in authenticate_complete()', 'Check auth_data.counter > stored_counter to detect cloned authenticators'],
      bestPractices: ['Use Fido2Server.authenticate_begin() / authenticate_complete() pair — never construct responses manually'],
    },
    'itsdangerous': {
      overview: "Flask's signing library — creates tamper-proof tokens using HMAC. Used for secure cookies, email confirmation links.",
      security: ['Tokens are signed but not encrypted — never include sensitive data', 'Set max_age on loads() to enforce token expiry', 'Use a strong secret_key and rotate it periodically'],
      bestPractices: ['Use URLSafeTimedSerializer for email confirmation / password-reset tokens', 'Always use loads() not loads_unsafe() in production'],
    },
    'spring-security': {
      overview: 'The standard security framework for Spring/Spring Boot — authentication, authorization, CSRF, session management.',
      security: ['Default CSRF protection is enabled — only disable for stateless REST APIs using JWT', 'BCryptPasswordEncoder with strength ≥12 is the minimum; prefer Argon2PasswordEncoder', 'Avoid anyRequest().permitAll() — explicitly list permitted paths'],
      bestPractices: ['Use SecurityContextHolder.getContext().getAuthentication() for the current principal', 'Enable @EnableMethodSecurity for @PreAuthorize / @Secured on service methods', 'Configure SessionCreationPolicy.STATELESS for JWT-based APIs'],
    },
    'spring-security-oauth2': {
      overview: "Spring Security's OAuth2 Resource Server and Client support for JWT and opaque token validation.",
      security: ['Configure oauth2ResourceServer().jwt() with a JWKS URI — never hardcode a public key in production', 'Set JwtDecoder with issuer validation via JwtValidators.createDefaultWithIssuer()', 'Restrict scopes: use hasAuthority("SCOPE_read") in access rules'],
      bestPractices: ['Validate iss, aud, and exp claims — Spring Security does this by default if configured correctly'],
    },
    'jjwt': {
      overview: 'Java JWT (JJWT) — a library for creating, parsing, and validating JWTs in Java/Kotlin.',
      security: ['Always call .verifyWith(key) or .decryptWith(key) — never use parseClaimsJwt() (unverified)', 'Specify the expected algorithm explicitly', 'Use Keys.secretKeyFor(SignatureAlgorithm.HS256) for key generation'],
      bestPractices: ['Set expiration in the builder: .expiration(Date)', 'Use RS256 for services that only verify, not sign'],
    },
    'java-jwt': {
      overview: "Auth0's Java JWT library for signing and verifying JWTs.",
      security: ['Always use JWT.require(algorithm).withIssuer(...).build().verify(token)', 'Specify algorithm explicitly in JWTVerifier — prevents algorithm confusion', 'Rotate secrets/keys periodically and invalidate old tokens'],
      bestPractices: ['Set withExpiresAt() and withNotBefore() claims', 'Use RSAKeyProvider or ECKeyProvider for asymmetric signing in distributed systems'],
    },
    'nimbus-jose-jwt': {
      overview: 'Nimbus JOSE+JWT — comprehensive Java library for JOSE (JWE, JWS, JWK) and JWT.',
      security: ['Configure JWSVerifier or JWEDecrypter with explicit algorithm allow-lists', 'Use RemoteJWKSet with a cache to validate against JWKS endpoints', 'Check JWTClaimsSet for exp, iss, aud after verification'],
      bestPractices: ["Used internally by Spring Security OAuth2 — prefer Spring's abstraction unless you need low-level JOSE"],
    },
    'apache-shiro': {
      overview: 'Apache Shiro — Java security framework for authentication, authorization, cryptography, and session management.',
      security: ['Use SecurityUtils.getSubject().login(token) — never bypass Subject for auth', 'Configure Realm with salted hashing: HashedCredentialsMatcher with Argon2 or bcrypt', 'Enable RememberMe only with a properly configured AES key — default key is insecure'],
      bestPractices: ['Use @RequiresAuthentication and @RequiresPermissions on service methods', 'Shiro < 1.10 had critical deserialization CVEs — keep version current'],
    },
    'keycloak-spring': {
      overview: 'Keycloak adapter for Spring Boot — integrates Keycloak as the identity provider via OpenID Connect.',
      security: ['The legacy Keycloak Spring adapter is deprecated since Keycloak 17 — migrate to Spring Security OAuth2', 'Validate realm and client_id in the token claims', 'Configure SSL/TLS for Keycloak server communication'],
      bestPractices: ['Migrate to spring-boot-starter-oauth2-resource-server + Keycloak JWKS endpoint', 'Use keycloak.ssl-required=external in production'],
    },
    'webauthn4j': {
      overview: 'WebAuthn4J — Java WebAuthn/FIDO2 library implementing W3C WebAuthn for server-side ceremony verification.',
      security: ['Validate origin and rpId in WebAuthnRegistrationManager and WebAuthnAuthenticationManager', 'Store and increment credential counter; reject authentication if counter does not increase', 'Use a proper challenge repository — challenges must be single-use'],
      bestPractices: ['Use Spring Security integration (webauthn4j-spring-security) for Spring Boot apps', 'Support both platform authenticators (Touch ID) and cross-platform keys'],
    },
    'yubico-webauthn': {
      overview: "Yubico's java-webauthn-server — a WebAuthn Relying Party server library for Java.",
      security: ['Call relyingParty.finishRegistration() and finishAssertion() — never skip verification', 'Configure RelyingPartyIdentity with correct id (origin domain) and name', 'Store CredentialRegistration per user and validate on every authentication'],
      bestPractices: ['Use InMemoryRegistrationStorage only for testing — implement a persistent store', 'Enable user verification (UV) for high-assurance operations'],
    },
    'spring-security-crypto': {
      overview: "Spring Security's crypto module — password encoding, key generation, and text encryption.",
      security: ['BCryptPasswordEncoder with strength ≥12 is the minimum recommended', 'Prefer Argon2PasswordEncoder.withSecureDefaults() for new projects', 'Never use NoOpPasswordEncoder, Md4PasswordEncoder, or ShaPasswordEncoder in production'],
      bestPractices: ['Use DelegatingPasswordEncoder for upgrading hash algorithms without breaking existing logins', 'PasswordEncoderFactories.createDelegatingPasswordEncoder() is the recommended default'],
    },
  };

  function renderTechnologies(techs) {
    const emptyEl = document.getElementById('tech-empty');
    const contentEl = document.getElementById('tech-content');

    if (!techs || !techs.length) {
      emptyEl.style.display = 'flex';
      contentEl.style.display = 'none';
      return;
    }

    emptyEl.style.display = 'none';
    contentEl.style.display = 'block';

    document.getElementById('tech-grid').innerHTML = techs.map(t => {
      const exp = TECH_EXPLANATIONS[t.name];
      const detailHtml = exp ? \`
        <div class="tech-detail" id="techdetail-\${escAttr(t.name)}">
          <div class="tech-detail-overview">\${escHtml(exp.overview)}</div>
          <div class="tech-detail-section">
            <div class="tech-detail-section-title">Security Considerations</div>
            <ul>\${exp.security.map(s => \`<li>\${escHtml(s)}</li>\`).join('')}</ul>
          </div>
          <div class="tech-detail-section">
            <div class="tech-detail-section-title">Best Practices</div>
            <ul>\${exp.bestPractices.map(s => \`<li>\${escHtml(s)}</li>\`).join('')}</ul>
          </div>
        </div>
      \` : '';
      return \`
        <div class="tech-card" data-name="\${escAttr(t.name)}" onclick="toggleTechDetail('\${escAttr(t.name)}')">
          <div class="tech-name">\${escHtml(t.displayName)}</div>
          <div style="margin-bottom:6px"><span class="badge badge-\${t.type === 'library' ? 'low' : 'info'}">\${escHtml(t.type)}</span></div>
          <div class="tech-desc">\${escHtml(t.description)}</div>
          <div class="tech-files">Found in \${t.files.length} file(s)</div>
          \${exp ? \`<button class="tech-expand-btn" id="techbtn-\${escAttr(t.name)}">▼ Show details</button>\` : ''}
          \${detailHtml}
        </div>
      \`;
    }).join('');
  }

  function toggleTechDetail(name) {
    const detail = document.getElementById('techdetail-' + name);
    const btn = document.getElementById('techbtn-' + name);
    if (!detail) return;
    const open = detail.classList.toggle('open');
    if (btn) btn.textContent = open ? '▲ Hide details' : '▼ Show details';
  }

  // ---- JWT Simulation ----
  function generateJWT() {
    let customClaims = {};
    try { customClaims = JSON.parse(document.getElementById('jwt-custom').value || '{}'); } catch { }

    const expSeconds = parseInt(document.getElementById('jwt-exp').value);
    const now = Math.floor(Date.now() / 1000);

    const payload = {
      sub: document.getElementById('jwt-sub').value || undefined,
      iss: document.getElementById('jwt-iss').value || undefined,
      aud: document.getElementById('jwt-aud').value || undefined,
      iat: now,
      ...(expSeconds > 0 ? { exp: now + expSeconds } : {}),
      ...customClaims,
    };

    Object.keys(payload).forEach(k => payload[k] === undefined && delete payload[k]);

    vscode.postMessage({
      type: 'simulateJWT',
      data: {
        algorithm: document.getElementById('jwt-alg').value,
        secret: document.getElementById('jwt-secret').value,
        payload,
      },
    });
  }

  function verifyJWT() {
    const algsRaw = document.getElementById('jwt-verify-algs').value;
    const algs = algsRaw.split(',').map(s => s.trim()).filter(Boolean);
    vscode.postMessage({
      type: 'verifyJWT',
      data: {
        token: document.getElementById('jwt-verify-token').value.trim(),
        secret: document.getElementById('jwt-verify-secret').value,
        expectedAlgorithms: algs,
      },
    });
  }

  function renderJWTResult(data) {
    const el = document.getElementById('jwt-result-area');

    const tokenHtml = \`<span class="part-header">\${escHtml(data.headerEncoded)}</span>.<span class="part-payload">\${escHtml(data.payloadEncoded)}</span>.<span class="part-sig">\${escHtml(data.signature)}</span>\`;

    el.innerHTML = \`
      <div class="jwt-result">
        <div class="section-title">Generated Token</div>
        <div class="jwt-token-display">\${tokenHtml}</div>
        <button class="btn btn-secondary" onclick="copyToken('\${escAttr(data.token)}')" style="align-self:flex-start;font-size:0.75rem">📋 Copy Token</button>

        <div class="section-title" style="margin-top:4px">Decoded Parts</div>
        <div class="jwt-parts">
          <div class="jwt-part">
            <div class="jwt-part-header"><div class="dot dot-header"></div>Header</div>
            <div class="jwt-part-content">\${escHtml(JSON.stringify(data.header, null, 2))}</div>
          </div>
          <div class="jwt-part">
            <div class="jwt-part-header"><div class="dot dot-payload"></div>Payload</div>
            <div class="jwt-part-content">\${escHtml(JSON.stringify(data.payload, null, 2))}</div>
          </div>
          <div class="jwt-part">
            <div class="jwt-part-header"><div class="dot dot-signature"></div>Signature</div>
            <div class="jwt-part-content">HMAC-\${escHtml(data.header.alg.replace('HS',''))}(\${escHtml(data.headerEncoded)}.\${escHtml(data.payloadEncoded)}, secret)</div>
          </div>
        </div>

        \${data.securityWarnings.length ? \`
          <div class="section-title">Security Warnings</div>
          <div class="warnings-list">\${data.securityWarnings.map(w =>
            \`<div class="warning-item">⚠️ <span>\${escHtml(w)}</span></div>\`
          ).join('')}</div>
        \` : '<div style="font-size:0.8rem;color:var(--color-success)">✓ No immediate security warnings</div>'}

        <div class="section-title">Simulation Log</div>
        <div class="sim-logs">\${renderLogs(data.logs)}</div>
      </div>
    \`;

    // Auto-fill verify fields
    document.getElementById('jwt-verify-token').value = data.token;
    document.getElementById('jwt-verify-secret').value = document.getElementById('jwt-secret').value;
  }

  function renderJWTVerify(data) {
    const el = document.getElementById('jwt-result-area');
    const statusColor = data.valid ? 'var(--color-success)' : 'var(--color-critical)';
    const statusIcon = data.valid ? '✅' : '❌';

    el.innerHTML = \`
      <div class="jwt-result">
        <div style="display:flex;align-items:center;gap:10px;padding:14px;border-radius:var(--radius);background:\${data.valid ? 'rgba(34,197,94,0.1)' : 'rgba(239,68,68,0.1)'};border:1px solid \${statusColor};margin-bottom:12px">
          <span style="font-size:1.5rem">\${statusIcon}</span>
          <div>
            <div style="font-weight:700;color:\${statusColor}">\${data.valid ? 'Token Valid' : 'Token Invalid'}</div>
            \${data.error ? \`<div style="font-size:0.8rem;opacity:0.8">\${escHtml(data.error)}</div>\` : ''}
            \${data.expiresAt ? \`<div style="font-size:0.8rem;opacity:0.8">Expires: \${escHtml(data.expiresAt)}</div>\` : ''}
          </div>
        </div>
        \${data.payload ? \`
          <div class="section-title">Decoded Payload</div>
          <div class="jwt-part">
            <div class="jwt-part-content">\${escHtml(JSON.stringify(data.payload, null, 2))}</div>
          </div>
        \` : ''}
        <div class="section-title" style="margin-top:12px">Verification Log</div>
        <div class="sim-logs">\${renderLogs(data.logs)}</div>
      </div>
    \`;
  }

  function copyToken(token) {
    navigator.clipboard.writeText(token).catch(() => {});
  }

  // ---- WebAuthn Simulation ----
  function simulateWebAuthnReg() {
    vscode.postMessage({
      type: 'simulateWebAuthnRegistration',
      data: {
        rpId: document.getElementById('wa-reg-rpid').value || 'example.com',
        rpName: document.getElementById('wa-reg-rpname').value || 'Example App',
        userName: document.getElementById('wa-reg-user').value || 'user@example.com',
      },
    });
  }

  function simulateWebAuthnAuth() {
    vscode.postMessage({
      type: 'simulateWebAuthnAuthentication',
      data: {
        rpId: document.getElementById('wa-auth-rpid').value || 'example.com',
        credentialId: document.getElementById('wa-auth-credid').value || 'demo-credential-id',
        publicKey: document.getElementById('wa-auth-pubkey').value || 'demo-public-key',
      },
    });
  }

  function renderWebAuthnSteps(data, containerId, credential) {
    const el = document.getElementById(containerId);

    if (credential && containerId === 'wa-reg-result') {
      lastRegisteredCredential = credential;
      document.getElementById('wa-auth-credid').value = credential.id;
      document.getElementById('wa-auth-pubkey').value = credential.publicKey;
    }

    el.innerHTML = \`
      <div>
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:16px">
          <span style="font-size:1.2rem">\${data.verified ? '✅' : '❌'}</span>
          <strong style="color:\${data.verified ? 'var(--color-success)' : 'var(--color-critical)'}">\${data.verified ? 'Ceremony completed successfully' : 'Ceremony failed'}</strong>
        </div>
        <div class="wa-steps">
          \${data.steps.map(step => renderWebAuthnStep(step)).join('')}
        </div>
        <div style="margin-top:16px">
          <div class="section-title">Ceremony Log</div>
          <div class="sim-logs">\${renderLogs(data.logs)}</div>
        </div>
      </div>
    \`;

    // Add expand/collapse to steps
    el.querySelectorAll('.wa-step-header').forEach(header => {
      header.addEventListener('click', () => {
        const body = header.nextElementSibling;
        body.classList.toggle('open');
      });
    });
  }

  function renderWebAuthnStep(step) {
    const actorColors = { server: '#8b5cf6', client: '#3b82f6', authenticator: '#f97316', database: '#22c55e', identityProvider: '#06b6d4' };
    const color = actorColors[step.actor] || '#6b7280';

    return \`<div class="wa-step">
      <div class="wa-step-header">
        <div class="step-number">\${step.stepNumber}</div>
        <div class="step-title">\${escHtml(step.title)}</div>
        <div class="step-actor" style="background:\${color}20;color:\${color}">\${escHtml(step.actor)}</div>
        <span style="opacity:0.4;font-size:0.8rem">▼</span>
      </div>
      <div class="wa-step-body">
        <div class="wa-step-desc">\${escHtml(step.description)}</div>
        <div class="section-title">Data</div>
        <div class="data-viewer">\${escHtml(JSON.stringify(step.data, null, 2))}</div>
        \${step.securityNotes.length ? \`
          <div class="section-title">Security Notes</div>
          <div class="security-notes">
            \${step.securityNotes.map(note => \`
              <div class="security-note">
                <span class="note-icon">🔒</span>
                <span>\${escHtml(note)}</span>
              </div>
            \`).join('')}
          </div>
        \` : ''}
      </div>
    </div>\`;
  }

  function renderLogs(logs) {
    return logs.map(l => {
      const cls = 'log-' + l.level;
      const time = l.timestamp.split('T')[1].split('.')[0];
      const dataStr = l.data ? \` \${JSON.stringify(l.data).substring(0, 60)}\` : '';
      return \`<div class="log-entry"><span class="log-time">\${escHtml(time)}</span><span class="\${cls}">[\${l.level.toUpperCase()}]</span><span>\${escHtml(l.message)}\${escHtml(dataStr)}</span></div>\`;
    }).join('');
  }

  // ---- Helpers ----
  function openFile(file, line) {
    if (!file) return;
    vscode.postMessage({ type: 'openFile', data: { file, line } });
  }

  function toggleVuln(btn) {
    const body = btn.closest('.vuln-card').querySelector('.vuln-card-body');
    const open = body.style.display !== 'none';
    body.style.display = open ? 'none' : 'block';
    btn.textContent = open ? '▼' : '▲';
  }

  function showError(message) {
    document.getElementById('overview-loading').style.display = 'none';
    document.getElementById('overview-empty').style.display = 'flex';
    document.getElementById('overview-empty').innerHTML = \`
      <div class="icon">⚠️</div>
      <strong>Error</strong>
      <span>\${escHtml(message)}</span>
      <button class="btn btn-secondary" onclick="analyzeWorkspace()" style="margin-top:10px">Try Again</button>
    \`;
  }

  function escHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  function escAttr(str) {
    return String(str || '').replace(/'/g, "\\'");
  }
</script>
</body>
</html>`;
}

export function generateNonce(): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < 32; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}
