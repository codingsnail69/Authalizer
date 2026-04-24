// Minimal vscode mock for unit tests
export const workspace = { getConfiguration: () => ({ get: () => undefined }) };
export const window = { showErrorMessage: jest.fn(), showInformationMessage: jest.fn() };
export const Uri = { file: (p: string) => ({ fsPath: p }) };
export const DiagnosticSeverity = { Error: 0, Warning: 1, Information: 2, Hint: 3 };
export class Diagnostic { constructor(public range: unknown, public message: string, public severity?: number) {} }
export class Range { constructor(public start: unknown, public end: unknown) {} }
export class Position { constructor(public line: number, public character: number) {} }
