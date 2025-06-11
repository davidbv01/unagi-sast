import * as vscode from 'vscode';
import { ScanOrchestrator } from '../scanners/ScanOrchestrator';

export class AutoTrigger {
  private scanOrchestrator: ScanOrchestrator;
  private debounceTimer: NodeJS.Timeout | undefined;

  constructor() {
    this.scanOrchestrator = new ScanOrchestrator();
  }

  public registerAutoTriggers(context: vscode.ExtensionContext): void {
    // Auto-scan on file save
    const onSaveDisposable = vscode.workspace.onDidSaveTextDocument((document) => {
      this.onFileSave(document);
    });

    // Auto-scan on file open
    const onOpenDisposable = vscode.workspace.onDidOpenTextDocument((document) => {
      this.onFileOpen(document);
    });

    // Auto-scan on content change (debounced)
    const onChangeDisposable = vscode.workspace.onDidChangeTextDocument((event) => {
      this.onFileChange(event);
    });

    context.subscriptions.push(onSaveDisposable, onOpenDisposable, onChangeDisposable);
  }

  private async onFileSave(document: vscode.TextDocument): Promise<void> {
    if (this.shouldScanDocument(document)) {
      await this.scanOrchestrator.scanFile(document);
    }
  }

  private async onFileOpen(document: vscode.TextDocument): Promise<void> {
    if (this.shouldScanDocument(document)) {
      await this.scanOrchestrator.scanFile(document);
    }
  }

  private onFileChange(event: vscode.TextDocumentChangeEvent): void {
    if (!this.shouldScanDocument(event.document)) {
      return;
    }

    // Debounce the scan to avoid too frequent scans
    if (this.debounceTimer) {
      clearTimeout(this.debounceTimer);
    }

    this.debounceTimer = setTimeout(async () => {
      await this.scanOrchestrator.scanFile(event.document);
    }, 2000); // 2 second debounce
  }

  private shouldScanDocument(document: vscode.TextDocument): boolean {
    // Skip untitled documents and non-supported languages
    if (document.isUntitled) {
      return false;
    }

    return document.languageId === 'python';
  }
}
