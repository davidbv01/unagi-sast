// The module 'vscode' contains the VS Code extensibility API
// Import the module and reference it with the alias vscode in your code below
import * as vscode from 'vscode';
import { ESLint } from 'eslint';
import { exec } from 'child_process';
import { promisify } from 'util';
import * as path from 'path';

const execAsync = promisify(exec);

// This method is called when your extension is activated
// Your extension is activated the very first time the command is executed
export async function activate(context: vscode.ExtensionContext) {
	console.log('Unagi-SAST is now active!');

	let disposable = vscode.commands.registerCommand('unagi-sast.scanFile', async () => {
		const editor = vscode.window.activeTextEditor;
		if (!editor) {
			vscode.window.showErrorMessage('No file is currently open');
			return;
		}

		const document = editor.document;
		const filePath = document.uri.fsPath;

		try {
			// Start progress indication
			await vscode.window.withProgress({
				location: vscode.ProgressLocation.Notification,
				title: "Running security scan...",
				cancellable: false
			}, async (progress) => {
				progress.report({ increment: 0 });

				// Run ESLint checks
				const eslintResults = await runESLintCheck(filePath);
				progress.report({ increment: 50 });

				// Run Semgrep checks
				const semgrepResults = await runSemgrepCheck(filePath);
				progress.report({ increment: 100 });

				// Combine and display results
				displayResults(eslintResults, semgrepResults);
			});
		} catch (error) {
			vscode.window.showErrorMessage(`Error during security scan: ${error}`);
		}
	});

	// Register a custom sidebar provider
	const provider = new SecurityResultsViewProvider(context.extensionUri);
	context.subscriptions.push(
		vscode.window.registerWebviewViewProvider(SecurityResultsViewProvider.viewType, provider)
	);

	context.subscriptions.push(disposable);
}

async function runESLintCheck(filePath: string): Promise<any[]> {
	const eslint = new ESLint({
		useEslintrc: false,
		baseConfig: {
			root: true,
			plugins: ['@typescript-eslint', 'security'],
			extends: [
				'eslint:recommended',
				'plugin:@typescript-eslint/recommended',
				'plugin:security/recommended'
			]
		}
	});

	try {
		const results = await eslint.lintFiles([filePath]);
		return results;
	} catch (error) {
		console.error('ESLint error:', error);
		return [];
	}
}

async function runSemgrepCheck(filePath: string): Promise<any> {
	try {
		const { stdout } = await execAsync(`semgrep --config=auto ${filePath}`);
		return JSON.parse(stdout);
	} catch (error) {
		console.error('Semgrep error:', error);
		return [];
	}
}

function displayResults(eslintResults: any[], semgrepResults: any) {
	const outputChannel = vscode.window.createOutputChannel('Unagi-SAST Results');
	outputChannel.clear();
	outputChannel.show();

	outputChannel.appendLine('=== Security Scan Results ===\n');
	
	// Display ESLint results
	outputChannel.appendLine('ESLint Security Issues:');
	eslintResults.forEach(result => {
		result.messages.forEach((msg: any) => {
			outputChannel.appendLine(`[${msg.severity}] ${msg.message} (${msg.line}:${msg.column})`);
		});
	});

	// Display Semgrep results
	outputChannel.appendLine('\nSemgrep Security Issues:');
	if (Array.isArray(semgrepResults)) {
		semgrepResults.forEach(result => {
			outputChannel.appendLine(`[${result.severity}] ${result.message} (${result.line}:${result.column})`);
		});
	}
}

class SecurityResultsViewProvider implements vscode.WebviewViewProvider {
	public static readonly viewType = 'unagi-sast.securityResults';

	constructor(private readonly _extensionUri: vscode.Uri) {}

	public resolveWebviewView(
		webviewView: vscode.WebviewView,
		context: vscode.WebviewViewResolveContext,
		_token: vscode.CancellationToken,
	) {
		webviewView.webview.options = {
			enableScripts: true,
			localResourceRoots: [this._extensionUri]
		};

		webviewView.webview.html = this._getHtmlForWebview(webviewView.webview);
	}

	private _getHtmlForWebview(webview: vscode.Webview) {
		return `
			<!DOCTYPE html>
			<html lang="en">
			<head>
				<meta charset="UTF-8">
				<meta name="viewport" content="width=device-width, initial-scale=1.0">
				<title>Security Results</title>
			</head>
			<body>
				<h2>Security Scan Results</h2>
				<div id="results">
					Click "Scan File" command to start a security scan.
				</div>
			</body>
			</html>
		`;
	}
}

// This method is called when your extension is deactivated
export function deactivate() {}
