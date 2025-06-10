// The module 'vscode' contains the VS Code extensibility API
// Import the module and reference it with the alias vscode in your code below
import * as vscode from 'vscode';
import { CommandTrigger } from './triggers/CommandTrigger';
import { AutoTrigger } from './triggers/AutoTrigger';
import { configManager } from './config/ConfigurationManager';

// This method is called when your extension is activated
// Your extension is activated the very first time the command is executed
export function activate(context: vscode.ExtensionContext) {

	// Use the console to output diagnostic information (console.log) and errors (console.error)
	// This line of code will only be executed once when your extension is activated
	console.log('🛡️ Unagi SAST extension is now active!');

	// Initialize configuration manager
	configManager.refresh();

	// Initialize command triggers
	const commandTrigger = new CommandTrigger();
	commandTrigger.registerCommands(context);

	// Initialize auto triggers
	const autoTrigger = new AutoTrigger();
	autoTrigger.registerAutoTriggers(context);

	// Register configuration change listener
	const configChangeDisposable = vscode.workspace.onDidChangeConfiguration((event) => {
		if (event.affectsConfiguration('unagi')) {
			configManager.refresh();
		}
	});

	context.subscriptions.push(configChangeDisposable);
}

// This method is called when your extension is deactivated
export function deactivate() {}
