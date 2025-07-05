// The module 'vscode' contains the VS Code extensibility API
// Import the module and reference it with the alias vscode in your code below
import * as vscode from 'vscode';
import { CommandTrigger } from './core/CommandTrigger';
import { configManager } from './config/ConfigurationManager';
import './extensionTcpServer';

/**
 * Called when the extension is activated (first command execution).
 * @param context The VSCode extension context.
 */
export function activate(context: vscode.ExtensionContext): void {
	console.log('🛡️ Unagi SAST extension is now active!');
	console.log('📝 Initializing extension components...');

	// Initialize configuration manager
	console.log('⚙️ Loading configuration...');
	configManager.refresh();
	console.log('✅ Configuration loaded successfully');

	// Retrieve API key from global state
	const apiKey = getOpenAIApiKey(context);
	console.log(apiKey ? '🔑 API key loaded' : '🔑 No API key found');

	// Initialize and register command triggers
	console.log('🔧 Setting up command triggers...');
	const commandTrigger = new CommandTrigger(apiKey || '', context.globalStorageUri.fsPath);
	commandTrigger.registerCommands(context);
	console.log('✅ Command triggers registered');

	// Register configuration change listener
	const configChangeDisposable = vscode.workspace.onDidChangeConfiguration(event => {
		if (event.affectsConfiguration('unagi')) {
			console.log('⚙️ Configuration changed, refreshing...');
			configManager.refresh();
			console.log('✅ Configuration refreshed');
		}
	});
	context.subscriptions.push(configChangeDisposable);

	// Start TCP server for extension
	try {
		require('./extensionTcpServer');
		console.log('🚦 TCP server for extension started');
	} catch (err) {
		console.error('❌ Failed to start TCP server:', err);
	}

	console.log('🎉 Extension initialization complete!');
}

/**
 * Called when the extension is deactivated.
 */
export function deactivate(): void {
	console.log('🛑 Unagi SAST extension is being deactivated');
}

/**
 * Retrieves the OpenAI API key from the global state.
 * @param context The VSCode extension context.
 * @returns The API key string, or undefined if not set.
 */
export function getOpenAIApiKey(context: vscode.ExtensionContext): string | undefined {
	return context.globalState.get<string>('OPENAI_API_KEY');
}
