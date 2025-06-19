// The module 'vscode' contains the VS Code extensibility API
// Import the module and reference it with the alias vscode in your code below
import * as vscode from 'vscode';
import { CommandTrigger } from './core/CommandTrigger';
import { configManager } from './config/ConfigurationManager';

// This method is called when your extension is activated
// Your extension is activated the very first time the command is executed
export function activate(context: vscode.ExtensionContext) {
	console.log('🛡️ Unagi SAST extension is now active!');
	console.log('📝 Initializing extension components...');

	// Initialize configuration manager
	console.log('⚙️ Loading configuration...');
	configManager.refresh();
	console.log('✅ Configuration loaded successfully');

	// Get the API key from the global state
	const apiKey: string | undefined = getOpenAIApiKey(context);
	if (apiKey) {
		console.log('🔑 API key loaded');
	} else {
		console.log('🔑 No API key found');
	}

	// Initialize command triggers
	console.log('🔧 Setting up command triggers...');
	const commandTrigger = new CommandTrigger(apiKey || '');
	commandTrigger.registerCommands(context);
	console.log('✅ Command triggers registered');

	// Register configuration change listener
	console.log('👂 Registering configuration change listener...');
	const configChangeDisposable = vscode.workspace.onDidChangeConfiguration((event) => {
		if (event.affectsConfiguration('unagi')) {
			console.log('⚙️ Configuration changed, refreshing...');
			configManager.refresh();
			console.log('✅ Configuration refreshed');
		}
	});

	context.subscriptions.push(configChangeDisposable);
	console.log('🎉 Extension initialization complete!');
}

// This method is called when your extension is deactivated
export function deactivate() {
	console.log('🛑 Unagi SAST extension is being deactivated');
}


// Helper to retrieve the API key from global state
export function getOpenAIApiKey(context: vscode.ExtensionContext): string | undefined {
	return context.globalState.get<string>('OPENAI_API_KEY');
  } 