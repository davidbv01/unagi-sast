// The module 'vscode' contains the VS Code extensibility API
// Import the module and reference it with the alias vscode in your code below
import * as vscode from 'vscode';
import { CommandTrigger } from './core/CommandTrigger';
import { configManager } from './config/ConfigurationManager';
import { UnagiMcpServerProvider } from './mcp/McpServerProvider';
import './extensionTcpServer';

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
	const commandTrigger = new CommandTrigger(apiKey || '', context.globalStorageUri.fsPath);
	commandTrigger.registerCommands(context);
	console.log('✅ Command triggers registered');

	// Register MCP server provider
	console.log('🌐 Setting up MCP server provider...');
	try {
		const mcpProvider = new UnagiMcpServerProvider(context);
		
		// Register the MCP server definition provider (when API becomes available)
		// For now, we'll just prepare the provider
		if ('lm' in vscode && 'registerMcpServerDefinitionProvider' in (vscode as any).lm) {
			const mcpDisposable = (vscode as any).lm.registerMcpServerDefinitionProvider('unagiSastProvider', mcpProvider);
			context.subscriptions.push(mcpDisposable);
		} else {
			console.log('📝 MCP API not yet available - provider prepared for future use');
		}
		
		context.subscriptions.push(mcpProvider);
		console.log('✅ MCP server provider setup completed');
	} catch (error) {
		console.warn('⚠️ MCP server provider setup failed (this is normal if MCP is not available):', error);
	}

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

	// Start TCP server for extension
	try {
		require('./extensionTcpServer');
		console.log('🚦 TCP server for extension started');
	} catch (err) {
		console.error('❌ Failed to start TCP server:', err);
	}

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