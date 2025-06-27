import * as vscode from 'vscode';
import * as path from 'path';

export class UnagiMcpServerProvider {
    private readonly _onDidChangeMcpServerDefinitions = new vscode.EventEmitter<void>();
    
    public readonly onDidChangeMcpServerDefinitions = this._onDidChangeMcpServerDefinitions.event;

    constructor(private context: vscode.ExtensionContext) {}

    async provideMcpServerDefinitions(): Promise<any[]> {
        const servers: any[] = [];

        // Get the extension's root directory
        const extensionPath = this.context.extensionPath;
        
        // Add Unagi SAST MCP Server
        servers.push({
            label: 'unagi-sast-server',
            command: 'node',
            args: [path.join(extensionPath, 'out', 'mcp', 'server.js')],
            cwd: vscode.Uri.file(extensionPath),
            env: {
                // Add any environment variables needed for your MCP server
                NODE_ENV: 'production'
            },
            version: '1.0.0'
        });

        return servers;
    }

    async resolveMcpServerDefinition(server: any): Promise<any | undefined> {
        // Handle any additional setup when the server needs to be started
        if (server.label === 'unagi-sast-server') {
            // You can add any authentication or setup logic here
            // For example, check if the server file exists
            const serverPath = path.join(this.context.extensionPath, 'out', 'mcp', 'server.js');
            
            try {
                await vscode.workspace.fs.stat(vscode.Uri.file(serverPath));
                console.log('🛡️ Unagi SAST MCP server found and ready to start');
                return server;
            } catch (error) {
                console.error('❌ Unagi SAST MCP server not found:', error);
                vscode.window.showErrorMessage('Unagi SAST MCP server is not available. Please rebuild the extension.');
                return undefined;
            }
        }

        return server;
    }

    // Method to trigger server definitions change
    public refresh(): void {
        this._onDidChangeMcpServerDefinitions.fire();
    }

    public dispose(): void {
        this._onDidChangeMcpServerDefinitions.dispose();
    }
} 