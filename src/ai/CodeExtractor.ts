import { AiAnalysisRequest } from '../types/ai';
import { PatternVulnerability, DataFlowVulnerability } from '../types/vulnerabilities';
import { SymbolTableEntry } from '../types/ast';

/**
 * Utility class for extracting code snippets and function contexts for AI analysis.
 * 
 * This class provides comprehensive context extraction capabilities for:
 * - Pattern-based vulnerabilities
 * - Single-file data flow vulnerabilities 
 * - Cross-file data flow vulnerabilities
 */
export class CodeExtractor {
  
  /**
   * Main function: extractContext
   * Extracts comprehensive context from vulnerabilities for AI analysis
   * @param request - The AI analysis request containing file, content, symbols, and vulnerabilities
   * @returns Formatted context string for AI analysis
   */
  public static extractContext(request: AiAnalysisRequest): string {
    const { file, content, symbols, patternVulnerabilities, dataFlowVulnerabilities, context } = request;
    
    let extractedContext = `File: ${file}\n`;
    
    if (context) {
      extractedContext += `Language: ${context.language}\n`;
      if (context.framework) {
        extractedContext += `Framework: ${context.framework}\n`;
      }
      if (context.additionalInfo) {
        extractedContext += `Additional Info: ${context.additionalInfo}\n`;
      }
    }
    
    extractedContext += '\n=== VULNERABILITIES CONTEXT ===\n\n';
    
    // Extract pattern vulnerabilities context
    if (patternVulnerabilities.length > 0) {
      extractedContext += '=== PATTERN VULNERABILITIES ===\n';
      for (const vulnerability of patternVulnerabilities) {
        const context = this.extractContextPatternVulnerability(file, content, vulnerability);
        console.log('[CodeExtractor] PatternVulnerability context:', context);
        extractedContext += context;
        extractedContext += '\n';
      }
    }
    
    // Extract data flow vulnerabilities context
    if (dataFlowVulnerabilities.length > 0) {
      extractedContext += '=== DATA FLOW VULNERABILITIES ===\n';
      for (const vulnerability of dataFlowVulnerabilities) {
        const isCrossFile = !!vulnerability.isCrossFile;
        if (isCrossFile && context && context.filesContent && context.filesSymbols) {
          // Use the full cross-file extractor if maps are provided
          const crossFileContext = this.extractContextDataFlowVulnerabilityCrossFile(
            vulnerability,
            context.filesContent,
            context.filesSymbols
          );
          console.log('[CodeExtractor] Cross-file DataFlowVulnerability context (full):', crossFileContext);
          extractedContext += crossFileContext;
        } else if (isCrossFile) {
          // Fallback: add a note and use the regular extractor
          const fallbackContext = this.extractContextDataFlowVulnerability(file, content, vulnerability, symbols);
          console.log('[CodeExtractor] Cross-file DataFlowVulnerability context (limited):', fallbackContext);
          extractedContext += '// NOTE: This is a cross-file vulnerability. Full context requires multiple files.\n';
          extractedContext += fallbackContext;
        } else {
          const context = this.extractContextDataFlowVulnerability(file, content, vulnerability, symbols);
          console.log('[CodeExtractor] DataFlowVulnerability context:', context);
          extractedContext += context;
        }
        extractedContext += '\n';
      }
    }
    
    return extractedContext;
  }

  /**
   * Function: extractContextPatternVulnerability
   * Extracts the context of pattern vulnerabilities by adding 10 lines before and after the pattern line
   * @param file - The file path
   * @param content - The file content
   * @param vulnerability - The pattern vulnerability to extract context for
   * @returns Context string for the pattern vulnerability
   */
  public static extractContextPatternVulnerability(
    file: string,
    content: string,
    vulnerability: PatternVulnerability
  ): string {
    const lines = content.split('\n');
    const targetLine = vulnerability.line - 1; // Convert to 0-based index
    
    // Calculate context range (10 lines before and after)
    const startLine = Math.max(0, targetLine - 10);
    const endLine = Math.min(lines.length - 1, targetLine + 10);
    
    let contextLines: string[] = [];
    for (let i = startLine; i <= endLine; i++) {
      const lineNumber = i + 1; // Convert back to 1-based
      const marker = i === targetLine ? ' <-- PATTERN VULNERABILITY' : '';
      contextLines.push(`${lineNumber.toString().padStart(4)}: ${lines[i]}${marker}`);
    }
    
    return `Pattern Vulnerability: ${vulnerability.type}\n` +
           `Message: ${vulnerability.message}\n` +
           `Line: ${vulnerability.line}\n` +
           `Code Context:\n${contextLines.join('\n')}\n`;
  }

  /**
   * Function: extractContextDataFlowVulnerability
   * Extracts the context of data flow vulnerabilities using pathLines and symbols
   * @param file - The file path
   * @param content - The file content
   * @param vulnerability - The data flow vulnerability
   * @param symbols - The symbol table entries for the file
   * @returns Context string for the data flow vulnerability
   */
  public static extractContextDataFlowVulnerability(
    file: string,
    content: string,
    vulnerability: DataFlowVulnerability,
    symbols: SymbolTableEntry[]
  ): string {
    const lines = content.split('\n');
    const pathLines = vulnerability.pathLines || [];
    const seenLines = new Set<number>();
    let contextParts: string[] = [];
    
    // Process each line in the data flow path
    for (const lineNumber of pathLines) {
      if (seenLines.has(lineNumber)) continue;
      
      // Find function containing this line
      const containingFunction = this.findContainingFunction(lineNumber, symbols);
      
      if (containingFunction) {
        // Extract the entire function context
        const functionContext = this.extractFunctionContext(
          containingFunction,
          lines,
          lineNumber,
          vulnerability
        );
        contextParts.push(functionContext);
        
        // Mark all lines in this function as seen
        for (let i = containingFunction.loc.start.line; i <= containingFunction.loc.end.line; i++) {
          seenLines.add(i);
        }
      } else {
        // Extract 10 lines before and after if not in a function
        const lineContext = this.extractLineContext(lines, lineNumber, vulnerability);
        contextParts.push(lineContext);
        
        // Mark the context lines as seen
        const startLine = Math.max(1, lineNumber - 10);
        const endLine = Math.min(lines.length, lineNumber + 10);
        for (let i = startLine; i <= endLine; i++) {
          seenLines.add(i);
        }
      }
    }
    
    const sourcesInfo = vulnerability.sources.map(s => `${s.type} at line ${s.loc.start.line}`).join(', ');
    const sinkInfo = `${vulnerability.sink.type} at line ${vulnerability.sink.loc.start.line}`;
    const sanitizersInfo = vulnerability.sanitizers.length > 0 
      ? vulnerability.sanitizers.map(s => `${s.type} at line ${s.loc.start.line}`).join(', ')
      : 'None';
    
    return `Data Flow Vulnerability: ${vulnerability.type}\n` +
           `Message: ${vulnerability.message}\n` +
           `Sources: ${sourcesInfo}\n` +
           `Sink: ${sinkInfo}\n` +
           `Sanitizers: ${sanitizersInfo}\n` +
           `Code Context:\n${contextParts.join('\n\n')}\n`;
  }

  /**
   * Function: extractContextDataFlowVulnerabilityCrossFile
   * Handles cross-file data flow vulnerabilities by extracting context from multiple files
   * @param vulnerability - The cross-file data flow vulnerability
   * @param filesContent - Map of file paths to their content
   * @param filesSymbols - Map of file paths to their symbol tables
   * @returns Context string for cross-file data flow vulnerabilities
   */
  public static extractContextDataFlowVulnerabilityCrossFile(
    vulnerability: DataFlowVulnerability,
    filesContent: Map<string, string>,
    filesSymbols: Map<string, SymbolTableEntry[]>
  ): string {
    let crossFileContext = '';
    
    // Extract information about the vulnerability
    const sourcesInfo = vulnerability.sources.map(s => `${s.type} at line ${s.loc.start.line} in ${s.filePath}`).join(', ');
    const sinkInfo = `${vulnerability.sink.type} at line ${vulnerability.sink.loc.start.line} in ${vulnerability.filePath}`;
    const sanitizersInfo = vulnerability.sanitizers.length > 0 
      ? vulnerability.sanitizers.map(s => `${s.type} at line ${s.loc.start.line} in ${s.filePath || vulnerability.filePath}`).join(', ')
      : 'None';
    
    crossFileContext += `Cross-file Data Flow Vulnerability: ${vulnerability.type}\n`;
    crossFileContext += `Message: ${vulnerability.message}\n`;
    crossFileContext += `Sources: ${sourcesInfo}\n`;
    crossFileContext += `Sink: ${sinkInfo}\n`;
    crossFileContext += `Sanitizers: ${sanitizersInfo}\n\n`;
    
    // Group components by file
    const fileComponents = new Map<string, {
      sources: typeof vulnerability.sources,
      sinks: typeof vulnerability.sink[],
      sanitizers: typeof vulnerability.sanitizers
    }>();
    
    // Process sources
    for (const source of vulnerability.sources) {
      const filePath = source.filePath;
      if (!fileComponents.has(filePath)) {
        fileComponents.set(filePath, { sources: [], sinks: [], sanitizers: [] });
      }
      fileComponents.get(filePath)!.sources.push(source);
    }
    
    // Process sink
    const sinkFilePath = vulnerability.filePath;
    if (!fileComponents.has(sinkFilePath)) {
      fileComponents.set(sinkFilePath, { sources: [], sinks: [], sanitizers: [] });
    }
    fileComponents.get(sinkFilePath)!.sinks.push(vulnerability.sink);
    
    // Process sanitizers
    for (const sanitizer of vulnerability.sanitizers) {
      const filePath = sanitizer.filePath || vulnerability.filePath;
      if (!fileComponents.has(filePath)) {
        fileComponents.set(filePath, { sources: [], sinks: [], sanitizers: [] });
      }
      fileComponents.get(filePath)!.sanitizers.push(sanitizer);
    }
    
    // Extract context for each file
    crossFileContext += '=== CROSS-FILE CONTEXT ===\n\n';
    
    for (const [filePath, components] of fileComponents) {
      const content = filesContent.get(filePath);
      const symbols = filesSymbols.get(filePath) || [];
      
      if (!content) {
        crossFileContext += `File: ${filePath}\n`;
        crossFileContext += `Content not available\n\n`;
        continue;
      }
      
      crossFileContext += `File: ${filePath}\n`;
      crossFileContext += `${'-'.repeat(50)}\n`;
      
      const lines = content.split('\n');
      const relevantLines = new Set<number>();
      
      // Collect all relevant line numbers
      components.sources.forEach(s => relevantLines.add(s.loc.start.line));
      components.sinks.forEach(s => relevantLines.add(s.loc.start.line));
      components.sanitizers.forEach(s => relevantLines.add(s.loc.start.line));
      
      // For each relevant line, try to extract function context or line context
      const processedFunctions = new Set<string>();
      
      for (const lineNumber of Array.from(relevantLines).sort((a, b) => a - b)) {
        const containingFunction = this.findContainingFunction(lineNumber, symbols);
        
        if (containingFunction && !processedFunctions.has(containingFunction.name)) {
          // Extract entire function context
          const functionContext = this.extractCrossFileFunctionContext(
            containingFunction,
            lines,
            components,
            vulnerability
          );
          crossFileContext += functionContext + '\n\n';
          processedFunctions.add(containingFunction.name);
        } else if (!containingFunction) {
          // Extract line context if not in a function
          const lineContext = this.extractCrossFileLineContext(
            lines,
            lineNumber,
            components,
            vulnerability
          );
          crossFileContext += lineContext + '\n\n';
        }
      }
    }
    
    return crossFileContext;
  }

  /**
   * Helper method to find the function containing a specific line number
   * @param lineNumber - The line number to search for
   * @param symbols - The symbol table entries
   * @returns The function symbol containing the line, or undefined
   */
  private static findContainingFunction(
    lineNumber: number,
    symbols: SymbolTableEntry[]
  ): SymbolTableEntry | undefined {
    return symbols.find(symbol => 
      symbol.type === 'function' &&
      symbol.loc.start.line <= lineNumber &&
      symbol.loc.end.line >= lineNumber
    );
  }

  /**
   * Helper method to extract function context with vulnerability markers
   * @param functionSymbol - The function symbol
   * @param lines - The file lines
   * @param targetLine - The specific line of interest
   * @param vulnerability - The vulnerability for context
   * @returns Formatted function context
   */
  private static extractFunctionContext(
    functionSymbol: SymbolTableEntry,
    lines: string[],
    targetLine: number,
    vulnerability: DataFlowVulnerability
  ): string {
    const startLine = functionSymbol.loc.start.line - 1; // Convert to 0-based
    const endLine = functionSymbol.loc.end.line - 1;
    
    let contextLines: string[] = [];
    for (let i = startLine; i <= endLine; i++) {
      const lineNumber = i + 1; // Convert back to 1-based
      let marker = '';
      
      // Add markers for sources, sinks, and sanitizers
      if (vulnerability.sources.some(s => s.loc.start.line === lineNumber)) {
        marker = ' <-- SOURCE';
      } else if (vulnerability.sink.loc.start.line === lineNumber) {
        marker = ' <-- SINK';
      } else if (vulnerability.sanitizers.some(s => s.loc.start.line === lineNumber)) {
        marker = ' <-- SANITIZER';
      } else if (lineNumber === targetLine) {
        marker = ' <-- PATH';
      }
      
      contextLines.push(`${lineNumber.toString().padStart(4)}: ${lines[i]}${marker}`);
    }
    
    return `Function: ${functionSymbol.name}\n${contextLines.join('\n')}`;
  }

  /**
   * Helper method to extract line context when not in a function
   * @param lines - The file lines
   * @param targetLine - The target line number
   * @param vulnerability - The vulnerability for context
   * @returns Formatted line context
   */
  private static extractLineContext(
    lines: string[],
    targetLine: number,
    vulnerability: DataFlowVulnerability
  ): string {
    const targetIndex = targetLine - 1; // Convert to 0-based
    const startLine = Math.max(0, targetIndex - 10);
    const endLine = Math.min(lines.length - 1, targetIndex + 10);
    
    let contextLines: string[] = [];
    for (let i = startLine; i <= endLine; i++) {
      const lineNumber = i + 1; // Convert back to 1-based
      let marker = '';
      
      // Add markers for sources, sinks, and sanitizers
      if (vulnerability.sources.some(s => s.loc.start.line === lineNumber)) {
        marker = ' <-- SOURCE';
      } else if (vulnerability.sink.loc.start.line === lineNumber) {
        marker = ' <-- SINK';
      } else if (vulnerability.sanitizers.some(s => s.loc.start.line === lineNumber)) {
        marker = ' <-- SANITIZER';
      } else if (lineNumber === targetLine) {
        marker = ' <-- PATH';
      }
      
      contextLines.push(`${lineNumber.toString().padStart(4)}: ${lines[i]}${marker}`);
    }
    
    return `Code Context:\n${contextLines.join('\n')}`;
  }

  /**
   * Helper method to extract function context for cross-file vulnerabilities
   * @param functionSymbol - The function symbol
   * @param lines - The file lines
   * @param components - The vulnerability components in this file
   * @param vulnerability - The full vulnerability for context
   * @returns Formatted function context
   */
  private static extractCrossFileFunctionContext(
    functionSymbol: SymbolTableEntry,
    lines: string[],
    components: {
      sources: any[],
      sinks: any[],
      sanitizers: any[]
    },
    vulnerability: DataFlowVulnerability
  ): string {
    const startLine = functionSymbol.loc.start.line - 1; // Convert to 0-based
    const endLine = functionSymbol.loc.end.line - 1;
    
    let contextLines: string[] = [];
    for (let i = startLine; i <= endLine; i++) {
      const lineNumber = i + 1; // Convert back to 1-based
      let marker = '';
      
      // Add markers for sources, sinks, and sanitizers in this file
      if (components.sources.some(s => s.loc.start.line === lineNumber)) {
        marker = ' <-- SOURCE (Cross-file)';
      } else if (components.sinks.some(s => s.loc.start.line === lineNumber)) {
        marker = ' <-- SINK (Cross-file)';
      } else if (components.sanitizers.some(s => s.loc.start.line === lineNumber)) {
        marker = ' <-- SANITIZER (Cross-file)';
      }
      
      contextLines.push(`${lineNumber.toString().padStart(4)}: ${lines[i]}${marker}`);
    }
    
    return `Function: ${functionSymbol.name}\n${contextLines.join('\n')}`;
  }

  /**
   * Helper method to extract line context for cross-file vulnerabilities when not in a function
   * @param lines - The file lines
   * @param targetLine - The target line number
   * @param components - The vulnerability components in this file
   * @param vulnerability - The full vulnerability for context
   * @returns Formatted line context
   */
  private static extractCrossFileLineContext(
    lines: string[],
    targetLine: number,
    components: {
      sources: any[],
      sinks: any[],
      sanitizers: any[]
    },
    vulnerability: DataFlowVulnerability
  ): string {
    const targetIndex = targetLine - 1; // Convert to 0-based
    const startLine = Math.max(0, targetIndex - 10);
    const endLine = Math.min(lines.length - 1, targetIndex + 10);
    
    let contextLines: string[] = [];
    for (let i = startLine; i <= endLine; i++) {
      const lineNumber = i + 1; // Convert back to 1-based
      let marker = '';
      
      // Add markers for sources, sinks, and sanitizers in this file
      if (components.sources.some(s => s.loc.start.line === lineNumber)) {
        marker = ' <-- SOURCE (Cross-file)';
      } else if (components.sinks.some(s => s.loc.start.line === lineNumber)) {
        marker = ' <-- SINK (Cross-file)';
      } else if (components.sanitizers.some(s => s.loc.start.line === lineNumber)) {
        marker = ' <-- SANITIZER (Cross-file)';
      }
      
      contextLines.push(`${lineNumber.toString().padStart(4)}: ${lines[i]}${marker}`);
    }
    
    return `Code Context:\n${contextLines.join('\n')}`;
  }
}