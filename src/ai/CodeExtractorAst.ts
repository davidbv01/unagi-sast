import * as fs from 'fs';

export interface FunctionExtraction {
  functionName: string;
  startLine: number;
  endLine: number;
  sourceCode: string;
  filePath: string;
  language: string;
}

export interface DataFlowCodeExtraction {
  sourceFunction?: FunctionExtraction;
  sinkFunction?: FunctionExtraction;
  sanitizerFunctions: FunctionExtraction[];
  involvedLines: number[];
  fullContext: string;
  filePath: string;
}

export class CodeExtractor {
  
  /**
   * Extracts Python source code for functions involved in data flow analysis
   */
  public static extractDataFlowCode(
    filePath: string,
    lines: number[],
    ast: any
  ): DataFlowCodeExtraction {
    try {
      const fileContent = fs.readFileSync(filePath, 'utf-8');
      const codeLines = fileContent.split('\n');
      
      console.log(`[DEBUG] 🔍 Extracting code for data flow involving lines: ${lines.join(', ')}`);
      
      // Find functions containing each line
      const functionExtractions: FunctionExtraction[] = [];
      const processedFunctions = new Set<string>(); // To avoid duplicates
      
              for (const lineNumber of lines) {
          const functionInfo = this.findFunctionContainingLine(codeLines, lineNumber);
          if (functionInfo && !processedFunctions.has(`${functionInfo.functionName}_${functionInfo.startLine}`)) {
            functionExtractions.push({
              ...functionInfo,
              filePath,
              language: 'python'
            });
            processedFunctions.add(`${functionInfo.functionName}_${functionInfo.startLine}`);
            console.log(`[DEBUG] 📝 Extracted function: ${functionInfo.functionName} (lines ${functionInfo.startLine}-${functionInfo.endLine})`);
          }
        }
      
      // Generate full context (extended lines around the data flow)
      const minLine = Math.max(1, Math.min(...lines) - 5);
      const maxLine = Math.min(codeLines.length, Math.max(...lines) + 5);
      const contextLines = codeLines.slice(minLine - 1, maxLine);
      const fullContext = contextLines.map((line, index) => {
        const lineNum = minLine + index;
        const marker = lines.includes(lineNum) ? '>>> ' : '    ';
        return `${marker}${lineNum.toString().padStart(4, ' ')}: ${line}`;
      }).join('\n');
      
      // Categorize functions (simplified heuristic)
      const result: DataFlowCodeExtraction = {
        involvedLines: lines,
        fullContext,
        filePath,
        sanitizerFunctions: []
      };
      
      // First function is likely the source, last is likely the sink
      if (functionExtractions.length > 0) {
        result.sourceFunction = functionExtractions[0];
      }
      if (functionExtractions.length > 1) {
        result.sinkFunction = functionExtractions[functionExtractions.length - 1];
        // Middle functions are potential sanitizers
        result.sanitizerFunctions = functionExtractions.slice(1, -1);
      }
      
      console.log(`[DEBUG] ✅ Code extraction complete. Found ${functionExtractions.length} functions`);
      
      // Generate LLM input format for AI analysis
      const llmInput = this.generateLLMInput(result);
      console.log(`[DEBUG] 🤖 LLM Input: ${llmInput}`);
      
      return result;
      
    } catch (error) {
      console.error(`[ERROR] Failed to extract code from ${filePath}:`, error);
      return {
        involvedLines: lines,
        fullContext: `Error reading file: ${error}`,
        filePath,
        sanitizerFunctions: []
      };
    }
  }
  
  /**
   * Finds the function that contains a specific line number
   */
  private static findFunctionContainingLine(
    codeLines: string[],
    targetLine: number
  ): Omit<FunctionExtraction, 'filePath' | 'language'> | null {
    
    // Python function patterns
    const functionPatterns = this.getFunctionPatterns();
    
    let functionStart = -1;
    let functionName = 'unknown';
    let braceCount = 0;
    let inFunction = false;
    
    // Search backwards from target line to find function start
    for (let i = targetLine - 1; i >= 0; i--) {
      const line = codeLines[i].trim();
      
      for (const pattern of functionPatterns) {
        const match = line.match(pattern.regex);
        if (match) {
          functionName = match[pattern.nameGroup] || 'anonymous';
          functionStart = i + 1; // Convert to 1-based line numbers
          inFunction = true;
          console.log(`[DEBUG] 🎯 Found function '${functionName}' starting at line ${functionStart}`);
          break;
        }
      }
      
      if (inFunction) break;
    }
    
    if (!inFunction || functionStart === -1) {
      console.log(`[DEBUG] ⚠️ No function found containing line ${targetLine}`);
      return null;
    }
    
    // Find function end using Python indentation
    let functionEnd = functionStart;
    
    for (let i = functionStart - 1; i < codeLines.length; i++) {
      const line = codeLines[i];
      
      // For Python, use indentation to determine function boundaries
      if (i > functionStart && line.trim() !== '' && !line.startsWith(' ') && !line.startsWith('\t')) {
        functionEnd = i;
        break;
      }
      
      functionEnd = i + 1;
    }
    
    // Extract the function source code
    const functionLines = codeLines.slice(functionStart - 1, functionEnd);
    const sourceCode = functionLines.join('\n');
    
    console.log(`[DEBUG] 📋 Function '${functionName}' spans lines ${functionStart}-${functionEnd} (${functionLines.length} lines)`);
    
    return {
      functionName,
      startLine: functionStart,
      endLine: functionEnd,
      sourceCode
    };
  }
  
  /**
   * Returns function detection patterns for Python
   */
  private static getFunctionPatterns(): Array<{regex: RegExp, nameGroup: number}> {
    return [
      { regex: /def\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(/, nameGroup: 1 },
      { regex: /async\s+def\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(/, nameGroup: 1 }
    ];
  }
  
  
  
  /**
   * Generates LLM input text format for AI analysis
   */
  private static generateLLMInput(extraction: DataFlowCodeExtraction): string {
    let llmInput = '\n=== PYTHON CODE ANALYSIS REQUEST ===\n';
    llmInput += `File: ${extraction.filePath}\n`;
    llmInput += `Data flow lines: ${extraction.involvedLines.join(', ')}\n\n`;
    
    if (extraction.sourceFunction) {
      llmInput += `=== SOURCE FUNCTION ===\n`;
      llmInput += `Function: ${extraction.sourceFunction.functionName}\n`;
      llmInput += `Lines: ${extraction.sourceFunction.startLine}-${extraction.sourceFunction.endLine}\n`;
      llmInput += `Code:\n${extraction.sourceFunction.sourceCode}\n\n`;
    }
    
    if (extraction.sanitizerFunctions.length > 0) {
      llmInput += `=== SANITIZER FUNCTIONS ===\n`;
      extraction.sanitizerFunctions.forEach((sanitizer, index) => {
        llmInput += `Sanitizer ${index + 1}: ${sanitizer.functionName}\n`;
        llmInput += `Lines: ${sanitizer.startLine}-${sanitizer.endLine}\n`;
        llmInput += `Code:\n${sanitizer.sourceCode}\n\n`;
      });
    }
    
    if (extraction.sinkFunction) {
      llmInput += `=== SINK FUNCTION ===\n`;
      llmInput += `Function: ${extraction.sinkFunction.functionName}\n`;
      llmInput += `Lines: ${extraction.sinkFunction.startLine}-${extraction.sinkFunction.endLine}\n`;
      llmInput += `Code:\n${extraction.sinkFunction.sourceCode}\n\n`;
    }
    
    llmInput += `=== FULL CONTEXT ===\n`;
    llmInput += extraction.fullContext;
    llmInput += '\n\n=== END OF INPUT ===\n';
    
    return llmInput;
  }
  
  /**
   * Extracts multiple data flow contexts in batch
   */
  public static extractMultipleDataFlows(
    dataFlows: Array<{ lines: number[]; filePath?: string }>,
    defaultFilePath: string,
    ast: any
  ): DataFlowCodeExtraction[] {
    const extractions: DataFlowCodeExtraction[] = [];
    
    for (const flow of dataFlows) {
      const filePath = flow.filePath || defaultFilePath;
      const extraction = this.extractDataFlowCode(filePath, flow.lines, ast);
      extractions.push(extraction);
    }
    
    console.log(`[DEBUG] 📦 Batch extraction complete. Processed ${extractions.length} data flows`);
    return extractions;
  }
} 