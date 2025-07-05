import { FunctionExtraction, DataFlowCodeExtraction } from '../types';

export class CodeExtractor {
  /**
   * Extracts the full source code of a function from the file given its line range.
   */
  private static extractFunctionSource(
    fileContent: string[],
    func: any,
    filePath: string
  ): FunctionExtraction {
    const lines = fileContent.slice(func.startLine - 1, func.endLine); // 1-based to 0-based
    return {
      functionName: func.name,
      startLine: func.startLine,
      endLine: func.endLine,
      sourceCode: lines.join('\n'),
      filePath,
      language: 'python'
    };
  }

  
  /**
   * Extracts the source code of all Python functions that contain any of the involved lines.
   * The full context will include the source code of these functions.
   */
  public static extractDataFlowCode(
    filePath: string,
    lines: number[],
    functions: any[],
    fileContent: string,
  ): DataFlowCodeExtraction {
    try {
      const fileLines = fileContent.split('\n');

      // Get unique line numbers
      const uniqueLines = Array.from(new Set(lines));

      // Find all functions that contain any of the involved lines
      const involvedFunctions = functions.filter(fn =>
        uniqueLines.some(line => line >= fn.startLine && line <= fn.endLine)
      );

      // Extract the full source code of those functions
      const fullContext = involvedFunctions
        .map(fn => this.extractFunctionSource(fileLines, fn, filePath).sourceCode)
        .join('\n\n');

      return {
        sourceFunction: undefined,
        sinkFunction: undefined,
        sanitizerFunctions: [], // not used in this version
        involvedLines: uniqueLines,
        fullContext,
        filePath
      };
    } catch (error) {
      console.error(`Failed to extract data flow code from ${filePath}:`, error);
      return {
        sourceFunction: undefined,
        sinkFunction: undefined,
        sanitizerFunctions: [],
        involvedLines: lines,
        fullContext: '',
        filePath
      };
    }
  }
}