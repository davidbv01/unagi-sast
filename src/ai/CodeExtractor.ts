import { FunctionExtraction, DataFlowCodeExtraction } from '../types';

/**
 * Utility class for extracting code snippets and function contexts for AI analysis.
 */
export class CodeExtractor {
  /**
   * Extracts the full source code of a function from the file given its line range.
   * @param fileContent The file content as an array of lines.
   * @param func The function object with name, startLine, and endLine.
   * @param filePath The file path.
   * @returns The extracted function information.
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
   * @param filePath The file path.
   * @param lines The involved line numbers.
   * @param functions The list of function objects.
   * @param fileContent The file content as a string.
   * @returns The extracted data flow code context.
   */
  public static extractDataFlowCode(
    filePath: string,
    lines: number[],
    functions: any[],
    fileContent: string,
  ): DataFlowCodeExtraction {
    try {
      const fileLines = fileContent.split('\n');
      const uniqueLines = Array.from(new Set(lines));
      const involvedFunctions = functions.filter(fn =>
        uniqueLines.some(line => line >= fn.startLine && line <= fn.endLine)
      );
      const fullContext = involvedFunctions
        .map(fn => this.extractFunctionSource(fileLines, fn, filePath).sourceCode)
        .join('\n\n');
      return {
        sourceFunction: undefined,
        sinkFunction: undefined,
        sanitizerFunctions: [],
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