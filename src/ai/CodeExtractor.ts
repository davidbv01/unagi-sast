import * as fs from 'fs';
import { PythonFunction } from '../types';

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
   * Extracts the full source code of a function from the file given its line range.
   */
  private static extractFunctionSource(
    fileContent: string[],
    func: PythonFunction,
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
   * Extracts Python source code for functions involved in data flow analysis.
   * This includes the source, sink, any sanitizers, and the full context involved.
   */
  public static extractDataFlowCode(
    filePath: string,
    lines: number[],
    functions: PythonFunction[]
  ): DataFlowCodeExtraction {
    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      const fileLines = content.split('\n');

      // Get full source code for each line involved in the taint path
      const involvedSource = lines
        .map(line => fileLines[line - 1]) // line numbers are 1-based
        .filter(Boolean)
        .join('\n');

      // Identify all functions that overlap with any of the involved lines
      const involvedFunctions = functions.filter(fn =>
        lines.some(line => line >= fn.startLine && line <= fn.endLine)
      );

      // Classify source, sink, and sanitizers based on first-come order
      const [sourceFunction, sinkFunction, ...sanitizers] = involvedFunctions;

      return {
        sourceFunction: sourceFunction
          ? this.extractFunctionSource(fileLines, sourceFunction, filePath)
          : undefined,
        sinkFunction: sinkFunction
          ? this.extractFunctionSource(fileLines, sinkFunction, filePath)
          : undefined,
        sanitizerFunctions: sanitizers.map(s =>
          this.extractFunctionSource(fileLines, s, filePath)
        ),
        involvedLines: lines,
        fullContext: involvedSource,
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