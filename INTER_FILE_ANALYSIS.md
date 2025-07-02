# Inter-File Data Flow Analysis

This document describes the implementation of cross-file vulnerability detection in the Unagi SAST tool.

## Overview

The inter-file analysis system enables detection of security vulnerabilities that span across multiple files in a workspace. This is crucial for modern applications where:

- User input comes from one file (e.g., HTTP request handlers)
- Data processing happens in utility modules  
- Dangerous operations are performed in separate files

## Architecture

### Core Components

#### 1. InterFileAnalyzer (`src/analysis/InterFileAnalyzer.ts`)
- **Main orchestrator** for the entire cross-file analysis process
- Coordinates file-by-file analysis and cross-file connection building
- Manages the workspace-level vulnerability detection workflow

#### 2. ImportResolver (`src/analysis/ImportResolver.ts`)
- **Tracks imports and exports** between files
- Resolves module dependencies and function call relationships
- Maps which functions/variables are imported from which files
- Handles Python import statements: `import`, `from ... import`

#### 3. WorkspaceDataFlowGraph (`src/analysis/WorkspaceDataFlowGraph.ts`)
- **Extends data flow analysis** across file boundaries
- Maintains individual file graphs while building cross-file connections
- Propagates taint across imports and function calls
- Detects vulnerabilities that span multiple files

#### 4. Enhanced Types (`src/types/index.ts`)
- `FileAnalysisResult`: Per-file analysis results with imports/exports
- `CrossFileDataFlow`: Represents data flow between files
- `WorkspaceScanResult`: Comprehensive workspace analysis results

## How It Works

### Phase 1: Individual File Analysis
```typescript
// For each Python file in the workspace:
1. Parse AST using tree-sitter
2. Extract functions, imports, and exports
3. Detect sources, sinks, and sanitizers
4. Build local data flow graph
5. Store file analysis results
```

### Phase 2: Import Resolution
```typescript
// Map relationships between files:
1. Extract import statements from each file
2. Resolve import paths to actual file locations
3. Map function calls to their definitions in other files
4. Build cross-file dependency graph
```

### Phase 3: Cross-File Connection Building
```typescript
// Create edges between files:
1. For each import, create connection to exporting file
2. Map function call sites to function definitions
3. Create parameter mapping for function arguments
4. Build workspace-level data flow graph
```

### Phase 4: Taint Propagation
```typescript
// Propagate taint across file boundaries:
1. Start with sources in individual files
2. Propagate taint within each file
3. Follow import/export relationships
4. Propagate taint across file boundaries
5. Respect sanitizers that stop propagation
```

### Phase 5: Vulnerability Detection
```typescript
// Detect cross-file vulnerabilities:
1. Find tainted sinks in any file
2. Trace back to original sources (possibly in other files)
3. Check for sanitizers in the path
4. Generate cross-file vulnerability reports
```

## Example Scenario

Consider this FastAPI application structure:

### main.py (Sources)
```python
from fastapi import FastAPI, Request
from utils import process_user_data

@app.post("/process")
async def process_endpoint(request: Request):
    user_data = await request.json()  # SOURCE: User input
    user_input = user_data.get("data", "")
    result = process_user_data(user_input)  # Cross-file call
    return {"result": result}
```

### utils.py (Sinks)
```python
import sqlite3

def process_user_data(user_input):  # Function called from main.py
    query = f"SELECT * FROM users WHERE name = '{user_input}'"  # SINK: SQL injection
    cursor.execute(query)
```

### Detection Process
1. **File Analysis**: 
   - `main.py`: Detects `request.json()` as source, `process_user_data` call
   - `utils.py`: Detects `cursor.execute(query)` as sink, `process_user_data` function

2. **Import Resolution**:
   - Maps `from utils import process_user_data` in main.py
   - Resolves to `process_user_data` function in utils.py

3. **Cross-File Connection**:
   - Creates edge: `main.py:user_input` → `utils.py:user_input parameter`

4. **Taint Propagation**:
   - Taint starts at `request.json()` in main.py
   - Flows to `user_input` variable
   - Crosses file boundary through function call
   - Reaches `cursor.execute()` sink in utils.py

5. **Vulnerability Detection**:
   - Detects cross-file SQL injection vulnerability
   - Reports: "Tainted data from main.py reaches SQL sink in utils.py"

## Configuration

The inter-file analysis is automatically enabled when using `scanWorkspace()`. It:

- Only analyzes Python files (`.py` extension)
- Respects the same exclude patterns as regular scanning
- Provides enhanced progress reporting
- Generates detailed statistics about cross-file connections

## Output

### Enhanced Workspace Scan Results
```typescript
interface WorkspaceScanResult {
  fileResults: ScanResult[];           // Individual file results
  crossFileVulnerabilities: DataFlowVulnerability[];  // Cross-file vulnerabilities
  totalFiles: number;
  totalVulnerabilities: number;
  interFileConnections: CrossFileDataFlow[];  // Import/export relationships
  scanTime: number;
}
```

### Progress Reporting
The analysis provides detailed progress updates:
- "Analyzing individual files and building workspace graph..."
- "Building cross-file connections..."
- "Detecting cross-file vulnerabilities..."
- "Scan complete: X total vulnerabilities (Y cross-file)"

### Statistics
```
📊 Inter-file Analysis Statistics:
  - Total files analyzed: 25
  - Total nodes in graphs: 1,247
  - Cross-file connections: 18
  - Files with vulnerabilities: 7
```

## Limitations and Future Improvements

### Current Limitations
1. **Python Only**: Currently only supports Python files
2. **Simple Import Resolution**: Basic module resolution (no complex Python path handling)
3. **Function-Level Granularity**: Tracks function calls but not internal data flow within functions
4. **No Class Analysis**: Doesn't track method calls through class instances

### Future Enhancements
1. **Multi-Language Support**: Extend to JavaScript/TypeScript, Java, etc.
2. **Advanced Path Resolution**: Support virtual environments, PYTHONPATH, etc.
3. **Class and Method Tracking**: Full object-oriented analysis
4. **API Framework Integration**: Better understanding of Flask, Django, FastAPI patterns
5. **Configuration-Based Rules**: Allow customization of what constitutes sources/sinks per framework

## Performance Considerations

- **Memory Usage**: Workspace graph can become large for big codebases
- **Analysis Time**: Scales with number of files and complexity of imports
- **Caching**: Import resolution results are cached for efficiency
- **Incremental Analysis**: Future versions could support incremental updates

## Integration with Existing Systems

The inter-file analysis integrates seamlessly with:
- Existing pattern-based vulnerability detection
- AI-powered verification (when API key is provided)
- VS Code diagnostics and problem reporting
- Output management and reporting systems

The system maintains backward compatibility while providing enhanced cross-file detection capabilities.