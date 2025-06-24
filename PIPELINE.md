1. Parse Source Code → AST

Use a parser like Tree-sitter to parse the source code and generate the full AST.

2. Detect Source Nodes

Traverse the AST to identify all nodes that act as data sources (external inputs, untrusted variables, etc.).
 
3. For Each Identified Source:

3.1 Initialize Taint Tracking

Mark the variable or expression from the source node as "tainted."

3.2 Traverse AST to Track Taint Propagation

Search for assignments, function calls, and operations where tainted data propagates to other variables or expressions. Update the taint tracking structure (list or graph) to include newly tainted variables.

3.3 During this traversal also:

Detect if tainted data passes through any functions or nodes that act as sanitizers, and mark that path as "clean."

Detect if tainted data reaches a sink (a vulnerable function or critical point).

3.4 Stop or mark paths as clean when:

A sanitizer node is detected (which neutralizes the risk).

A sink node is detected, which will then be marked as a potential vulnerability.