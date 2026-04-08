import ast
import glob
import sys

def check_file(filepath):
    with open(filepath, "r", encoding="utf-8") as f:
        tree = ast.parse(f.read(), filename=filepath)
    
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # Check if body only contains 'pass' or docstring + 'pass' or 'raise NotImplementedError'
            body = node.body
            is_empty = False
            for stmt in body:
                if isinstance(stmt, ast.Pass):
                    is_empty = True
                elif isinstance(stmt, ast.Raise):
                    is_empty = True
                elif isinstance(stmt, ast.Return) and stmt.value is None:
                    is_empty = True
                elif isinstance(stmt, ast.Expr): # Docstring or other expr
                    pass
                else:
                    is_empty = False
                    break
            
            if is_empty:
                print(f"Empty/NotImplemented function: {node.name} in {filepath} at line {node.lineno}")

for f in glob.glob("src/**/*.py", recursive=True):
    check_file(f)
for f in glob.glob("scripts/**/*.py", recursive=True):
    check_file(f)
