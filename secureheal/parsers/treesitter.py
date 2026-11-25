"""Tree-sitter source code parser for SecureHeal-AI.

Provides Java and Python source code parsing capabilities for:
- Function and class/method identification
- Import/dependency extraction
- Runtime-to-source evidence correlation
- API endpoint mapping
- Control flow graph generation

Integrates with Context Intelligence Agent and Evidence Correlator.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("secureheal.parsers.treesitter")

# Try to import tree-sitter; gracefully fall back if not available
try:
    from tree_sitter import Language, Node, Parser
    from tree_sitter_javalanguage import language as java_language
    TREE_SITTER_AVAILABLE = True
    logger.info("Tree-sitter with Java language support available")
except ImportError:
    TREE_SITTER_AVAILABLE = False
    java_language = None
    Language = Node = Parser = None
    logger.warning("Tree-sitter not available — running in fallback mode")


class ParsedFunction:
    """Represents a parsed function/method with location and metadata."""
    def __init__(
        self,
        name: str,
        file_path: str,
        start_line: int,
        end_line: int,
        parameters: Optional[List[str]] = None,
        return_type: Optional[str] = None,
        is_async: bool = False,
    ):
        self.name = name
        self.file_path = file_path
        self.start_line = start_line
        self.end_line = end_line
        self.parameters = parameters or []
        self.return_type = return_type
        self.is_async = is_async

    def __repr__(self):
        return f"ParsedFunction(name='{self.name}', file='{self.file_path}', lines={self.start_line}-{self.end_line})"


class ParsedClass:
    """Represents a parsed class with location and metadata."""
    def __init__(
        self,
        name: str,
        file_path: str,
        start_line: int,
        end_line: int,
        methods: Optional[List[ParsedFunction]] = None,
        implements: Optional[List[str]] = None,
    ):
        self.name = name
        self.file_path = file_path
        self.start_line = start_line
        self.end_line = end_line
        self.methods = methods or []
        self.implements = implements or []

    def __repr__(self):
        return f"ParsedClass(name='{self.name}', file='{self.file_path}', lines={self.start_line}-{self.end_line})"


class ParsedImport:
    """Represents an imported module or package."""
    def __init__(
        self,
        name: str,
        alias: Optional[str] = None,
        line: Optional[int] = None,
        is_wildcard: bool = False,
    ):
        self.name = name
        self.alias = alias
        self.line = line
        self.is_wildcard = is_wildcard

    def __repr__(self):
        alias_str = f" as {self.alias}" if self.alias else ""
        return f"ParsedImport(name='{self.name}{alias_str}', line={self.line})"


class SourceCodeContext:
    """Container for all parsed structural information from a source file."""
    def __init__(
        self,
        file_path: str,
        language: str,
        functions: Optional[List[ParsedFunction]] = None,
        classes: Optional[List[ParsedClass]] = None,
        imports: Optional[List[ParsedImport]] = None,
        dependencies: Optional[List[str]] = None,
        api_endpoints: Optional[Dict[str, dict]] = None,
    ):
        self.file_path = file_path
        self.language = language
        self.functions = functions or []
        self.classes = classes or []
        self.imports = imports or []
        self.dependencies = dependencies or []
        self.api_endpoints = api_endpoints or {}


def get_parser() -> Optional[Parser]:
    """Get or create a Tree-sitter parser instance."""
    if not TREE_SITTER_AVAILABLE:
        return None
    try:
        parser = Parser()
        return parser
    except Exception as e:
        logger.warning("Failed to create Tree-sitter parser: %s", e)
        return None


def load_java_language() -> Optional[Language]:
    """Load the Tree-sitter Java language module."""
    if not TREE_SITTER_AVAILABLE or java_language is None:
        return None
    try:
        return Language(java_language, "java")
    except Exception as e:
        logger.warning("Failed to load Java language: %s", e)
        return None


def load_python_language() -> Optional[Language]:
    """Load the Tree-sitter Python language module."""
    if not TREE_SITTER_AVAILABLE:
        return None
    try:
        # Build Python language from tree-sitter
        Language.build_library(
            "./build/my-languages.so",
            ["tree-sitter-python"],
        )
        from tree_sitter import Language
        return Language("./build/my-languages.so", "python")
    except Exception as e:
        logger.warning("Failed to load Python language: %s", e)
        return None


def parse_python_source(
    source_code: str,
    file_path: str = "<unknown>",
) -> SourceCodeContext:
    """Parse Python source code using Tree-sitter and extract structural elements.

    Args:
        source_code: Python source code string
        file_path: Path to the source file (for error reporting)

    Returns:
        SourceCodeContext with extracted functions, classes, imports, and endpoints
    """
    if not TREE_SITTER_AVAILABLE:
        logger.warning("Tree-sitter not available — returning fallback context")
        return _fallback_python_parse(source_code, file_path)

    parser = get_parser()
    if parser is None:
        return _fallback_python_parse(source_code, file_path)

    try:
        # Parse the source code
        tree = parser.parse(bytes(source_code, "utf-8"))
        root_node = tree.root_node

        functions: list[ParsedFunction] = []
        classes: list[ParsedClass] = []
        imports: list[ParsedImport] = []

        # Walk the AST to find functions, classes, and imports
        def walk_node(node: Node, depth: int = 0):
            if node is None:
                return

            # Get node type and text
            node_type = node.type
            node_text = node_text_from_node(node)

            # Find function definitions
            if node_type == "function_definition":
                func_name = ""
                start_line = node.start_point.row + 1
                end_line = node.end_point.row + 1
                is_async = False

                # Check for async
                for child in node.children:
                    if child.type == "async_function_definition":
                        is_async = True
                        break

                # Get function name
                for child in node.children:
                    if child.type == "identifier":
                        func_name = child_text(child)
                        break

                # Get parameters
                params = []
                for child in node.children:
                    if child.type == "parameters":
                        for param in child.children:
                            if param.type == "identifier":
                                params.append(child_text(param))

                # Get return type
                return_type = None
                for child in node.children:
                    if child.type == "return_type":
                        return_type = child_text(child)

                func = ParsedFunction(
                    name=func_name or "unknown",
                    file_path=file_path,
                    start_line=start_line,
                    end_line=end_line,
                    parameters=params,
                    return_type=return_type,
                    is_async=is_async,
                )
                functions.append(func)

            # Find class definitions
            elif node_type == "class_definition":
                class_name = ""
                start_line = node.start_point.row + 1
                end_line = node.end_point.row + 1

                for child in node.children:
                    if child.type == "class_name":
                        class_name = child_text(child)
                        break

                # Extract methods from the class
                methods: list[ParsedFunction] = []
                # Look for function_definition children within this class range
                for child in node.children:
                    if child.type == "function_definition":
                        func_name = ""
                        func_start = child.start_point.row + 1
                        func_end = child.end_point.row + 1

                        for gc in child.children:
                            if gc.type == "identifier":
                                func_name = child_text(gc)
                                break

                        params = []
                        for gc2 in child.children:
                            if gc2.type == "parameters":
                                for gc3 in gc2.children:
                                    if gc3.type == "identifier":
                                        params.append(child_text(gc3))

                        ret_type = None
                        for gc2 in child.children:
                            if gc2.type == "return_type":
                                ret_type = child_text(gc2)

                        func = ParsedFunction(
                            name=func_name or "unknown",
                            file_path=file_path,
                            start_line=func_start,
                            end_line=func_end,
                            parameters=params,
                            return_type=ret_type,
                            is_async=False,
                        )
                        methods.append(func)

                cls = ParsedClass(
                    name=class_name or "UnknownClass",
                    file_path=file_path,
                    start_line=start_line,
                    end_line=end_line,
                    methods=methods,
                )
                classes.append(cls)

            # Find import statements
            elif node_type == "import_statement" or node_type == "import_from":
                import_name = ""
                import_alias = None
                is_wildcard = False

                for child in node.children:
                    if child.type == "dotted_name":
                        import_name = child_text(child)
                    elif child.type == "as_name":
                        import_alias = child_text(child)
                    elif child.type == "star":
                        is_wildcard = True

                # Only add if we have a meaningful import name
                if import_name:
                    imp = ParsedImport(
                        name=import_name,
                        alias=import_alias,
                        line=node.start_point.row + 1,
                        is_wildcard=is_wildcard,
                    )
                    imports.append(imp)

            # Recurse into children
            for child in node.children:
                walk_node(child, depth + 1)

        walk_node(root_node)

        # Also extract API endpoints from decorator patterns
        api_endpoints = _extract_python_api_endpoints(source_code)

        return SourceCodeContext(
            file_path=file_path,
            language="python",
            functions=functions,
            classes=classes,
            imports=imports,
            api_endpoints=api_endpoints,
        )

    except Exception as e:
        logger.error("Error parsing Python source %s: %s", file_path, e)
        return _fallback_python_parse(source_code, file_path)


def parse_java_source(
    source_code: str,
    file_path: str = "<unknown>",
) -> SourceCodeContext:
    """Parse Java source code using Tree-sitter and extract structural elements.

    Args:
        source_code: Java source code string
        file_path: Path to the source file (for error reporting)

    Returns:
        SourceCodeContext with extracted methods, classes, imports, and endpoints
    """
    if not TREE_SITTER_AVAILABLE:
        logger.warning("Tree-sitter not available — returning fallback context")
        return _fallback_java_parse(source_code, file_path)

    java_lang = load_java_language()
    if java_lang is None:
        return _fallback_java_parse(source_code, file_path)

    parser = get_parser()
    if parser is None:
        return _fallback_java_parse(source_code, file_path)

    try:
        # Parse the source code
        tree = parser.parse(bytes(source_code, "utf-8"))
        root_node = tree.root_node

        methods: list[ParsedFunction] = []
        classes: list[ParsedClass] = []
        imports: list[ParsedImport] = []

        # Collect all method names and locations
        method_pattern = re.compile(r"public\s+(?:static\s+)?(?:\s+\w+(?:\s+<[^>]+>)?\s+)?(\w+)\s*\(([^)]*)\)\s*\{")

        def walk_node(node: Node):
            if node is None:
                return

            node_type = node.type

            # Find method definitions
            if node_type == "method_declaration":
                method_name = ""
                start_line = node.start_point.row + 1
                end_line = node.end_point.row + 1
                parameters = []

                # Get method name
                for child in node.children:
                    if child.type == "identifier":
                        method_name = child_text(child)
                        break

                # Get parameters
                for child in node.children:
                    if child.type == "formal_parameters":
                        for param in child.children:
                            if param.type == "identifier":
                                parameters.append(child_text(param))

                methods.append(ParsedFunction(
                    name=method_name or "unknown",
                    file_path=file_path,
                    start_line=start_line,
                    end_line=end_line,
                    parameters=parameters,
                    is_async=False,
                ))

            # Find class definitions
            elif node_type == "class_declaration":
                class_name = ""
                start_line = node.start_point.row + 1
                end_line = node.end_point.row + 1
                implements: list[str] = []

                for child in node.children:
                    if child.type == "identifier":
                        class_name = child_text(child)
                    elif child.type == "implements_clause":
                        # Extract interface names
                        for impl_child in child.children:
                            if impl_child.type == "identifier":
                                implements.append(child_text(impl_child))

                cls = ParsedClass(
                    name=class_name or "UnknownClass",
                    file_path=file_path,
                    start_line=start_line,
                    end_line=end_line,
                    implements=implements,
                )
                classes.append(cls)

            # Find import statements
            elif node_type == "import_declaration":
                import_name = ""
                for child in node.children:
                    if child.type == "qualified_name":
                        import_name = child_text(child)
                        break

                if import_name:
                    imp = ParsedImport(
                        name=import_name,
                        line=node.start_point.row + 1,
                    )
                    imports.append(imp)

            # Recurse into children
            for child in node.children:
                walk_node(child)

        walk_node(root_node)

        # Extract API endpoints from annotations
        api_endpoints = _extract_java_api_endpoints(source_code)

        return SourceCodeContext(
            file_path=file_path,
            language="java",
            functions=methods,
            classes=classes,
            imports=imports,
            api_endpoints=api_endpoints,
        )

    except Exception as e:
        logger.error("Error parsing Java source %s: %s", file_path, e)
        return _fallback_java_parse(source_code, file_path)


def child_text(node: Node) -> str:
    """Get text content from a Tree-sitter node."""
    try:
        return node.text.decode("utf-8") if node.text else ""
    except Exception:
        return ""


def child_text_from_range(node: Node, start_row: int, end_row: int) -> str:
    """Extract text from a node within a row range."""
    try:
        # Tree-sitter rows are 0-indexed
        text = node.text.decode("utf-8") if node.text else ""
        lines = text.split("\n")
        # Return relevant lines
        relevant = []
        for i, line in enumerate(lines):
            if start_row <= i <= end_row:
                relevant.append(line)
        return "\n".join(relevant)
    except Exception:
        return ""


def _extract_python_api_endpoints(source_code: str) -> Dict[str, dict]:
    """Extract API endpoint mappings from Python source code.

    Looks for Flask/FastAPI decorator patterns to map routes to handler functions.
    """
    endpoints: Dict[str, dict] = {}

    # Common patterns for route definitions
    patterns = [
        # Flask @app.route
        (r'@app\.(get|post|put|delete|patch)\(["\']([^"\']+)["\']', "flask_app"),
        # Flask @router.route
        (r'@router\.(get|post|put|delete|patch)\(["\']([^"\']+)["\']', "flask_router"),
        # FastAPI @app.get/post etc.
        (r'@app\.(get|post|put|delete|patch)\(["\']([^"\']+)["\']', "fastapi_app"),
        # FastAPI @router.get/post etc.
        (r'@router\.(get|post|put|delete|patch)\(["\']([^"\']+)["\']', "fastapi_router"),
        # Function definition with route-like naming
        (r'def\s+(\w+)\s*\([^)]*\):\s*\s*["\']([^"\']+)["\']', "function_route"),
    ]

    for pattern, pattern_type in patterns:
        for match in re.finditer(pattern, source_code, re.MULTILINE):
            try:
                method = match.group(1) if len(match.groups()) >= 1 else "GET"
                route = match.group(2) if len(match.groups()) >= 2 else match.group(1)

                # Get the line number
                line_match = source_code[:match.start()].count("\n") + 1

                endpoints[route] = {
                    "handler": route,
                    "file": "<source>",
                    "method": method.upper(),
                    "line": line_match,
                    "type": pattern_type,
                }
            except Exception:
                continue

    return endpoints


def _extract_java_api_endpoints(source_code: str) -> Dict[str, dict]:
    """Extract API endpoint mappings from Java source code.

    Looks for Spring MVC annotation patterns.
    """
    endpoints: Dict[str, dict] = []

    # Spring MVC annotations
    annotation_patterns = [
        r'@(Get|Post|Put|Delete|Patch)Mapping\(value\s*=\s*["\']([^"\']+)["\']',
        r'@RequestMapping\(value\s*=\s*["\']([^"\']+)["\']',
    ]

    for pattern in annotation_patterns:
        for match in re.finditer(pattern, source_code):
            try:
                method = match.group(1) if len(match.groups()) >= 1 else "GET"
                route = match.group(2) if len(match.groups()) >= 2 else ""

                # Get the line number
                line_match = source_code[:match.start()].count("\n") + 1

                endpoints.append({
                    "route": route if route else "<inline>",
                    "method": method.upper(),
                    "line": line_match,
                })
            except Exception:
                continue

    # Convert list to dict keyed by route
    result: Dict[str, dict] = {}
    for ep in endpoints:
        route = ep["route"] if ep["route"] else f"line_{ep['line']}"
        result[route] = {
            "method": ep["method"],
            "line": ep["line"],
        }

    return result


def _fallback_python_parse(
    source_code: str,
    file_path: str,
) -> SourceCodeContext:
    """Fallback Python parser using regex when Tree-sitter is unavailable."""
    logger.info("Using fallback regex parser for Python %s", file_path)

    functions: list[ParsedFunction] = []
    classes: list[ParsedClass] = []
    imports: list[ParsedImport] = []

    # Extract function definitions
    func_pattern = r'def\s+(\w+)\s*\(([^)]*)\)\s*->?\s*\w*'
    for match in re.finditer(func_pattern, source_code):
        func_name = match.group(1)
        params_str = match.group(2)
        params = [p.strip() for p in params_str.split(",") if p.strip()]
        line_num = source_code[:match.start()].count("\n") + 1

        functions.append(ParsedFunction(
            name=func_name,
            file_path=file_path,
            start_line=line_num,
            end_line=line_num,
            parameters=params,
        ))

    # Extract class definitions
    class_pattern = r'class\s+(\w+)'
    for match in re.finditer(class_pattern, source_code):
        class_name = match.group(1)
        line_num = source_code[:match.start()].count("\n") + 1

        # Find methods within this class (simple heuristic)
        methods: list[ParsedFunction] = []
        # Look for def statements after the class keyword
        class_start = match.start()
        class_end = match.end()
        after_class = source_code[class_end:]

        method_matches = re.finditer(r'def\s+(\w+)\s*\(', after_class)
        for m2 in method_matches:
            m2_name = m2.group(1)
            # Adjust line number
            rel_pos = m2.start()
            actual_line = after_class[:rel_pos].count("\n") + line_num + 1
            methods.append(ParsedFunction(
                name=m2_name,
                file_path=file_path,
                start_line=actual_line,
                end_line=actual_line,
                parameters=[],
            ))

        cls = ParsedClass(
            name=class_name,
            file_path=file_path,
            start_line=line_num,
            end_line=line_num + len(methods),
            methods=methods,
        )
        classes.append(cls)

    # Extract imports
    import_pattern = r'^(?:from\s+(\S+)\s+import|import\s+(\S+))'
    for match in re.finditer(import_pattern, source_code, re.MULTILINE):
        module = match.group(1) or match.group(2)
        # Skip built-ins and common standard library
        if module and module not in ("os", "sys", "json", "pickle", "base64", "math"):
            line_num = source_code[:match.start()].count("\n") + 1
            imports.append(ParsedImport(
                name=module,
                line=line_num,
            ))

    # Extract API endpoints
    api_endpoints = _extract_python_api_endpoints(source_code)

    return SourceCodeContext(
        file_path=file_path,
        language="python",
        functions=functions,
        classes=classes,
        imports=imports,
        api_endpoints=api_endpoints,
    )


def _fallback_java_parse(
    source_code: str,
    file_path: str,
) -> SourceCodeContext:
    """Fallback Java parser using regex when Tree-sitter is unavailable."""
    logger.info("Using fallback regex parser for Java %s", file_path)

    methods: list[ParsedFunction] = []
    classes: list[ParsedClass] = []
    imports: list[ParsedImport] = []

    # Extract method definitions
    method_pattern = r'(?:public|private|protected)?\s*(?:static\s+)?(?:\s+\w+(?:\s+<[^>]+>)?\s+)?(\w+)\s*\([^)]*\)'
    for match in re.finditer(method_pattern, source_code):
        method_name = match.group(1)
        line_num = source_code[:match.start()].count("\n") + 1

        methods.append(ParsedFunction(
            name=method_name,
            file_path=file_path,
            start_line=line_num,
            end_line=line_num,
            parameters=[],
        ))

    # Extract class definitions
    class_pattern = r'class\s+(\w+)(?:\s+extends\s+\w+)?(?:\s+implements\s+[\w\s<>]+)?'
    for match in re.finditer(class_pattern, source_code):
        class_name = match.group(1)
        line_num = source_code[:match.start()].count("\n") + 1

        # Find methods within this class range
        class_start = match.start()
        class_end = match.end()
        after_class = source_code[class_end:]

        # Count methods in the class by looking for the next class or end
        method_count = len(re.findall(r'(?:public|private|protected|\s)\s*\w+\s*\(', after_class))

        cls = ParsedClass(
            name=class_name,
            file_path=file_path,
            start_line=line_num,
            end_line=line_num + method_count,
            methods=methods,
        )
        classes.append(cls)

    # Extract imports
    import_pattern = r'import\s+([^;]+);'
    for match in re.finditer(import_pattern, source_code):
        module = match.group(1).strip()
        if module and not module.startswith("java.") and not module.startswith("javax."):
            line_num = source_code[:match.start()].count("\n") + 1
            imports.append(ParsedImport(
                name=module,
                line=line_num,
            ))

    # Extract API endpoints
    api_endpoints = _extract_java_api_endpoints(source_code)

    return SourceCodeContext(
        file_path=file_path,
        language="java",
        functions=methods,
        classes=classes,
        imports=imports,
        api_endpoints=api_endpoints,
    )