from vulnscanner.analyzers.ast_python import PythonASTAnalyzer
from vulnscanner.analyzers.base import BaseAnalyzer
from vulnscanner.analyzers.command_injection import CommandInjectionAnalyzer
from vulnscanner.analyzers.hardcoded_secrets import HardcodedSecretsAnalyzer
from vulnscanner.analyzers.path_traversal import PathTraversalAnalyzer
from vulnscanner.analyzers.sql_injection import SQLInjectionAnalyzer
from vulnscanner.analyzers.xss import XSSAnalyzer

ALL_ANALYZERS: list[BaseAnalyzer] = [
    # Python: AST-based (high precision, replaces regex for .py)
    PythonASTAnalyzer(),
    # Other languages: regex-based
    SQLInjectionAnalyzer(),
    XSSAnalyzer(),
    CommandInjectionAnalyzer(),
    PathTraversalAnalyzer(),
    # Runs on all languages including .py (for SEC-004/005/007 content patterns)
    HardcodedSecretsAnalyzer(),
]
