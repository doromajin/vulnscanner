from vulnscanner.analyzers.ast_php import PhpASTAnalyzer
from vulnscanner.analyzers.ast_python import PythonASTAnalyzer
from vulnscanner.analyzers.base import BaseAnalyzer
from vulnscanner.analyzers.client_side import ClientSideAnalyzer
from vulnscanner.analyzers.command_injection import CommandInjectionAnalyzer
from vulnscanner.analyzers.dependencies import DependencyAnalyzer
from vulnscanner.analyzers.deserialization import DeserializationAnalyzer
from vulnscanner.analyzers.go_analyzer import GoAnalyzer
from vulnscanner.analyzers.hardcoded_secrets import HardcodedSecretsAnalyzer
from vulnscanner.analyzers.java_analyzer import JavaAnalyzer
from vulnscanner.analyzers.open_redirect import OpenRedirectAnalyzer
from vulnscanner.analyzers.path_traversal import PathTraversalAnalyzer
from vulnscanner.analyzers.prototype_pollution import PrototypePollutionAnalyzer
from vulnscanner.analyzers.sql_injection import SQLInjectionAnalyzer
from vulnscanner.analyzers.ssrf import SSRFAnalyzer
from vulnscanner.analyzers.ssti import SSTIAnalyzer
from vulnscanner.analyzers.xss import XSSAnalyzer

ALL_ANALYZERS: list[BaseAnalyzer] = [
    # Python: AST-based (high precision, covers SQL/CMD/PATH/XSS/DESER/SSRF/REDIR/SSTI)
    PythonASTAnalyzer(),
    # Multi-language: regex-based
    SQLInjectionAnalyzer(),
    XSSAnalyzer(),
    # PHP: AST-based multi-hop XSS taint (2-hop, null-coalescing, function propagation)
    PhpASTAnalyzer(),
    CommandInjectionAnalyzer(),
    PathTraversalAnalyzer(),
    DeserializationAnalyzer(),
    SSRFAnalyzer(),
    OpenRedirectAnalyzer(),
    SSTIAnalyzer(),
    PrototypePollutionAnalyzer(),
    # Browser-specific patterns (localStorage, SRI, postMessage, client-side SSRF)
    ClientSideAnalyzer(),
    # Runs on all languages including .py (for SEC-004/005/007 content patterns)
    HardcodedSecretsAnalyzer(),
    # Checks dependency manifests against OSV.dev CVE database
    DependencyAnalyzer(),
    # Language-specific analyzers
    JavaAnalyzer(),
    GoAnalyzer(),
]
