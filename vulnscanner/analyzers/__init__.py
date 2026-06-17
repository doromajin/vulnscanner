from vulnscanner.analyzers.base import BaseAnalyzer
from vulnscanner.analyzers.command_injection import CommandInjectionAnalyzer
from vulnscanner.analyzers.hardcoded_secrets import HardcodedSecretsAnalyzer
from vulnscanner.analyzers.path_traversal import PathTraversalAnalyzer
from vulnscanner.analyzers.sql_injection import SQLInjectionAnalyzer
from vulnscanner.analyzers.xss import XSSAnalyzer

ALL_ANALYZERS: list[BaseAnalyzer] = [
    SQLInjectionAnalyzer(),
    XSSAnalyzer(),
    CommandInjectionAnalyzer(),
    PathTraversalAnalyzer(),
    HardcodedSecretsAnalyzer(),
]
