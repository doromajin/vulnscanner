"""Shared evidence check: does a PHP file read request-derived input at all?

Used to lower the severity of "dynamic value reaches a sink" regex rules in files that
never touch request data (configuration helpers, installers, internal utilities).
"""
import re

# Superglobals carrying client data, request objects (Laravel, Symfony, PSR-7, CakePHP),
# CLI argv and the raw body.  $_SERVER keys that the web server derives from its own
# configuration (SCRIPT_NAME, DOCUMENT_ROOT …) do not count; HTTP_*, REQUEST_URI, PHP_SELF
# and dynamic keys do.
PHP_REQUEST_INPUT_RE = re.compile(
    r'\$_(?:GET|POST|REQUEST|COOKIE|FILES)\b'
    r'|\$_SERVER\s*\[\s*[\'"](?!SCRIPT_NAME|SCRIPT_FILENAME|DOCUMENT_ROOT|SERVER_SOFTWARE)'
    r'|\$_SERVER\s*\[\s*[^\'"\s\]]'
    r'|\$argv\b'
    r'|\$(?:this->)?request\b|\bRequest::|\bgetRequest\s*\(|\brequest\s*\(\s*\)'
    r'|php://input|\bgetallheaders\s*\(',
    re.IGNORECASE,
)


def has_request_input(content: str) -> bool:
    return bool(PHP_REQUEST_INPUT_RE.search(content))
