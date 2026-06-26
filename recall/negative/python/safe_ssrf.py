"""Negative: HTTP requests to literal hard-coded URLs — must not produce SSRF findings."""
import requests

# Direct literal URLs — AST resolves to CLEAN immediately
response = requests.get("https://api.github.com/repos/owner/repo")
response = requests.post("https://internal.service.example.com/health")
response = requests.get("http://localhost:8080/status")
