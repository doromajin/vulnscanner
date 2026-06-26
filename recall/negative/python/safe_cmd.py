"""Negative: safe command execution patterns — must produce zero active findings."""
import os
import subprocess

# String literals are CLEAN — AST suppresses via clean_taint_source
os.system("git status")
os.system("ls -la /tmp")

# subprocess without shell=True has no shell injection vector
subprocess.run(["git", "status"])
subprocess.call(["ls", "-la"])
subprocess.run(["ping", "-c", "1", "localhost"], check=True)
subprocess.check_output(["whoami"])
