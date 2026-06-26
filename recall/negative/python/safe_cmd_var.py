"""Negative: subprocess with list args — shell=False by default, no injection vector.

Even when list elements contain user-controlled values, the OS exec() family
never invokes a shell interpreter, so argument boundaries cannot be escaped.
AST-CMD-002 requires shell=True; CMD-002 regex matches shell=True — neither fires.
"""
import subprocess


def clone_repo(url: str) -> None:
    # Variable in list args: no shell=True → no injection vector
    subprocess.run(["git", "clone", url, "/tmp/repo"], check=True)


def fetch_updates(repo_path: str) -> str:
    # Variable path in list — still shell-safe
    result = subprocess.run(
        ["git", "-C", repo_path, "fetch", "--all"],
        capture_output=True,
        text=True,
    )
    return result.stdout


def run_tests(project_dir: str) -> int:
    # subprocess.Popen with list, no shell=True
    proc = subprocess.Popen(
        ["python", "-m", "pytest", project_dir, "-q"],
        stdout=subprocess.PIPE,
    )
    proc.wait()
    return proc.returncode
