import os
import subprocess
from flask import request


def run(req):
    cmd = req.args.get("cmd")

    # AST-CMD-001: HIGH — os.system() with tainted input
    os.system(cmd)

    # AST-CMD-002: HIGH — subprocess with shell=True and tainted input
    subprocess.Popen(cmd, shell=True)
