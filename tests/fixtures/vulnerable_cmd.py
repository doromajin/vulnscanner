# Intentionally vulnerable code for testing — do NOT deploy
import os
import subprocess


def ping_host_bad(host):
    os.system("ping " + host)           # CMD-001


def run_cmd_bad(cmd):
    subprocess.run(cmd, shell=True)     # CMD-002


def eval_input_bad(user_code):
    eval(user_code)                     # CMD-004


def ping_host_safe(host):
    subprocess.run(["ping", host])      # safe — list form, no shell
