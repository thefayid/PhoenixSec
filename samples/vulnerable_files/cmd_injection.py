# Intentionally vulnerable Python file for testing Command Injection
import os
import subprocess


def run_diagnostic(request):
    # Retrieve user input
    target_host = request.GET.get('host')

    # Vulnerable: string concatenation with shell execution
    command = "ping -c 1 " + target_host
    os.system(command)

def run_nslookup(request):
    domain = request.GET.get('domain')

    # Vulnerable: string concatenation with shell=True execution sink
    subprocess.run("nslookup " + domain, shell=True)
