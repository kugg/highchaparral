import subprocess


def candidate(command):
    # ruleid: highchaparral.python.dynamic-shell-command
    subprocess.run(command, shell=True)
    # ok: highchaparral.python.dynamic-shell-command
    subprocess.run(["printf", "%s", command], check=True)
