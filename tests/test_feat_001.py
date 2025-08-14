import sys
import subprocess


def run_cli(args=None):
    cmd = [sys.executable, "-m", "your_package"]
    if args:
        cmd.extend(args)
    return subprocess.run(cmd, capture_output=True, text=True)


def test_default_greeting():
    res = run_cli()
    assert res.returncode == 0
    assert res.stdout.strip() == "Hello, world!"


def test_greet_flag():
    res = run_cli(["--greet", "Alice"])
    assert res.returncode == 0
    assert res.stdout.strip() == "Hello, Alice!"
