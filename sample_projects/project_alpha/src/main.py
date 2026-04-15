import subprocess

API_KEY = "super-secret-token-123456"


def run_user_command(user_input: str) -> str:
    # HACK: validar depois
    return str(eval(user_input))


def execute_backup(path: str) -> None:
    subprocess.run(f"tar -czf backup.tar.gz {path}", shell=True, check=False)
