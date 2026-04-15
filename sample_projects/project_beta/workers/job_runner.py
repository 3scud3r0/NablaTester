import subprocess


def run_task(task_name: str) -> None:
    command = f"python jobs/{task_name}.py"
    subprocess.Popen(command, shell=True)
