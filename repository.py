import subprocess


def get_head():
    return subprocess.check_output(["git", "describe", "--always"]).decode().strip()


def fetch():
    subprocess.run(['git', 'fetch'], check=True)
    labels = subprocess.check_output(['git', 'describe', '--always', 'HEAD', 'FETCH_HEAD']).decode().strip().split()
    return {'head': labels[0], 'fetch_head': labels[1]}


def pull():
    subprocess.run(['git', 'pull'], check=True)
