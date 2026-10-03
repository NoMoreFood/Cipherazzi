import argparse
import json
import subprocess
import sys
import time
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--configuration', required=True)
    parser.add_argument('--detach', action='store_true')
    parser.add_argument('--hold', action='store_true')
    args = parser.parse_args()
    configuration = json.loads(Path(args.configuration).read_text())
    children = [subprocess.Popen(command, stdin=subprocess.PIPE if 'input' in configuration else None,
        creationflags=subprocess.CREATE_NO_WINDOW)
        for command in configuration['commands']]
    if 'input' in configuration:
        for child in children:
            child.communicate(configuration['input'].encode(), timeout=25)
            assert child.returncode == 0, 'The configured child exchange failed'
    if configuration.get('nested'):
        children.append(subprocess.Popen([sys.executable, __file__, '--configuration', configuration['nested'],
            '--hold'], creationflags=subprocess.CREATE_NO_WINDOW))
    Path(configuration['pids']).write_text(json.dumps([child.pid for child in children]))
    if not args.detach and not args.hold:
        return
    gate = Path(configuration['release'])
    deadline = time.monotonic() + 25
    while not gate.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert gate.exists(), 'Parent was not released after observation stopped'
    assert all(child.wait(15) == 0 for child in children), 'TLS worker failed after detachment'
    if args.detach or configuration.get('observe_late'):
        late = subprocess.Popen(configuration['late'], creationflags=subprocess.CREATE_NO_WINDOW)
        Path(configuration['pids']).write_text(json.dumps([child.pid for child in children] + [late.pid]))
        assert late.wait(15) == 0, 'A worker started after release failed'
    Path(configuration['finished']).write_text('All children completed')


if __name__ == '__main__':
    main()
