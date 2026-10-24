"""Safety modules must remain inert until explicitly called."""

import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class SafetyImportTests(unittest.TestCase):
    def test_all_safety_imports_under_preimport_effect_guard(self):
        script = r'''
import os
from pathlib import Path
import sys
import sysconfig

source = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(source))
reads = (source, *(Path(sysconfig.get_path(key)).resolve()
                  for key in ('stdlib', 'platstdlib')))
attempts = []

def guard(event, args):
    if event == 'open':
        path, mode, flags = args
        write = any(c in (mode or '') for c in 'wax+') or bool(
            (flags or 0) & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC))
        if isinstance(path, int) or write or not any(
            Path(path).resolve().is_relative_to(root) for root in reads):
            attempts.append(event)
            raise PermissionError('IO denied')
    if event.startswith('socket.') or event in {
        'subprocess.Popen', 'os.system', 'os.posix_spawn', 'os.fork',
        'os.remove', 'os.rename', 'os.rmdir', 'os.mkdir', 'os.symlink',
        'os.link', 'os.truncate', 'os.chmod', 'os.chown',
    }:
        attempts.append(event)
        raise PermissionError('effect denied')

sys.addaudithook(guard)
for action in (lambda: os.mkdir('/AD02-positive-control'),
               lambda: os.system('AD02-positive-control')):
    try:
        action()
    except PermissionError:
        pass
    else:
        raise AssertionError('guard did not deny effect')
assert len(attempts) == 2
attempts.clear()
import autodev.contracts
import autodev.safety.storage
import autodev.safety.locks
import autodev.safety.journal
import autodev.safety.runner
import autodev.safety.git_read
assert not attempts, 'import attempted effects'
print('safety imports: no effects')
'''
        result = subprocess.run(
            [sys.executable, "-B", "-c", script, str(ROOT / "src")],
            env={"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"},
            cwd=ROOT, capture_output=True, text=True, timeout=15, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "safety imports: no effects")
