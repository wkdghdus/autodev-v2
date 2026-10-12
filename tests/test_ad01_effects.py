"""Contract imports must remain offline before any application code loads."""

from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]


class ContractEffectTests(unittest.TestCase):
    def test_import_under_preimport_effect_guard(self):
        script = r'''
import os
from pathlib import Path
import sys
import sysconfig

src = Path(sys.argv[1]).resolve()
allowed_reads = (src, *(
    Path(sysconfig.get_path(name)).resolve()
    for name in ('stdlib', 'platstdlib')
))
sys.path.insert(0, str(src))
attempts = []

def guard(event, args):
    if event == 'open':
        path, mode, flags = args
        if isinstance(path, int):
            attempts.append('descriptor IO')
            raise PermissionError('descriptor IO denied')
        write = any(c in (mode or '') for c in 'wax+') or bool(
            (flags or 0) & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC)
        )
        resolved = Path(path).resolve()
        if write or not any(resolved.is_relative_to(root) for root in allowed_reads):
            attempts.append('filesystem effect')
            raise PermissionError('filesystem effect denied')
    if event.startswith('socket.') or event in {
        'subprocess.Popen', 'os.system', 'os.posix_spawn', 'os.fork',
        'os.remove', 'os.rename', 'os.rmdir', 'os.mkdir', 'os.symlink',
        'os.link', 'os.truncate', 'os.chmod', 'os.chown',
    }:
        attempts.append('external effect')
        raise PermissionError('external effect denied')

sys.addaudithook(guard)
for action in (
    lambda: os.mkdir('/AD01-guard-positive-control'),
    lambda: open('/AD01-guard-positive-control', 'w'),
    lambda: open('/AD01-guard-positive-control', 'r'),
    lambda: os.system('AD01-guard-positive-control'),
):
    try:
        action()
    except PermissionError:
        pass
    else:
        raise AssertionError('effect guard failed positive control')
assert len(attempts) == 4
attempts.clear()
import autodev.contracts
from autodev.contracts import (
    load_execution_yaml, load_project_yaml, parse_yaml_subset,
    preview_v1_migration, validate_change_plan,
)
assert parse_yaml_subset('name: "hello!"')['name'] == 'hello!'
project = load_project_yaml(sys.argv[2])
index = load_execution_yaml(sys.argv[3], project)
assert index.project_id == project.project_id
preview = preview_v1_migration(b'schema_version: 1\nprovider: github\n')
assert preview.applicable is False and preview.writes_performed is False
assert validate_change_plan({'kind': 'repair', 'schema_version': 1, 'plan_id': 'p'}).reason == 'UNSUPPORTED'
assert not attempts, 'application attempted effects'
print('contract import: no effects')
'''
        result = subprocess.run(
            [
                sys.executable, "-B", "-c", script, str(ROOT / "src"),
                (ROOT / "fixtures/AD-01/project-configured.yaml").read_text(),
                (ROOT / "fixtures/AD-01/execution.yaml").read_text(),
            ],
            cwd=ROOT,
            env={"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"},
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "contract import: no effects")
