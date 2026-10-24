"""Explicit, recoverable application of an exact init proposal.

The private manifest is durable before any alignment edit. Preview inspection
never constructs storage or locks. Multi-file atomicity is not claimed.
"""
from __future__ import annotations

import base64
import os
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from autodev.evidence import sha256_bytes
from autodev.safety.locks import repository_lock
from autodev.safety.repository_files import (FileSnapshot, checked_root,
                                            create_parent, directory_identity, planned_stage, publish,
                                            parent_descriptor,
                                            remove_owned_stage, remove_owned_target, remove_parent,
                                            snapshot, stage, target_path)
from autodev.safety.storage import SafeStore, canonical_json_bytes, decode_json
from autodev.safety.types import SafetyError


OWNER = 'autodev-init-v1'
STATE = '.agent/.init-state'
MAX_MANIFEST = 16 * 1024 * 1024
Checkpoint = Callable[[str, str | None], None]


@dataclass(frozen=True)
class ApplyResult:
    status: str
    diagnostics: tuple[str, ...] = ()
    alignment_changes: tuple[str, ...] = ()
    infrastructure_effects: tuple[str, ...] = ()

    @property
    def exit_code(self) -> int:
        return 0 if self.status in {'applied', 'noop', 'recovered', 'clean'} else (2 if self.status in {
            'stale_proposal', 'needs_input', 'bootstrap_recovery_required'} else 1)

    def to_dict(self) -> dict[str, Any]:
        return {'status': self.status, 'diagnostics': list(self.diagnostics),
                'alignment_changes': list(self.alignment_changes),
                'infrastructure_effects': list(self.infrastructure_effects), 'exit_code': self.exit_code}


def _read_json(path: Path, *, parent: int | None = None) -> Any:
    info = path.lstat() if parent is None else os.stat(path.name, dir_fd=parent, follow_symlinks=False)
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid()
            or info.st_mode & 0o077 or info.st_size > MAX_MANIFEST):
        raise ValueError('unsafe private record')
    fd = os.open(path if parent is None else path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
    try:
        with os.fdopen(fd, 'rb', closefd=False) as handle:
            data = handle.read(MAX_MANIFEST + 1)
        if len(data) > MAX_MANIFEST:
            raise ValueError('private record exceeds bound')
        return decode_json(data)
    finally:
        os.close(fd)


def _owner(root: Path) -> dict[str, Any]:
    return {'schema_version': 1, 'owner': OWNER, 'repository_root': str(root)}


def _state_valid(root: Path) -> bool:
    with parent_descriptor(root, '.agent/owner.json') as (agent, _name):
        state = os.open('.init-state', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=agent)
        try:
            info = os.fstat(state)
            if info.st_uid != os.getuid() or info.st_mode & 0o077:
                return False
            return _read_json(Path('owner.json'), parent=state) == _owner(root)
        finally:
            os.close(state)


def _decoded(value: str | None) -> bytes | None:
    return None if value is None else base64.b64decode(value, validate=True)


def _manifest(root: Path) -> dict[str, Any] | None:
    path = root / STATE / 'transaction.json'
    if not path.exists() and not path.is_symlink():
        return None
    record = _read_json(path)
    if (not isinstance(record, dict) or record.get('schema_version') != 1
            or record.get('owner') != _owner(root) or record.get('phase') not in {
                'prepared', 'committed', 'rolled_back', 'recovery_required'}
            or not isinstance(record.get('operations'), list) or len(record['operations']) > 200
            or not isinstance(record.get('parents'), list)):
        raise ValueError('invalid transaction manifest')
    seen = set()
    for item in record['operations']:
        target_path(root, item['path'], missing_parents=True)
        if item['path'] in seen:
            raise ValueError('duplicate transaction path')
        seen.add(item['path'])
        for key in ('original', 'proposed'):
            data = _decoded(item[key])
            if (data is None and key == 'proposed') or (data is not None and len(data) > 128 * 1024):
                raise ValueError('invalid transaction bytes')
            if item[key + '_sha256'] != (None if data is None else sha256_bytes(data)):
                raise ValueError('transaction hash mismatch')
        if type(item['mode']) is not int or not 0 <= item['mode'] <= 0o7777:
            raise ValueError('invalid file mode')
        for key in ('original_inode', 'published_inode', 'restored_inode'):
            identity = item.get(key)
            if identity is not None and (not isinstance(identity, list) or len(identity) != 2
                                        or any(type(n) is not int or n < 0 for n in identity)):
                raise ValueError('invalid inode identity')
        for key in ('staging', 'restore_staging'):
            if item.get(key):
                temporary = target_path(root, item[key], missing_parents=True)
                if temporary.parent != (root / item['path']).parent or not temporary.name.startswith('.autodev-init-'):
                    raise ValueError('invalid staging path')
    for parent in record['parents']:
        target_path(root, parent['path'], missing_parents=True)
    return record


def inspect_recovery(root: Path | str) -> dict[str, Any]:
    """Read-only bounded pending-state inventory, including an unowned bootstrap."""
    try:
        root = checked_root(root)
        path = root / STATE
        # Never follow a linked .agent component while inspecting state.
        if (root / '.agent').is_symlink():
            return {'status': 'bootstrap_recovery_required', 'diagnostics': ['linked .agent parent'], 'operations': []}
        if not path.exists() and not path.is_symlink():
            return {'status': 'clean', 'diagnostics': [], 'operations': []}
        if not _state_valid(root):
            raise ValueError('private state owner is absent, unsafe, malformed, or foreign')
        record = _manifest(root)
        pending = record is not None and record['phase'] not in {'committed', 'rolled_back'}
        return {'status': 'recovery_required' if pending else 'clean', 'diagnostics': [],
                'operations': [] if not pending else [
                    {'path': item['path'], 'original_sha256': item['original_sha256'],
                     'proposed_sha256': item['proposed_sha256']} for item in record['operations']]}
    except (OSError, ValueError, KeyError, TypeError, SafetyError):
        return {'status': 'bootstrap_recovery_required', 'diagnostics': ['private_state_untrusted'], 'operations': []}


def _bootstrap(root: Path, checkpoint: Checkpoint | None, effects: list[str]) -> SafeStore:
    with parent_descriptor(root, '.agent') as (repository, name):
        try:
            os.mkdir(name, mode=0o755, dir_fd=repository)
            effects.append('.agent/')
            os.fsync(repository)
        except FileExistsError:
            pass
        agent = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=repository)
        try:
            created = False
            try:
                os.mkdir('.init-state', mode=0o700, dir_fd=agent)
                created = True
                effects.append(STATE + '/')
                os.fsync(agent)
            except FileExistsError:
                pass
            if created:
                state = os.open('.init-state', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=agent)
                try:
                    _point(checkpoint, 'bootstrap_directory')
                    fd = os.open('owner.json', os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW,
                                 0o600, dir_fd=state)
                    try:
                        with os.fdopen(fd, 'wb', closefd=False) as handle:
                            handle.write(canonical_json_bytes(_owner(root)))
                            handle.flush()
                            os.fsync(fd)
                    finally:
                        os.close(fd)
                    os.fsync(state)
                    effects.append(STATE + '/owner.json')
                finally:
                    os.close(state)
            else:
                # A live creator gets a short bounded window to publish its owner.
                deadline = time.monotonic() + 0.25
                while time.monotonic() < deadline:
                    try:
                        if _state_valid(root):
                            break
                    except (OSError, ValueError):
                        pass
                    time.sleep(0.01)
        finally:
            os.close(agent)
    if not _state_valid(root):
        raise ValueError('bootstrap_recovery_required: private state cannot be adopted')
    return SafeStore(root / STATE)


def _save(store: SafeStore, record: dict[str, Any]) -> None:
    # SafeStore's durable owned-record primitive; no repository YAML uses it.
    store._intent(store.resolve('transaction.json'), record)


def _point(checkpoint: Checkpoint | None, label: str, path: str | None = None) -> None:
    if checkpoint:
        checkpoint(label, path)


def _rollback(root: Path, store: SafeStore, record: dict[str, Any], checkpoint: Checkpoint | None = None) -> list[str]:
    conflicts = []
    for item in reversed(record['operations']):
        try:
            original, proposed = _decoded(item['original']), _decoded(item['proposed'])
            published = None if item['published_inode'] is None else tuple(item['published_inode'])
            restored = None if item.get('restored_inode') is None else tuple(item['restored_inode'])
            before = None if item['original_inode'] is None else tuple(item['original_inode'])
            uncertain_stage = False
            for key, identity in (('staging', published), ('restore_staging', restored)):
                if item.get(key) and identity is None and snapshot(root, item[key]).data is not None:
                    uncertain_stage = True
            if uncertain_stage:
                conflicts.append(item['path'])
                continue
            # A crash between link publication and staging-name unlink can
            # leave two links to our inode. Drop only the recorded staging
            # name before enforcing the ordinary single-link target rule.
            remove_owned_stage(root, item.get('staging'), published, proposed)
            remove_owned_stage(root, item.get('restore_staging'), restored, original)
            current = snapshot(root, item['path'])
            if item.get('rolled_back'):
                continue
            if current.data == original and current.inode in {before, restored}:
                pass
            elif current.data == proposed and published is not None and current.inode == published:
                if original is None:
                    remove_owned_target(root, item['path'], current)
                else:
                    staging = planned_stage(item['path'])
                    item['restore_staging'], item['restored_inode'] = staging, None
                    _save(store, record)
                    staging, identity = stage(root, item['path'], original, item['mode'], staging=staging)
                    item['restore_staging'], item['restored_inode'] = staging, list(identity)
                    _save(store, record)
                    publish(root, item['path'], staging, current,
                            staged=FileSnapshot(original, item['mode'], identity))
                _point(checkpoint, 'after_restore', item['path'])
            else:
                conflicts.append(item['path'])
                continue
            item['rolled_back'] = True
            _save(store, record)
        except (OSError, ValueError, SafetyError):
            conflicts.append(item['path'])
    for parent in reversed(record['parents']):
        try:
            identity = directory_identity(root, parent['path'])
            if identity is not None:
                if parent['inode'] is None or list(identity) != parent['inode']:
                    conflicts.append(parent['path'])
                else:
                    remove_parent(root, parent['path'], identity)
        except FileNotFoundError:
            pass
        except (OSError, SafetyError):
            # Nonempty or externally replaced parents survive.
            conflicts.append(parent['path'])
    record['phase'] = 'recovery_required' if conflicts else 'rolled_back'
    _save(store, record)
    return conflicts


def apply_proposal(proposal: Any, *, expected_digest: str | None = None,
                   recompute: Callable[[], Any] | None = None,
                   checkpoint: Checkpoint | None = None,
                   verify: Callable[[], None] | None = None) -> ApplyResult:
    effects: list[str] = []
    changed: list[str] = []
    try:
        root = checked_root(proposal.root)
        if expected_digest is not None and expected_digest != proposal.digest:
            return ApplyResult('stale_proposal', ('reviewed proposal digest differs',))
        pending = inspect_recovery(root)
        if pending['status'] != 'clean':
            return ApplyResult(pending['status'], tuple(pending['diagnostics']))
        if proposal.status not in {'preview', 'noop', 'ready'}:
            return ApplyResult('needs_input', ('proposal is not applicable',))
        if not proposal.operations:
            return ApplyResult('noop')
        if recompute is None:
            from .proposal import build_proposal
            recompute = lambda: build_proposal(root, **proposal.options)
        fresh = recompute()
        if fresh.digest != proposal.digest:
            return ApplyResult('stale_proposal', ('repository changed before bootstrap',))
        for operation in proposal.operations:
            if snapshot(root, operation.path).data != operation.original:
                return ApplyResult('stale_proposal', ('reviewed target changed: ' + operation.path,))
        if (root / '.git').exists():
            from autodev.safety.git_read import git_tracked_paths
            tracked = git_tracked_paths(root, STATE)
            if not tracked.ok or tracked.paths:
                return ApplyResult('needs_input', ('private state is tracked or index evidence unavailable',))
        if (not hasattr(os, 'O_NOFOLLOW') or not hasattr(os, 'O_DIRECTORY')
                or any(function not in os.supports_dir_fd for function in (os.link, os.rename, os.unlink))):
            return ApplyResult('needs_input', ('required safe filesystem primitives unavailable',))
        store = _bootstrap(root, checkpoint, effects)
        lock = repository_lock(store.root, sha256_bytes(str(root).encode()), owner_identity=OWNER)
        effects.append(str(lock.path.relative_to(root)))
        lock.acquire(blocking=True)
        try:
            _point(checkpoint, 'lock_acquired')
            pending = _manifest(root)
            if pending is not None and pending['phase'] not in {'committed', 'rolled_back'}:
                return ApplyResult('recovery_required', ('pending transaction requires explicit recovery',), (), tuple(effects))
            fresh = recompute()
            if fresh.digest != proposal.digest:
                return ApplyResult('stale_proposal', ('repository changed after apply bootstrap; private state retained',), (), tuple(effects))
            operations, parents = [], {}
            for operation in sorted(proposal.operations, key=lambda item: item.path):
                before = snapshot(root, operation.path)
                if before.data != operation.original:
                    return ApplyResult('stale_proposal', ('reviewed target changed under lock',), (), tuple(effects))
                path = target_path(root, operation.path, missing_parents=True)
                for parent in reversed(path.parents):
                    if parent == root or root not in parent.parents:
                        continue
                    if not parent.exists():
                        parents[parent.relative_to(root).as_posix()] = {'path': parent.relative_to(root).as_posix(), 'inode': None}
                operations.append({'path': operation.path,
                    'original': None if before.data is None else base64.b64encode(before.data).decode(),
                    'proposed': base64.b64encode(operation.proposed).decode(),
                    'original_sha256': None if before.data is None else sha256_bytes(before.data),
                    'proposed_sha256': sha256_bytes(operation.proposed),
                    'mode': before.mode if before.data is not None else operation.mode,
                    'original_inode': None if before.inode is None else list(before.inode),
                    'published_inode': None, 'restored_inode': None, 'staging': None, 'restore_staging': None})
            record = {'schema_version': 1, 'owner': _owner(root), 'digest': proposal.digest,
                      'phase': 'prepared', 'operations': operations,
                      'parents': sorted(parents.values(), key=lambda item: (len(Path(item['path']).parts), item['path']))}
            _save(store, record)
            effects.append(STATE + '/transaction.json')
            committed = False
            try:
                _point(checkpoint, 'after_intent')
                for parent in record['parents']:
                    parent['inode'] = list(create_parent(root, parent['path']))
                    _save(store, record)
                for item in operations:
                    item['staging'] = planned_stage(item['path'])
                    _save(store, record)
                    staging, identity = stage(root, item['path'], _decoded(item['proposed']), item['mode'], staging=item['staging'])
                    item['staging'], item['published_inode'] = staging, list(identity)
                    _save(store, record)
                    _point(checkpoint, 'before_publish', item['path'])
                    before = FileSnapshot(_decoded(item['original']), item['mode'],
                                          None if item['original_inode'] is None else tuple(item['original_inode']))
                    publish(root, item['path'], staging, before,
                            staged=FileSnapshot(_decoded(item['proposed']), item['mode'], identity))
                    changed.append(item['path'])
                    _point(checkpoint, 'after_publish', item['path'])
                    item['published'] = True
                    _save(store, record)
                    _point(checkpoint, 'after_checkpoint', item['path'])
                if any(item['path'] == '.gitignore' for item in operations):
                    from autodev.safety.git_read import git_bucket_postcheck
                    bucket = proposal.options.get('worktree_bucket')
                    if not bucket or not git_bucket_postcheck(root, bucket):
                        raise ValueError('managed bucket ignore postcheck failed')
                if verify:
                    verify()
                report = getattr(proposal, 'report', {})
                if report.get('project_path') and report.get('execution_index_path'):
                    from autodev.contracts import load_execution_yaml, load_project_yaml
                    project_bytes = snapshot(root, report['project_path']).data
                    index_bytes = snapshot(root, report['execution_index_path']).data
                    if project_bytes is None or index_bytes is None:
                        raise ValueError('aligned contract pair is missing')
                    load_execution_yaml(index_bytes, load_project_yaml(project_bytes))
                for item in operations:
                    observed = snapshot(root, item['path'])
                    if (observed.data != _decoded(item['proposed'])
                            or observed.inode != tuple(item['published_inode'])):
                        raise ValueError('alignment changed before commit')
                _point(checkpoint, 'before_commit')
                record['phase'] = 'committed'
                _save(store, record)
                committed = True
                _point(checkpoint, 'after_commit')
                return ApplyResult('applied', (), tuple(changed), tuple(effects))
            except Exception:
                # Once committed, the durable intent is the completed outcome.
                if committed:
                    return ApplyResult('applied', ('post_commit_observer_failed',), tuple(changed), tuple(effects))
                conflicts = _rollback(root, store, record)
                return ApplyResult('recovery_required' if conflicts else 'failed',
                                   ('alignment_failed', *('recovery_conflict:' + p for p in conflicts)),
                                   tuple(conflicts), tuple(effects))
        finally:
            lock.release()
    except (OSError, ValueError, SafetyError) as error:
        reason = ('bootstrap_recovery_required' if 'bootstrap' in str(error) else
                  'recovery_required' if changed else 'failed')
        return ApplyResult(reason, ('apply_precondition_or_storage_failed',), tuple(changed), tuple(effects))


def recover_repository(root: Path | str, *, checkpoint: Checkpoint | None = None) -> ApplyResult:
    """Explicit recovery only; callers must present inspect_recovery first."""
    try:
        root = checked_root(root)
        inspection = inspect_recovery(root)
        if inspection['status'] == 'clean':
            return ApplyResult('clean')
        if inspection['status'] != 'recovery_required':
            return ApplyResult(inspection['status'], tuple(inspection['diagnostics']))
        if (root / '.git').exists():
            from autodev.safety.git_read import git_tracked_paths
            tracked = git_tracked_paths(root, STATE)
            if not tracked.ok or tracked.paths:
                return ApplyResult('recovery_required', ('private state is tracked or index evidence unavailable',))
        store = SafeStore(root / STATE)
        lock = repository_lock(store.root, sha256_bytes(str(root).encode()), owner_identity=OWNER)
        lock.acquire(blocking=True)
        try:
            record = _manifest(root)
            if record is None or record['phase'] in {'committed', 'rolled_back'}:
                return ApplyResult('clean')
            conflicts = _rollback(root, store, record, checkpoint)
            return ApplyResult('recovery_required' if conflicts else 'recovered', tuple(conflicts),
                               (), (STATE + '/transaction.json', str(lock.path.relative_to(root))))
        finally:
            lock.release()
    except (OSError, ValueError, KeyError, TypeError, SafetyError):
        return ApplyResult('recovery_required', ('recovery_precondition_or_storage_failed',))
