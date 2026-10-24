"""Bounded POSIX command execution; this is not a hostile-code sandbox."""
from __future__ import annotations

import math
import os
import selectors
import signal
import subprocess
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from autodev.redaction import redact_text


@dataclass(frozen=True)
class CommandRequest:
    argv: Sequence[str]
    cwd: str | Path
    timeout_seconds: float = 30
    kill_grace_seconds: float = 0.2
    env_allowlist: tuple[str, ...] = ("LANG", "LC_ALL", "PATH")
    env_overrides: Mapping[str, str] = field(default_factory=dict)
    max_stdout_bytes: int = 65536
    max_stderr_bytes: int = 65536
    canaries: tuple[str, ...] = ()
    stdin_bytes: bytes | None = None


@dataclass(frozen=True)
class CommandResult:
    argv: tuple[str, ...]
    cwd: str
    returncode: int | None
    stdout: str
    stderr: str
    stdout_bytes: int
    stderr_bytes: int
    stdout_truncated: bool
    stderr_truncated: bool
    timed_out: bool
    overflowed: bool
    killed: bool
    env_keys: tuple[str, ...]

    def diagnostics(self) -> Mapping[str, object]:
        return dict(self.__dict__)


def _signal_group(pid: int, sig: int) -> None:
    try:
        os.killpg(pid, sig)
    except ProcessLookupError:
        pass


def run_command(request: CommandRequest) -> CommandResult:
    if os.name != "posix":
        raise ValueError("command execution requires POSIX")
    if (isinstance(request.argv, (str, bytes)) or not isinstance(request.argv, Sequence)
            or not request.argv or any(type(arg) is not str or not arg or '\x00' in arg for arg in request.argv)):
        raise ValueError("argv must be a nonempty sequence of strings")
    for limit in (request.max_stdout_bytes, request.max_stderr_bytes):
        if type(limit) is not int or limit < 0:
            raise ValueError("output limits must be nonnegative integers")
    if request.stdin_bytes is not None and (type(request.stdin_bytes) is not bytes
                                           or len(request.stdin_bytes) > 65536):
        raise ValueError("stdin must be bytes bounded to 65536 bytes")
    for duration in (request.timeout_seconds, request.kill_grace_seconds):
        if type(duration) not in (int, float) or not math.isfinite(duration) or duration <= 0:
            raise ValueError("time limits must be positive finite numbers")
    try:
        cwd = Path(request.cwd).absolute()
        if not cwd.is_dir():
            raise ValueError
    except (OSError, ValueError, TypeError):
        raise ValueError("cwd must be an existing directory") from None
    env = {"LANG": "C.UTF-8", "LC_ALL": "C", "PATH": "/usr/bin:/bin"}
    if not isinstance(request.env_overrides, Mapping):
        raise ValueError("environment overrides must be a mapping")
    for key in request.env_allowlist:
        if type(key) is not str or not key or '=' in key or '\x00' in key:
            raise ValueError("invalid environment allowlist")
        if key in os.environ:
            env[key] = os.environ[key]
    for key, value in request.env_overrides.items():
        if (type(key) is not str or not key or '=' in key or '\x00' in key
                or type(value) is not str or '\x00' in value):
            raise ValueError("invalid environment override")
        env[key] = value
    if any(type(canary) is not str for canary in request.canaries):
        raise ValueError("canaries must be strings")
    canaries = tuple(request.canaries) + tuple(value for key, value in env.items()
                    if any(word in key.lower() for word in ("secret", "token", "password", "key", "credential")))
    try:
        process = subprocess.Popen(tuple(request.argv), cwd=str(cwd), env=env,
                                   stdin=subprocess.PIPE if request.stdin_bytes is not None else subprocess.DEVNULL,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, start_new_session=True)
    except Exception:
        raise ValueError("command could not be started") from None
    limits = (request.max_stdout_bytes, request.max_stderr_bytes)
    buffers = (bytearray(), bytearray())
    counts = [0, 0]
    truncated = [False, False]
    timed_out = overflowed = killed = False
    stopped_at = parent_exited_at = None
    started = time.monotonic()
    pipes = (process.stdout, process.stderr)
    with selectors.DefaultSelector() as selector:
        try:
            input_offset = 0
            if process.stdin is not None:
                if request.stdin_bytes:
                    os.set_blocking(process.stdin.fileno(), False)
                    selector.register(process.stdin, selectors.EVENT_WRITE, 2)
                else:
                    process.stdin.close()
            for index, pipe in enumerate(pipes):
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ, index)
            while selector.get_map() or process.poll() is None:
                now = time.monotonic()
                if process.poll() is not None and parent_exited_at is None:
                    parent_exited_at = now
                if stopped_at is None:
                    timed_out = now - started >= request.timeout_seconds
                    pipe_child = parent_exited_at is not None and now - parent_exited_at >= 0.1
                    if timed_out or overflowed or (pipe_child and selector.get_map()):
                        _signal_group(process.pid, signal.SIGTERM)
                        killed = True
                        stopped_at = now
                elif now - stopped_at >= request.kill_grace_seconds:
                    # Kill the whole owned group even if its leader already exited.
                    _signal_group(process.pid, signal.SIGKILL)
                    if now - stopped_at >= request.kill_grace_seconds + 1:
                        for key in list(selector.get_map().values()):
                            if key.data < 2:
                                truncated[key.data] = True
                            selector.unregister(key.fileobj)
                        break
                for key, _events in selector.select(0.02):
                    if key.data == 2:
                        try:
                            input_offset += os.write(key.fd, request.stdin_bytes[input_offset:input_offset + 8192])
                        except BlockingIOError:
                            continue
                        except BrokenPipeError:
                            input_offset = len(request.stdin_bytes)
                        if input_offset == len(request.stdin_bytes):
                            selector.unregister(key.fileobj)
                            key.fileobj.close()
                        continue
                    chunk = os.read(key.fileobj.fileno(), 8192)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    index = key.data
                    counts[index] += len(chunk)
                    remaining = limits[index] - len(buffers[index])
                    buffers[index].extend(chunk[:max(0, remaining)])
                    if len(chunk) > remaining:
                        truncated[index] = True
                        overflowed = True
            if killed:
                _signal_group(process.pid, signal.SIGKILL)
            returncode = process.wait(timeout=1)
        except Exception:
            try:
                _signal_group(process.pid, signal.SIGKILL)
                process.wait(timeout=1)
            except Exception:
                pass
            raise ValueError("command cleanup failed") from None
        finally:
            for pipe in pipes:
                pipe.close()
            if process.stdin is not None:
                process.stdin.close()
    output = tuple("" if truncated[index] else redact_text(buffer.decode("utf-8", errors="replace"), canaries)
                   for index, buffer in enumerate(buffers))
    return CommandResult(tuple(redact_text(arg, canaries) for arg in request.argv),
                         redact_text(str(cwd), canaries), returncode, output[0], output[1],
                         counts[0], counts[1], truncated[0], truncated[1], timed_out,
                         overflowed, killed, tuple(redact_text(key, canaries) for key in sorted(env)))
