from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path


def run_guarded_child(repo_root: Path) -> dict[str, object]:
    """Run real AD-00 app paths in a child guarded before app import."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        home = tmp_path / "home"
        config = tmp_path / "config"
        cwd = tmp_path / "cwd"
        owned = tmp_path / "owned"
        protected = tmp_path / "protected"
        provided = tmp_path / "provided"
        for path in (home, config, cwd, owned, protected, provided):
            path.mkdir()
        for name in ("nous", "hermes", "gjc", "cron", "account"):
            (protected / f"{name}.sentinel").write_text(f"{name}:unchanged\n", encoding="utf-8")

        script = tmp_path / "guarded_child.py"
        script.write_text(_guarded_child_source(), encoding="utf-8")
        env = {
            "PYTHONPATH": str(repo_root / "src"),
            "PYTHONDONTWRITEBYTECODE": "1",
            "HOME": str(home),
            "XDG_CONFIG_HOME": str(config),
            "PATH": "/usr/bin:/bin",
            "LANG": "C.UTF-8",
        }
        result = subprocess.run(
            [
                sys.executable,
                "-B",
                str(script),
                json.dumps(
                    {
                        "repo_root": str(repo_root),
                        "tmp_root": str(tmp_path),
                        "cwd": str(cwd),
                        "owned": str(owned),
                        "protected": str(protected),
                        "provided": str(provided),
                    },
                    sort_keys=True,
                ),
            ],
            cwd=cwd,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if result.returncode != 0:
            raise AssertionError("guarded child failed with sanitized nonzero exit")
        return json.loads(result.stdout)


def _guarded_child_source() -> str:
    return textwrap.dedent(
        r'''
        from __future__ import annotations

        import contextlib
        import hashlib
        import io
        import json
        import os
        import runpy
        import socket
        import subprocess
        import sys
        import sysconfig
        from pathlib import Path

        cfg = json.loads(sys.argv[1])
        repo_root = Path(cfg["repo_root"]).resolve()
        tmp_root = Path(cfg["tmp_root"]).resolve()
        owned = Path(cfg["owned"]).resolve()
        protected = Path(cfg["protected"]).resolve()
        provided = Path(cfg["provided"]).resolve()
        src_root = repo_root / "src"
        evidence_root = repo_root / "evidence" / "AD-00"
        fixtures_root = repo_root / "fixtures" / "AD-00"
        baseline_root = repo_root / "docs" / "baseline"
        decisions_root = repo_root / "docs" / "decisions"
        stdlib_roots = tuple(
            Path(sysconfig.get_path(name)).resolve()
            for name in ("stdlib", "platstdlib")
            if sysconfig.get_path(name)
        )
        allowed_read_roots = (
            src_root,
            evidence_root,
            fixtures_root,
            baseline_root,
            decisions_root,
            provided,
            protected,
            *stdlib_roots,
        )
        allowed_write_roots = (owned, provided)
        attempts = []

        def rel_kind(path):
            try:
                return str(Path(path).resolve().relative_to(tmp_root))
            except Exception:
                return "outside-temp"

        def relative_to_any(path, roots):
            resolved = Path(path).resolve()
            for root in roots:
                try:
                    resolved.relative_to(root)
                    return True
                except ValueError:
                    pass
            return False

        def record(kind, detail):
            attempts.append({"kind": kind, "detail": detail})

        def snapshot(root):
            out = {}
            for path in sorted(root.rglob("*")):
                rel = path.relative_to(root).as_posix()
                if path.is_file():
                    out[rel] = path.read_text(encoding="utf-8")
                elif path.is_dir():
                    out[rel + "/"] = "<dir>"
                else:
                    out[rel] = "<other>"
            return out

        before = snapshot(protected)

        def audit(event, args):
            if event == "open":
                path, mode, flags = args
                if path in (None,):
                    return
                path_text = str(path)
                if path_text in ("<stdin>", "<stdout>", "<stderr>") or path_text.startswith("/dev/"):
                    return
                mode_text = "" if mode is None else str(mode)
                flag_value = 0 if flags is None else int(flags)
                write_like = (
                    any(token in mode_text for token in ("w", "a", "x", "+"))
                    or bool(flag_value & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_TRUNC))
                )
                if write_like:
                    if relative_to_any(path_text, allowed_write_roots):
                        record("write-allowed", "owned-temp")
                    else:
                        record("write-denied", rel_kind(path_text))
                        raise PermissionError("guarded child write denied")
                elif not relative_to_any(path_text, allowed_read_roots):
                    record("read-denied", rel_kind(path_text))
                    raise PermissionError("guarded child read denied")
            elif event in {"subprocess.Popen", "os.system", "os.posix_spawn", "os.fork", "os.exec"}:
                record("process-denied", event)
                raise PermissionError("guarded child process denied")
            elif event.startswith("socket."):
                record("network-denied", event)
                raise PermissionError("guarded child network denied")
            elif event in {"os.remove", "os.rename", "os.rmdir", "os.mkdir"}:
                paths = [str(arg) for arg in args if isinstance(arg, (str, bytes, os.PathLike))]
                if not paths or not all(relative_to_any(path, allowed_write_roots) for path in paths):
                    record("write-denied", "filesystem-mutation")
                    raise PermissionError("guarded child filesystem mutation denied")

        sys.addaudithook(audit)

        # App imports happen only after the audit hook is active.
        import autodev
        from autodev.cli import main
        from autodev.evidence import (
            EvidenceError,
            assert_repo_relative,
            load_fixture_manifest,
            load_input_manifest,
            load_source_records,
            read_allowed_provided_file,
            sha256_bytes,
            sha256_file,
        )
        from autodev.redaction import sanitized_json

        help_stdout = io.StringIO()
        with contextlib.redirect_stdout(help_stdout):
            try:
                main(["--help"])
            except SystemExit as exc:
                help_code = exc.code
            else:
                help_code = 0

        module_help_stdout = io.StringIO()
        old_argv = sys.argv[:]
        sys.argv = ["autodev", "--help"]
        with contextlib.redirect_stdout(module_help_stdout):
            try:
                runpy.run_module("autodev", run_name="__main__")
            except SystemExit as exc:
                module_help_code = exc.code
            else:
                module_help_code = 0
        sys.argv = old_argv

        unsupported_stdout = io.StringIO()
        unsupported_stderr = io.StringIO()
        unsupported_codes = {}
        with contextlib.redirect_stdout(unsupported_stdout), contextlib.redirect_stderr(unsupported_stderr):
            for command in ("dispatch", "onboard", "supervise", "doctor", "run"):
                try:
                    main([command])
                except SystemExit as exc:
                    unsupported_codes[command] = exc.code
                else:
                    unsupported_codes[command] = 0

        fixture_count = 0
        for fixture in load_fixture_manifest()["fixtures"]:
            path = assert_repo_relative(fixture["path"])
            if sha256_file(path) != fixture["measured_sha256"]:
                raise AssertionError("fixture hash mismatch")
            fixture_count += 1

        canary = "CHILD-CANARY-secret-value"
        provided_file = provided / "provided.txt"
        provided_file.write_text("operator note\napi_key=" + canary + "\n", encoding="utf-8")
        expected = hashlib.sha256(provided_file.read_bytes()).hexdigest()
        data = read_allowed_provided_file(
            provided_file,
            expected_sha256=expected,
            allowed_roots=(provided,),
        )
        report = sanitized_json({"body": data.decode("utf-8"), canary: canary}, [canary])
        (owned / "report.json").write_text(report, encoding="utf-8")

        try:
            read_allowed_provided_file(
                provided_file,
                expected_sha256=sha256_bytes(b"changed"),
                allowed_roots=(provided,),
            )
        except EvidenceError as exc:
            tamper_message = str(exc)
        else:
            tamper_message = "missing-error"

        controls = []
        for label, func in (
            ("write", lambda: (protected / "nous.sentinel").write_text("changed\n", encoding="utf-8")),
            ("lowlevel-write", lambda: os.open(protected / "hermes.sentinel", os.O_WRONLY | os.O_TRUNC)),
            ("read", lambda: (repo_root / "README.md").read_text(encoding="utf-8")),
            ("process", lambda: subprocess.Popen(["python3", "--version"])),
            ("process-system", lambda: os.system("python3 --version")),
            ("network", lambda: socket.socket()),
            ("network-connect", lambda: socket.create_connection(("127.0.0.1", 1), timeout=0.01)),
        ):
            try:
                func()
            except PermissionError:
                controls.append(label)

        after = snapshot(protected)
        payload = {
            "autodev_version": autodev.__version__,
            "help_code": help_code,
            "help_usage": "usage: autodev" in help_stdout.getvalue(),
            "module_help_code": module_help_code,
            "module_help_usage": "usage: autodev" in module_help_stdout.getvalue(),
            "unsupported_code": unsupported_codes["dispatch"],
            "unsupported_codes": unsupported_codes,
            "unsupported_has_success": any(
                word in (unsupported_stdout.getvalue() + unsupported_stderr.getvalue()).lower()
                for word in ("success", "receipt")
            ),
            "protected_unchanged": before == after,
            "controls": sorted(controls),
            "attempt_kinds": sorted({attempt["kind"] for attempt in attempts}),
            "attempts": attempts,
            "parent_child_launch": "fixed-python-guarded-script",
            "canary_absent": canary not in report and canary not in json.dumps(attempts),
            "tamper_message": tamper_message,
            "source_count": len(load_source_records()["records"]),
            "input_count": len(load_input_manifest()["entries"]),
            "fixture_count": fixture_count,
        }
        print(json.dumps(payload, sort_keys=True))
        '''
    )
