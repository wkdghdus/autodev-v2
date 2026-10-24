"""Bounded, static discovery with one budget for enumeration and explicit reads."""
from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path, PurePosixPath

MAX_DEPTH = 4
MAX_ENTRIES = 2000
MAX_CANDIDATES = 200
MAX_FILE_BYTES = 128 * 1024
MAX_TOTAL_BYTES = 4 * 1024 * 1024
REGISTRY_VERSION = 1
ROOTS = ("docs", "context", "requirements", "plans", "milestones", "tests", "test")
SKIP = frozenset({".git", "node_modules", ".venv", "venv", "dist", "build", "__pycache__"})
TEXT_SUFFIXES = frozenset({".md", ".yaml", ".yml", ".json", ".toml", ".txt"})
METADATA = frozenset({"pyproject.toml", "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
                      "poetry.lock", "uv.lock", "cargo.toml", "cargo.lock", "makefile", "pytest.ini",
                      "tox.ini", "setup.cfg", "jest.config.json", "tsconfig.json"})


class DiscoveryError(ValueError):
    def __init__(self, code: str, path: str):
        self.code, self.path = code, path
        super().__init__(code)


def safe_relative(value: str) -> str:
    if (not isinstance(value, str) or not value or value.startswith("/") or "\\" in value
            or any(ord(char) < 32 or ord(char) == 127 for char in value)):
        raise DiscoveryError("unsafe_path", str(value) if isinstance(value, str) else "")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise DiscoveryError("unsafe_path", value)
    return PurePosixPath(value).as_posix()


def checked_path(root: Path, value: str, *, mutation: bool = False) -> Path:
    value = safe_relative(value)
    current = root
    for index, component in enumerate(value.split("/")):
        current = current / component
        try:
            info = current.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode):
            raise DiscoveryError("symlink_path", value)
        if index < len(value.split("/")) - 1 and not stat.S_ISDIR(info.st_mode):
            raise DiscoveryError("non_directory_component", value)
        if mutation and index == len(value.split("/")) - 1:
            if not stat.S_ISREG(info.st_mode):
                raise DiscoveryError("non_regular_target", value)
            if info.st_nlink != 1:
                raise DiscoveryError("hardlinked_target", value)
    return current


def directory_descriptor(root: Path, relative: str = "", *, identity: tuple[int, int] | None = None) -> int:
    """Walk from filesystem root using held descriptors; never follow an ancestor link."""
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in root.parts[1:]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        info = os.fstat(descriptor)
        if identity is not None and (info.st_dev, info.st_ino) != identity:
            raise DiscoveryError("repository_identity_changed", "")
        for component in relative.split("/") if relative else ():
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def categories(path: str) -> tuple[str, ...]:
    parts = PurePosixPath(path).parts
    basename = parts[-1].casefold()
    stem, suffix = os.path.splitext(basename)
    result: list[str] = []
    text = suffix in TEXT_SUFFIXES
    if basename in {"agent.md", "agents.md", "claude.md", "gemini.md"} or (suffix == ".md" and "context" in parts[:-1]):
        result.append("context")
    if text and stem in {"product", "prd", "requirements", "specification"}:
        result.append("requirements")
    if text and stem == "roadmap":
        result.append("execution")
    if text and ("plans" in parts[:-1]):
        result.append("plans")
    if text and stem in {"acceptance", "acceptance-criteria"}:
        result.append("acceptance")
    if ("tests" in parts[:-1] or "test" in parts[:-1]) and (basename.startswith("test_") or basename.endswith(("_test.py", ".test.js", ".test.ts", ".spec.js", ".spec.ts"))):
        result.append("tests")
    if basename in METADATA:
        result.append("metadata")
    if path == ".agent/EXECUTION.yaml":
        result.append("execution_index")
    return tuple(result)


class Discovery:
    def __init__(self, root: Path, *, bucket: str | None = None):
        self.root = root
        self.bucket = bucket
        self.entries = 0
        self.bytes_read = 0
        self.contents: dict[str, bytes | None] = {}
        self.inventory: dict[str, dict] = {}
        self.candidates: dict[str, list[str]] = {key: [] for key in ("context", "requirements", "execution", "plans", "acceptance", "tests", "metadata", "execution_index")}
        self.diagnostics: list[dict] = []
        self._candidate_paths: set[str] = set()
        self._directories: dict[str, bool] = {}
        self._seen_case: dict[str, str] = {}
        self.limited = False
        try:
            info = root.lstat()
            self._root_identity = (info.st_dev, info.st_ino)
        except OSError:
            self._root_identity = None

    def diagnostic(self, code: str, path: str = "", *, blocking: bool = True, field: str | None = None) -> None:
        item = {"code": code, "path": path, "blocking": blocking}
        if field:
            item["field"] = field
        if item not in self.diagnostics:
            self.diagnostics.append(item)

    def _limit(self, path: str) -> None:
        self.limited = True
        self.diagnostic("discovery_limit", path)

    def _case(self, path: str) -> None:
        folded = path.casefold()
        old = self._seen_case.setdefault(folded, path)
        if old != path:
            self.diagnostic("casefold_collision", path)

    def read(self, path: str, *, required: bool = False, mutation: bool = False,
             inspect_parents: bool = True) -> bytes | None:
        if self.limited:
            return None
        try:
            checked_path(self.root, path, mutation=mutation)
            # Exact references may be beyond traversal depth or inside an explicit hidden root.
            # Enumerate each parent with the same budget to catch case-ambiguous destinations.
            parts = PurePosixPath(path).parts
            for size in range(len(parts)):
                parent = "/".join(parts[:size])
                if inspect_parents and (self.root / parent).is_dir() and parent not in self._directories:
                    self._scan_directory(parent, 0, root_only=True)
                if parent:
                    self._case(parent)
            if self.limited:
                return None
            self._case(path)
            if path in self.contents:
                data = self.contents[path]
                if required and data is None:
                    self.diagnostic("missing_reference", path)
                return data
            parent_descriptor = None
            try:
                parent = PurePosixPath(path).parent
                parent_descriptor = directory_descriptor(self.root, "" if parent == PurePosixPath(".") else str(parent), identity=self._root_identity)
                info = os.stat(PurePosixPath(path).name, dir_fd=parent_descriptor, follow_symlinks=False)
            except FileNotFoundError:
                if parent_descriptor is not None:
                    os.close(parent_descriptor)
                self.contents[path] = None
                if required:
                    self.diagnostic("missing_reference", path)
                return None
            except OSError:
                if parent_descriptor is not None:
                    os.close(parent_descriptor)
                raise
            try:
                if not stat.S_ISREG(info.st_mode):
                    raise DiscoveryError("non_regular_file", path)
                if mutation and info.st_nlink != 1:
                    raise DiscoveryError("hardlinked_target", path)
                if path not in self._candidate_paths:
                    if len(self._candidate_paths) >= MAX_CANDIDATES:
                        self._limit(path)
                        return None
                    self._candidate_paths.add(path)
                if info.st_size > MAX_FILE_BYTES:
                    raise DiscoveryError("file_read_limit", path)
                if self.bytes_read + info.st_size > MAX_TOTAL_BYTES:
                    self._limit(path)
                    return None
                descriptor = os.open(PurePosixPath(path).name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_descriptor)
                try:
                    opened = os.fstat(descriptor)
                    if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                        raise DiscoveryError("file_changed_during_read", path)
                    if mutation and opened.st_nlink != 1:
                        raise DiscoveryError("hardlinked_target", path)
                    with os.fdopen(descriptor, "rb", closefd=False) as stream:
                        data = stream.read(MAX_FILE_BYTES + 1)
                    if len(data) > MAX_FILE_BYTES:
                        raise DiscoveryError("file_read_limit", path)
                    if self.bytes_read + len(data) > MAX_TOTAL_BYTES:
                        self._limit(path)
                        return None
                    self.bytes_read += len(data)
                finally:
                    os.close(descriptor)
            finally:
                os.close(parent_descriptor)
            self.contents[path] = data
            self.inventory[path] = {"path": path, "kind": "file", "sha256": hashlib.sha256(data).hexdigest(), "mode": stat.S_IMODE(info.st_mode)}
            return data
        except (DiscoveryError, OSError) as error:
            self.contents[path] = None
            self.diagnostic(error.code if isinstance(error, DiscoveryError) else "unreadable_file", path)
            return None

    def scan(self, extra_roots: tuple[str, ...] = ()) -> None:
        self._scan_directory("", 0, root_only=True)
        for path in (*ROOTS, *extra_roots):
            if self.limited:
                break
            try:
                if path == "." and path in extra_roots:
                    self._scan_directory("", 0)
                    continue
                target = checked_path(self.root, path)
                if target.is_dir():
                    self._scan_directory(path, 0)
                elif path in extra_roots:
                    self.diagnostic("missing_discovery_root", path)
            except (DiscoveryError, OSError) as error:
                self.diagnostic(error.code if isinstance(error, DiscoveryError) else "unreadable_directory", path)

    def _scan_directory(self, path: str, depth: int, *, root_only: bool = False) -> None:
        if (path in self._directories and (root_only or self._directories[path])) or self.limited:
            return
        self._directories[path] = not root_only
        buffered = []
        descriptor = None
        try:
            descriptor = directory_descriptor(self.root, path, identity=self._root_identity)
            with os.scandir(descriptor) as iterator:
                for entry in iterator:
                    relative = f"{path}/{entry.name}" if path else entry.name
                    if relative == ".agent/.init-state":
                        continue
                    if relative == ".agent":
                        buffered.append(entry)
                        continue
                    self.entries += 1
                    if self.entries > MAX_ENTRIES:
                        self._limit(path)
                        return
                    if entry.name in SKIP or relative == self.bucket:
                        continue
                    buffered.append(entry)
            for entry in sorted(buffered, key=lambda item: item.name):
                relative = f"{path}/{entry.name}" if path else entry.name
                self._case(relative)
                info = os.stat(entry.name, dir_fd=descriptor, follow_symlinks=False)
                kind = "directory" if stat.S_ISDIR(info.st_mode) else "file" if stat.S_ISREG(info.st_mode) else "symlink" if stat.S_ISLNK(info.st_mode) else "special"
                # The bootstrap's empty .agent container is deliberately not a premise.
                if relative != ".agent":
                    self.inventory.setdefault(relative, {"path": relative, "kind": kind})
                found = categories(relative)
                if found:
                    if relative not in self._candidate_paths:
                        if len(self._candidate_paths) >= MAX_CANDIDATES:
                            self._limit(relative)
                            return
                        self._candidate_paths.add(relative)
                    for category in found:
                        if relative not in self.candidates[category]:
                            self.candidates[category].append(relative)
                    self.read(relative, required=True)
                if not root_only and kind == "directory" and depth + 1 < MAX_DEPTH and not entry.name.startswith("."):
                    self._scan_directory(relative, depth + 1)
                    if self.limited:
                        return
        except OSError:
            self.diagnostic("unreadable_directory", path)
        except DiscoveryError as error:
            self.diagnostic(error.code, path)
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def result_inventory(self) -> list[dict]:
        return [self.inventory[key] for key in sorted(self.inventory)]
