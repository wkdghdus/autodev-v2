from __future__ import annotations

import re
from collections.abc import MutableMapping
from typing import Any

from .errors import ContractError, Issue, fail, issue


MAX_BYTES = 128 * 1024
MAX_DEPTH = 24
_KEY_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
_INT_RE = re.compile(r"^-?(0|[1-9][0-9]*)$")
_ALIAS_RE = re.compile(r"^\*[A-Za-z0-9_.-]+$")


class ParsedMap(dict[str, Any]):
    def __init__(self) -> None:
        super().__init__()
        self._line_map: dict[str, int] = {}

    def set_item(self, key: str, value: Any, line_no: int) -> None:
        self[key] = value
        self._line_map[key] = line_no

    def line_for(self, key: str) -> int | None:
        return self._line_map.get(key)


def parse_yaml_subset(data: bytes | str, *, source_name: str = "<memory>") -> Any:
    text = data.decode("utf-8") if isinstance(data, bytes) else data
    if len(text.encode("utf-8")) > MAX_BYTES:
        fail(source_name, "oversized_input", "YAML input exceeds AD-01 parser limit")
    lines = _logical_lines(text, source_name)
    if not lines:
        return {}
    value, next_index = _parse_block(lines, 0, lines[0][0], source_name, 0)
    if next_index != len(lines):
        line_no = lines[next_index][1]
        fail(source_name, "malformed_indentation", "unexpected trailing block", line_no)
    return value


def _logical_lines(text: str, source_name: str) -> list[tuple[int, int, str]]:
    out: list[tuple[int, int, str]] = []
    for line_no, raw in enumerate(text.splitlines(), 1):
        if "\t" in raw:
            fail(source_name, "tab_indentation", "tabs are not supported", line_no)
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped in {"---", "..."}:
            fail(source_name, "document_marker", "document markers are not supported", line_no)
        if stripped.startswith("%"):
            fail(source_name, "directive", "YAML directives are not supported", line_no)
        if stripped.startswith("!") or stripped.startswith("&"):
            fail(source_name, "unsafe_syntax", "tags and anchors are not supported", line_no)
        indent = len(raw) - len(raw.lstrip(" "))
        if indent % 2:
            fail(source_name, "malformed_indentation", "indentation must use two spaces", line_no)
        out.append((indent, line_no, _strip_comment(raw[indent:])))
    return out


def _strip_comment(text: str) -> str:
    quote: str | None = None
    escaped = False
    for index, char in enumerate(text):
        if quote:
            if char == "\\" and not escaped:
                escaped = True
                continue
            if char == quote and not escaped:
                quote = None
            escaped = False
            continue
        if char in {"'", '"'}:
            quote = char
            continue
        if char == "#" and (index == 0 or text[index - 1].isspace()):
            return text[:index].rstrip()
    return text.rstrip()


def _parse_block(
    lines: list[tuple[int, int, str]],
    index: int,
    indent: int,
    source_name: str,
    depth: int,
) -> tuple[Any, int]:
    if depth > MAX_DEPTH:
        fail(source_name, "excessive_nesting", "YAML nesting exceeds AD-01 limit", lines[index][1])
    if lines[index][0] < indent:
        return {}, index
    head = lines[index][2]
    if head.startswith("- "):
        return _parse_sequence(lines, index, indent, source_name, depth)
    return _parse_mapping(lines, index, indent, source_name, depth)


def _parse_mapping(
    lines: list[tuple[int, int, str]],
    index: int,
    indent: int,
    source_name: str,
    depth: int,
) -> tuple[ParsedMap, int]:
    result = ParsedMap()
    while index < len(lines):
        current_indent, line_no, text = lines[index]
        if current_indent < indent:
            break
        if current_indent > indent:
            fail(source_name, "malformed_indentation", "unexpected nested mapping line", line_no)
        if text.startswith("- "):
            break
        key, raw_value = _split_key_value(text, source_name, line_no)
        if key in result:
            fail(key, "duplicate_key", "duplicate key in YAML mapping", line_no)
        if raw_value == "":
            if index + 1 >= len(lines) or lines[index + 1][0] <= indent:
                result.set_item(key, None, line_no)
                index += 1
            else:
                value, index = _parse_block(lines, index + 1, lines[index + 1][0], source_name, depth + 1)
                result.set_item(key, value, line_no)
        else:
            result.set_item(key, _parse_scalar(raw_value, key, line_no), line_no)
            index += 1
    return result, index


def _parse_sequence(
    lines: list[tuple[int, int, str]],
    index: int,
    indent: int,
    source_name: str,
    depth: int,
) -> tuple[list[Any], int]:
    result: list[Any] = []
    while index < len(lines):
        current_indent, line_no, text = lines[index]
        if current_indent < indent:
            break
        if current_indent > indent:
            fail(source_name, "malformed_indentation", "unexpected nested sequence line", line_no)
        if not text.startswith("- "):
            break
        item_text = text[2:].strip()
        if item_text == "":
            if index + 1 >= len(lines) or lines[index + 1][0] <= indent:
                result.append(None)
                index += 1
            else:
                item, index = _parse_block(lines, index + 1, lines[index + 1][0], source_name, depth + 1)
                result.append(item)
            continue
        if _looks_like_key_value(item_text):
            key, raw_value = _split_key_value(item_text, source_name, line_no)
            item = ParsedMap()
            item.set_item(key, None if raw_value == "" else _parse_scalar(raw_value, key, line_no), line_no)
            index += 1
            while index < len(lines) and lines[index][0] > indent:
                nested_indent, nested_line, nested_text = lines[index]
                if nested_indent != indent + 2 or nested_text.startswith("- "):
                    fail(source_name, "malformed_indentation", "unsupported nested sequence item", nested_line)
                nested_key, nested_raw = _split_key_value(nested_text, source_name, nested_line)
                if nested_key in item:
                    fail(nested_key, "duplicate_key", "duplicate key in YAML mapping", nested_line)
                if nested_raw == "":
                    if index + 1 >= len(lines) or lines[index + 1][0] <= nested_indent:
                        item.set_item(nested_key, None, nested_line)
                        index += 1
                    else:
                        nested_value, index = _parse_block(
                            lines, index + 1, lines[index + 1][0], source_name, depth + 1
                        )
                        item.set_item(nested_key, nested_value, nested_line)
                else:
                    item.set_item(nested_key, _parse_scalar(nested_raw, nested_key, nested_line), nested_line)
                    index += 1
            result.append(item)
        else:
            result.append(_parse_scalar(item_text, "[]", line_no))
            index += 1
    return result, index


def _looks_like_key_value(text: str) -> bool:
    return ":" in text and bool(re.match(r"^[A-Za-z0-9_.-]+:", text))


def _split_key_value(text: str, source_name: str, line_no: int) -> tuple[str, str]:
    if ":" not in text:
        fail(source_name, "malformed_mapping", "mapping line requires ':'", line_no)
    key, raw_value = text.split(":", 1)
    key = key.strip()
    if key == "<<":
        fail(key, "merge_key", "merge keys are not supported", line_no)
    if not key or not _KEY_RE.match(key):
        fail(key or source_name, "invalid_key", "unsupported mapping key", line_no)
    return key, raw_value.strip()


def _parse_scalar(text: str, field: str, line_no: int) -> Any:
    if text.startswith("!") or text.startswith("&") or _ALIAS_RE.match(text):
        fail(field, "unsafe_syntax", "tags, anchors, and aliases are not supported", line_no)
    if _inline_depth(text) > MAX_DEPTH:
        fail(field, "excessive_nesting", "YAML nesting exceeds AD-01 limit", line_no)
    if text in {"null", "~"}:
        return None
    if text == "true":
        return True
    if text == "false":
        return False
    if text in {"True", "False", "TRUE", "FALSE"}:
        fail(field, "invalid_boolean", "booleans must be lowercase true/false", line_no)
    if _INT_RE.match(text):
        return int(text)
    if text.startswith("[") and text.endswith("]"):
        inner = text[1:-1].strip()
        if not inner:
            return []
        return [_parse_scalar(part.strip(), field, line_no) for part in _split_inline(inner)]
    if text.startswith("{") and text.endswith("}"):
        inner = text[1:-1].strip()
        result = ParsedMap()
        if not inner:
            return result
        for part in _split_inline(inner):
            key, raw_value = _split_key_value(part.strip(), field, line_no)
            if key in result:
                fail(key, "duplicate_key", "duplicate key in inline map", line_no)
            result.set_item(key, _parse_scalar(raw_value, key, line_no), line_no)
        return result
    if text.startswith(('"', "'")) and not text.endswith(text[0]):
        fail(field, "malformed_scalar", "unterminated quoted scalar", line_no)
    if (text.startswith('"') and text.endswith('"')) or (text.startswith("'") and text.endswith("'")):
        return _unquote(text)
    if text.startswith("[") or text.startswith("{"):
        fail(field, "malformed_inline", "malformed inline collection", line_no)
    return text


def _split_inline(text: str) -> list[str]:
    parts: list[str] = []
    quote: str | None = None
    current: list[str] = []
    for char in text:
        if quote:
            current.append(char)
            if char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
            current.append(char)
            continue
        if char == ",":
            parts.append("".join(current).strip())
            current = []
            continue
        current.append(char)
    parts.append("".join(current).strip())
    return parts


def _inline_depth(text: str) -> int:
    depth = 0
    max_depth = 0
    quote: str | None = None
    for char in text:
        if quote:
            if char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
            continue
        if char in "[{":
            depth += 1
            max_depth = max(max_depth, depth)
        elif char in "]}":
            depth = max(0, depth - 1)
    return max_depth


def _unquote(text: str) -> str:
    if text[0] == "'":
        return text[1:-1].replace("''", "'")
    return bytes(text[1:-1], "utf-8").decode("unicode_escape")


def require_mapping(value: Any, field: str) -> MutableMapping[str, Any]:
    if not isinstance(value, dict):
        fail(field, "invalid_type", "expected mapping")
    return value


def reject_unknowns(value: MutableMapping[str, Any], allowed: set[str], field: str) -> None:
    for key in value:
        if key not in allowed:
            line = value.line_for(key) if isinstance(value, ParsedMap) else 0
            raise ContractError(Issue(f"{field}.{key}" if field else key, "unknown_field", "unknown field", line))


def line_for(value: Any, key: str) -> int | None:
    if isinstance(value, ParsedMap):
        return value.line_for(key)
    return None
