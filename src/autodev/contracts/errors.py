from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Issue:
    field: str
    code: str
    message: str
    line: int | None = None


class ContractError(ValueError):
    def __init__(self, issues: Issue | list[Issue]) -> None:
        self.issues = [issues] if isinstance(issues, Issue) else list(issues)
        detail = "; ".join(
            f"{issue.field}: {issue.code}: {issue.message}" for issue in self.issues
        )
        super().__init__(detail)


def issue(field: str, code: str, message: str, line: int | None = None) -> Issue:
    return Issue(field=field, code=code, message=message, line=line)


def fail(field: str, code: str, message: str, line: int | None = None) -> None:
    raise ContractError(issue(field, code, message, line))
