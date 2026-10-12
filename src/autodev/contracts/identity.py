from __future__ import annotations

from dataclasses import dataclass

from .model import InstallationBinding, MetadataSnapshot, ProjectContract


@dataclass(frozen=True)
class IdentityDecision:
    classification: str
    reason_codes: tuple[str, ...]


def classify_installation_identity(
    project: ProjectContract,
    installation: InstallationBinding | None,
    metadata: MetadataSnapshot,
) -> IdentityDecision:
    if installation is None:
        return IdentityDecision("NEW_INSTALLATION_REQUIRED", ("installation_missing",))
    reasons: list[str] = []
    if metadata.project_id is None:
        reasons.append("project_metadata_missing")
    if metadata.installation_id is None:
        reasons.append("installation_metadata_missing")
    if installation.project_id != project.project_id:
        reasons.append("project_id_mismatch")
    if metadata.installation_id and installation.installation_id != metadata.installation_id:
        reasons.append("installation_id_mismatch")
    if installation.repo_realpath != metadata.repo_realpath:
        reasons.append("repo_realpath_mismatch")
    if installation.git_common_dir_realpath != metadata.git_common_dir_realpath:
        reasons.append("git_common_dir_realpath_mismatch")
    if installation.slug and installation.slug != project.slug:
        reasons.append("slug_mismatch")
    if not reasons:
        return IdentityDecision("EXACT_MATCH", ())
    if "project_metadata_missing" in reasons or "installation_metadata_missing" in reasons:
        return IdentityDecision("CONFLICT", tuple(reasons))
    if installation.project_id == project.project_id and (
        "repo_realpath_mismatch" in reasons or "git_common_dir_realpath_mismatch" in reasons
    ):
        return IdentityDecision("NEW_INSTALLATION_REQUIRED", tuple(reasons))
    return IdentityDecision("CONFLICT", tuple(reasons))
