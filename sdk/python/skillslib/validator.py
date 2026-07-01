"""Validator that mirrors the Go CLI's `secure-vibe dev validate` schema checks."""

from __future__ import annotations

import re
from typing import List

from .skill import Skill

_SKILL_ID_RE = re.compile(r"^[a-z][a-z0-9-]{1,63}$")
_SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
_CATEGORIES = {"prevention", "hardening", "detection", "compliance", "supply-chain"}
_SEVERITIES = {"low", "medium", "high", "critical"}


def validate(skill: Skill) -> List[str]:
    """Return a list of human-readable validation errors.

    An empty list means the skill is valid.
    """
    errs: List[str] = []
    if skill is None:
        return ["skill is None"]
    fm = skill.frontmatter
    if not _SKILL_ID_RE.match(fm.id):
        errs.append(
            f"id {fm.id!r} must match ^[a-z][a-z0-9-]{{1,63}}$"
        )
    if not _SEMVER_RE.match(fm.version):
        errs.append(f"version {fm.version!r} is not valid semver")
    if not fm.title:
        errs.append("title is required")
    if not fm.description:
        errs.append("description is required")
    if fm.category not in _CATEGORIES:
        errs.append(
            f"category {fm.category!r} must be one of "
            f"{sorted(_CATEGORIES)}"
        )
    if fm.severity not in _SEVERITIES:
        errs.append(
            f"severity {fm.severity!r} must be one of "
            f"{sorted(_SEVERITIES)}"
        )
    if not fm.languages:
        errs.append("languages must list at least one language id (or ['*'])")
    if fm.token_budget.minimal <= 0:
        errs.append("token_budget.minimal must be > 0")
    if fm.token_budget.compact <= 0:
        errs.append("token_budget.compact must be > 0")
    if fm.token_budget.full <= 0:
        errs.append("token_budget.full must be > 0")
    if not fm.last_updated:
        errs.append("last_updated is required")
    if not skill.body.strip():
        errs.append("SKILL body is empty")
    return errs
