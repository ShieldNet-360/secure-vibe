"""skillslib — Python SDK for the Skills Library.

This package parses SKILL.md files (YAML frontmatter + markdown body) and
provides a minimal validator that mirrors the Go CLI's
`secure-vibe dev validate` checks for use in Python tooling, dashboards, and
agent frameworks.
"""

from .skill import Frontmatter, Skill, load_all, load_skill, extract
from .validator import validate

__all__ = [
    "Frontmatter",
    "Skill",
    "load_skill",
    "load_all",
    "extract",
    "validate",
    "__version__",
]

__version__ = "0.1.0"
