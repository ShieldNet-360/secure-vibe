"""SKILL.md parser and tier extraction for the Skills Library Python SDK."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Iterable, List, Optional

try:
    import yaml  # type: ignore
except ImportError as exc:  # pragma: no cover
    raise RuntimeError(
        "skillslib requires PyYAML. Install it with `pip install pyyaml`."
    ) from exc

FRONTMATTER_RE = re.compile(r"\A---\s*\n(.*?)\n---\s*(?:\n|\Z)", re.DOTALL)

TIER_MINIMAL = "minimal"
TIER_COMPACT = "compact"
TIER_FULL = "full"
VALID_TIERS = (TIER_MINIMAL, TIER_COMPACT, TIER_FULL)


@dataclass
class TokenBudget:
    minimal: int = 0
    compact: int = 0
    full: int = 0


@dataclass
class Frontmatter:
    id: str = ""
    version: str = ""
    title: str = ""
    description: str = ""
    category: str = ""
    severity: str = ""
    applies_to: List[str] = field(default_factory=list)
    languages: List[str] = field(default_factory=list)
    token_budget: TokenBudget = field(default_factory=TokenBudget)
    rules_path: str = ""
    related_skills: List[str] = field(default_factory=list)
    last_updated: str = ""
    sources: List[str] = field(default_factory=list)


@dataclass
class Skill:
    path: str
    frontmatter: Frontmatter
    body: str

    def extract(self, tier: str) -> str:
        """Render the SKILL body for the requested tier.

        - minimal: ALWAYS + NEVER sections
        - compact: minimal + KNOWN FALSE POSITIVES + References
        - full: complete body
        """
        if tier not in VALID_TIERS:
            raise ValueError(
                f"invalid tier {tier!r} (valid: {', '.join(VALID_TIERS)})"
            )
        if tier == TIER_FULL:
            return self.body
        sections = _split_sections(self.body)
        out: List[str] = []
        always = sections.get("ALWAYS")
        never = sections.get("NEVER")
        if always:
            out.append("### ALWAYS\n\n" + always)
        if never:
            out.append("### NEVER\n\n" + never)
        if tier == TIER_COMPACT:
            kfp = sections.get("KNOWN FALSE POSITIVES")
            refs = sections.get("References")
            if kfp:
                out.append("### KNOWN FALSE POSITIVES\n\n" + kfp)
            if refs:
                out.append("## References\n\n" + refs)
        return "\n\n".join(out).rstrip() + "\n"


def load_skill(path: str) -> Skill:
    """Parse a single SKILL.md file."""
    with open(path, "r", encoding="utf-8") as fh:
        data = fh.read()
    match = FRONTMATTER_RE.search(data)
    if not match:
        raise ValueError(f"{path}: missing YAML frontmatter delimited by ---")
    fm_raw = match.group(1)
    body = data[match.end():]
    fm_dict = yaml.safe_load(fm_raw) or {}
    fm = _build_frontmatter(fm_dict)
    return Skill(path=path, frontmatter=fm, body=body)


def load_all(dir: str) -> List[Skill]:
    """Walk a `skills/` directory tree and return every parsed SKILL.md."""
    skills: List[Skill] = []
    for root, _, files in os.walk(dir):
        for name in files:
            if name == "SKILL.md":
                skills.append(load_skill(os.path.join(root, name)))
    skills.sort(key=lambda s: s.frontmatter.id)
    return skills


def extract(skill: Skill, tier: str) -> str:
    """Convenience function so callers can use a flat API."""
    return skill.extract(tier)


def _build_frontmatter(d: dict) -> Frontmatter:
    fm = Frontmatter()
    fm.id = str(d.get("id", ""))
    fm.version = str(d.get("version", ""))
    fm.title = str(d.get("title", ""))
    fm.description = str(d.get("description", ""))
    fm.category = str(d.get("category", ""))
    fm.severity = str(d.get("severity", ""))
    fm.applies_to = _as_list(d.get("applies_to"))
    fm.languages = _as_list(d.get("languages"))
    fm.related_skills = _as_list(d.get("related_skills"))
    fm.sources = _as_list(d.get("sources"))
    fm.rules_path = str(d.get("rules_path", ""))
    fm.last_updated = str(d.get("last_updated", ""))
    tb = d.get("token_budget") or {}
    if isinstance(tb, dict):
        fm.token_budget = TokenBudget(
            minimal=int(tb.get("minimal", 0) or 0),
            compact=int(tb.get("compact", 0) or 0),
            full=int(tb.get("full", 0) or 0),
        )
    return fm


def _as_list(value) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, Iterable):
        return [str(v) for v in value]
    return [str(value)]


_HEADING_RE = re.compile(r"^(#{2,3})\s+(.+?)\s*$", re.MULTILINE)


def _split_sections(body: str) -> dict:
    """Split the markdown body into a {heading: content} dictionary keyed by
    the trimmed heading text. Both ## and ### are tracked so callers can ask
    for either rule subsections (### ALWAYS) or top-level (## References).

    Duplicate headings are merged with a blank line between blocks instead of
    being silently overwritten. This matches the Go parser, which appends
    bullets across duplicate `### ALWAYS` / `### NEVER` subsections into the
    same list, and ensures all three SDKs (Go, Python, TypeScript) agree on
    what a malformed SKILL.md contains.
    """
    sections: dict = {}
    matches = list(_HEADING_RE.finditer(body))
    for i, m in enumerate(matches):
        heading = m.group(2).strip()
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(body)
        content = body[start:end].strip()
        if heading in sections:
            if content:
                sections[heading] = sections[heading] + "\n\n" + content
        else:
            sections[heading] = content
    return sections
