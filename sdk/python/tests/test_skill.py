import os
import pathlib

import pytest

skillslib = pytest.importorskip("skillslib")


def repo_root() -> str:
    here = pathlib.Path(__file__).resolve().parent
    for ancestor in [here, *here.parents]:
        if (ancestor / "skills").is_dir() and (ancestor / "manifest.json").exists():
            return str(ancestor)
    pytest.skip("could not locate repo root")
    return ""


def test_load_secret_detection():
    root = repo_root()
    s = skillslib.load_skill(os.path.join(root, "skills", "secret-detection", "SKILL.md"))
    assert s.frontmatter.id == "secret-detection"
    assert s.frontmatter.version
    assert s.frontmatter.token_budget.minimal > 0


def test_load_all_finds_at_least_20():
    root = repo_root()
    skills = skillslib.load_all(os.path.join(root, "skills"))
    assert len(skills) >= 20


def test_validate_passes_for_real_skill():
    root = repo_root()
    s = skillslib.load_skill(os.path.join(root, "skills", "secret-detection", "SKILL.md"))
    errs = skillslib.validate(s)
    assert errs == []


def test_extract_tiers_are_ordered():
    root = repo_root()
    s = skillslib.load_skill(os.path.join(root, "skills", "secret-detection", "SKILL.md"))
    mini = skillslib.extract(s, "minimal")
    compact = skillslib.extract(s, "compact")
    full = skillslib.extract(s, "full")
    assert mini and compact and full
    assert len(compact) >= len(mini)
    assert len(full) >= len(compact)


def test_extract_rejects_unknown_tier():
    root = repo_root()
    s = skillslib.load_skill(os.path.join(root, "skills", "secret-detection", "SKILL.md"))
    with pytest.raises(ValueError):
        s.extract("ginormous")


def test_extract_merges_duplicate_heading_sections():
    """Regression for L1: a SKILL.md with two `### ALWAYS` blocks must
    surface bullets from BOTH blocks under the minimal tier. The previous
    implementation silently overwrote the first block with the second,
    losing bullets and disagreeing with the Go parser, which appends.
    """
    body = (
        "## Rules\n\n"
        "### ALWAYS\n\n"
        "- first-always-bullet-marker\n\n"
        "### NEVER\n\n"
        "- only-never-bullet-marker\n\n"
        "### ALWAYS\n\n"
        "- second-always-bullet-marker\n"
    )
    s = skillslib.Skill(
        path="/tmp/fake-skill",
        frontmatter=skillslib.Frontmatter(),
        body=body,
    )
    out = s.extract("minimal")
    assert "first-always-bullet-marker" in out, out
    assert "second-always-bullet-marker" in out, out
    assert "only-never-bullet-marker" in out, out
