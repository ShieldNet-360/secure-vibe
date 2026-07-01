# SecureVibe — Python SDK

`skillslib` is a thin Python loader and validator for the **SecureVibe**
SKILL.md format.

## Install

```bash
pip install skillslib
```

## Quick start

```python
import skillslib

skill = skillslib.load_skill("skills/secret-detection/SKILL.md")
assert skillslib.validate(skill) == []

print(skill.extract("compact"))

# Walk a tree of skills.
all_skills = skillslib.load_all("skills")
print(len(all_skills), "skills loaded")
```

## API

- `load_skill(path) -> Skill`
- `load_all(dir) -> list[Skill]`
- `validate(skill) -> list[str]`
- `extract(skill, tier) -> str` (tier: `"minimal" | "compact" | "full"`)

## License

MIT — same as the parent repository. Copyright (c) 2024-2026
[ShieldNet360](https://www.shieldnet360.com).
