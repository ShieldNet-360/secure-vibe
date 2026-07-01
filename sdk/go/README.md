# SecureVibe — Go SDK

`skillslib` is the public Go SDK for **SecureVibe** (Go module path
`github.com/shieldnet-360/secure-vibe`).

It is a thin re-export of `internal/skill` so downstream Go programs can load
and validate skills without depending on internal packages.

## Install

```bash
go get github.com/shieldnet-360/secure-vibe/sdk/go
```

## Quick start

```go
package main

import (
    "fmt"

    skillslib "github.com/shieldnet-360/secure-vibe/sdk/go"
)

func main() {
    s, err := skillslib.LoadSkill("skills/secret-detection/SKILL.md")
    if err != nil {
        panic(err)
    }
    if errs := skillslib.Validate(s); len(errs) != 0 {
        panic(errs)
    }
    fmt.Println(skillslib.Extract(s, skillslib.TierCompact))
}
```

## API

- `LoadSkill(path string) (*Skill, error)` — parse a single SKILL.md file.
- `LoadAll(dir string) ([]*Skill, error)` — walk a `skills/` directory.
- `Validate(s *Skill) []error` — same checks as `secure-vibe dev validate`.
- `Extract(s *Skill, tier Tier) string` — render a tier-specific body.

Tier constants: `TierMinimal`, `TierCompact`, `TierFull`.

## License

MIT — same as the parent repository. Copyright (c) 2024-2026
[ShieldNet360](https://www.shieldnet360.com).
