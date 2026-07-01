import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { dirname, join, resolve } from "node:path";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { loadSkill, loadAll, extract, validate, Skill } from "../src/index.js";

function repoRoot(): string {
  const here = dirname(fileURLToPath(import.meta.url));
  let dir = resolve(here);
  while (dir !== "/" && dir.length > 1) {
    if (
      existsSync(join(dir, "manifest.json")) &&
      existsSync(join(dir, "skills"))
    ) {
      return dir;
    }
    dir = dirname(dir);
  }
  throw new Error("could not locate repo root from " + here);
}

describe("skillslib", () => {
  const root = repoRoot();

  it("loads secret-detection", () => {
    const s = loadSkill(join(root, "skills", "secret-detection", "SKILL.md"));
    assert.equal(s.frontmatter.id, "secret-detection");
    assert.ok(s.frontmatter.version);
    assert.ok(s.frontmatter.token_budget.minimal > 0);
  });

  it("loads at least 20 skills", () => {
    const all = loadAll(join(root, "skills"));
    assert.ok(all.length >= 20, `expected >= 20 skills, got ${all.length}`);
  });

  it("validates a real skill with no errors", () => {
    const s = loadSkill(join(root, "skills", "secret-detection", "SKILL.md"));
    assert.deepEqual(validate(s), []);
  });

  it("orders tiers minimal <= compact <= full", () => {
    const s = loadSkill(join(root, "skills", "secret-detection", "SKILL.md"));
    const mini = extract(s, "minimal");
    const compact = extract(s, "compact");
    const full = extract(s, "full");
    assert.ok(mini.length > 0);
    assert.ok(compact.length >= mini.length);
    assert.ok(full.length >= compact.length);
  });

  it("rejects unknown tier", () => {
    const s = loadSkill(join(root, "skills", "secret-detection", "SKILL.md"));
    assert.throws(() => extract(s, "ginormous" as never));
  });

  // Regression for L1: two `### ALWAYS` blocks in a single SKILL.md must
  // surface bullets from BOTH blocks under the minimal tier. The previous
  // splitSections silently overwrote the first block with the second,
  // losing bullets and disagreeing with the Go parser, which appends.
  it("merges duplicate ### headings instead of silently overwriting", () => {
    const body = [
      "## Rules",
      "",
      "### ALWAYS",
      "",
      "- first-always-bullet-marker",
      "",
      "### NEVER",
      "",
      "- only-never-bullet-marker",
      "",
      "### ALWAYS",
      "",
      "- second-always-bullet-marker",
      "",
    ].join("\n");
    const s: Skill = {
      path: "/tmp/fake-skill",
      body,
      frontmatter: {
        id: "",
        version: "",
        title: "",
        description: "",
        category: "",
        severity: "",
        applies_to: [],
        languages: [],
        related_skills: [],
        sources: [],
        last_updated: "",
        token_budget: { minimal: 0, compact: 0, full: 0 },
      },
    };
    const out = extract(s, "minimal");
    assert.ok(out.includes("first-always-bullet-marker"), out);
    assert.ok(out.includes("second-always-bullet-marker"), out);
    assert.ok(out.includes("only-never-bullet-marker"), out);
  });
});
