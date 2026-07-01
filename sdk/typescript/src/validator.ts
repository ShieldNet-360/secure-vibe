import type { Skill } from "./skill.js";

const SKILL_ID_RE = /^[a-z][a-z0-9-]{1,63}$/;
const SEMVER_RE = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const CATEGORIES = new Set([
  "prevention",
  "hardening",
  "detection",
  "compliance",
  "supply-chain",
]);
const SEVERITIES = new Set(["low", "medium", "high", "critical"]);

/**
 * Return a list of human-readable validation errors. An empty list means
 * the skill is valid.
 */
export function validate(skill: Skill | null | undefined): string[] {
  if (!skill) return ["skill is null"];
  const errs: string[] = [];
  const fm = skill.frontmatter;
  if (!SKILL_ID_RE.test(fm.id)) {
    errs.push(`id ${JSON.stringify(fm.id)} must match ^[a-z][a-z0-9-]{1,63}$`);
  }
  if (!SEMVER_RE.test(fm.version)) {
    errs.push(`version ${JSON.stringify(fm.version)} is not valid semver`);
  }
  if (!fm.title) errs.push("title is required");
  if (!fm.description) errs.push("description is required");
  if (!CATEGORIES.has(fm.category)) {
    errs.push(
      `category ${JSON.stringify(fm.category)} must be one of ${[...CATEGORIES].sort()}`,
    );
  }
  if (!SEVERITIES.has(fm.severity)) {
    errs.push(
      `severity ${JSON.stringify(fm.severity)} must be one of ${[...SEVERITIES].sort()}`,
    );
  }
  if (!fm.languages.length) {
    errs.push("languages must list at least one language id (or ['*'])");
  }
  if (fm.token_budget.minimal <= 0) errs.push("token_budget.minimal must be > 0");
  if (fm.token_budget.compact <= 0) errs.push("token_budget.compact must be > 0");
  if (fm.token_budget.full <= 0) errs.push("token_budget.full must be > 0");
  if (!fm.last_updated) errs.push("last_updated is required");
  if (!skill.body.trim()) errs.push("SKILL body is empty");
  return errs;
}
