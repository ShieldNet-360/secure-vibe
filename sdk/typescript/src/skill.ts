import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import * as yaml from "js-yaml";

export type Tier = "minimal" | "compact" | "full";
export const VALID_TIERS: Tier[] = ["minimal", "compact", "full"];

export interface TokenBudget {
  minimal: number;
  compact: number;
  full: number;
}

export interface Frontmatter {
  id: string;
  version: string;
  title: string;
  description: string;
  category: string;
  severity: string;
  applies_to: string[];
  languages: string[];
  token_budget: TokenBudget;
  rules_path?: string;
  related_skills: string[];
  last_updated: string;
  sources: string[];
}

export interface Skill {
  path: string;
  frontmatter: Frontmatter;
  body: string;
}

const FRONTMATTER_RE = /^---\s*\n([\s\S]*?)\n---\s*(?:\n|$)/;

/** Parse a single SKILL.md file from disk. */
export function loadSkill(path: string): Skill {
  const data = readFileSync(path, "utf-8");
  const match = FRONTMATTER_RE.exec(data);
  if (!match) {
    throw new Error(`${path}: missing YAML frontmatter delimited by ---`);
  }
  const fmRaw = match[1];
  const body = data.slice(match[0].length);
  const fmDict = yaml.load(fmRaw) as Record<string, unknown> | null;
  return {
    path,
    body,
    frontmatter: buildFrontmatter(fmDict ?? {}),
  };
}

/** Walk a `skills/` directory and return every parsed SKILL.md. */
export function loadAll(dir: string): Skill[] {
  const out: Skill[] = [];
  walk(dir, (file) => {
    if (file.endsWith("/SKILL.md") || file.endsWith("\\SKILL.md")) {
      out.push(loadSkill(file));
    }
  });
  out.sort((a, b) => a.frontmatter.id.localeCompare(b.frontmatter.id));
  return out;
}

/** Render the SKILL body for the given tier (minimal | compact | full). */
export function extract(skill: Skill, tier: Tier): string {
  if (!VALID_TIERS.includes(tier)) {
    throw new Error(`invalid tier ${tier} (valid: ${VALID_TIERS.join(", ")})`);
  }
  if (tier === "full") return skill.body;
  const sections = splitSections(skill.body);
  const parts: string[] = [];
  if (sections.ALWAYS) parts.push("### ALWAYS\n\n" + sections.ALWAYS);
  if (sections.NEVER) parts.push("### NEVER\n\n" + sections.NEVER);
  if (tier === "compact") {
    const kfp = sections["KNOWN FALSE POSITIVES"];
    const refs = sections.References;
    if (kfp) parts.push("### KNOWN FALSE POSITIVES\n\n" + kfp);
    if (refs) parts.push("## References\n\n" + refs);
  }
  return parts.join("\n\n").replace(/\s+$/, "") + "\n";
}

function buildFrontmatter(d: Record<string, unknown>): Frontmatter {
  const tb = (d.token_budget ?? {}) as Record<string, unknown>;
  return {
    id: String(d.id ?? ""),
    version: String(d.version ?? ""),
    title: String(d.title ?? ""),
    description: String(d.description ?? ""),
    category: String(d.category ?? ""),
    severity: String(d.severity ?? ""),
    applies_to: asList(d.applies_to),
    languages: asList(d.languages),
    related_skills: asList(d.related_skills),
    sources: asList(d.sources),
    rules_path: d.rules_path ? String(d.rules_path) : undefined,
    last_updated: String(d.last_updated ?? ""),
    token_budget: {
      minimal: Number(tb.minimal ?? 0),
      compact: Number(tb.compact ?? 0),
      full: Number(tb.full ?? 0),
    },
  };
}

function asList(v: unknown): string[] {
  if (v == null) return [];
  if (typeof v === "string") return [v];
  if (Array.isArray(v)) return v.map((x) => String(x));
  return [String(v)];
}

function walk(dir: string, visit: (file: string) => void): void {
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return;
  }
  for (const name of entries) {
    const full = join(dir, name);
    let st;
    try {
      st = statSync(full);
    } catch {
      continue;
    }
    if (st.isDirectory()) {
      walk(full, visit);
    } else {
      visit(full);
    }
  }
}

const HEADING_RE = /^(#{2,3})\s+(.+?)\s*$/gm;

// splitSections splits the markdown body into a { heading: content } map
// keyed by the trimmed heading text. Both ## and ### are tracked so callers
// can ask for either rule subsections (### ALWAYS) or top-level (## References).
//
// Duplicate headings are merged with a blank line between blocks instead of
// being silently overwritten. This matches the Go parser, which appends
// bullets across duplicate `### ALWAYS` / `### NEVER` subsections into the
// same list, and ensures all three SDKs (Go, Python, TypeScript) agree on
// what a malformed SKILL.md contains.
function splitSections(body: string): Record<string, string> {
  const out: Record<string, string> = {};
  const matches: {
    heading: string;
    matchStart: number;
    contentStart: number;
    end: number;
  }[] = [];
  let m: RegExpExecArray | null;
  HEADING_RE.lastIndex = 0;
  while ((m = HEADING_RE.exec(body)) !== null) {
    matches.push({
      heading: m[2].trim(),
      matchStart: m.index,
      contentStart: m.index + m[0].length,
      end: body.length,
    });
  }
  for (let i = 0; i < matches.length; i++) {
    if (i + 1 < matches.length) {
      matches[i].end = matches[i + 1].matchStart;
    }
    const heading = matches[i].heading;
    const content = body
      .slice(matches[i].contentStart, matches[i].end)
      .trim();
    if (Object.prototype.hasOwnProperty.call(out, heading)) {
      if (content) {
        out[heading] = out[heading] + "\n\n" + content;
      }
    } else {
      out[heading] = content;
    }
  }
  return out;
}
