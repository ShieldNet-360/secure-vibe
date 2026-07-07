export const meta = {
  name: 'secure-vibe-audit',
  description: 'Fan secure-vibe audit across a repo, then merge + rank findings into one report',
  whenToUse: 'Run a repo-wide SecureVibe audit from Claude Code, fanning out per directory.',
  phases: [
    { title: 'Scout', detail: 'list top-level source directories to audit' },
    { title: 'Audit', detail: 'run `secure-vibe audit` per directory (parallel)' },
    { title: 'Synthesize', detail: 'merge, dedup, rank, and summarize' },
  ],
}

// Thin Claude Code front-end for `secure-vibe audit`. The real engine is the
// single Go binary — this script only fans the deterministic audit out per
// directory and synthesizes one ranked report, so it stays a convenience layer,
// not a reimplementation. Point it at a repo via args (default: current dir).
// To turn on the AI lanes, add `--model <provider>` to the audit command below
// and export SECURE_VIBE_MODEL_API_KEY (bring your own key).

const TARGET = typeof args === 'string' && args.trim() ? args.trim() : '.'

const DIRS_SCHEMA = {
  type: 'object',
  properties: {
    dirs: { type: 'array', items: { type: 'string' }, description: 'Relative paths of top-level source directories.' },
  },
  required: ['dirs'],
}

const FINDINGS_SCHEMA = {
  type: 'object',
  properties: {
    dir: { type: 'string' },
    findings: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          file_path: { type: 'string' },
          rule_id: { type: 'string' },
          severity: { type: 'string' },
          title: { type: 'string' },
          triage: { type: 'string' },
        },
        required: ['rule_id', 'severity', 'title'],
      },
    },
  },
  required: ['findings'],
}

phase('Scout')
const scout = await agent(
  `List the top-level directories under "${TARGET}" that contain application source code worth a security audit ` +
    `(skip .git, node_modules, vendor, dist, build). Use \`ls\`/\`find\`. Return relative paths.`,
  { label: 'scout', schema: DIRS_SCHEMA },
)
const dirs = scout && scout.dirs && scout.dirs.length ? scout.dirs : [TARGET]
log(`auditing ${dirs.length} director${dirs.length === 1 ? 'y' : 'ies'}`)

phase('Audit')
const perDir = await parallel(
  dirs.map((dir) => () =>
    agent(
      `Run exactly: secure-vibe audit ${dir} --format json\n` +
        `Parse the JSON stdout and return {dir:"${dir}", findings:[...]} using the "findings" array from the report ` +
        `(each item's file_path, rule_id, severity, title, triage). If the command is not found, return {dir:"${dir}", findings:[]}.`,
      { label: `audit:${dir}`, phase: 'Audit', schema: FINDINGS_SCHEMA },
    ),
  ),
)

phase('Synthesize')
// Barrier is justified: synthesis needs every directory's findings at once to
// dedup and rank across the whole repo.
const all = perDir
  .filter(Boolean)
  .flatMap((r) => (r.findings || []).map((f) => ({ ...f, dir: r.dir })))
const confirmed = all.filter((f) => !f.triage)
log(`${all.length} findings (${confirmed.length} confirmed, ${all.length - confirmed.length} triaged)`)

const summary = await agent(
  `Produce a concise, severity-ranked executive summary of this SecureVibe audit across ${dirs.length} directories. ` +
    `Lead with the confirmed critical/high findings; note the triaged (likely-fixture) count separately. ` +
    `Findings JSON:\n${JSON.stringify(confirmed).slice(0, 20000)}`,
  { label: 'synthesize' },
)

return { target: TARGET, dirs, totals: { all: all.length, confirmed: confirmed.length }, summary }
