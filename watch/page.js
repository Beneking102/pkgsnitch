// Turns the JSON of `pkgsnitch watch` into a self-contained HTML page.
//
//   node watch/page.js <watch.json> <output-directory>
//
// Everything shown comes from observed packages and is therefore escaped:
// a package must not be able to put markup on this page.
const fs = require('fs');
const path = require('path');

const [input, outDir] = process.argv.slice(2);
const plan = JSON.parse(fs.readFileSync(input, 'utf8'));
const date = new Date().toISOString().slice(0, 10);
const REPO = 'https://github.com/Beneking102/pkgsnitch';

const esc = (value) =>
  String(value ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

const RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

// What a reader needs to know about one package this week.
function status(outcome) {
  if (outcome.error) return { key: 'unknown', label: 'not observed' };
  const verdict = outcome.report.verdict;
  if (RANK[verdict] >= 3) return { key: 'look', label: 'needs a look' };
  if (verdict === 'medium') return { key: 'new', label: 'new behavior' };
  return { key: 'clean', label: 'nothing new' };
}

const outcomes = plan.outcomes
  .map((outcome) => ({ outcome, state: status(outcome) }))
  .sort((a, b) => {
    const rank = (x) => (x.outcome.error ? -1 : RANK[x.outcome.report.verdict]);
    return rank(b) - rank(a) || a.outcome.name.localeCompare(b.outcome.name);
  });
const count = (key) => outcomes.filter((o) => o.state.key === key).length;

function findings(outcome) {
  if (outcome.error) return `<p class="error">${esc(outcome.error)}</p>`;
  const shown = outcome.report.findings.filter((f) => f.change !== 'removed' && f.severity !== 'info');
  if (shown.length === 0) return '<p class="quiet">Nothing the previous release did not already do.</p>';
  return shown
    .map(
      (f) => `<div class="finding">
  <span class="sev ${esc(f.severity)}">${esc(f.severity)}</span>
  <span class="phase">${esc(f.phase || 'manifest')}</span>
  <b>${esc(f.title)}</b> <code>${esc(f.target)}</code>
  ${f.actor ? `<div class="by">by <code>${esc(f.actor)}</code></div>` : ''}
  ${f.evidence ? `<div class="seen">seen: <code>${esc(f.evidence)}</code></div>` : ''}
</div>`
    )
    .join('\n');
}

const rows = outcomes
  .map(({ outcome, state }) => {
    const registry = outcome.ecosystem === 'pypi' ? 'PyPI' : 'npm';
    return `<details class="pkg ${state.key}">
  <summary>
    <span class="state">${esc(state.label)}</span>
    <span class="name">${esc(outcome.name)}</span>
    <span class="eco">${registry}</span>
    <span class="ver">${esc(outcome.from)} &rarr; ${esc(outcome.to)}</span>
    <span class="bump">${esc(outcome.bump)}</span>
  </summary>
  <div class="body">${findings(outcome)}</div>
</details>`;
  })
  .join('\n');

const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>pkgsnitch watch</title>
<meta name="description" content="What the latest release of widely used npm and PyPI packages does that the one before did not.">
<style>
  :root { --bg:#fbfbfa; --fg:#1c1c1a; --dim:#6b6b66; --line:#e3e3df; --card:#fff; --ok:#2f7d4f; --new:#b7791f; --look:#c0392b; --code:#f1f1ee; }
  @media (prefers-color-scheme: dark) { :root { --bg:#161615; --fg:#ececea; --dim:#9a9a94; --line:#2c2c2a; --card:#1e1e1d; --ok:#5fbf85; --new:#e0a94a; --look:#ef6f61; --code:#262624; } }
  * { box-sizing: border-box; }
  body { margin:0; background:var(--bg); color:var(--fg); font:16px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; }
  main { max-width: 60rem; margin: 0 auto; padding: 2.5rem 1rem 4rem; }
  h1 { font-size: 1.9rem; margin: 0 0 .3rem; letter-spacing: -.01em; }
  .lead { color: var(--dim); margin: 0 0 1.6rem; max-width: 44rem; }
  a { color: inherit; }
  .counts { display:flex; flex-wrap:wrap; gap:.6rem; margin: 0 0 1.6rem; }
  .counts div { background:var(--card); border:1px solid var(--line); border-radius:.6rem; padding:.6rem .9rem; min-width:8.5rem; }
  .counts b { display:block; font-size:1.5rem; line-height:1.2; }
  .counts span { color:var(--dim); font-size:.85rem; }
  .pkg { background:var(--card); border:1px solid var(--line); border-radius:.6rem; margin:.4rem 0; }
  summary { cursor:pointer; padding:.6rem .9rem; display:flex; flex-wrap:wrap; gap:.3rem .9rem; align-items:baseline; list-style:none; }
  summary::-webkit-details-marker { display:none; }
  .state { font-size:.78rem; font-weight:600; text-transform:uppercase; letter-spacing:.04em; min-width:7.5rem; }
  .clean .state { color:var(--ok); } .new .state { color:var(--new); } .look .state { color:var(--look); } .unknown .state { color:var(--dim); }
  .name { font-weight:600; }
  .eco, .bump, .ver { color:var(--dim); font-size:.88rem; }
  .ver { margin-left:auto; font-variant-numeric: tabular-nums; }
  .body { border-top:1px solid var(--line); padding:.8rem .9rem; }
  .finding { padding:.45rem 0; border-bottom:1px dashed var(--line); overflow-wrap:anywhere; }
  .finding:last-child { border-bottom:0; }
  .sev { font-size:.72rem; font-weight:700; text-transform:uppercase; padding:.1rem .4rem; border-radius:.3rem; border:1px solid currentColor; }
  .sev.critical, .sev.high { color:var(--look); } .sev.medium { color:var(--new); } .sev.low { color:var(--dim); }
  .phase { color:var(--dim); font-size:.85rem; margin: 0 .3rem; }
  code { background:var(--code); padding:.05rem .3rem; border-radius:.25rem; font:.85em ui-monospace, SFMono-Regular, Consolas, monospace; }
  .by, .seen { color:var(--dim); font-size:.88rem; margin-top:.2rem; }
  .quiet, .error { color:var(--dim); margin:0; }
  footer { color:var(--dim); font-size:.9rem; margin-top:2.2rem; border-top:1px solid var(--line); padding-top:1.2rem; }
  footer p { max-width: 46rem; }
</style>
</head>
<body>
<main>
  <h1>pkgsnitch watch</h1>
  <p class="lead">What the latest release of ${outcomes.length} widely used npm and PyPI packages does at install and import time that the release before it did not. Observed on ${date} with <a href="${REPO}">pkgsnitch</a>.</p>
  <div class="counts">
    <div><b>${count('clean')}</b><span>nothing new</span></div>
    <div><b>${count('new')}</b><span>new behavior</span></div>
    <div><b>${count('look')}</b><span>needs a look</span></div>
    <div><b>${count('unknown')}</b><span>not observed</span></div>
  </div>
${rows}
  <footer>
    <p><b>How to read this.</b> Each package ran twice in a sandbox, once per version, under <code>strace</code> and without network. Only what the newer version adds is listed. New behavior is a fact about what the code did, not a judgment: a release that starts a helper process or adds a dependency has a reason more often than not. &ldquo;Needs a look&rdquo; means network activity, a read of a planted credential, or a new install script.</p>
    <p>A clean entry means nothing new was observed during install and import, not that a release is safe. See <a href="${REPO}#how-it-knows">how it knows</a> and <a href="${REPO}#limits">its limits</a>. The raw data is in <a href="watch.json">watch.json</a>.</p>
  </footer>
</main>
</body>
</html>
`;

fs.mkdirSync(outDir, { recursive: true });
fs.writeFileSync(path.join(outDir, 'index.html'), html);
fs.copyFileSync(input, path.join(outDir, 'watch.json'));
console.log(`${outcomes.length} packages: ${count('clean')} nothing new, ${count('new')} new behavior, ${count('look')} need a look, ${count('unknown')} not observed`);
