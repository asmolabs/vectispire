// The load scenario: people, pipelines and agents against one control plane, at one concurrency.
//
// Run by `load/run.sh`, which passes the level and the seed's output; on its own:
//   docker run --rm -i --network host -v "$PWD/load:/load" -e VUS=10 -e DURATION=90s \
//     grafana/k6@sha256:… run /load/k6/scenario.js
//
// **A closed model for people, an open one for machines.** `VUS` people each loop over the screens
// they open — the issue list, a detail, a triage, the dashboards — with a think time between two
// clicks (THINK, a second by default, jittered), so a level of 50 is fifty people working, not fifty
// threads hammering. Pipelines and agents arrive at a rate of their own, independent of how slow the
// server answers, as they do in production: a gate call per pipeline run, scans finishing as the
// queue drains. Each request is tagged with its route, and the summary carries p50/p95/p99 per tag.
import http from 'k6/http';
import { check, sleep } from 'k6';
import { SharedArray } from 'k6/data';
import exec from 'k6/execution';
import { Counter } from 'k6/metrics';

const SEED = JSON.parse(open(__ENV.SEED_FILE || '/load/.state/seed.json'));
const BASE = __ENV.BASE || SEED.base;
const VUS = parseInt(__ENV.VUS || '10', 10);
const DURATION = __ENV.DURATION || '90s';
const THINK = parseFloat(__ENV.THINK || '1');
// Pipelines and agents: per second. Zero switches the scenario off.
const GATE_RATE = parseFloat(__ENV.GATE_RATE || '2');
const LOGIN_RATE = parseFloat(__ENV.LOGIN_RATE || '0.5');
const SCAN_RATE = parseFloat(__ENV.SCAN_RATE || '0.2');
const AGENTS = parseInt(__ENV.AGENTS || '4', 10);

// The result bodies an agent hands back, one per target, written by `seed/bodies.py`.
const BODIES = new SharedArray('bodies', () => {
  try {
    return JSON.parse(open(__ENV.BODIES_FILE || '/load/.state/bodies.json'));
  } catch (e) {
    return [];
  }
});

const errors = new Counter('route_errors');

const ROUTES = [
  'login', 'issues_admin', 'issues_admin_filtered', 'issues_admin_search', 'issues_admin_deep_page',
  'issues_reader', 'issues_reader_filtered', 'issue_detail', 'issue_triage', 'dashboard', 'dashboard_trends',
  'posture_analytics', 'security_overview', 'scorecards_global', 'scorecard_repository', 'repositories', 'containers',
  'scans', 'inventory_search', 'licenses_summary', 'licenses_inventory', 'owasp_coverage', 'remediation_debt',
  'export_csv', 'gate', 'scan_trigger', 'agent_claim', 'agent_result',
];

const scenarios = {
  people: { executor: 'constant-vus', vus: VUS, duration: DURATION, exec: 'person' },
};
if (GATE_RATE > 0) {
  scenarios.pipelines = {
    executor: 'constant-arrival-rate', rate: Math.round(GATE_RATE * 10), timeUnit: '10s', duration: DURATION,
    preAllocatedVUs: 20, maxVUs: 200, exec: 'pipeline',
  };
}
if (LOGIN_RATE > 0) {
  scenarios.signins = {
    executor: 'constant-arrival-rate', rate: Math.round(LOGIN_RATE * 10), timeUnit: '10s', duration: DURATION,
    preAllocatedVUs: 5, maxVUs: 50, exec: 'signin',
  };
}
if (SCAN_RATE > 0 && BODIES.length > 0) {
  scenarios.scan_triggers = {
    executor: 'constant-arrival-rate', rate: Math.max(1, Math.round(SCAN_RATE * 60)), timeUnit: '60s',
    duration: DURATION, preAllocatedVUs: 2, maxVUs: 20, exec: 'trigger',
  };
  scenarios.agents = { executor: 'constant-vus', vus: AGENTS, duration: DURATION, exec: 'agent' };
}

const thresholds = { route_errors: ['count>=0'] };
for (const r of ROUTES) {
  // Never failing: present only so the summary carries a line per route.
  thresholds[`http_req_duration{route:${r}}`] = ['max>=0'];
  thresholds[`http_reqs{route:${r}}`] = ['count>=0'];
  thresholds[`http_req_failed{route:${r}}`] = ['rate>=0'];
}

export const options = {
  scenarios,
  thresholds,
  summaryTrendStats: ['avg', 'med', 'p(95)', 'p(99)', 'max', 'count'],
  discardResponseBodies: false,
  setupTimeout: '300s',
  // The agent's long poll answers after its wait; the export can take long on a large target.
};

function signIn(username, password) {
  const res = http.post(`${BASE}/api/v1/auth/login`, JSON.stringify({ username, password }), {
    headers: { 'Content-Type': 'application/json' }, tags: { route: 'login' },
  });
  if (res.status !== 200) {
    throw new Error(`sign-in of ${username} answered ${res.status}: ${res.body}`);
  }
  return res.json('token');
}

export function setup() {
  const admin = signIn(SEED.admin, SEED.password);
  const lead = signIn(SEED.lead, SEED.password);
  const readers = SEED.readers.slice(0, 12).map((u) => ({ username: u, token: signIn(u, SEED.password) }));
  const auth = { headers: { Authorization: `Bearer ${admin}` } };
  // Issues to open and triage: the first pages of the open backlog, as people would find them.
  const ids = [];
  for (let offset = 0; offset < 2000; offset += 500) {
    const page = http.get(`${BASE}/api/v1/issues?state=open&limit=500&offset=${offset}`, auth).json('items');
    page.forEach((i) => ids.push(i.id));
  }
  const readerIssues = readers.map((r) => http
    .get(`${BASE}/api/v1/issues?state=open&limit=100`, { headers: { Authorization: `Bearer ${r.token}` } })
    .json('items').map((i) => i.id));
  const total = http.get(`${BASE}/api/v1/issues?state=open&limit=1`, auth).json('total');
  return { admin, lead, readers, ids, readerIssues, total };
}

function get(path, token, route) {
  const res = http.get(`${BASE}${path}`, { headers: { Authorization: `Bearer ${token}` }, tags: { route }, timeout: '120s' });
  record(res, route);
  return res;
}

function record(res, route, ok = [200]) {
  const good = ok.includes(res.status);
  if (!good) {
    errors.add(1, { route, status: String(res.status) });
  }
  check(res, { [`${route} ${ok.join('/')}`]: () => good });
}

function pick(list) {
  return list[Math.floor(Math.random() * list.length)];
}

function think() {
  sleep(THINK * (0.5 + Math.random()));
}

const repos = SEED.targets.filter((t) => t.kind === 'repository');
const SEVERITIES = ['critical', 'high', 'medium', 'low'];
const TYPES = ['vulnerability', 'sast', 'license', 'iac'];

// One person's working loop. Two thirds are administrators or leads (the estate-wide screens), one third
// restricted readers who see their team's targets only — the visibility filter is on every one of their
// queries, and that is the path that has been slow before.
export function person(data) {
  const vu = exec.vu.idInTest;
  const reader = vu % 3 === 0;
  if (reader) {
    const me = data.readers[vu % data.readers.length];
    const mine = data.readerIssues[vu % data.readers.length];
    get('/api/v1/issues?state=open&limit=50&offset=0', me.token, 'issues_reader');
    think();
    get(`/api/v1/issues?state=open&severity=${pick(SEVERITIES)}&limit=50`, me.token, 'issues_reader_filtered');
    think();
    if (mine.length) {
      get(`/api/v1/issues/${pick(mine)}`, me.token, 'issue_detail');
      think();
    }
    get('/api/v1/dashboard', me.token, 'dashboard');
    think();
    get('/api/v1/repositories?limit=50', me.token, 'repositories');
    think();
    return;
  }
  const token = vu % 3 === 1 ? data.admin : data.lead;
  const step = exec.vu.iterationInScenario % 4;
  get('/api/v1/issues?state=open&limit=50&offset=0', token, 'issues_admin');
  think();
  get(`/api/v1/issues?state=open&severity=${pick(SEVERITIES)}&type=${pick(TYPES)}&limit=50`, token, 'issues_admin_filtered');
  think();
  const id = pick(data.ids);
  get(`/api/v1/issues/${id}`, token, 'issue_detail');
  think();
  if (vu % 3 === 2) {
    // A lead's decision. Alternating statuses so each one writes a history entry.
    const status = Math.random() < 0.5 ? 'AFFECTED' : 'UNDER_REVIEW';
    const res = http.post(`${BASE}/api/v1/issues/${id}/triage`, JSON.stringify({ status, comment: 'load test' }), {
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, tags: { route: 'issue_triage' },
    });
    record(res, 'issue_triage');
    think();
  }
  switch (step) {
    case 0:
      get('/api/v1/dashboard', token, 'dashboard');
      think();
      get('/api/v1/dashboard/trends?days=30', token, 'dashboard_trends');
      think();
      get('/api/v1/security/overview', token, 'security_overview');
      think();
      get(`/api/v1/issues?state=open&search=${pick(['CVE-2024', 'sqli', 'org.', 'xss'])}&limit=50`, token, 'issues_admin_search');
      break;
    case 1:
      get('/api/v1/scorecards/global', token, 'scorecards_global');
      think();
      get(`/api/v1/scorecards/repositories/${pick(repos).id}`, token, 'scorecard_repository');
      think();
      get('/api/v1/dashboard/posture-analytics?days=30', token, 'posture_analytics');
      think();
      get(`/api/v1/issues?state=open&limit=50&offset=${Math.floor(Math.random() * Math.max(1, data.total - 50))}`, token, 'issues_admin_deep_page');
      break;
    case 2:
      get(`/api/v1/inventory/search?name=${pick(['ar', 'bel', 'cor', 'org.dax', 'zen'])}`, token, 'inventory_search');
      think();
      get('/api/v1/licenses/summary', token, 'licenses_summary');
      think();
      get('/api/v1/licenses/inventory?limit=100', token, 'licenses_inventory');
      think();
      get('/api/v1/owasp/coverage', token, 'owasp_coverage');
      break;
    default:
      get('/api/v1/containers?limit=100', token, 'containers');
      think();
      get('/api/v1/scans?limit=50', token, 'scans');
      think();
      get('/api/v1/remediation/debt', token, 'remediation_debt');
      think();
      get(`/api/v1/targets/repository/${pick(repos).id}/issues.csv`, token, 'export_csv');
  }
  think();
}

// A pipeline's gate call, with the key restricted to its repository.
export function pipeline() {
  const key = pick(SEED.gate_keys);
  const res = http.post(`${BASE}/api/v1/gate`, JSON.stringify({ repository_id: key.repository_id, fail_on_severity: 'critical' }), {
    headers: { Authorization: `Bearer ${key.secret}`, 'Content-Type': 'application/json' }, tags: { route: 'gate' }, timeout: '60s',
  });
  record(res, 'gate');
}

export function signin() {
  const user = pick(SEED.readers);
  const res = http.post(`${BASE}/api/v1/auth/login`, JSON.stringify({ username: user, password: SEED.password }), {
    headers: { 'Content-Type': 'application/json' }, tags: { route: 'login' },
  });
  record(res, 'login');
  if (res.status === 200) {
    // Sign out again: a load run must not leave thousands of open sessions behind it.
    http.del(`${BASE}/api/v1/auth/session`, null, { headers: { Authorization: `Bearer ${res.json('token')}` }, tags: { route: 'logout' } });
  }
}

// Somebody (or a schedule) asks for a scan; the agents below pick it up.
export function trigger(data) {
  const t = pick(SEED.targets);
  const path = `/api/v1/${t.kind === 'repository' ? 'repositories' : 'containers'}/${t.id}/scan`;
  const res = http.post(`${BASE}${path}`, null, { headers: { Authorization: `Bearer ${data.admin}` }, tags: { route: 'scan_trigger' } });
  // 409: a scan of that target is already queued — the trigger is refused, not an error of the server.
  record(res, 'scan_trigger', [200, 409]);
}

export function agent() {
  const auth = { Authorization: `Bearer ${SEED.agent_secret}` };
  const claim = http.get(`${BASE}/api/v1/agent/jobs?wait=5`, { headers: auth, tags: { route: 'agent_claim' }, timeout: '30s' });
  record(claim, 'agent_claim', [200, 204]);
  if (claim.status !== 200) {
    return;
  }
  const scanId = claim.json('scanId');
  const target = claim.json('task.target');
  const match = target.kind === 'repository'
    ? `repository|${target.url}`
    : `image|${target.reference.imageName}|${target.reference.tag}`;
  const body = bodyFor(match);
  const res = http.post(`${BASE}/api/v1/agent/jobs/${scanId}/result`, body, {
    headers: Object.assign({ 'Content-Type': 'application/json' }, auth), tags: { route: 'agent_result' }, timeout: '300s',
  });
  record(res, 'agent_result');
}

let index = null;
function bodyFor(match) {
  if (index === null) {
    index = {};
    for (let i = 0; i < BODIES.length; i++) {
      index[BODIES[i].match] = i;
    }
  }
  return BODIES[index[match]].body;
}

export function handleSummary(data) {
  const out = {};
  out[__ENV.SUMMARY_FILE || '/load/results/summary.json'] = JSON.stringify(data, null, 1);
  out.stdout = textTable(data);
  return out;
}

function textTable(data) {
  const lines = [`level VUS=${VUS} duration=${DURATION} think=${THINK}s`,
    'route                      count     rps   p50ms   p95ms   p99ms   maxms  failed'];
  for (const r of ROUTES) {
    const d = data.metrics[`http_req_duration{route:${r}}`];
    const n = data.metrics[`http_reqs{route:${r}}`];
    const f = data.metrics[`http_req_failed{route:${r}}`];
    if (!d || !n || n.values.count === 0) {
      continue;
    }
    const v = d.values;
    lines.push(`${r.padEnd(24)} ${String(n.values.count).padStart(7)} ${n.values.rate.toFixed(2).padStart(7)} `
      + `${v.med.toFixed(0).padStart(7)} ${v['p(95)'].toFixed(0).padStart(7)} ${v['p(99)'].toFixed(0).padStart(7)} `
      + `${v.max.toFixed(0).padStart(7)} ${(f ? (f.values.rate * 100).toFixed(2) : '0.00').padStart(6)}%`);
  }
  return lines.join('\n') + '\n';
}
