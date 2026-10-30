#!/usr/bin/env python3
"""Turns run directories into the Markdown tables of a load-test report.

  python3 load/report.py load/results/<run>[,<run>…] [--compare load/results/<other run>[,…]]

Several directories separated by commas are read as one campaign (a level re-run in a second
directory overrides the first's). With --compare, a second table gives the p95 of both campaigns side
by side. Prints to stdout.
"""
import argparse
import json
import os

ROUTES = [
    'login', 'issues_admin', 'issues_admin_filtered', 'issues_admin_search', 'issues_admin_deep_page',
    'issues_reader', 'issues_reader_filtered', 'issue_detail', 'issue_triage', 'dashboard', 'dashboard_trends',
    'posture_analytics', 'security_overview', 'scorecards_global', 'scorecard_repository', 'repositories', 'containers',
    'scans', 'inventory_search', 'licenses_summary', 'licenses_inventory', 'owasp_coverage', 'remediation_debt',
    'export_csv', 'gate', 'scan_trigger', 'agent_claim', 'agent_result',
]


def load(dirs):
    levels = {}
    for d in dirs.split(','):
        for name in sorted(os.listdir(d)):
            if name.startswith('vus-') and os.path.exists(os.path.join(d, name, 'summary.json')):
                levels[int(name[4:])] = json.load(open(os.path.join(d, name, 'summary.json')))
    return dict(sorted(levels.items()))


def route(summary, r):
    m = summary['metrics']
    d, n, f = (m.get('http_req_duration{route:%s}' % r), m.get('http_reqs{route:%s}' % r),
               m.get('http_req_failed{route:%s}' % r))
    if not d or not n or n['values']['count'] == 0:
        return None
    return {'p50': d['values']['med'], 'p95': d['values']['p(95)'], 'p99': d['values']['p(99)'],
            'rps': n['values']['rate'], 'count': n['values']['count'], 'failed': f['values']['rate'] * 100 if f else 0}


def ms(v):
    return '—' if v is None else ('%.0f' % v if v < 10000 else '%.1f s' % (v / 1000))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('runs')
    ap.add_argument('--compare')
    args = ap.parse_args()
    levels = load(args.runs)

    head = '| Route | ' + ' | '.join('%d users: p50 / p95 / p99 ms (err %%)' % v for v in levels) + ' |'
    print(head)
    print('|---|' + '---|' * len(levels))
    for r in ROUTES:
        cells = []
        for summary in levels.values():
            x = route(summary, r)
            cells.append('—' if x is None else '%s / %s / %s%s' % (
                ms(x['p50']), ms(x['p95']), ms(x['p99']), (' (%.0f %%)' % x['failed']) if x['failed'] else ''))
        print('| `%s` | %s |' % (r, ' | '.join(cells)))
    total = ['%.1f req/s' % sum(route(s, r)['rps'] for r in ROUTES if route(s, r)) for s in levels.values()]
    print('| *all routes* | %s |' % ' | '.join(total))

    if args.compare:
        before = load(args.compare)
        print()
        print('| Route | ' + ' | '.join('%d users: before → after p95 ms' % v for v in levels if v in before) + ' |')
        print('|---|' + '---|' * len([v for v in levels if v in before]))
        for r in ROUTES:
            cells = []
            for v, summary in levels.items():
                if v not in before:
                    continue
                a, b = route(summary, r), route(before[v], r)
                cells.append('%s → %s' % ('—' if b is None else ms(b['p95']) + (' (%.0f %% err)' % b['failed'] if b['failed'] else ''),
                                          '—' if a is None else ms(a['p95'])))
            print('| `%s` | %s |' % (r, ' | '.join(cells)))


if __name__ == '__main__':
    main()
