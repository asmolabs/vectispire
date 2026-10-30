#!/usr/bin/env python3
"""The verdict on a ZAP baseline run (scripts/zap-baseline.sh): refuses a new medium or high alert,
and refuses a run that saw too little to have an opinion.

    gate.py <report.json> <seen.json> <accepted-alerts.txt>

**Why the verdict is not zap-baseline.py's own exit code.** The baseline decides per rule (`-c`
marks a rule FAIL, WARN or IGNORE) and not per risk, and an IGNORE silences a rule everywhere: a
header accepted on the bundles would be silenced on the API too. Here an acceptance names the rule
*and* the paths it covers, so the same alert anywhere else is new.

**Why it reads what the scan saw.** The report lists alerts, and nothing else. A session the server
refused, an import that sent nothing, a spider that stopped at the sign-in page: each gives a report
with fewer alerts, which reads as better. The minimums below are well under what a working run
sees (the job's log prints the counts) and far above what a broken one does.
"""

import json
import re
import sys
from urllib.parse import urlsplit

# A working run, 2026-10-30: 36 interface URLs, 242 API URLs, 175 answers 2xx. The run whose session
# never reached ZAP's requests saw the same URLs and 9 answers 2xx — the anonymous routes — so the
# last minimum is the one that tells the two apart. The counts are printed on every run.
MIN_INTERFACE_URLS = 15     # the shell, its bundles, styles, assets
MIN_API_URLS = 150          # the contract's GET operations, as sent
MIN_API_ANSWERED = 100      # answered 2xx, which only an accepted session gets on guarded routes

RISK = {0: 'informational', 1: 'low', 2: 'medium', 3: 'high'}


def read_accepted(path):
    accepted = []
    with open(path, encoding='utf-8') as lines:
        for number, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            fields = [f.strip() for f in line.split(' | ')]
            if len(fields) != 4 or not all(fields):
                sys.exit(f'{path}:{number}: expected "<plugin id> | <path regex> | <alert> | <why>", got: {line}')
            plugin, paths, alert, why = fields
            accepted.append({'line': number, 'plugin': plugin, 'paths': re.compile(paths),
                             'alert': alert, 'why': why, 'used': 0})
    return accepted


def main(report_path, seen_path, accepted_path):
    with open(report_path, encoding='utf-8') as f:
        report = json.load(f)
    with open(seen_path, encoding='utf-8') as f:
        seen = json.load(f)
    accepted = read_accepted(accepted_path)

    problems = []

    paths = [urlsplit(u).path for u in seen['urls']]
    api = [p for p in paths if p.startswith('/api/')]
    interface = [p for p in paths if not p.startswith('/api/') and not p.startswith('/actuator')]
    statuses = seen['apiStatuses']
    answered = sum(n for code, n in statuses.items() if code.startswith('2'))
    print(f'seen: {len(interface)} interface URL(s), {len(api)} API URL(s); '
          f'API answers by status: {dict(sorted(statuses.items()))}')
    if len(interface) < MIN_INTERFACE_URLS:
        problems.append(f'the spider saw {len(interface)} interface URL(s), fewer than {MIN_INTERFACE_URLS}')
    if len(api) < MIN_API_URLS:
        problems.append(f'the import sent {len(api)} API URL(s), fewer than {MIN_API_URLS}')
    if answered < MIN_API_ANSWERED:
        problems.append(f'{answered} API answer(s) were 2xx, fewer than {MIN_API_ANSWERED}: '
                        'was the session refused?')

    new = []
    for site in report.get('site', []):
        for alert in site.get('alerts', []):
            risk = int(alert['riskcode'])
            uncovered = []
            for instance in alert.get('instances', []):
                path = urlsplit(instance['uri']).path
                match = next((a for a in accepted
                              if a['plugin'] == str(alert['pluginid']) and a['paths'].fullmatch(path)), None)
                if match:
                    match['used'] += 1
                else:
                    uncovered.append(f"{instance.get('method', '?')} {path}")
            label = f"[{alert['pluginid']}] {alert['alert']} ({RISK.get(risk, risk)})"
            if not uncovered:
                print(f'accepted   {label}: {len(alert.get("instances", []))} instance(s)')
            elif risk >= 2:
                new.append((label, uncovered))
            else:
                print(f'not gated  {label}: {len(uncovered)} instance(s), e.g. {uncovered[0]}')

    for label, uncovered in new:
        problems.append(f'new alert {label} on {len(uncovered)} path(s):\n      '
                        + '\n      '.join(sorted(set(uncovered))[:20]))

    for a in accepted:
        if not a['used']:
            # A warning, not a failure: what the spider reaches varies a little from night to night,
            # and a red nightly over a line that merely went unexercised teaches people to ignore it.
            print(f"::warning::{accepted_path}:{a['line']}: accepted [{a['plugin']}] {a['alert']} matched "
                  'nothing this run — if the alert is fixed, remove the line')

    if problems:
        for p in problems:
            print(f'::error::{p}')
        print(f'\nAn alert is fixed, or accepted in {accepted_path} with its reason — never by widening a regex '
              'past the paths the reason covers.')
        return 1
    print('ZAP baseline: no new medium or high alert')
    return 0


if __name__ == '__main__':
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    sys.exit(main(*sys.argv[1:]))
