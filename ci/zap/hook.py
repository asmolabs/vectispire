# Hooks for zap-baseline.py, read with `--hook=/zap/wrk/hook.py` (scripts/zap-baseline.sh).
#
# **Why a hook at all.** The baseline spiders from the target's root, and the interface is a
# single-page application: its routes live in a JavaScript bundle and the spider finds the shell,
# the bundles and the assets, never `/api/v1`. The API is what an attacker talks to, so it is put
# in the sites tree here, from the contract the build pins (`vectispire-angular/openapi.json`,
# `ClientContractSpecTest`), and the passive rules then read every answer it gave.
#
# The file handed over holds the GET operations only. ZAP's import *sends* every operation it
# reads, with generated values: a POST to `/auth/logout` revokes the session the scan runs on, a
# DELETE removes whatever its generated id names. A baseline that writes is not a baseline.

import json
import os

WORK = '/zap/wrk'


def zap_started(zap, target):
    base = target.rstrip('/')
    errors = zap.openapi.import_file(os.path.join(WORK, 'openapi-get.json'), base)
    # The import answers a list of the operations it could not send; an empty answer is success.
    # Printed rather than fatal: a few unparameterisable paths are expected, and the gate reads
    # what reached the server, which is the number that matters.
    print('openapi import: %d operation(s) not sent' % (len(errors) if isinstance(errors, list) else 0))


def zap_pre_shutdown(zap):
    # What the scan saw, written for scripts/zap-gate.py. The report lists alerts only: a run
    # whose session was refused, or whose import sent nothing, has no alerts on the API and reads
    # exactly like a clean one — the `secrets` lesson in the quality-gate skill.
    target = os.environ['ZAP_TARGET'].rstrip('/')
    urls = zap.core.urls(baseurl=target)
    statuses = {}
    trace = []
    total = int(zap.core.number_of_messages(baseurl=target + '/api/v1'))
    start = 0
    while start < total:
        for message in zap.core.messages(baseurl=target + '/api/v1', start=start, count=500):
            status_line = message.get('responseHeader', '').split('\r\n', 1)[0].split(' ')
            code = status_line[1] if len(status_line) > 1 else '???'
            # Status 0: a node of the sites tree ZAP made for a path prefix, never sent.
            if code == '0':
                continue
            statuses[code] = statuses.get(code, 0) + 1
            # Per request, for the run that fails: whether the session was on it is the first question.
            trace.append([message.get('id'), code, 'authorization:' in message.get('requestHeader', '').lower(),
                          message.get('requestHeader', '').split('\r\n', 1)[0]])
        start += 500
    with open(os.path.join(WORK, 'seen.json'), 'w') as out:
        json.dump({'urls': urls, 'apiStatuses': statuses, 'trace': trace}, out, indent=1)
