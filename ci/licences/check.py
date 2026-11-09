#!/usr/bin/env python3
"""Refuses a dependency Vectispire distributes under a licence nobody has reviewed.

    check.py <allowed.txt> [--notice NOTICE]
             [--sbom jar.cdx.json]...        the jars (CycloneDX from syft, the `sbom` job's)
             [--npm-lock package-lock.json]  the packages the interface is built from
             [--image image.cdx.json]...     the operating-system packages of an image

**What "reviewed" means.** `allowed.txt` lists the licences whose terms permit shipping the
component inside an Apache-2.0 distribution, each with the reason, and the components whose
metadata is missing, ambiguous or names a licence outside that list — each with the licence it is
actually distributed under and why that is acceptable. Everything else fails: a copyleft licence,
an unknown one, and none at all. The verdict on a new case is a person's, recorded in that file;
this script only makes sure nobody skips the question.

**An image is judged on its own list** (`image` lines). Its packages are separate programs aggregated
beside the jar — busybox, coreutils, the JRE — rather than code linked into Vectispire, which is why
GPL is acceptable there and not in a jar: what it costs is the source offer `NOTICE` makes.

**NOTICE is checked too**, with `--notice`: every jar component under a licence other than
Apache-2.0 must be named there by its group. Apache-2.0 asks for nothing beyond the component's own
NOTICE file, which travels inside its jar unmodified.
"""

import argparse
import json
import re
import sys
import urllib.parse

# Spellings found in POMs, syft output and package.json, mapped to SPDX. A spelling missing here
# fails as unknown, and is added here — never to the allowlist under the wrong name.
ALIASES = {
    'apache license, version 2.0': 'Apache-2.0',
    'apache license 2.0': 'Apache-2.0',
    'apache 2.0': 'Apache-2.0',
    'apache-2.0': 'Apache-2.0',
    'the apache software license, version 2.0': 'Apache-2.0',
    'apache license, version 2': 'Apache-2.0',
    'https://www.apache.org/licenses/license-2.0': 'Apache-2.0',
    'http://www.apache.org/licenses/license-2.0': 'Apache-2.0',
    'https://www.apache.org/licenses/license-2.0.txt': 'Apache-2.0',
    'http://www.apache.org/licenses/license-2.0.txt': 'Apache-2.0',
    'https://www.apache.org/licenses/license-2.0.html': 'Apache-2.0',
    'http://www.apache.org/licenses/license-2.0.html': 'Apache-2.0',
    'https://repository.jboss.org/licenses/apache-2.0.txt': 'Apache-2.0',
    'https://opensource.org/license/mit': 'MIT',
    'https://opensource.org/licenses/mit': 'MIT',
    'http://www.eclipse.org/legal/epl-2.0': 'EPL-2.0',
    'https://www.eclipse.org/legal/epl-2.0': 'EPL-2.0',
    'https://www.eclipse.org/legal/epl-v20.html': 'EPL-2.0',
    'http://www.eclipse.org/org/documents/edl-v10.php': 'BSD-3-Clause',  # EDL-1.0 is BSD-3-Clause
    'https://www.gnu.org/software/classpath/license.html': 'GPL-2.0-only WITH Classpath-exception-2.0',
    'https://www.gnu.org/licenses/old-licenses/lgpl-2.1.html': 'LGPL-2.1-only',
    'http://creativecommons.org/publicdomain/zero/1.0': 'CC0-1.0',
    'https://opensource.org/licenses/bsd-2-clause': 'BSD-2-Clause',
    'https://www.antlr.org/license.html': 'BSD-3-Clause',
    'gpl-2.0+ce': 'GPL-2.0-only WITH Classpath-exception-2.0',
    'domain': 'Public-Domain',
    'public': 'Public-Domain',
    'public-domain': 'Public-Domain',
}


def normalise(raw):
    """One licence as written in the metadata, as an SPDX id or expression — or the raw text."""
    text = raw.strip().strip('"')
    text = re.sub(r'";link=.*$', '', text)          # syft keeps the POM's name and URL together
    text = re.sub(r';link=.*$', '', text)
    return ALIASES.get(text.lower().rstrip('/'), text)


def ids_of(expression):
    """The licence ids an SPDX expression names, WITH exceptions kept attached to their licence."""
    tokens = re.findall(r'\(|\)|[^\s()]+', expression)
    out, i = [], 0
    while i < len(tokens):
        t = tokens[i]
        if t.upper() in ('AND', 'OR') or t in '()':
            i += 1
            continue
        if i + 2 < len(tokens) and tokens[i + 1].upper() == 'WITH':
            out.append(f'{t} WITH {tokens[i + 2]}')
            i += 3
            continue
        out.append(t)
        i += 1
    return out


def satisfied(expression, allowed):
    """Whether an SPDX expression is acceptable: an OR needs one side, an AND both."""
    expr = expression.strip()
    while expr.startswith('(') and expr.endswith(')') and balanced(expr[1:-1]):
        expr = expr[1:-1].strip()
    for op, need_all in ((' OR ', False), (' AND ', True)):
        parts = split_top(expr, op)
        if len(parts) > 1:
            results = [satisfied(p, allowed) for p in parts]
            return all(results) if need_all else any(results)
    return expr in allowed


def balanced(s):
    depth = 0
    for c in s:
        depth += {'(': 1, ')': -1}.get(c, 0)
        if depth < 0:
            return False
    return depth == 0


def split_top(expr, op):
    parts, depth, start, i = [], 0, 0, 0
    upper = expr.upper()
    while i < len(expr):
        c = expr[i]
        depth += {'(': 1, ')': -1}.get(c, 0)
        if depth == 0 and upper.startswith(op, i):
            parts.append(expr[start:i])
            i += len(op)
            start = i
            continue
        i += 1
    parts.append(expr[start:])
    return parts


def read_allowed(path):
    licences = {'jar': {}, 'npm': {}, 'image': {}}
    components = []
    with open(path, encoding='utf-8') as lines:
        for number, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            fields = [f.strip() for f in line.split(' | ')]
            if fields[0] == 'licence' and len(fields) == 4:
                _, scope, spdx, why = fields
                for s in (('jar', 'npm', 'image') if scope == 'all' else scope.split(',')):
                    licences[s][spdx] = why
            elif fields[0] == 'component' and len(fields) == 6 and fields[1] in licences:
                _, kind, name, distributed_under, declared, why = fields
                components.append({'line': number, 'kind': kind, 'name': name, 'under': distributed_under,
                                   'declared': set() if declared == '-' else {d.strip() for d in declared.split(',')},
                                   'why': why, 'used': False})
            else:
                sys.exit(f'{path}:{number}: expected "licence | <scope> | <SPDX id> | <why>" or '
                         f'"component | <jar|npm|image> | <name> | <distributed under> | <declared ids or -> | <why>", got: {line}')
            if not fields[-1]:
                sys.exit(f'{path}:{number}: an entry without its reason')
    return licences, components


def sbom_components(path):
    with open(path, encoding='utf-8') as f:
        bom = json.load(f)
    for c in bom.get('components', []):
        purl = c.get('purl') or ''
        declared = []
        for entry in c.get('licenses') or []:
            if 'expression' in entry:
                declared.append(entry['expression'])
            else:
                lic = entry.get('license') or {}
                declared.append(lic.get('id') or lic.get('name') or lic.get('url') or '')
        # A POM with several <license> elements reaches syft's output as one name, its URLs joined by
        # commas: split back into one licence each.
        declared = [re.sub(r'"?;link=.*$', '', d).strip().strip('"') for d in declared]
        split = [part for d in declared for part in (d.split(',') if '://' in d else [d])]
        yield c, purl, [normalise(d) for d in split if d.strip()]


def maven_name(purl):
    # pkg:maven/<group>/<artifact>@<version> → <group>/<artifact>
    return purl[len('pkg:maven/'):].split('@', 1)[0]


def judge(kind, name, declared, allowed, components, problems, notice_needed):
    entry = next((e for e in components if e['kind'] == kind and e['name'] == name or e['kind'] == kind and
                  (e['name'].endswith('/*') and name.startswith(e['name'][:-1]))), None)
    if entry:
        # The entry vouches for what the metadata declared when it was written, and for nothing a
        # new version might add: a relicensing must come back to review.
        names = {i for d in declared for i in ids_of(d)}
        if names - entry['declared']:
            problems.append(f'{kind} {name}: declares {sorted(names)}, but allowed.txt:{entry["line"]} vouches '
                            f'only for {sorted(entry["declared"]) or "no declaration"} — review it again')
            return
        entry['used'] = True
        if not satisfied(entry['under'], allowed[kind]):
            problems.append(f'{kind} {name}: allowed.txt:{entry["line"]} says {entry["under"]}, which no licence line allows')
        if kind == 'jar' and entry['under'] != 'Apache-2.0':
            notice_needed.append((name, entry['under']))
        return
    if not declared:
        problems.append(f'{kind} {name}: no licence in its metadata')
        return
    expression = ' AND '.join(f'({d})' for d in declared) if len(declared) > 1 else declared[0]
    if not satisfied(expression, allowed[kind]):
        problems.append(f'{kind} {name}: {expression} — not on the allowlist')
    elif kind == 'jar' and expression != 'Apache-2.0':
        notice_needed.append((name, expression))


def main():
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('allowed')
    parser.add_argument('--sbom', action='append', default=[])
    parser.add_argument('--npm-lock')
    parser.add_argument('--image', action='append', default=[])
    parser.add_argument('--notice')
    args = parser.parse_args()

    allowed, components = read_allowed(args.allowed)
    problems, notice_needed, counted = [], [], {}

    for path in args.sbom:
        n = 0
        for c, purl, declared in sbom_components(path):
            if not purl.startswith('pkg:maven/'):
                continue                       # the jar itself, as a file
            name = maven_name(purl)
            # Vectispire's own modules, nested in the jar under the build's coordinates.
            if name.startswith(('vectispire-', 'org.springframework.boot.loader.launch.JarLauncher/')):
                continue
            n += 1
            judge('jar', name, declared, allowed, components, problems, notice_needed)
        counted[path] = n

    if args.npm_lock:
        with open(args.npm_lock, encoding='utf-8') as f:
            lock = json.load(f)
        n = 0
        for path, meta in lock.get('packages', {}).items():
            # What the interface depends on at run time and at build time, development tools aside:
            # stricter than what the bundle carries (`3rdpartylicenses.txt`), never looser.
            if 'node_modules/' not in path or meta.get('dev') or meta.get('link'):
                continue
            n += 1
            name = path.rsplit('node_modules/', 1)[1]
            lic = meta.get('license')
            judge('npm', name, [normalise(lic)] if lic else [], allowed, components, problems, notice_needed)
        counted[args.npm_lock] = n

    for path in args.image:
        n = 0
        for c, purl, declared in sbom_components(path):
            if not (purl.startswith('pkg:apk/') or purl.startswith('pkg:deb/')):
                continue
            n += 1
            name = urllib.parse.unquote(purl.split('/', 2)[2].split('@', 1)[0])
            # Distribution metadata lists every licence of every file in a package with no operator
            # between them: each one has to be acceptable.
            judge('image', name, [' AND '.join(f'({d})' for d in declared)] if declared else [],
                  allowed, components, problems, notice_needed)
        counted[path] = n

    # **A run that examined nothing is not a pass** — the `secrets` job scanned no commit for six
    # weeks and said "no leaks found".
    for path, n in counted.items():
        print(f'{path}: {n} component(s) checked')
        if n == 0:
            problems.append(f'{path}: no component read — the input is empty or not what this script expects')

    read = {'jar': bool(args.sbom), 'npm': bool(args.npm_lock), 'image': bool(args.image)}
    for e in components:
        # Only an entry of a kind this run read can be stale: the images are checked in another job.
        if read[e['kind']] and not e['used']:
            problems.append(f'{args.allowed}:{e["line"]}: {e["kind"]} {e["name"]} matched no component — remove the line')

    if args.notice:
        with open(args.notice, encoding='utf-8') as f:
            notice = f.read()
        for name, under in sorted(set(notice_needed)):
            group = name.split('/', 1)[0]
            if group not in notice and name not in notice:
                problems.append(f'NOTICE does not name {name} ({under}); add it under its licence')

    if problems:
        for p in problems:
            print(f'::error::{p}')
        print(f'\nA new licence is a decision: record it in {args.allowed} with its reason, or choose another '
              'dependency. A licence that does not permit distribution under Apache-2.0 is not added there.')
        return 1
    print('every distributed component is under a reviewed licence')
    return 0


if __name__ == '__main__':
    sys.exit(main())
