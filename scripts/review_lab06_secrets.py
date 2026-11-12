"""Reproducible keyword inventory; publishes locations and decisions, never source values."""
import collections
import csv
import datetime
import hashlib
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / 'docs/evidence/lab06-stage3-secret-review.json'
CSV = ROOT / 'docs/evidence/lab06-stage3-secret-matches.csv'
KEYWORDS = re.compile(r'password|passwd|secret|api.?key|securitystamp|connectionstring|cookie|token', re.I)
TEXT_EXTENSIONS = {'.cs', '.csproj', '.props', '.targets', '.sln', '.json', '.md', '.txt', '.csv',
                   '.js', '.cjs', '.html', '.css', '.py', '.ps1', '.sh', '.yaml', '.yml', '.http', '.config', '.example'}


def git_paths(*args):
    result = subprocess.run(['git', 'ls-files', '-z', *args], cwd=ROOT, check=True, capture_output=True)
    return set(result.stdout.decode('utf-8').split('\0')) - {''}


def scan(runtime_values=()):
    tracked = git_paths()
    other = git_paths('--others', '--exclude-standard')
    # Explicit additional release scope, not a claim that untracked files are tracked.
    planned = {p for p in other if p.startswith(('src/', 'tests/', 'scripts/'))
               or p in {'docs/security-review.md', 'docs/threat-model.md', 'docs/advanced-variant-proposal.md'}
               or p.startswith(('docs/findings/', 'docs/lab-06', 'docs/evidence/lab06'))}
    excluded_outputs = {OUTPUT.relative_to(ROOT).as_posix(), CSV.relative_to(ROOT).as_posix()}
    matches, manifest, skipped = [], [], []
    counts = collections.Counter()
    issues = []
    for name in sorted((tracked | planned) - excluded_outputs):
        file = ROOT / name
        if not file.is_file(): continue
        if file.suffix.lower() not in TEXT_EXTENSIONS and name not in {'.gitignore', 'Dockerfile', 'global.json'}:
            skipped.append(name); continue
        content = file.read_bytes()
        if b'\0' in content:
            skipped.append(name); continue
        try: source = content.decode('utf-8-sig')
        except UnicodeDecodeError:
            skipped.append(name); continue
        manifest.append({'path': name, 'sha256': hashlib.sha256(content).hexdigest(),
                         'scope': 'tracked' if name in tracked else 'planned-release-untracked'})
        for value in runtime_values:
            if len(value) >= 16 and value in source:
                issues.append({'path': name, 'kind': 'exact runtime sensitive value', 'value': 'omitted'})
        for number, line in enumerate(source.splitlines(), 1):
            if not KEYWORDS.search(line): continue
            if 'local-study-password' in line:
                decision = 'accepted study-only local fixture'
            elif re.search(r'(?:WrongStudyPassword|NotARealPassword|unreachable-study-value|invalid-study-token|wrong-study-value|LOG_BODY_SENTINEL)', line):
                decision = 'synthetic negative-test marker'
            elif name.startswith(('docs/', 'README')):
                decision = 'documentation, redacted evidence or configuration name'
            elif name.startswith(('tests/', 'scripts/')):
                decision = 'test/automation code; secret is read at runtime or synthetic'
            else:
                decision = 'implementation/configuration identifier, not a credential value'
            counts[decision] += 1
            matches.append({'path': name, 'line': number, 'decision': decision,
                            'source': 'tracked' if name in tracked else 'planned-release-untracked'})
        # Independent signatures supplement broad keyword classification. Never publish the matched value.
        signatures = {
            'private key material': r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
            'GitHub credential': r'\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{50,})\b',
            'AWS access key': r'\bAKIA[A-Z0-9]{16}\b',
            'JWT value': r'\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b',
            'antiforgery/cookie protected value': r'\bCfDJ[A-Za-z0-9_-]{80,}\b'
        }
        for kind, pattern in signatures.items():
            if re.search(pattern, source): issues.append({'path': name, 'kind': kind, 'value': 'omitted'})
    with CSV.open('w', newline='', encoding='utf-8') as stream:
        writer = csv.DictWriter(stream, fieldnames=['path', 'line', 'decision', 'source'])
        writer.writeheader(); writer.writerows(matches)
    report = {'checkedAtUtc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'method': 'git ls-files + explicitly selected planned-release untracked text; case-insensitive keyword/signature scan',
              'keywords': KEYWORDS.pattern, 'matches': len(matches), 'matchedFiles': len({m['path'] for m in matches}),
              'classifications': dict(counts), 'reviewMethod': 'rule-based per-match inventory plus source review of local fixtures, runtime secret flow and suspicious signatures',
              'scope': {'trackedTextFiles': sum(m['scope'] == 'tracked' for m in manifest),
                        'plannedReleaseUntrackedTextFiles': sum(m['scope'] != 'tracked' for m in manifest),
                        'excludedBinaryOrOtherPaths': skipped,
                        'excluded': 'ignored tmp/.env/local.runsettings, unrelated untracked user documents/resources, stash, external CI/clones, full Git history'},
              'history': 'Stage-1 limited history of three study DB configuration files retained; no full-history absence claim.',
              'exactRuntimeValuesChecked': len(runtime_values), 'suspiciousFindings': issues,
              'realCredentialDiscovered': bool(issues), 'manifest': manifest,
              'limitations': ['Heuristic classification is not proof that no unknown secret exists.',
                              'Binary Word/PDF files and unrelated untracked materials are not parsed.',
                              'A real leaked secret requires revocation/rotation and history review, not only file deletion.']}
    OUTPUT.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    if issues: raise RuntimeError('Sensitive candidate found; inspect redacted review locations locally.')
    return {key: report[key] for key in ('checkedAtUtc', 'matches', 'matchedFiles', 'classifications', 'scope',
                                        'exactRuntimeValuesChecked', 'suspiciousFindings', 'realCredentialDiscovered')}


if __name__ == '__main__':
    print(json.dumps(scan(), ensure_ascii=False, indent=2))
