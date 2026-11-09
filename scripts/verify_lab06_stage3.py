"""CP-03 and approved extension. Resets only the known local synthetic PostgreSQL DB.

Raw logs/TRX remain ignored. Published evidence contains only allowlisted summaries.
Requires dotnet, Python, Node+Playwright+Chrome and healthy local compose PostgreSQL.
"""
import datetime
import argparse
import hashlib
import json
import re
import socket
import subprocess
import time
import xml.etree.ElementTree as ET
import verify_lab06_stage1 as support
import review_lab06_secrets

ROOT = support.ROOT
NS = {'t': 'http://microsoft.com/schemas/VisualStudio/TeamTest/2010'}


def build_inputs_hash():
    digest = hashlib.sha256()
    files = [ROOT / 'global.json', ROOT / 'Directory.Build.props']
    for folder in ('src', 'tests'):
        files += [file for file in (ROOT / folder).rglob('*') if file.is_file()
                  and file.suffix in {'.cs', '.csproj', '.json', '.html', '.js', '.props', '.targets'}
                  and not {'bin', 'obj'}.intersection(file.relative_to(ROOT).parts)]
    for file in sorted(files):
        digest.update(file.relative_to(ROOT).as_posix().encode()); digest.update(file.read_bytes())
    return digest.hexdigest()


def runtime_db_values():
    # Capture only in memory, never route these values through command() or public logs.
    result = subprocess.run(['docker', 'exec', 'secure-lab-postgres-1', 'psql', '-U', 'securelab', '-d', 'securelab',
                             '-tAc', 'SELECT "SecurityStamp" FROM identity_users;'],
                            cwd=ROOT, env=support.ENV, capture_output=True, timeout=20, check=True)
    return [line.strip() for line in result.stdout.decode().splitlines() if line.strip()]


def assert_clean_log(path, values):
    log = path.read_text(encoding='utf-8', errors='replace')
    exact = sum(log.count(value) for value in values if value and len(value) >= 8)
    headers = {key: len(re.findall(pattern, log, re.I | re.M)) for key, pattern in {
        'cookieHeader': r'^\s*(?:set-)?cookie\s*:', 'csrfHeader': r'^\s*X-CSRF-TOKEN\s*:',
        'connectionStringValue': r'Host=.+;.*(?:Username|Password)=',
        'requestBodyLogging': r'LOG_BODY_SENTINEL_9e261f'
    }.items()}
    assert exact == 0 and all(value == 0 for value in headers.values()), 'Sensitive log match (value omitted).'
    return {'source': str(path.relative_to(ROOT)).replace('\\', '/'), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
            'exactSensitiveValueMatches': exact, 'valuesChecked': len(values), 'patternMatchCounts': headers,
            'scope': 'original complete console log, including exception details; output contains counts only'}


def parse_test_results():
    trx = ET.parse(support.LOCAL / 'test-results/stage3.trx')
    counters = trx.find('.//t:Counters', NS).attrib
    assert int(counters['failed']) == 0 and int(counters['notExecuted']) == 0
    results, advanced, race = [], [], []
    for result in trx.findall('.//t:UnitTestResult', NS):
        results.append({'test': result.attrib['testName'], 'outcome': result.attrib['outcome']})
        for node in result.findall('.//t:StdOut', NS):
            for line in (node.text or '').splitlines():
                if line.startswith('LAB06_ADVANCED '): advanced.append(json.loads(line[len('LAB06_ADVANCED '):]))
                if line.startswith('LAB06_TRIAGE '): race.append(json.loads(line[len('LAB06_TRIAGE '):]))
    assert len(advanced) == 7 and len(race) == 1, 'Expected extension evidence missing.'
    support.record('tests', {'exitCode': 0, **counters, 'scenarios': results})
    support.record('advanced-integration', advanced)
    support.record('triage-concurrency-after', race[0])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--resume-after-tests', action='store_true', help='Reuse passing tests only when all build inputs have exactly the saved hash.')
    parser.add_argument('--release', action='store_true', help='Verify a clean committed tree; write every generated artifact under ignored tmp/lab06/release.')
    args = parser.parse_args()
    assert not (args.release and args.resume_after_tests), 'Release verification requires a full fresh run.'
    support.LOCAL = ROOT / ('tmp/lab06/release' if args.release else 'tmp/lab06/stage3')
    support.LOCAL.mkdir(parents=True, exist_ok=True)
    support.EVIDENCE = support.LOCAL / 'verification.json' if args.release else ROOT / 'docs/evidence/lab06-stage3.json'
    support.report = {'startedAtUtc': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'status': 'in_progress', 'checks': {}}
    if args.resume_after_tests:
        previous = json.loads(support.EVIDENCE.read_text(encoding='utf-8'))
        assert previous['checks']['build']['inputsSha256'] == build_inputs_hash(), 'Build inputs changed; run complete verification.'
        assert int(previous['checks']['tests']['failed']) == 0
        support.report = previous
        support.report['status'] = 'in_progress'
        support.report['checks'].pop('failure', None)
    sensitive_file = support.LOCAL / 'runtime-sensitive-values.json'
    support.ENV['LAB06_RUNTIME_VALUES_PATH'] = str(sensitive_file)
    if args.release:
        assert not support.command('git-status-before', ['git', 'status', '--porcelain=v1', '-uall']).strip(), 'Release worktree must be clean.'
        support.ENV['LAB06_SCREENSHOT_DIRECTORY'] = str(support.LOCAL / 'screenshots/regression')
        support.ENV['LAB06_ADVANCED_SCREENSHOT_DIRECTORY'] = str(support.LOCAL / 'screenshots/advanced')
        review_lab06_secrets.OUTPUT = support.LOCAL / 'secret-review.json'
        review_lab06_secrets.CSV = support.LOCAL / 'secret-matches.csv'
    runtime_values = [support.ENV['SeedUsers__Password'], 'WrongStudyPassword-1!', 'NotARealPassword1!', 'unreachable-study-value']
    try:
        for port in (5080, 4173, 4174, 54399):
            with socket.socket() as sock: assert sock.connect_ex(('127.0.0.1', port)) != 0, 'Required local port occupied.'
        if not args.resume_after_tests:
            verify_build_and_tests(args.release)
        support.reset('reset-after-tests')
        runtime_values += runtime_db_values()
        # Enable ordinary request completion metadata in this child only; no body/header logging.
        support.ENV['Logging__LogLevel__Microsoft.AspNetCore.Hosting.Diagnostics'] = 'Information'
        if not args.release:
            support.ENV['LAB06_SCREENSHOT_DIRECTORY'] = 'docs/evidence/screenshots/lab06-stage3/regression'
        with support.server('development-regression', 'Development'):
            browser = json.loads(support.command('browser-regression', ['node', 'scripts/lab06_stage2_browser.cjs']))
            support.record('browser-regression', browser)
        # Original A-11 expects the exact known seed; browser forms intentionally create new incidents.
        support.reset('reset-before-legacy-regression')
        with support.server('legacy-regression', 'Development'):
            support.command('lab04-access', ['python', 'scripts/lab04_access.py', '--expect', 'fixed', '--perimeter', '--mutation'])
            support.command('lab04-triage', ['python', 'scripts/lab04_triage_fixed.py'])
            support.record('legacy-regression', {'lab04AccessExitCode': 0, 'lab04TriageExitCode': 0,
                'coverage': 'original access/perimeter/mutation and privileged triage scenarios; standard CSRF pair added to legitimate requests'})
            _, _, raw = support.request('/openapi/v1.json')
            mutations = [{'method': method.upper(), 'route': route, 'responses': sorted(operation.get('responses', {}))}
                for route, operations in json.loads(raw)['paths'].items() for method, operation in operations.items()
                if method in ('post', 'put', 'patch', 'delete')]
            expected = {('POST', '/api/auth/login'), ('POST', '/api/auth/register'), ('POST', '/api/auth/logout'),
                ('POST', '/api/incidents'), ('PUT', '/api/incidents/{id}'), ('DELETE', '/api/incidents/{id}'),
                ('POST', '/api/incidents/{id}/triage'), ('POST', '/api/me/sessions/revoke-all')}
            assert {(item['method'], item['route']) for item in mutations} == expected
            support.record('csrf-perimeter', {'protectedCookieMutations': 6, 'publicAuthMutations': 2, 'operations': mutations})
        support.reset('reset-before-log-audit')
        runtime_values += runtime_db_values()
        with support.server('six-log-scenarios', 'Development') as log_path:
            browser = json.loads(support.command('browser-advanced', ['node', 'scripts/lab06_stage3_browser.cjs']))
            support.record('browser-advanced', browser)
            runtime_values += json.loads(sensitive_file.read_text(encoding='utf-8')) + runtime_db_values()
            time.sleep(0.5)
            log = log_path.read_text(encoding='utf-8', errors='replace')
            for item in browser['logScenarios']:
                assert 'TraceId:' + item['traceId'] in log, 'Scenario trace absent from original log.'
            for marker in ('Authentication event: login succeeded.', 'Authentication event: login failed.',
                           'incident.triage.denied', 'incident.triage.allowed', 'sessions.revoke_all'):
                assert marker in log, 'Required event absent from log.'
            safe_events = [line.strip() for line in log.splitlines() if re.search(
                r'^\s*(?:Authentication event:|incident\.triage\.(?:allowed|denied) |sessions\.revoke_all )', line)]
            support.record('log-audit-normal', {**assert_clean_log(log_path, runtime_values),
                'scenarios': browser['logScenarios'], 'safeEventExcerpts': safe_events,
                'privilegedTransition': 'Reporter 403 unchanged; Analyst 204 canonical status Triaged; subject/action/resource/result/time/trace logged'})
        support.ENV.pop('Logging__LogLevel__Microsoft.AspNetCore.Hosting.Diagnostics', None)
        with support.server('production-unexpected-error', 'Production', broken=True) as log_path:
            status, headers, body = support.request('/api/auth/login', {'userName': 'alice', 'password': 'NotARealPassword1!'})
            assert status == 500 and 'application/problem+json' in headers.get('Content-Type', '')
            problem = json.loads(body); trace = problem['traceId']
            assert re.fullmatch(r'00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}', trace)
            expected_headers = {'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
                'x-content-type-options': 'nosniff', 'referrer-policy': 'no-referrer'}
            lower = {key.lower(): value for key, value in headers.items()}
            assert all(lower.get(key) == value for key, value in expected_headers.items())
            assert not any(value.lower() in body.lower() for value in runtime_values if value)
            assert not any(value in body for value in ('Npgsql', 'StackTrace', 'SELECT ', 'Host=', 'F:\\', 'C:\\'))
            time.sleep(0.5)
            log = log_path.read_text(encoding='utf-8', errors='replace')
            lines = log.splitlines()
            index = next(index for index, line in enumerate(lines) if 'fail: Microsoft.AspNetCore.Diagnostics.ExceptionHandlerMiddleware[1]' in line)
            excerpt = lines[index:index+3]
            assert 'TraceId:' + trace.split('-')[1] in '\n'.join(excerpt)
            support.record('log-audit-unexpected', {**assert_clean_log(log_path, runtime_values),
                'profile': 'Production', 'status': status, 'response': problem, 'headers': expected_headers,
                'traceMatches': True, 'exceptionLogExcerpt': excerpt})
        with support.server('production-normal', 'Production'):
            status, _, body = support.request('/health')
            assert status == 200 and json.loads(body)['status'] == 'ready'
            openapi_status, openapi_headers, _ = support.request('/openapi/v1.json')
            scalar_status, scalar_headers, scalar_body = support.request('/scalar/v1')
            _, _, index_body = support.request('/')
            assert openapi_status == 404 and scalar_status == 200 and scalar_body == index_body
            assert 'text/html' in scalar_headers.get('Content-Type', '')
            support.record('production-normal', {'environment': 'Production', 'health': 200,
                'openapiStatus': openapi_status, 'openapiContentType': openapi_headers.get('Content-Type'),
                'scalarStatus': scalar_status, 'scalarContentType': scalar_headers.get('Content-Type'),
                'scalarEqualsClientFallback': True, 'interactiveDocumentationRegistered': False,
                'resetAndMigrationsDisabled': 'verified by ProductionProfileTests',
                'debugHooks': 'No production throw/debug endpoint; controlled failure uses child-only unreachable loopback DB.'})
        # Deliberately public negative-test markers must be absent from logs but are expected in test source.
        synthetic_markers = {'WrongStudyPassword-1!', 'NotARealPassword1!', 'unreachable-study-value', 'LOG_BODY_SENTINEL_9e261f'}
        support.record('secret-review', review_lab06_secrets.scan(sorted(set(runtime_values) - synthetic_markers)))
        support.reset('final-reset')
        with support.server('restored-normal', 'Development'):
            status, _, body = support.request('/health')
            assert status == 200 and json.loads(body)['status'] == 'ready'
            support.browser_flow('restored-browser')
        support.report['status'] = 'PASS'
        support.report['finishedAtUtc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        if args.release:
            assert not support.command('git-status-after', ['git', 'status', '--porcelain=v1', '-uall']).strip(), 'Release run changed tracked/untracked files.'
            support.record('verified-git-state', {'commit': support.command('verified-head', ['git', 'rev-parse', 'HEAD']).strip(),
                'cleanBefore': True, 'cleanAfter': True, 'generatedOutputs': 'ignored tmp/lab06/release only'})
        support.record('final-state', {'database': 'known synthetic seed restored', 'apiProcesses': 'stopped',
            'advancedVariant': 'implemented and verified', 'remaining': 'Create verified tag and export submission outside repository' if args.release
                else 'CP-04 release uses a separate clean committed run; historical stage-3 snapshot retained'})
    except Exception as error:
        support.report['status'] = 'FAIL'
        support.record('failure', {'type': type(error).__name__, 'detail': 'Inspect ignored tmp/lab06/stage3 logs locally; sensitive values omitted.'})
        raise SystemExit('Stage 3 verification failed; inspect ignored local logs.')
    finally:
        sensitive_file.unlink(missing_ok=True)


def verify_build_and_tests(release=False):
    support.record('environment', {'sdk': support.command('sdk', ['dotnet', '--version']).strip(),
        'branch': support.command('branch', ['git', 'branch', '--show-current']).strip(),
        'baseCommit': support.command('head', ['git', 'rev-parse', 'HEAD']).strip(),
        'scope': 'clean committed release tree' if release else 'local working tree, CP-03; not final release commit',
        'teacherApproval': 'docs/evidence/lab06-advanced-approval.md'})
    support.command('restore', ['dotnet', 'restore', 'SecureLab.sln', '--locked-mode'])
    audit_text = support.command('dependency-audit', ['dotnet', 'package', 'list', '--vulnerable', '--include-transitive', '--no-restore']).replace('\r\n', '\n')
    audit_json = json.loads(support.command('dependency-audit-json', ['dotnet', 'package', 'list', '--vulnerable', '--include-transitive', '--no-restore', '--format', 'json']))
    vulnerable = [package for project in audit_json.get('projects', []) for framework in project.get('frameworks', [])
                  for group in ('topLevelPackages', 'transitivePackages') for package in framework.get(group, [])
                  if package.get('vulnerabilities')]
    assert not vulnerable, 'Dependency advisory requires explicit remediation decision.'
    audit_path = support.LOCAL / 'dependency-audit.txt' if release else ROOT / 'docs/evidence/lab06-dependency-audit.txt'
    audit_path.write_text(
        'Checked UTC: ' + datetime.datetime.now(datetime.timezone.utc).isoformat() + '\n'
        + 'SDK: ' + support.report['checks']['environment']['sdk'] + '\n'
        + 'Command: dotnet restore SecureLab.sln --locked-mode; exit 0\n'
        + 'Command: dotnet package list --vulnerable --include-transitive --no-restore; exit 0\n\n' + audit_text,
        encoding='utf-8')
    support.record('dependencies', {'restoreExitCode': 0, 'auditExitCode': 0, 'jsonAuditExitCode': 0,
        'directAndTransitive': True, 'advisoryCount': len(vulnerable), 'sources': audit_json['sources'],
        'decision': 'No known advisory returned by configured sources; retain locked versions; no warning suppression or blind upgrade.',
        'output': audit_path.relative_to(ROOT).as_posix(), 'limitation': 'Point-in-time source result, not proof against unknown vulnerabilities.'})
    build = support.command('build', ['dotnet', 'build', 'SecureLab.sln', '-c', 'Release', '--no-restore'])
    assert re.search(r'0 Warning\(s\)', build) and re.search(r'0 Error\(s\)', build)
    support.record('build', {'exitCode': 0, 'configuration': 'Release', 'warnings': 0, 'errors': 0, 'inputsSha256': build_inputs_hash()})
    support.reset('initial-reset')
    support.command('tests', ['dotnet', 'test', 'SecureLab.sln', '-c', 'Release', '--no-build', '--no-restore',
        '--logger', 'trx;LogFileName=stage3.trx', '--results-directory', str(support.LOCAL / 'test-results')])
    parse_test_results()


if __name__ == '__main__':
    main()
