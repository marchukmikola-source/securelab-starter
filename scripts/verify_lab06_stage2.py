"""Repeat stage 2 on the known local study target; no credential/token values in evidence."""
import datetime
import json
from pathlib import Path
import re
import socket
import time
import xml.etree.ElementTree as ET
import verify_lab06_stage1 as support


def main():
    support.LOCAL = support.ROOT / 'tmp/lab06/stage2'
    support.LOCAL.mkdir(parents=True, exist_ok=True)
    support.EVIDENCE = support.ROOT / 'docs/evidence/lab06-stage2.json'
    support.report = {'startedAtUtc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                      'status': 'in_progress', 'checks': {}}
    try:
        for port in (5080, 4173, 4174, 54399):
            with socket.socket() as sock:
                assert sock.connect_ex(('127.0.0.1', port)) != 0, 'Required loopback port is occupied.'
        support.record('environment', {
            'sdk': support.command('sdk', ['dotnet', '--version']).strip(),
            'branch': support.command('branch', ['git', 'branch', '--show-current']).strip(),
            'baseCommit': support.command('head', ['git', 'rev-parse', 'HEAD']).strip(),
            'workingTreeChanges': 'Stage 1 and stage 2 changes are local; this is not a final release commit.'})
        support.command('restore', ['dotnet', 'restore', 'SecureLab.sln', '--locked-mode'])
        support.command('build', ['dotnet', 'build', 'SecureLab.sln', '-c', 'Release', '--no-restore'])
        support.record('build', {'restoreExitCode': 0, 'buildExitCode': 0, 'warnings': 0, 'errors': 0})
        support.reset('initial-reset')
        support.command('tests', ['dotnet', 'test', 'SecureLab.sln', '-c', 'Release', '--no-build', '--no-restore',
                                 '--logger', 'trx;LogFileName=stage2.trx', '--results-directory', str(support.LOCAL / 'test-results')])
        ns = {'t': 'http://microsoft.com/schemas/VisualStudio/TeamTest/2010'}
        trx = ET.parse(support.LOCAL / 'test-results/stage2.trx')
        counters = trx.find('.//t:Counters', ns).attrib
        selected = [{'test': x.attrib['testName'], 'outcome': x.attrib['outcome']}
                    for x in trx.findall('.//t:UnitTestResult', ns)
                    if any(name in x.attrib['testName'] for name in
                           ('BrowserHardeningTests', 'SearchRateLimitTests', 'ProductionProfileTests',
                            'LoginAttemptLimiterTests', 'AuthenticationProtectionTests'))]
        support.record('tests', {'exitCode': 0, **counters, 'securityScenarios': selected})
        support.reset('reset-after-tests')
        with support.server('development-stage2', 'Development'):
            status, _, body = support.request('/health')
            assert status == 200 and json.loads(body)['status'] == 'ready'
            browser = json.loads(support.command('browser', ['node', 'scripts/lab06_stage2_browser.cjs']))
            support.record('browser', browser)
            _, _, openapi = support.request('/openapi/v1.json')
            schema = json.loads(openapi)
            mutations = [{'method': method.upper(), 'route': route, 'responses': sorted(operation.get('responses', {}))}
                         for route, operations in schema['paths'].items()
                         for method, operation in operations.items() if method in ('post', 'put', 'patch', 'delete')]
            expected = {('POST', '/api/auth/login'), ('POST', '/api/auth/register'), ('POST', '/api/auth/logout'),
                        ('POST', '/api/incidents'), ('PUT', '/api/incidents/{id}'),
                        ('DELETE', '/api/incidents/{id}'), ('POST', '/api/incidents/{id}/triage'),
                        ('POST', '/api/me/sessions/revoke-all')}
            assert {(x['method'], x['route']) for x in mutations} == expected
            support.record('openapi-mutation-perimeter', mutations)
        with support.server('production-broken-stage2', 'Production', broken=True) as log_path:
            status, headers, body = support.request('/api/auth/login', {'userName': 'alice', 'password': 'NotARealPassword1!'})
            assert status == 500
            problem = json.loads(body)
            trace = problem['traceId']
            assert re.fullmatch(r'00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}', trace)
            expected_headers = {'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
                                'x-content-type-options': 'nosniff', 'referrer-policy': 'no-referrer'}
            lower_headers = {key.lower(): value for key, value in headers.items()}
            for key, value in expected_headers.items():
                assert lower_headers.get(key) == value, 'Expected security header absent on 500.'
            for forbidden in ('Npgsql', 'StackTrace', 'SELECT ', 'Host=', 'Password=', 'F:\\', 'C:\\',
                              support.ENV['SeedUsers__Password'], 'NotARealPassword1!', 'unreachable-study-value'):
                assert forbidden.lower() not in body.lower(), 'Unexpected sensitive response value; omitted.'
            time.sleep(0.5)
            log = log_path.read_text(encoding='utf-8', errors='replace')
            lines = log.splitlines()
            index = next(i for i, line in enumerate(lines) if 'fail: Microsoft.AspNetCore.Diagnostics.ExceptionHandlerMiddleware[1]' in line)
            excerpt = lines[index:index + 3]
            assert 'TraceId:' + trace.split('-')[1] in '\n'.join(excerpt)
            sensitive = {'seedPassword': support.ENV['SeedUsers__Password'], 'requestPassword': 'NotARealPassword1!',
                         'brokenDbPassword': 'unreachable-study-value', 'cookieHeader': 'Cookie:',
                         'setCookieHeader': 'Set-Cookie:', 'csrfHeader': 'X-CSRF-TOKEN:'}
            matches = {key: log.lower().count(value.lower()) for key, value in sensitive.items()}
            assert all(count == 0 for count in matches.values()), 'Unexpected sensitive log value; omitted.'
            support.record('production-500-headers', {'profile': 'Production', 'method': 'POST', 'route': '/api/auth/login',
                'status': status, 'contentType': headers.get('Content-Type'), 'headers': expected_headers,
                'response': problem, 'exceptionLogExcerpt': excerpt, 'traceMatches': True, 'sensitiveLogMatchCounts': matches})
        support.reset('final-reset')
        with support.server('development-restored-stage2', 'Development'):
            status, _, body = support.request('/health')
            assert status == 200 and json.loads(body)['status'] == 'ready'
            normal = json.loads(support.command('restored-browser', ['node', 'scripts/lab06_browser_check.cjs']))
            support.record('restoration', {'profile': 'Development', 'health': 200, 'dbTarget': '127.0.0.1:54329/securelab',
                                            'browser': normal, 'temporaryConfiguration': 'child processes only'})
        support.report['status'] = 'PASS'
        support.report['finishedAtUtc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        support.record('final-state', {'apiVerificationProcesses': 'stopped', 'database': 'normal known seed',
                                       'v1.0.0Created': False, 'remainingWork': 'Stages 3–4 and approved advanced variant'})
    except Exception as error:
        support.report['status'] = 'FAIL'
        support.record('failure', {'type': type(error).__name__, 'detail': 'Inspect ignored tmp/lab06/stage2 logs locally.'})
        raise SystemExit('Stage 2 verification failed; raw values omitted.')


if __name__ == '__main__':
    main()
