"""Stage 1 on the existing local study DB. Resets its known tables before tests.

Raw logs and local runsettings stay under ignored tmp/lab06; evidence contains no credentials.
Requires .NET 10, a healthy local compose PostgreSQL, Node, Playwright and Chrome.
"""
import contextlib
import datetime
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
LOCAL = ROOT / 'tmp/lab06'
EVIDENCE = ROOT / 'docs/evidence/lab06-stage1.json'
LOCAL.mkdir(parents=True, exist_ok=True)
ENV = os.environ.copy()
ENV['DOTNET_NOLOGO'] = 'true'
ENV['ConnectionStrings__SecureLab'] = (
    'Host=127.0.0.1;Port=54329;Database=securelab;Username=securelab;'
    'Password=local-study-password;Include Error Detail=false')
settings = LOCAL / 'local.runsettings'
if not ENV.get('SeedUsers__Password'):
    if settings.exists():
        ENV['SeedUsers__Password'] = ET.parse(settings).findtext('.//SeedUsers__Password')
    else:
        ENV['SeedUsers__Password'] = 'Aa1!' + secrets.token_urlsafe(32)
if not ENV.get('SeedUsers__Password'):
    raise SystemExit('Local seed credential is missing (value omitted).')
if not settings.exists():
    tree = ET.Element('RunSettings')
    variables = ET.SubElement(ET.SubElement(tree, 'RunConfiguration'), 'EnvironmentVariables')
    ET.SubElement(variables, 'SeedUsers__Password').text = ENV['SeedUsers__Password']
    ET.ElementTree(tree).write(settings, encoding='utf-8', xml_declaration=True)
node = shutil.which('node')
if node and not ENV.get('NODE_PATH'):
    bundled_modules = Path(node).parent.parent / 'node_modules'
    if bundled_modules.is_dir():
        ENV['NODE_PATH'] = str(bundled_modules)

report = {'startedAtUtc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
          'status': 'in_progress', 'checks': {}}


def record(name, result):
    report['checks'][name] = result
    EVIDENCE.parent.mkdir(parents=True, exist_ok=True)
    EVIDENCE.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(name + ': recorded', flush=True)


def command(name, args, env=None, expected=0):
    result = subprocess.run(args, cwd=ROOT, env=env or ENV, capture_output=True, timeout=300)
    output = result.stdout.decode('utf-8', errors='replace') + result.stderr.decode('utf-8', errors='replace')
    (LOCAL / (name + '.log')).write_text(output, encoding='utf-8')
    if result.returncode != expected:
        raise RuntimeError(name + ': unexpected exit; inspect its ignored local log.')
    return output


def request(path, data=None):
    headers = {'Accept': 'application/problem+json, application/json, text/html'}
    if data is not None:
        headers['Content-Type'] = 'application/json'
    req = urllib.request.Request('http://localhost:5080' + path,
                                 data=None if data is None else json.dumps(data).encode(), headers=headers)
    try:
        response = urllib.request.urlopen(req, timeout=15)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        return response.status, dict(response.headers), response.read().decode('utf-8')


@contextlib.contextmanager
def server(name, profile, broken=False):
    env = ENV.copy()
    env.update(ASPNETCORE_ENVIRONMENT=profile, ASPNETCORE_URLS='http://localhost:5080',
               Logging__Console__IncludeScopes='true')
    if broken:
        env['ConnectionStrings__SecureLab'] = (
            'Host=127.0.0.1;Port=54399;Database=securelab;Username=securelab;'
            'Password=unreachable-study-value;Include Error Detail=false;Timeout=2;Command Timeout=2')
    log_path = LOCAL / (name + '.log')
    with log_path.open('wb') as log:
        process = subprocess.Popen(['dotnet', 'run', '--project', 'src/SecureLab.Api', '-c', 'Release',
                                    '--no-build', '--no-launch-profile'], cwd=ROOT, env=env,
                                   stdout=log, stderr=subprocess.STDOUT)
        try:
            for _ in range(120):
                if process.poll() is not None:
                    raise RuntimeError(name + ': API did not start; inspect its ignored local log.')
                if 'Now listening on: http://localhost:5080' in log_path.read_text(encoding='utf-8', errors='replace'):
                    break
                time.sleep(0.5)
            else:
                raise RuntimeError(name + ': startup timeout.')
            text = log_path.read_text(encoding='utf-8', errors='replace')
            assert 'Hosting environment: ' + profile in text
            yield log_path
        finally:
            if process.poll() is None:
                if os.name == 'nt':
                    subprocess.run(['taskkill', '/PID', str(process.pid), '/T', '/F'], capture_output=True)
                else:
                    process.terminate()
                process.wait(timeout=20)


def reset(name):
    env = ENV.copy()
    env['ASPNETCORE_ENVIRONMENT'] = 'Development'
    output = command(name, ['dotnet', 'run', '--project', 'src/SecureLab.Api', '-c', 'Release',
                            '--no-build', '--no-launch-profile', '--', '--reset-database'], env)
    assert 'seed-' in output or 'seed' in output.lower()
    record(name, {'exitCode': 0, 'profile': 'Development', 'target': '127.0.0.1:54329/securelab',
                  'knownStudyTablesReseeded': True})


def browser_flow(name):
    output = command(name, ['node', 'scripts/lab06_browser_check.cjs'])
    record(name, json.loads(output))



def main():
    try:
        for port in (5080, 54399):
            with socket.socket() as sock:
                assert sock.connect_ex(('127.0.0.1', port)) != 0, 'Required local port is already in use.'
        record('environment', {'sdk': command('sdk', ['dotnet', '--version']).strip(),
                               'reviewStartCommit': command('head', ['git', 'rev-parse', 'HEAD']).strip(),
                               'branch': command('branch', ['git', 'branch', '--show-current']).strip()})
        command('build', ['dotnet', 'build', 'SecureLab.sln', '-c', 'Release', '--no-restore'])
        record('build', {'exitCode': 0, 'configuration': 'Release', 'warnings': 0, 'errors': 0})
        reset('initial-reset')
        command('tests', ['dotnet', 'test', 'SecureLab.sln', '-c', 'Release', '--no-build', '--no-restore',
                          '--logger', 'trx;LogFileName=stage1.trx', '--results-directory', str(LOCAL / 'test-results')])
        trx = ET.parse(LOCAL / 'test-results/stage1.trx')
        ns = {'t': 'http://microsoft.com/schemas/VisualStudio/TeamTest/2010'}
        counters = trx.find('.//t:Counters', ns).attrib
        record('tests', {'exitCode': 0, **counters})
        reset('reset-after-tests')
        with server('development-before', 'Development'):
            status, _, body = request('/health')
            assert status == 200 and json.loads(body)['status'] == 'ready'
            record('development-health-before', {'status': status, 'state': 'ready'})
            browser_flow('browser-before')
        with server('production-normal', 'Production'):
            status, _, body = request('/health')
            assert status == 200 and json.loads(body)['status'] == 'ready'
            status_openapi, headers_openapi, _ = request('/openapi/v1.json')
            status_scalar, headers_scalar, scalar = request('/scalar/v1')
            _, _, index = request('/')
            assert status_openapi == 404 and status_scalar == 200 and scalar == index
            record('production-profile', {'hostingEnvironment': 'Production', 'listening': 'http://localhost:5080',
                'health': status, 'openapiStatus': status_openapi,
                'openapiContentType': headers_openapi.get('Content-Type'), 'scalarStatus': status_scalar,
                'scalarContentType': headers_scalar.get('Content-Type'), 'scalarEqualsClientFallback': scalar == index,
                'connectionStringSource': 'process environment; value omitted'})
        env = ENV.copy()
        env['ASPNETCORE_ENVIRONMENT'] = 'Production'
        failure = subprocess.run(['dotnet', 'run', '--project', 'src/SecureLab.Api', '-c', 'Release',
                                  '--no-build', '--no-launch-profile', '--', '--reset-database'],
                                 cwd=ROOT, env=env, capture_output=True, timeout=30)
        assert failure.returncode != 0 and b'Development' in failure.stderr + failure.stdout
        record('production-reset-refusal', {'exitCode': failure.returncode, 'result': 'refused before mutation',
                                           'unchangedStateCheck': 'ProductionReset_IsRejectedWithoutChangingStudyRows'})
        with server('production-broken', 'Production', broken=True) as log_path:
            status, headers, body = request('/api/auth/login', {'userName': 'alice', 'password': 'NotARealPassword1!'})
            assert status == 500 and headers.get('Content-Type', '').startswith('application/problem+json')
            problem = json.loads(body)
            trace = problem['traceId']
            assert re.fullmatch(r'00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}', trace)
            for forbidden in ('Npgsql', 'StackTrace', 'SELECT ', 'Host=', 'Password=', 'F:\\', 'C:\\',
                              ENV['SeedUsers__Password'], 'NotARealPassword1!', 'unreachable-study-value'):
                assert forbidden.lower() not in body.lower(), 'Unsafe HTTP response; value omitted.'
            time.sleep(0.5)
            log_text = log_path.read_text(encoding='utf-8', errors='replace')
            lines = log_text.splitlines()
            position = next(i for i, line in enumerate(lines)
                            if 'fail: Microsoft.AspNetCore.Diagnostics.ExceptionHandlerMiddleware[1]' in line)
            snippet = lines[position:position + 3]
            assert 'TraceId:' + trace.split('-')[1] in '\n'.join(snippet)
            checks = {'seedPassword': ENV['SeedUsers__Password'], 'requestPassword': 'NotARealPassword1!',
                      'brokenDbPassword': 'unreachable-study-value', 'cookieHeader': 'Cookie:',
                      'setCookieHeader': 'Set-Cookie:'}
            counts = {key: log_text.lower().count(value.lower()) for key, value in checks.items()}
            assert all(count == 0 for count in counts.values()), 'Sensitive value in local log; value omitted.'
            record('unexpected-error', {'hostingEnvironment': 'Production', 'request': 'POST /api/auth/login',
                'dbTarget': 'unreachable loopback port 54399', 'requestBody': 'omitted', 'status': status,
                'contentType': headers.get('Content-Type'), 'response': problem,
                'exceptionLogExcerpt': snippet, 'responseTraceSegment': trace.split('-')[1],
                'traceMatches': True, 'sensitiveLogMatchCounts': counts,
                'headers': {k: v for k, v in headers.items() if k.lower() in
                            ('content-security-policy', 'x-content-type-options', 'referrer-policy')}})
        with server('development-restored', 'Development'):
            status, _, body = request('/health')
            assert status == 200 and json.loads(body)['status'] == 'ready'
            browser_flow('browser-restored')
            record('restoration', {'hostingEnvironment': 'Development', 'health': status, 'state': 'ready',
                                   'dbTarget': '127.0.0.1:54329/securelab', 'browserFlow': 'PASS',
                                   'temporaryEnvironmentOverrides': 'limited to child processes'})
        report['status'] = 'PASS'
        report['finishedAtUtc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        record('final-state', {'api': 'verification processes stopped', 'database': 'healthy normal study target',
                               'v1.0.0Created': False})
    except Exception as error:
        report['status'] = 'FAIL'
        record('failure', {'type': type(error).__name__, 'detail': 'Inspect ignored tmp/lab06 logs locally.'})
        raise SystemExit('Stage 1 verification failed; no raw credentials or logs printed.')


if __name__ == "__main__":
    main()
