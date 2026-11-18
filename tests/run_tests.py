"""Run the real Godot engine against shared vectors and a loopback HTTP fixture.

The fixture records requests independently, so retries/non-replay and payload checks do not
merely mirror client internals. No hosted customer credentials or financial events are used.
"""
import argparse
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import ssl
import tempfile
import threading
import time

from security_fixtures import create as create_security_fixtures


def run(engine, project, output=None):
    project = project.resolve()
    vector_root = project / 'test-vectors'
    if not vector_root.exists():
        vector_root = project.parent / 'test-vectors'
    contract = json.loads((vector_root / 'http-contract.json').read_text(encoding='utf8'))
    cases = {f'{group}-{i}': value for group in (
        'httpAuthority', 'httpLicenseResponses', 'httpTransientResponses',
        'floatingCases', 'operationCases', 'transportCases')
        for i, value in enumerate(contract[group])}
    cases.update({'security-cache': {'status':503, 'body':''},
                  'timeout': {'status':200, 'body':'{"isValid":true}', 'delay':0.7},
                  'tls': {'status':200, 'body':'{"isValid":true}'},
                  'offline-online-valid': {'status':200, 'body':'{"isValid":true,"message":"Valid.","isRevoked":false}', 'operation':'offline_verify'},
                  'offline-online-denied': {'status':403, 'body':'{"isValid":true}', 'operation':'offline_verify'}})
    counts = Counter()
    bodies = {}
    fixture_failures = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            self.respond()

        def do_POST(self):
            self.respond()

        def respond(self):
            parts = self.path.split('/')
            case_id = parts[1] if len(parts) > 1 else ''
            value = cases.get(case_id)
            if value is None:
                fixture_failures.append('Unexpected path: ' + self.path)
                self.send_error(404)
                return
            nonce = self.path.endswith('/nonce')
            key = (case_id, 'nonce' if nonce else 'operation')
            request_index = counts[key]
            counts[key] += 1
            length = int(self.headers.get('Content-Length', '0'))
            raw = self.rfile.read(length) if length else b''
            bodies.setdefault(key, []).append((self.command, self.path, raw))
            statuses = value.get('nonceStatuses', [200]) if nonce else value.get('statuses', [value.get('status', 200)])
            status = statuses[min(request_index, len(statuses) - 1)]
            body = value.get('nonceBody', '{"nonce":"fixture-nonce"}') if nonce else value.get('body', '')
            payload = body.encode('utf8') if status != 204 else b''
            if value.get('delay'):
                time.sleep(value['delay'])
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Connection', 'close')
            if value.get('location'):
                self.send_header('Location', value['location'])
            self.send_header('Content-Length', str(len(payload) + (20 if value.get('truncatedBody') else 0)))
            self.end_headers()
            try:
                self.wfile.write(payload)
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, ssl.SSLError):
                pass  # The owned timeout/negative-TLS client intentionally disconnected.
            self.close_connection = True

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        # TemporaryDirectory owns only this fixture's synthetic cache, outside the source tree.
        with tempfile.TemporaryDirectory(prefix='permitcore-godot-') as directory:
            cache = Path(directory).resolve()
            assert cache.parent == Path(tempfile.gettempdir()).resolve()
            security = create_security_fixtures(cache)
            tls_server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
            tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls_context.load_cert_chain(cache/'leaf.pem', cache/'leaf.key')
            tls_server.socket = tls_context.wrap_socket(tls_server.socket, server_side=True)
            tls_thread = threading.Thread(target=tls_server.serve_forever, daemon=True)
            tls_thread.start()
            wrong_server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
            wrong_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            wrong_context.load_cert_chain(cache/'wrong-leaf.pem', cache/'leaf.key')
            wrong_server.socket = wrong_context.wrap_socket(wrong_server.socket, server_side=True)
            wrong_thread = threading.Thread(target=wrong_server.serve_forever, daemon=True)
            wrong_thread.start()
            security.update(tlsUrl=f'https://127.0.0.1:{tls_server.server_port}/tls',
                            wrongHostUrl=f'https://127.0.0.1:{wrong_server.server_port}/tls')
            security_file = cache / 'security-fixtures.json'
            security_file.write_text(json.dumps(security))
            try:
                process = subprocess.run([str(engine), '--headless', '--path', str(project),
                                          '--script', 'tests/test_client.gd', '--',
                                          f'http://127.0.0.1:{server.server_port}', str(cache), str(security_file)],
                                         capture_output=True, text=True, timeout=180)
            finally:
                tls_server.shutdown(); tls_server.server_close(); tls_thread.join(timeout=5)
                wrong_server.shutdown(); wrong_server.server_close(); wrong_thread.join(timeout=5)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    errors = list(fixture_failures)
    if any(marker in process.stdout + process.stderr for marker in ('SCRIPT ERROR:', 'Parse Error:', 'Compilation failed')):
        errors.append('Godot reported a script/compilation error, regardless of process exit code')
    for i, value in enumerate(contract['transportCases']):
        case_id = f'transportCases-{i}'
        if counts[case_id, 'operation'] != value['expectedRequests']:
            errors.append(case_id + ': wrong operation count ' + str(counts[case_id, 'operation']))
        if 'expectedNonceRequests' in value and counts[case_id, 'nonce'] != value['expectedNonceRequests']:
            errors.append(case_id + ': wrong nonce count ' + str(counts[case_id, 'nonce']))
    for case_id, value in cases.items():
        operation = value.get('operation', 'validate')
        for method, path, raw in bodies.get((case_id, 'operation'), []):
            if method != 'POST':
                errors.append(case_id + ': operation must POST')
            try:
                data = json.loads(raw)
            except ValueError:
                errors.append(case_id + ': malformed request JSON')
                continue
            required = {'validate': {'licenseKey', 'version', 'expectedProductId', 'deviceId'},
                        'activate': {'licenseKey', 'deviceId', 'nonce', 'deviceName', 'version', 'expectedProductId'},
                        'checkout': {'licenseKey', 'deviceId'}, 'heartbeat': {'sessionToken'},
                        'checkin': {'sessionToken'}, 'meter': {'licenseKey', 'eventName', 'quantity'},
                        'deactivate': {'licenseKey', 'activationId'}, 'offline_verify': {'token'}}[operation]
            if case_id in ('security-cache', 'tls'):
                required = required - {'deviceId'}
            if not required.issubset(data):
                errors.append(case_id + ': missing payload fields ' + str(required - set(data)))
            if operation == 'activate' and data.get('nonce') != 'fixture-nonce':
                errors.append(case_id + ': activation did not use fetched nonce')
            if operation == 'meter' and data.get('quantity', 0) < 1:
                errors.append(case_id + ': quantity not normalized')
    lines = [line for line in process.stdout.splitlines() if line.startswith('{')]
    native = json.loads(lines[-1]) if lines else {'result': 'FAIL', 'failures': ['No native result']}
    result = {'result': 'PASS' if process.returncode == 0 and not errors and native['result'] == 'PASS' else 'FAIL',
              'native': native, 'fixtureErrors': errors,
              'requests': sum(counts.values()), 'casesObserved': len(set(key[0] for key in counts)),
              'stdout': process.stdout, 'stderr': process.stderr}
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2), encoding='utf8')
    print(json.dumps(result, indent=2))
    return result['result'] == 'PASS'


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--godot', required=True, type=Path)
    parser.add_argument('--project', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--output', type=Path)
    arguments = parser.parse_args()
    raise SystemExit(0 if run(arguments.godot, arguments.project, arguments.output) else 1)
