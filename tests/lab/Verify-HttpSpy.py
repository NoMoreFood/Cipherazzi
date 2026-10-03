"""Judges one live HTTP Spy lab run: client outcomes, decoded messages, redaction, and process attribution."""
import json
import sqlite3
import sys
from pathlib import Path

output = Path(sys.argv[1])
port = int(sys.argv[2]) if len(sys.argv) > 2 else 443
client = json.loads((output / 'client-results.json').read_text(encoding='utf-8-sig'))
summary = (output / 'collector.stdout').read_text(encoding='utf-8', errors='replace')
failures = []


def check(condition, description):
    print(('Passed: ' if condition else 'FAILED: ') + description)
    if not condition:
        failures.append(description)


def database(name):
    return sqlite3.connect(f'file:{(output / name).as_posix()}?mode=ro', uri=True)


# Every client outcome, from the application's side of the proxy.
for name in ('get', 'post', 'chunked', 'close', 'headers-ok', 'noProcess'):
    check(client[name]['exit'] == 0, f'{name}: the request completed, including its revocation check')
check('"length":3' in client['post']['body'].replace(' ', ''), 'post: the body reached the server after the 100')
check(client['get']['body'] == 'ok', 'get: the response body arrived intact')
for name in ('interrupted-close', 'interrupted-length', 'interrupted-chunked', 'headers', 'requestHeaders'):
    check(client[name]['exit'] != 0, f'{name}: the incomplete exchange is not reported as successful')
check(client['wrongHost']['exit'] != 0, 'wrongHost: a server certificate for another name is refused')
check(client['pinFirst']['exit'] != 0, 'pinFirst: a pinning client rejects the proxy certificate')
check(client['pinSecond']['exit'] == 0, 'pinSecond: the next connection bypasses the proxy and the pin holds')

# The collector's account of what it could not intercept.
lines = summary.splitlines()
check(any('wrong.test' in line and '(0x80090322)' in line and 'bypass' not in line for line in lines),
      'wrong.test is reported as refused for its name, without a bypass')
check(any('httpspy.test' in line and 'bypass the proxy' in line for line in lines),
      'the pinning client is reported and its address bypassed')

# The decoded messages.
store = database('store.db')
rows = store.execute('SELECT flow_id,sequence,method,target,status,state,client_process,request_headers,'
                     'request_bytes,response_bytes FROM exchanges WHERE host=? AND state<>? ORDER BY id',
                     ('httpspy.test', 'encrypted')).fetchall()
encrypted = store.execute("SELECT host,note,client_process FROM exchanges WHERE state='encrypted'").fetchall()
check(any(host == 'wrong.test' and 'SEC_E_WRONG_PRINCIPAL (0x80090322)' in note and 'bypass' not in note
          for host, note, _ in encrypted), 'certificate name failures retain their Schannel name and code in the store')
check(any(host == 'httpspy.test' and 'bypass the proxy' in note for host, note, _ in encrypted),
      'the rejected interception remains visible as an encrypted connection')
check(all(process == 'curl.exe' for _, _, process in encrypted), 'failed connections name the client process')
targets = {row[3] for row in rows}
check({'/ok', '/echo', '/chunked', '/close'} <= targets, 'every fixture path was decoded')
check(all(row[4] == 200 for row in rows), 'no interim 100 response was recorded as a message')
for row in rows:
    expected = 'partial' if row[3].startswith('/interrupted-') or row[3] == '/headers' else 'complete'
    check(row[5] == expected, f'{row[3]}: exchange state is {expected}')
for target in ('/interrupted-close', '/interrupted-length', '/interrupted-chunked'):
    partial = next((row for row in rows if row[3] == target), None)
    check(partial is not None and partial[9] == 4, f'{target}: the partial response body was retained')
check('/headers' in targets and '/request-headers' not in targets, 'aggregate header limits apply in both directions')
check(any('request headers exceeded 64 KiB' in line for line in lines), 'request header limit is diagnosed')
check(any('Response headers exceeded 64 KiB' in line for line in lines), 'response header limit is diagnosed')
post = next(row for row in rows if row[3] == '/echo')
check('Authorization: [redacted' in post[7] and 'Cookie: [redacted' in post[7] and 'secret' not in post[7],
      'credential headers are redacted')
check(post[8] == 3, 'the request body size is recorded')
check(client['chunked']['body'] == 'okfirst second', 'mixed-case chunking preserves both keep-alive responses')
chunked = next(row for row in rows if row[3] == '/chunked')
shared = [row for row in rows if row[0] == chunked[0]]
check(chunked[9] == 12 and [(row[1], row[3]) for row in shared] == [(0, '/ok'), (1, '/chunked')],
      'token matching preserves message boundaries and reuses the connection despite x-close')
check(len({row[0] for row in rows}) == len(rows) - 1, 'independent connections have distinct flow ids')
check(all(row[6] == 'curl.exe' for row in rows), 'decoded messages name the client process')
session = store.execute('SELECT tls_flows,decoded_flows,failed,exchanges FROM sessions').fetchone()
check(session[0] > 0 and session[1] > 0 and session[3] >= len(rows), 'the store reports the proxy counters')
check(session[0] == len(client) - 2, 'failed responses do not count their connections twice')
check(store.execute("SELECT count(*) FROM exchanges WHERE state='complete' AND "
                    "(request_end_us<started_us OR response_start_us<request_end_us OR ended_us<response_start_us)"
                    ).fetchone()[0] == 0, 'completed exchanges preserve ordered send, wait, and receive timestamps')
check(store.execute("SELECT count(*) FROM exchanges WHERE client_path='' OR client_account='' OR "
                    "flow_started_us=0 OR connection_client_port=0").fetchone()[0] == 0,
      'messages and failures retain process details and their underlying connection tuple')

# The journal sees only the proxy's own connection to the server, which must name the client process.
journal = database('journal.db')
owners = {row[0] for row in journal.execute(
    "SELECT source_process FROM connections WHERE destination_port=? AND sni='httpspy.test'", (port,))}
check(owners == {'curl.exe'}, f'journal connections are attributed to the client process, not the proxy: {owners}')

# A separately started session with --no-process must not acquire identities through the proxy.
disabled = database('no-process-store.db')
check(disabled.execute('SELECT count(*) FROM exchanges').fetchone()[0] > 0 and
      disabled.execute("SELECT count(*) FROM exchanges WHERE client_pid IS NOT NULL OR client_process<>'' "
                       "OR server_pid IS NOT NULL OR server_process<>''").fetchone()[0] == 0,
      '--no-process leaves decoded messages unattributed')
disabled_journal = database('no-process.db')
check(disabled_journal.execute('SELECT count(*) FROM connections').fetchone()[0] > 0 and
      disabled_journal.execute("SELECT count(*) FROM connections WHERE source_pid IS NOT NULL "
                               "OR destination_pid IS NOT NULL").fetchone()[0] == 0,
      '--no-process leaves journal connections unattributed')

sys.exit(1 if failures else 0)
