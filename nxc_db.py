"""Read-only NetExec SMB database metadata; credential values are never selected."""
from pathlib import Path
import sqlite3
import time

LIMIT = 50000


def read_database(filename):
    path = Path(filename).resolve()
    if path.stat().st_size > 64 * 1024 * 1024:
        raise ValueError("NetExec database exceeds 64 MiB")
    with path.open('rb') as f:
        if f.read(16) != b'SQLite format 3\x00':
            raise ValueError("Not a SQLite database")
    connection = sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=1)
    started = time.monotonic()
    connection.set_progress_handler(lambda: int(time.monotonic()-started > 3), 1000)
    connection.row_factory = sqlite3.Row
    result = {"credentials": [], "hosts": [], "admin_relations": [], "warnings": []}
    try:
        connection.execute('PRAGMA query_only=ON')
        tables = {r[0] for r in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        required = {'users': {'id', 'domain', 'username', 'credtype'},
                    'hosts': {'id', 'ip', 'hostname', 'domain'},
                    'admin_relations': {'id', 'userid', 'hostid'}}
        for table, columns in required.items():
            if table not in tables:
                continue
            actual = {r[1] for r in connection.execute('PRAGMA table_info(' + table + ')')}
            if not columns.issubset(actual):
                result['warnings'].append('Unsupported columns in ' + table)
                continue
            if table == 'users':
                material = "CASE WHEN password IS NULL OR length(password)=0 THEN 0 ELSE 1 END" if 'password' in actual else 'NULL'
                # Deliberately do not SELECT the password/hash column itself.
                query = 'SELECT id,domain,username,credtype,' + material + ' AS material_present FROM users LIMIT 50001'
                key = 'credentials'
            elif table == 'hosts':
                query, key = 'SELECT id,ip,hostname,domain FROM hosts LIMIT 50001', 'hosts'
            else:
                query, key = 'SELECT id,userid,hostid FROM admin_relations LIMIT 50001', 'admin_relations'
            rows = [dict(row) for row in connection.execute(query)]
            result[key] = rows[:LIMIT]
            if len(rows) > LIMIT:
                result['warnings'].append(table + ' truncated at 50000 rows')
    finally:
        connection.close()
    return result
