"""Read bounded ordinary SQLite tables offline; never execute stored views or SQL."""
import sqlite3
import tempfile
import time
from pathlib import Path

MAX_TABLES = 64
MAX_COLUMNS = 128
MAX_ROWS = 1000
MAX_CELL = 4096

def inspect(data, emit, deadline):
    stats = {'status': 'partial', 'tables_checked': 0, 'tables_skipped': 0,
             'rows_checked': 0, 'cells_skipped': 0, 'row_limit_reached': False,
             'table_limit_reached': False, 'sqlite_version': sqlite3.sqlite_version,
             'journal_state': 'standalone_main_file_only'}
    if not data.startswith(b'SQLite format 3\x00'):
        raise ValueError('sqlite_header_invalid_or_encrypted')
    def quote(name):
        return '"' + name.replace('"', '""') + '"'
    with tempfile.TemporaryDirectory(prefix='app-security-sqlite-') as work:
        path = Path(work) / 'input.db'
        with path.open('xb') as out:
            path.chmod(0o600)
            out.write(data)
        connection = sqlite3.connect(path.as_uri() + '?mode=ro&immutable=1', uri=True)
        try:
            connection.execute('PRAGMA query_only=ON')
            connection.execute('PRAGMA trusted_schema=OFF')
            connection.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
            # Only ordinary tables: views, triggers, virtual tables and their SQL are not run.
            tables = connection.execute("SELECT name, sql, type FROM sqlite_master WHERE type IN ('table','view') ORDER BY name LIMIT ?", (MAX_TABLES + 1,)).fetchall()
            stats['table_limit_reached'] = len(tables) > MAX_TABLES
            for index, (name, sql, kind) in enumerate(tables[:MAX_TABLES]):
                if time.monotonic() > deadline:
                    raise ValueError('sqlite_deadline')
                if kind != 'table' or name.startswith('sqlite_') or not isinstance(sql, str) or not sql.lstrip().upper().startswith('CREATE TABLE'):
                    stats['tables_skipped'] += 1
                    continue
                # table_xinfo identifies generated/hidden columns so their expressions are never evaluated.
                columns = connection.execute('PRAGMA table_xinfo(' + quote(name) + ')').fetchmany(MAX_COLUMNS + 1)
                if not columns or len(columns) > MAX_COLUMNS or any(len(c) < 7 or c[6] != 0 for c in columns):
                    stats['tables_skipped'] += 1
                    continue
                # Authorizer forbids functions, writes, attachment and reads of unexpected tables.
                def authorize(action, arg1, arg2, db, trigger):
                    if action == sqlite3.SQLITE_SELECT: return sqlite3.SQLITE_OK
                    if action == sqlite3.SQLITE_READ and arg1 == name and db == 'main' and not trigger: return sqlite3.SQLITE_OK
                    return sqlite3.SQLITE_DENY
                connection.set_authorizer(authorize)
                try:
                    remaining = MAX_ROWS - stats['rows_checked']
                    query = 'SELECT ' + ','.join(quote(c[1]) for c in columns) + ' FROM ' + quote(name) + ' LIMIT ?'
                    rows = connection.execute(query, (remaining + 1,))
                    for row in rows:
                        if stats['rows_checked'] >= MAX_ROWS:
                            stats['row_limit_reached'] = True
                            break
                        if time.monotonic() > deadline: raise ValueError('sqlite_deadline')
                        stats['rows_checked'] += 1
                        values = {}
                        for column, value in zip(columns, row):
                            if isinstance(value, bytes) or isinstance(value, str) and len(value.encode('utf8')) > MAX_CELL:
                                stats['cells_skipped'] += 1
                            else: values[column[1]] = value
                        emit(values, {'usage': 'sqlite_table_record', 'table_index': index,
                                      'row_ordinal': stats['rows_checked']})
                    stats['tables_checked'] += 1
                finally:
                    # Python 3.9 does not reliably disable callbacks with None.
                    connection.set_authorizer(lambda *args: sqlite3.SQLITE_OK)
                if stats['row_limit_reached']: break
        except sqlite3.Error:
            raise ValueError('sqlite_parse_or_query_failed') from None
        finally:
            connection.close()
    return stats
