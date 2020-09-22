import json
import sqlite3


class KVstore(dict):
    debug = False

    def __init__(self, filename=None):
        super().__init__()
        self.conn = sqlite3.connect(filename)
        self.conn.execute("CREATE TABLE IF NOT EXISTS kv (key text unique, value text)")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def close(self):
        KVstore.debug and print("[*] Closing KVstore")
        self.conn.commit()
        self.conn.close()

    def commit(self):
        self.conn.commit()

    def __len__(self):
        rows = self.conn.execute('SELECT COUNT(*) FROM kv').fetchone()[0]
        return rows if rows is not None else 0

    def iterkeys(self):
        for row in self.conn.execute('SELECT key FROM kv'):
            yield row[0]

    def itervalues(self):
        c = self.conn.cursor()
        for row in c.execute('SELECT value FROM kv'):
            yield json.loads(row[0])

    def iteritems(self):
        c = self.conn.cursor()
        for row in c.execute('SELECT key, value FROM kv'):
            yield row[0], json.loads(row[1])

    def keys(self):
        return list(self.iterkeys())

    def values(self):
        return list(self.itervalues())

    def items(self):
        return list(self.iteritems())

    def __contains__(self, key):
        return self.conn.execute('SELECT 1 FROM kv WHERE key = ?', (key,)).fetchone() is not None

    def __getitem__(self, key):
        item = self.conn.execute('SELECT value FROM kv WHERE key = ?', (key,)).fetchone()
        if item is None:
            raise KeyError(key)
        el = json.loads(item[0])
        if type(el) is dict:
            return el
        return item[0]

    def __setitem__(self, key, value):
        if type(value) is dict:
            KVstore.debug and print("[*] Dict to json")
            self.conn.execute('REPLACE INTO kv (key, value) VALUES (?,?)', (key, json.dumps(value)))
        else:
            self.conn.execute('REPLACE INTO kv (key, value) VALUES (?,?)', (key, value))
        self.commit()

    def __delitem__(self, key):
        if key not in self:
            raise KeyError(key)
        self.conn.execute('DELETE FROM kv WHERE key = ?', (key,))

    def __iter__(self):
        return self.iterkeys()
