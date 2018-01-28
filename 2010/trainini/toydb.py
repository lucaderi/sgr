"""
Implement a simple round robin database suitable for
r2dlib.

"""
import os
import r2db
from r2dlib import DBMeta
from contextlib import contextmanager
import tempfile


class ToyDB(r2db.DB):
    """
    A simple implementation of a
    r2dlib database type

    """
    def __init__(self, ds_vector, cf_vector, step, creation, persistence=None):
        self._last = creation
        self._ds_meta = []
        self._reads = {}

        self._data = {}
        self._aggregations = {}

        self._maxreads = -1

        self._partial = {}

        if persistence:
            persistence = os.path.abspath(persistence)

        for i in ds_vector:
            self._ds_meta.append(i)
            self._reads[i.name] = []

        for i in cf_vector:
            if self._maxreads < i.rows:
                self._maxreads = i.rows

            tmp = self._aggregations.get(i.step)
            if not tmp:
                self._aggregations[i.step] = tmp = []
            tmp.append(i)

            self._data[(i.cf, i.step)] = {}
            for j in ds_vector:
                self._data[(i.cf, i.step)][j.name] = []

        self._meta = DBMeta(step, creation, persistence)

    @contextmanager
    def locked(self):
        """
        Lock the database
        
        """
        if not self._meta.persistence:
            return
        try:
            name = ".".join((self._meta.persistence, "lock"))
            filelock = os.open(name, os.O_EXCL | os.O_CREAT)
            os.close(filelock)
            self._locked = True
            yield
        except:
            raise
        finally:
            if self._locked:
                os.remove(name)

    def save(self):
        """
        Save the database state
        
        """
        try:
            import cPickle as pickle
        except ImportError:
            import pickle

        tmpfile = tempfile.NamedTemporaryFile(delete=False, 
                                              dir=os.path.dirname(self._meta.persistence))
        pickle.dump(self, tmpfile)
        tmpfile.close()
        os.rename(tmpfile.name, self._meta.persistence)

    @classmethod
    def load(cls, path):
        """
        Load a database from file
        
        Arguments:
        path: The file path

        """
        try:
            import cPickle as pickle
        except ImportError:
            import pickle

        with  open(path, 'r') as dbfile:
            result =  pickle.load(dbfile)

        return result


    def meta(self):
        return self._meta

    def fetch_data(self, start, stop, aggregation, resolution=None):
        keys = filter(lambda x: x[0] == aggregation, self._data.keys())

        if resolution:
            keys = filter(lambda x: x[1] == resolution, self._data.keys())
            key = keys.pop()

        elif resolution == None and keys:
            key = max(keys, key=lambda x: x[1])

        try:
            tmp = self._data[key]
        except UnboundLocalError:
            raise ValueError("No such congregation function")

        res = []
        for i in tmp:
            res.append([x for x in tmp[i] if start <= x[0] <= stop])

        return res

    def get_sources(self):
        return tuple(self._ds_meta)

    def last(self):
        return self._last

    def insert(self, name, timestamp, value):
        self._reads[name].append((timestamp, value))
        if len(self._reads[name]) > 2 * self._maxreads:
            del self._reads[name][0:self._maxreads]

    def get_aggregations(self, slot):
        tmp = []
        for i in self._aggregations.keys():
            if not slot % i:
                tmp += self._aggregations[i]

        return tmp

    def get_lastreads(self, name, step):
        return tuple(self._reads[name][-step:])

    def store(self, aggregation, datasource, steps, rows, timestamp, value):
        self._data[(aggregation, steps)][datasource].append((timestamp, value))
        if len(self._data[(aggregation, steps)][datasource]) > rows:
            del self._data[(aggregation, steps)][datasource][0:rows]

    def partial(self, name):
        return self._partial.get(name)

    def insert_partial(self, name, timestamp, newvalue):
        self._partial[name] = (timestamp, newvalue)

    def increment_last(self, timestamp):
        slot = (timestamp - self._meta.creation) // self._meta.step
        self._last = self._meta.creation + slot * self._meta.step
