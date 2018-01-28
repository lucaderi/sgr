"""
The r2dlib

"""

from collections import namedtuple
import default_types
import default_agg

DSMeta = namedtuple('DSMeta', 'type name heartbeat min max')
CFMeta = namedtuple('CFMeta', 'cf xff step rows')
DBMeta = namedtuple('DBMeta', 'step creation persistence')


__update_type__ = {
    'NI': default_types._not_interpolable,
    'GAUGE': default_types._gauge,
    'COUNTER': default_types._counter,
    'VECTOR': default_types._vector,
    }


def fetch(database, start, end, aggregation, resolution=None):
    """
    Fetch data from a database

    Arguments:
    database: The database object
    start: The initial timestamp
    end: The final timestamp
    aggregation: The desired aggregation function

    Optional Arguments:
    resolution: The desired resolution

    """

    fetched = database.fetch_data(start, end, aggregation, resolution)
    meta = database.meta()

    for i in fetched:
        if i != []:
            first = i[0][0]
            last = i[-1][0]
        else:
            first = end
            last = end
            i.append((end, None))

        while first > start:
            first = first - meta.step
            i.insert(0, (first, None))

        while last < end:
            last = last + meta.step
            i.append((last, None))

    return fetched


def update(database, timestamp, value_vec):
    """
    Insert an entry on a database

    Arguments:
    database: The database object
    timestamp: The timestamp of the entry
    value_vec: An iterable containing the values for the entry

    """

    datasources = database.get_sources()
    if len(datasources) != len(value_vec):
        raise ValueError("Wrong vector length")

    if timestamp <= database.last():
        raise ValueError("Timestamp exceeds the last read")

    for index, meta in enumerate(datasources):
        __update_type__[meta.type](database, meta, timestamp, value_vec[index])

    database.increment_last(timestamp)
