"""
Implement some aggregtion functions

"""
from __future__ import division

import default_types


def _last(database, name, xff, steps, rows, timestamp):
    """
    Last aggregation function

    """

    tmp = database.get_lastreads(name, steps)

    if sum(1 for t, v in tmp if v is None) >= xff:
        database.store('LAST', name, steps, rows, timestamp, None)
        return

    database.store('LAST', name, steps, rows, timestamp, tmp[-1][1])


def _average(database, name, xff, steps, rows, timestamp):
    """
    Average aggregation function

    """

    tmp = database.get_lastreads(name, steps)
    count = len(tmp)
    xff_count = 0
    total = 0
    for i in tmp:
        if not i[1]:
            count -= 1
            xff_count += 1
            if xff_count >= xff:
                database.store('AVG', name, steps, rows, timestamp, None)
                return
        else:
            total += i[1]
    try:
        database.store('AVG', name, steps, rows, timestamp, total / count)
    except TypeError:
        database.store('AVG', name, steps, rows, timestamp, None)


def _max(database, name, xff, steps, rows, timestamp):
    """
    Max aggregation function

    """

    tmp = database.get_lastreads(name, steps)
    if sum(1 for t, v in tmp if v is None) >= xff:
        database.store('MAX', name, steps, rows, timestamp, None)
        return
    max_item = max(tmp, key=lambda x: x[1])
    database.store('MAX', name, steps, rows, timestamp, max_item[1])


def _min(database, name, xff, steps, rows, timestamp):
    """
    Min aggregation function

    """

    tmp = database.get_lastreads(name, steps)
    tmp = filter(lambda value: value[1], tmp)
    if steps - len(tmp) >= xff:
        database.store('MIN', name, steps, rows, timestamp, None)
        return
    min_item = min(tmp, key=lambda x: x[1])
    database.store('MIN', name, steps, rows, timestamp, min_item[1])


def _sum(database, name, xff, steps, rows, timestamp):
    """
    Sum aggregation function

    """

    tmp = database.get_lastreads(name, steps)
    total = 0
    for i in tmp:
        if i[1] == None:
            xff -= 1
            if xff <= 0:
                database.store('SUM', name, steps, rows, timestamp, None)
                return
        else:
            total += i[1]
    database.store('SUM', name, steps, rows, timestamp, total)


default_types.add_aggregation('LAST', _last)
default_types.add_aggregation('AVG', _average)
default_types.add_aggregation('MAX', _max)
default_types.add_aggregation('MIN', _min)
default_types.add_aggregation('SUM', _sum)
