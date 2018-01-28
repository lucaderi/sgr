"""
Implement some default types

"""

from __future__ import division


__aggregations_type__ = {}


def add_aggregation(name, function):
    """
    Add a new aggregation function

    """
    __aggregations_type__[name] = function


def _gauge(database, dsmeta, timestamp, value):
    """
    Update function for the gauge type.

    """
    meta = database.meta()
    heartbeat = dsmeta.heartbeat
    last_read = database.last()
    next_timestamp = last_read + meta.step
    partial = database.partial(dsmeta.name)

    if value < dsmeta.min or value > dsmeta.max:
        value = None

    if partial:
        omega, partial_n = partial
    else:
        omega = 0
        partial_n = 0

    if timestamp <= omega:
        raise ValueError("Timestamp too old")

    if timestamp < next_timestamp and value:
        #Devo aggiornare il parziale
        if omega:
            omega = omega - last_read

        newvalue = ((value * (timestamp - last_read - omega)) +
                    (partial_n * omega)) / (timestamp - last_read)
        database.insert_partial(dsmeta.name, timestamp, newvalue)
        return

    to_void = timestamp - heartbeat

    if to_void <= next_timestamp:
        if omega:
            omega = omega - last_read
        if value:
            newvalue = ((value * (timestamp - last_read - omega)) +
                        (partial_n * omega)) / (timestamp - last_read)
        else:
            newvalue = None

        database.insert(dsmeta.name, timestamp, newvalue)
        slot = ((next_timestamp - meta.creation) // meta.step)
        aggregations = database.get_aggregations(slot)
        for i in aggregations:
            __aggregations_type__[i.cf](database, dsmeta.name,
                                     i.xff, i.step, i.rows, timestamp)
        next_timestamp = next_timestamp + meta.step

    while next_timestamp < to_void:
        database.insert(dsmeta.name, next_timestamp, None)
        slot = ((next_timestamp - meta.creation) // meta.step)
        aggregations = database.get_aggregations(slot)
        for i in aggregations:
            __aggregations_type__[i.cf](database, dsmeta.name,
                                     i.xff, i.step, i.rows, next_timestamp)
        next_timestamp = next_timestamp + meta.step

    #Inserire gli inserimenti buoni
        while next_timestamp <= timestamp:
            database.insert(dsmeta.name, next_timestamp, value)
            slot = ((next_timestamp - meta.creation) // meta.step)
            aggregations = database.get_aggregations(slot)
            for i in aggregations:
                __aggregations_type__[i.cf](database, dsmeta.name,
                                         i.xff, i.step, i.rows, next_timestamp)
            next_timestamp = next_timestamp + meta.step

    #Impostare il nuovo valore per partial
        if (next_timestamp - meta.step) - timestamp < 0 and value:
            database.insert_partial(dsmeta.name, timestamp, value)


def _counter(database, dsmeta, timestamp, value):
    """
    Update function for the counter type.

    """
    meta = database.meta()
    heartbeat = dsmeta.heartbeat
    next_timestamp = database.last() + meta.step
    if value < dsmeta.min or value > dsmeta.max:
        value = None

    to_void = timestamp - heartbeat

    while next_timestamp < to_void:
        database.insert(dsmeta.name, next_timestamp, None)
        slot = ((next_timestamp - meta.creation) // meta.step)
        aggregations = database.get_aggregations(slot)
        for i in aggregations:
            __aggregations_type__[i.cf](database, dsmeta.name,
                                     i.xff, i.step, i.rows, next_timestamp)

        database.insert_partial(dsmeta.name, next_timestamp, None)
        next_timestamp = next_timestamp + meta.step

    while next_timestamp <= timestamp:
        partial = database.partial(dsmeta.name)
        if partial and (partial[0] + meta.step) == next_timestamp and \
                value and partial[1]:
            database.insert(dsmeta.name, next_timestamp, value - partial[1])
            database.insert_partial(dsmeta.name, next_timestamp, value)
        else:
            database.insert(dsmeta.name, next_timestamp, None)
            if value:
                database.insert_partial(dsmeta.name, next_timestamp, value)

        slot = ((next_timestamp - meta.creation) // meta.step)
        aggregations = database.get_aggregations(slot)
        for i in aggregations:
            __aggregations_type__[i.cf](database, dsmeta.name,
                                     i.xff, i.step, i.rows, next_timestamp)
        next_timestamp = next_timestamp + meta.step


def _not_interpolable(database, dsmeta, timestamp, value):
    """
    Update function for the not interpolable type.

    """
    meta = database.meta()

    heartbeat = dsmeta.heartbeat
    next_timestamp = database.last() + meta.step
    if value < dsmeta.min or value > dsmeta.max:
        value = None

    to_void = timestamp - heartbeat

    while next_timestamp < to_void:
        database.insert(dsmeta.name, next_timestamp, None)
        slot = ((next_timestamp - meta.creation) // meta.step)
        aggregations = database.get_aggregations(slot)
        for i in aggregations:
            __aggregations_type__[i.cf](database, dsmeta.name,
                                     i.xff, i.step, i.rows, next_timestamp)
        next_timestamp = next_timestamp + meta.step

    while next_timestamp <= timestamp:
        database.insert(dsmeta.name, next_timestamp, value)
        slot = ((next_timestamp - meta.creation) // meta.step)
        aggregations = database.get_aggregations(slot)
        for i in aggregations:
            __aggregations_type__[i.cf](database, dsmeta.name,
                                     i.xff, i.step, i.rows, next_timestamp)
        next_timestamp = next_timestamp + meta.step

def _vector(database, dsmeta, timestamp, value):
    """
    Update function for the not interpolable type.

    """
    meta = database.meta()

    heartbeat = dsmeta.heartbeat
    next_timestamp = database.last() + meta.step

    to_void = timestamp - heartbeat

    while next_timestamp < to_void:
        database.insert(dsmeta.name, next_timestamp, None)
        slot = ((next_timestamp - meta.creation) // meta.step)
        aggregations = database.get_aggregations(slot)
        for i in aggregations:
            __aggregations_type__[i.cf](database, dsmeta.name,
                                     i.xff, i.step, i.rows, next_timestamp)
        next_timestamp = next_timestamp + meta.step

    while next_timestamp <= timestamp:
        database.insert(dsmeta.name, next_timestamp, value)
        slot = ((next_timestamp - meta.creation) // meta.step)
        aggregations = database.get_aggregations(slot)
        for i in aggregations:
            __aggregations_type__[i.cf](database, dsmeta.name,
                                     i.xff, i.step, i.rows, next_timestamp)
        next_timestamp = next_timestamp + meta.step
