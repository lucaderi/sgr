#!/usr/bin/env python
import argparse
import time

import toydb
import r2dlib


def fetch(request):
    start = request.start
    end = request.end
    cf = request.cf
    resolution = request.resolution

    try:
        db = toydb.ToyDB.load(request.db)
    except ValueError:
        print "Error loading database"
        print e
        return 
    
    try:
        res = r2dlib.fetch(db, start, end, cf, resolution)
    except ValueError as e:
        print e
        return

    for i in res:
        print "#"*80
        for j,t in i:
            print j, t
        print "#"*80


def create(request):
    ds_vector = []
    try:
        for i in request.datasource:
            tmp = i.split(':')
            ds_vector.append(r2dlib.DSMeta(tmp[0], tmp[1], 
                                           int(tmp[2]), int(tmp[3]),
                                           int(tmp[4])))
    except:
        print "Wrong datasouce format"
        return

    agg_vec = []
    try:
        for i in request.congregation:
            tmp = i.split(':')
            agg_vec.append(r2dlib.CFMeta(tmp[0], int(tmp[1]), int(tmp[2]),
                                         int(tmp[3])))
    except:
        print "Wrong congregation format"
        return

    try:
        step = int(request.step)
    except:
        print "Step has to be integer"
        return
    
    try:
        creation = int(request.creation)
    except:
        print "Creation has to be integer"
        return

    persistence = request.persistence
    
    try:
        db = toydb.ToyDB(ds_vector, agg_vec, step, creation, persistence)
        db.save()
    except ValueError as e:
        print "Error creating the database"
        print e


def update(request):
    db = None
    try:
        db = toydb.ToyDB.load(request.db)
    except:
        print 'Error loading database from file'
        return 

    if request.ts == None:
        ts = int(time.time())
    else:
        ts = request.ts
    
    vec = []
    for i in request.values:
        if ':' in i:
            vec.append(i.split(':'))
        elif "." in i:
            try:
                vec.append(float(i))
            except ValueError as e:
                print e
                return
        else:
            try:
                vec.append(int(i))
            except ValueError as e:
                print e
                return 
                
    try:
        r2dlib.update(db, ts, vec)

    except ValueError as e:
        print 'Error updating database'
        print e
        return
    
    try:
        db.save()
    except:
        print 'Error saving database'

command_table = {
    'create':create,
    'update':update,
    'fetch': fetch
    }

def main():
    parser = argparse.ArgumentParser(description = 'R2DLIB TOOL')
    subparsers = parser.add_subparsers(dest = 'command')

    create = subparsers.add_parser('create')
    update = subparsers.add_parser('update')
    fetch = subparsers.add_parser('fetch')

    create.add_argument('--datasource', action = 'append', 
                        metavar = "TYPE:NAME:HEARTBEAT:MIN:MAX",
                        required = True)
    create.add_argument('--congregation', action = 'append',
                        metavar = 'FUNCTION:XFF:RESOLUTION:ROWS',
                        required = True)
    create.add_argument('--step', action = 'store',
                        type = int,
                        required = True)
    create.add_argument('--creation', action = 'store',
                        type = int,
                        required = True)
    create.add_argument('--persistence', action = 'store',
                        required = True)

    update.add_argument('--ts', action = 'store', metavar = 'TIMESTAMP', type = int)

    update.add_argument('values', action = 'store', metavar = 'VALUE', nargs = '+')

    update.add_argument('--db', action = 'store', metavar = 'DATABASE', required = True)

    fetch.add_argument('--db', action = 'store', metavar = 'DATABASE', required = True)

    fetch.add_argument('--start', action = 'store', metavar = 'START', required = True, type = int) 

    fetch.add_argument('--end', action = 'store', metavar = 'END', required = True, type = int)

    fetch.add_argument('--cf', action = 'store', metavar = 'CF', required = True)

    fetch.add_argument('--resolution', action = 'store', metavar = 'RESOLUTION', type = int)

    res = parser.parse_args()
    command_table[res.command](res)


if __name__ == '__main__':
    main()

