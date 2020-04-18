import time
from os import path
import rrdtool
from easysnmp import Session
import argh


def createrrd(host:str, interfaceindex:int):
    rrdbname = host+str(interfaceindex)+'.rrd'
    if path.exists(rrdbname):
        return rrdbname
    rrdtool.create(
        rrdbname,
        '--start', 'now',
        '--step', '60',
        'DS:inoctets:COUNTER:100:0:4294967295',
        'RRA:AVERAGE:0.5:1:1440',
        'DS:outoctets:COUNTER:100:0:4294967295',
        'RRA:AVERAGE:0.5:1:1440',
        'DS:speed:GAUGE:100:0:4294967295',
        'RRA:AVERAGE:0.5:1:1440',
    )
    return rrdbname

def graph(rrdbname):
    """
    Creates a graph displaying monitored values stored in an rrd with name rrdbname
    """
    rrdtool.graph('netgraph-' + path.splitext(rrdbname)[0] + '.png',
                  '--vertical-label= bits per second',
                  '-t ' + "net-traffic",
                  '-w 600',
                  '--end', 'now',
                  '--start', 'end-1d',
                  'DEF:inoct=' + rrdbname + ':inoctets:AVERAGE',
                  'DEF:outoct=' + rrdbname + ':outoctets:AVERAGE',
                  'DEF:speed=' + rrdbname + ':speed:AVERAGE',

                  'CDEF:in=inoct,8,*',
                  'CDEF:out=outoct,8,*',
                  'CDEF:tot=in,out,+',
                  'CDEF:usage=tot,speed,/,100,*',

                  'AREA:out#DE48EC:out',
                  'GPRINT:out:AVERAGE:Avg %6.2lf %S',
                  'GPRINT:out:MAX:Max %6.2lf %S',
                  'GPRINT:out:MIN:Min %6.2lf %S',
                  'GPRINT:out:LAST:Last %6.2lf %S\l',

                  'AREA:in#48C4EC:in :STACK',
                  'GPRINT:in:AVERAGE:Avg %6.2lf %S',
                  'GPRINT:in:MAX:Max %6.2lf %S',
                  'GPRINT:in:MIN:Min %6.2lf %S',
                  'GPRINT:in:LAST:Last %6.2lf %S\l',

                  'VDEF:totpercentile=tot,95,PERCENT',
                  'HRULE:totpercentile#FF0000:95th',
                  'GPRINT:totpercentile:%6.2lf %S\l',

                  'COMMENT:------------------------------------------\l',
                  'COMMENT:tot\t',
                  'GPRINT:tot:AVERAGE:Avg %6.2lf %S',
                  'GPRINT:tot:MAX:Max %6.2lf %S',
                  'GPRINT:tot:MIN:Min %6.2lf %S',
                  'GPRINT:tot:LAST:Last %6.2lf %S\l',

                  'LINE1:tot#1598C3',
                  'LINE1:out#B415C7',

                  'COMMENT:bandwidth usage(%)',
                  'GPRINT:usage:AVERAGE:Avg %3.3lf',
                  'GPRINT:usage:MAX:Max %3.3lf',
                  'GPRINT:usage:MIN:Min %3.3lf\l'
                  )

    rrdtool.graph('bandwidth' + path.splitext(rrdbname)[0] + '.png',
                  '-t ' + "bandwidth usage",
                  '-w 600',
                  '--end', 'now',
                  '--start', 'end-1d',
                  'DEF:inoct=' + rrdbname + ':inoctets:AVERAGE',
                  'DEF:outoct=' + rrdbname + ':outoctets:AVERAGE',
                  'DEF:speed=' + rrdbname + ':speed:AVERAGE',
                  'CDEF:in=inoct,8,*',
                  'CDEF:out=outoct,8,*',

                  'CDEF:usage=in,out,+,speed,/,100,*',

                  'AREA:usage#54EC48:Bandwidth(%)',
                  'LINE1:usage#24BC14',
                  )


def callperiodically(f,period):
    """
    calls f periodically. Sleeps if finishes before next period
    :param f: f to call
    :param period: period in secs
    """
    while(1):
        starttime = time.time()
        f()
        endtime=time.time()
        delta=endtime-starttime
        if period-delta > 0:
            time.sleep(period-delta)

def f(session, interfaceindex, rddbname):
    oidsval=getinoutspeed(session,interfaceindex)
    rrdtool.update(rddbname, 'N:' + ":".join(oidsval))

def selectinterface(session:Session)->int:
    ninterface=int(session.get("IF-MIB::ifNumber.0").value)
    for i in range(1,ninterface+1):
        print(i,session.get("IF-MIB::ifDescr." + str(i)).value)
    interfaceindex=int(input("Select target interface: "))
    return interfaceindex

def getinoutspeed(session,interfaceindex):
    oids = session.get(["IF-MIB::ifInOctets." + str(interfaceindex),    #counter32
                        "IF-MIB::ifOutOctets." + str(interfaceindex),   #counter32
                        "IF-MIB::ifSpeed." + str(interfaceindex)])      #gauge32
    ret = list(map(lambda e:e.value, oids))
    print(ret)
    return ret

@argh.arg('-c','--community', help='snmp community',default="public")
@argh.arg('--host', help='snmp target host',default="localhost")
def netmonitor(community=None, host=None):
    """
    Monitors InOctets,OutOCtets,ifSpeed of the snmp target community host
    and saves them into an rrd database
    """
    try:
        session = Session(hostname=host, community=community, version=2)
        interfaceindex = selectinterface(session)
        rrdname = createrrd(host, interfaceindex)
        callperiodically(lambda:f(session,interfaceindex,rrdname),60)
    except KeyboardInterrupt as ex:
        print(ex)

if __name__ == '__main__':
    argh.dispatch_commands([netmonitor,graph])