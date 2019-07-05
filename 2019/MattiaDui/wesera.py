import argparse
import concurrent.futures._base
import pyshark
import re
import sys
import threading
import time

from datetime import timedelta, datetime
from timeloop import Timeloop

captured = {'redis': {'size': 0, 'hit': 0, 'set': 0, 'adm': 0}, 'sql': {'size': 0}}
locInter = "lo"
portRedis = 6379
portSql = 3306
timerDisplay = Timeloop()
timerFile = Timeloop()
reportName = "wesera_report.txt"

def intFromString(search):
    return int(re.search(r'\d+', search).group())

def sizeof_fmt(num, suffix='B'):
    for unit in ['','Ki','Mi','Gi','Ti','Pi','Ei','Zi']:
        if abs(num) < 1024.0:
            return "%3.1f%s%s" % (num, unit, suffix)
        num /= 1024.0
    return "%.1f%s%s" % (num, 'Yi', suffix)

def countPackets(pkt):
    global captured
    srcPort = intFromString(pkt.tcp.srcport)
    destPort = intFromString(pkt.tcp.dstport)

    if (srcPort == portRedis):
        captured['redis']['size'] += intFromString(pkt.tcp.len)
    elif (destPort == portRedis):
        try:
            t = bytearray.fromhex(pkt.data.data).decode().lower()
            setIndex = t.find("set")
            getIndex = t.find("get")
            if (setIndex >= 0 and getIndex >= 0):
                if(setIndex < getIndex):
                    captured['redis']['set'] += 1
                else:
                    captured['redis']['hit'] += 1
            elif (setIndex >= 0):
                captured['redis']['set'] += 1
            elif (getIndex >= 0):
                captured['redis']['hit'] += 1
            else:
                captured['redis']['adm'] += 1
        except AttributeError:
            pass
    else:
        captured['sql']['size'] += intFromString(pkt.tcp.len)

def getInfo():
    currDate = datetime.now()
    cacheRatio = 0.0;
    redisData = captured['redis']['size']
    sqlData = captured['sql']['size']
    cacheHit = captured['redis']['hit']
    cacheSet = captured['redis']['set']
    cacheAdmin = captured['redis']['adm']
    cacheTot = cacheHit + cacheSet
    cacheHitRatio = 0.0;
    cacheSetRatio = 0.0;
    if (cacheTot > 0.0):
        cacheHitRatio = cacheHit / cacheTot * 100.0
        cacheSetRatio = cacheSet / cacheTot * 100.0
    row1 = ("[" + str(currDate) + "] Redis "+sizeof_fmt(redisData)+" ; MySQL "+sizeof_fmt(sqlData))
    row2 = ("[" + str(currDate) + "] Hit: {}; Set: {}; Ratio: {:.2f}%/{:.2f}%; Admin: {}".format(cacheHit, cacheSet, cacheHitRatio, cacheSetRatio, cacheAdmin))
    return row1+"\n"+row2+"\n\n"

@timerDisplay.job(interval=timedelta(seconds=5))
def monitorStatus():
    print(getInfo())

@timerFile.job(interval=timedelta(minutes=2))
def reportWrite():
    print("[" + str(datetime.now()) + "] Adding report line...")
    f = open(reportName, 'a')
    f.write(getInfo())
    f.close()

def main():
    global reportName, reportTime, portRedis, portSql

    options = argparse.ArgumentParser(description='WEb SErver Redis Analyzer')
    options.add_argument('-i', '--interface', metavar='LOCAL_INTERFACE', default=locInter, help="Name of the local interface to listen on [default = {}]".format(locInter))
    options.add_argument('-pr', '--port-redis', metavar='REDIS_PORT', type=int, default=portRedis, help="Redis server port [default = {}]".format(portRedis))
    options.add_argument('-pm', '--port-mysql', metavar='MYSQL_PORT', type=int, default=portSql, help="MySQL server port [default = {}]".format(portSql))
    options.add_argument('-s', '--silent', action='store_true', help="Don't print anything on the stdout (must be used with -r, nohup launch suggested)")
    options.add_argument('-r', '--report', action='store_true', help="Generate a report file updated every 2 minutes (This option MUST be set for -rn)")
    options.add_argument('-rn', '--report-name', metavar='PATH_TO_FILE', default=reportName, help="Relative path complete with file name for the report file [default = {} ]".format(reportName))
    chop = options.parse_args()

    if(chop.silent and not chop.report):
        print("[WESERA] [ERR] Option -s (--silent) must be used along with -r (--report)")
        sys.exit(1)

    portRedis = chop.port_redis
    portSql = chop.port_mysql

    try:
        if(not chop.silent):
            timerDisplay.start()
        if(chop.report):
            reportName = chop.report_name
            timerFile.start()
        captureObj = pyshark.LiveCapture(interface=locInter, bpf_filter='tcp port '+str(portRedis)+' or tcp src port '+str(portSql))
        captureObj.apply_on_packets(countPackets)
        captureObj.close()
    except (KeyboardInterrupt, TypeError):
        if(not chop.silent):
            timerDisplay.stop()
        if(chop.report):
            timerFile.stop()
        print("\n[WESERA] Closing...")
    print("[WESERA] END!")

if __name__ == "__main__":
    main()
