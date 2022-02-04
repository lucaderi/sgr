from influxdb_client import WriteApi, Point, WritePrecision


def mstime(x):
    return int(round(x * 1000))


def influx_writepoint(mac, ip, name, timestamp, writeapi: WriteApi, bucket):
    try:
        p = Point(mac) \
            .field("presence", 1) \
            .tag("ip", ip) \
            .tag("name", name) \
            .time(mstime(timestamp), write_precision=WritePrecision.MS)
        writeapi.write(bucket=bucket, record=p)
    except Exception as e:
        print("Error writing to influx, configure config.json influx section")
        print(e)
