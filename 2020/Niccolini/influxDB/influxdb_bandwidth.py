#!/usr/bin/python3
from influxdb_client import InfluxDBClient
import matplotlib.pyplot as plt
import sys


def main():
    # By default the arguments are:
    my_token = 'rbuCuV6gRHPJRPIRrLB3kOp874S5mUywVUGXJIUe_o1bf2HpxSqy7E6VB9ZUHKzMK4vGNqo6g6TZipJ2PIEXog=='
    my_org = "UNIPI"
    bucket = "Bucket"
    interface = "en0"

    if len(sys.argv) == 5:
        my_token = sys.argv[1]
        my_org = sys.argv[2]
        bucket = sys.argv[3]
        interface = sys.argv[4]
    else:
        if len(sys.argv) != 1:
            print("Error: Number of arguments")
            exit(1)

    # Query for received bytes
    query1 = 'from(bucket: "' + bucket + '") |> range(start:-1h, stop: now()) ' \
                                         '|> filter(fn: (r) => r._measurement == "net" )' \
                                         '|> filter(fn: (r) => r._field == "bytes_recv" )' \
                                         '|> filter(fn: (r) => r.interface == "' + interface + '" )' \
                                                                                               '|> derivative(unit: 1s, nonNegative: true,columns: ["_value"])'

    # Query for sent bytes
    query2 = 'from(bucket: "' + bucket + '") |> range(start:-1h, stop: now()) ' \
                                         '|> filter(fn: (r) => r._measurement == "net" ) ' \
                                         '|> filter(fn: (r) => r._field == "bytes_sent" ) ' \
                                         '|> filter(fn: (r) => r.interface == "' + interface + '" ) ' \
                                                                                               '|> derivative(unit: 1s, nonNegative: true, columns: ["_value"] )'

    client = InfluxDBClient(url="http://localhost:9999", token=my_token, org=my_org)
    query_api = client.query_api()

    data1 = query_api.query_data_frame(query=query1)
    data2 = query_api.query_data_frame(query=query2)

    try:
        plt.plot(data1['_time'], data1['_value'], label='Bytes Received')
        plt.plot(data2['_time'], data2['_value'], label='Bytes Sent')
    except:
        print("Error: check the arguments")
        exit(1)
    plt.legend(loc='upper center', bbox_to_anchor=(0.5, -0.05),
               fancybox=True, shadow=True, ncol=5)
    plt.show()

    # Close client
    client.__del__()
    print("close client")


if __name__ == "__main__":
    main()
