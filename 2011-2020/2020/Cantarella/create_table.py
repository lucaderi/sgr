#!/usr/bin/python

from clickhouse_driver import Client
client = Client('localhost')




client.execute('DROP TABLE IF EXISTS netflowv5')
client.execute('CREATE TABLE  netflowv5 (total_record_count Int8 , version Int8, Data_flusso Datetime, srcaddr String , dstaddr String, next_hop String, snmp_input Int32, snmp_output Int32, number_packets Int32, dOctets Int32 , last Int32, srcport Int32, dstport Int32, protocol String) ENGINE = MergeTree ORDER BY(srcaddr, dstaddr,srcport,dstport)')

