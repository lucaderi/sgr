import rrdtool
import os


class Talker:
    def __init__(self, ip, prot7, in_bytes, out_bytes, filter, application_category_name
                 , guessType, requested_server_name, client_fingerprinting, server_fingerprinting,
                 user_agent, content_type):
        # Creating new talker

        # Standard infos
        self.prot7 = prot7
        self.ip = ip

        self.filter = filter

        # Period bytes
        self.in_bytes = int(in_bytes)
        self.out_bytes = int(out_bytes)
        self.inandout_bytes = int(in_bytes + out_bytes)

        # Current bytes
        self.in_bytes_current = int(in_bytes)
        self.out_bytes_current = int(out_bytes)
        self.inandout_bytes_current = int(in_bytes + out_bytes)

        # extra info
        self.application_category_name = application_category_name
        self.guessType = guessType
        self.requested_server_name = requested_server_name
        self.client_fingerprinting = client_fingerprinting
        self.server_fingerprinting = server_fingerprinting
        self.user_agent = user_agent
        self.content_type = content_type

    def update(self, ts, in_bytes, out_bytes):
        # Update Bytes in / out
        self.in_bytes += in_bytes
        self.out_bytes += out_bytes
        self.inandout_bytes += in_bytes + out_bytes

        self.in_bytes_current += in_bytes
        self.out_bytes_current += out_bytes
        self.inandout_bytes_current += in_bytes + out_bytes

        # Update lastUpdate
        self.lastupdate = ts

    def ResetCurrentCounter(self):
        self.inandout_bytes_current = 0
        self.in_bytes_current = 0
        self.out_bytes_current = 0

    def ResetTotalPeriodCounter(self):
        self.inandout_bytes = 0
        self.in_bytes = 0
        self.out_bytes = 0

    # ---------------------------------------------RRD_OPS-------------------------------------------#

    def RRDcreate(self, step, hb, min, max, ts, time):

        if self.filter == "ip":
            rrdtool.create("./rrd/RRD_" + self.ip + ".rrd", '--start', time,
                           '--step', step, 'RRA:AVERAGE:0.5:1:1000',
                           'DS:InOut:GAUGE:{}:{}:{}'.format(hb, min, max),
                           'DS:In:GAUGE:{}:{}:{}'.format(hb, min, max),
                           'DS:Out:GAUGE:{}:{}:{}'.format(hb, min, max))

        if self.filter == "prot7":
            rrdtool.create("./rrd/RRD_" + self.prot7 + ".rrd", '--start', time,
                           '--step', step, 'RRA:AVERAGE:0.5:1:1000',
                           'DS:InOut:GAUGE:{}:{}:{}'.format(hb, min, max),
                           'DS:In:GAUGE:{}:{}:{}'.format(hb, min, max),
                           'DS:Out:GAUGE:{}:{}:{}'.format(hb, min, max))
        
        self.lastupdate=ts

    def RRDupdate(self, timestamp):

        if self.filter == "ip":
            rrdtool.update("./rrd/RRD_" + self.ip + ".rrd", f'{timestamp}' + ':' + f'{self.inandout_bytes}' +
                           ':' + f'{self.in_bytes}' + ':' + f'{self.out_bytes}')

        if self.filter == "prot7":
            rrdtool.update("./rrd/RRD_" + self.prot7 + ".rrd", f'{timestamp}' + ':' + f'{self.inandout_bytes}' +
                           ':' + f'{self.in_bytes}' + ':' + f'{self.out_bytes}')

    def RRDdeletion(self):
        # Remove rrd
        if self.filter == "ip": os.remove("./rrd/RRD_" + self.ip + ".rrd")
        if self.filter == "prot7": os.remove("./rrd/RRD_" + self.prot7 + ".rrd")

    def __str__(self):
        if self.filter == "ip":
            return "\tTALKER IP: {}\n\tIN_BYTES: {}\n\tOUT_BYTES: {}\n\tIN+OUT_BYTES: {}\n".format(self.ip, self.prot7,
                                                                                                   self.in_bytes,
                                                                                                   self.out_bytes,
                                                                                                   self.inandout_bytes) \
                   + "\tCURRENT_IN_BYTES: {}\n\tCURRENT_OUT_BYTES: {}\n\tCURRENT_IN+OUT_BYTES: {}\n".format(
                self.in_bytes_current, self.out_bytes_current, self.inandout_bytes_current) \
                   + "\tAPPLICATION CATEGORY: {}\n\tGUESS IS PORT BASED: {}\n".format(self.application_category_name,
                                                                                      str(self.guessType == 1)) \
                   + "\tREQUEST SERVER_NAME: {}\n\tCLIENT FINGERPRINT: {}\n\tSERVER FINGERPRINT: {}\n".format(
                self.requested_server_name, self.client_fingerprinting, self.server_fingerprinting) \
                   + "\tUSER AGENT: {}\n\tCONTENT TYPE:{}\n".format(self.user_agent, self.content_type)

        elif self.filter == "prot7":
            return "\tAPPLICATION PROTOCOL: {}\n\tIN_BYTES: {}\n\tOUT_BYTES: {}\n\tIN+OUT_BYTES: {}\n".format(
                self.prot7, self.in_bytes, self.out_bytes, self.inandout_bytes) \
                   + "\tCURRENT_IN_BYTES: {}\n\tCURRENT_OUT_BYTES: {}\n\tCURRENT_IN+OUT_BYTES: {}\n".format(
                self.in_bytes_current, self.out_bytes_current, self.inandout_bytes_current) \
                   + "\tAPPLICATION CATEGORY: {}\n\tGUESS IS PORT BASED: {}\n".format(self.application_category_name,
                                                                                      str(self.guessType == 1)) \
                   + "\tREQUEST SERVER_NAME: {}\n\tCLIENT FINGERPRINT: {}\n\tSERVER FINGERPRINT: {}\n".format(
                self.requested_server_name, self.client_fingerprinting, self.server_fingerprinting) \
                   + "\tUSER AGENT: {}\n\tCONTENT TYPE:{}\n".format(self.user_agent, self.content_type)

    def __eq__(self, other_talker):
        if not isinstance(other_talker, Talker):
            print("Stai confrontando 2 oggetti di tipo diverso")
            return

        if self.filter == "ip": return self.ip == other_talker.ip
        if self.filter == "prot7": return self.prot7 == other_talker.prot7
