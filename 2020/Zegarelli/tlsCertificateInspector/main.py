import pyshark
from pyshark.packet.fields import LayerField, LayerFieldsContainer
from pyshark.packet.layer import Layer
from pyshark.packet.packet import Packet
from datetime import datetime
import sys
import argparse

parser = argparse.ArgumentParser(description='TLS certificate inspector to detect if it is invalid/self-signed')
parser.add_argument('-l', dest="live", action="store_true", default=False, help="Enables live capture")
parser.add_argument('-i', dest="interface", default='eth0', help="Interface from which to capture (Default eth0)")
parser.add_argument('-t', dest="timeout", help="Specify live sniff timeout in seconds (Default 0 means unlimited)",
                    type=int, default=0)
parser.add_argument('-mp', dest="max_packet", help="Maximum packet i want to read (Default 0 means unlimited)",
                    type=int, default=0)
parser.add_argument('-fi', dest="input_file", help="File that i want to read (Es. test.pcap)")
parser.add_argument('-fo', dest="output_file", help="Name for the log file where to store the results")
parser.add_argument('-v', dest="verbose", help="Enable verbose mode", default=False, action="store_true")
fo = None
fi = None
p_count_total = 0
p_count_valid = 0
p_count_invalid = 0
p_count_self = 0
p_count_both = 0


class TLSCert:
    def __init__(self, x):
        self.not_before = None
        self.not_after = None
        self.issuer = []
        self.subject = []
        self.num = x
        # self.ca_key = None
        # self.subject_key = None

    # def add_ca_key(self, key):
    # self.issuer.append(key)

    # def add_subject_key(self, key):
    # self.issuer.append(key)

    def add_issuer_sequence(self, seq):
        self.issuer.append(seq)

    def add_subject_sequence(self, seq):
        self.subject.append(seq)

    def add_not_before(self, time):
        try:
            self.not_before = datetime.strptime(time, '%Y-%m-%d %H:%M:%S (%Z)')

        except ValueError:
            try:
                self.not_before = datetime.strptime(time, '%y-%m-%d %H:%M:%S (%Z)')
            except ValueError:
                raise

    def add_not_after(self, time):
        try:
            self.not_after = datetime.strptime(time, '%Y-%m-%d %H:%M:%S (%Z)')

        except ValueError:
            try:
                self.not_after = datetime.strptime(time, '%y-%m-%d %H:%M:%S (%Z)')
            except ValueError:
                raise

    def isValid(self):
        now = datetime.now()
        if self.not_before > now or self.not_after < now:
            return False
        return True

    def isSelfSigned(self):
        if self.issuer == self.subject:  # or self.ca_key == self.subject_key:
            return True
        return False

    def __str__(self):
        return "\tIssuer: " + str(self.issuer) + "\n\tSubject: " + str(self.subject) + "\n\tNot Before: " + str(
            self.not_before) + "\n\tNot After: " + str(self.not_after)


def get_all(field_container):
    """
    ritorna una lista contenente tutti i field di quel campo
    :param field_container:
    :return:
    """
    field_container: LayerFieldsContainer
    field_container = field_container.all_fields
    tmp = []
    field: LayerField
    for field in field_container:
        tmp.append(field.get_default_value())
    return tmp


def extract_certs(tls_layer):
    """
    Estrae i certificati da un paccketto
    :param tls_layer:
    :return:
    """

    cert_count = 0
    if_rdnSequence_count = []
    times = []
    af_rdnSequence_count = []
    rdn = []
    subject_key = []
    ca_key = []
    field_container: LayerFieldsContainer
    a = list(tls_layer._all_fields.values())
    for field_container in a:  # prendo il field container per ogni campo
        field: LayerField
        field = field_container.main_field
        # controllo il nome del campo
        if field.name == 'x509if.RelativeDistinguishedName_item_element':
            rdn = (get_all(field_container))
        elif field.name == 'x509af.signedCertificate_element':
            cert_count = len(field_container.all_fields)
        elif field.name == 'x509if.rdnSequence':
            if_rdnSequence_count = get_all(field_container)
        elif field.name == 'x509af.utcTime':
            times = get_all(field_container)
        elif field.name == 'x509af.rdnSequence':
            af_rdnSequence_count = get_all(field_container)
        # elif field.name == 'x509ce.SubjectKeyIdentifier':
        # subject_key = get_all(field_container)
        # elif field.name == 'x509ce.keyIdentifier':
        # ca_key = get_all(field_container)

    certs = []
    for x in range(cert_count):
        cert = TLSCert(x + 1)  # +1 perchè parte da 0
        for y in range(int(if_rdnSequence_count[x])):
            cert.add_issuer_sequence(rdn.pop(0))
        for y in range(int(af_rdnSequence_count[x])):
            cert.add_subject_sequence(rdn.pop(0))
        cert.add_not_before(times.pop(0))
        cert.add_not_after(times.pop(0))
        # cert.add_ca_key(ca_key.pop(0))
        # cert.add_subject_key(subject_key.pop(0))
        certs.append(cert)

    return certs


def analyzePacket(packet):
    global p_count_total
    global p_count_self
    global p_count_valid
    global p_count_invalid
    global p_count_both
    packet: Packet
    layer: Layer
    layer = packet.tls
    field: LayerFieldsContainer
    cert_list = extract_certs(layer)
    sys.stdout.write("\r")
    sys.stdout.flush()
    for cert in cert_list:
        sys.stdout.write("\r ")
        sys.stdout.flush()
        p_count_total += 1
        out_verbose = "{}:{} {} Certificate (Chain position {}/{}):\n {}"
        out_normal = "{}:{} {} Certificate (Chain position {}/{})"
        out = None
        found = False
        if not cert.isValid() and cert.isSelfSigned():
            p_count_both += 1
            if results.verbose:
                out = out_verbose.format(packet.ip.src, packet.tcp.get_field_by_showname("Source Port"),
                                         'Not Valid and Self-Signed', cert.num, len(cert_list), cert)
            else:
                out = out_normal.format(packet.ip.src, packet.tcp.get_field_by_showname("Source Port"),
                                        'Not Valid and Self-Signed', cert.num, len(cert_list))
            found = True

        elif not cert.isValid():
            p_count_invalid += 1
            if results.verbose:
                out = out_verbose.format(packet.ip.src, packet.tcp.get_field_by_showname("Source Port"), 'Not Valid',
                                         cert.num,
                                         len(cert_list), cert)
            else:
                out = out_normal.format(packet.ip.src, packet.tcp.get_field_by_showname("Source Port"), 'Not Valid',
                                        cert.num,
                                        len(cert_list))
            found = True

        elif cert.isSelfSigned():
            p_count_self += 1
            if results.verbose:
                out = out_verbose.format(packet.ip.src, packet.tcp.get_field_by_showname("Source Port"), 'Self-Signed',
                                         cert.num,
                                         len(cert_list), cert)
            else:
                out = out_normal.format(packet.ip.src, packet.tcp.get_field_by_showname("Source Port"), 'Self-Signed',
                                        cert.num,
                                        len(cert_list))
            found = True

        if not found:
            out = out_normal.format(packet.ip.src, packet.tcp.get_field_by_showname("Source Port"),
                                    'Valid',
                                    cert.num,
                                    len(cert_list))
            p_count_valid += 1

        print(out)

        if results.output_file is not None:
            fo = open(results.output_file + ".txt", "a")
            fo.write(out+"\n")
            fo.close()
    print("")
    out="Total analyzed certs: {}, Valid certs: {}, Self-Signed certs: {}, Invalid certs: {}, Both Invalid and Self-Signed certs: {}".format(
            p_count_total, p_count_valid, p_count_self, p_count_invalid, p_count_both)
    if results.output_file is not None:
        fo = open(results.output_file + ".txt", "a")
        fo.write("\n"+out+"\n\n")
        fo.close()
    sys.stdout.write("\r"+out)
    sys.stdout.flush()


results = parser.parse_args()

if __name__ == "__main__":
    if results.live is False:
        if results.input_file is None:
            parser.error("At least -l or -fi required")
        else:
            capture = pyshark.FileCapture(input_file=results.input_file, display_filter='tls.handshake.certificate')
            capture.apply_on_packets(analyzePacket, packet_count=results.max_packet)
            # for packet in capture:
            #   analyzePacket(packet)

    else:
        if results.input_file is not None:
            parser.error("You can't use both -l and -fi")
        else:
            capture = pyshark.LiveCapture(interface=results.interface, display_filter='tls.handshake.certificate')
            capture.sniff(timeout=results.timeout)
            packet: Packet
            print('Listening on:', results.interface)
            capture.apply_on_packets(analyzePacket, packet_count=results.max_packet)
            # for packet in capture.sniff_continuously():
            #   analyzePacket(packet)

    if fo is not None:
        fo.close()
