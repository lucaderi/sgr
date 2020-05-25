import pyshark
from pyshark.packet.fields import LayerField, LayerFieldsContainer
from pyshark.packet.layer import Layer
from pyshark.packet.packet import Packet
from datetime import datetime
import sys
import argparse

parser = argparse.ArgumentParser(description='TLS certificate inspector to detect if it is invalid/self-signed')
parser.add_argument('-i', dest="interface", default='eth0', help="Interface from which to capture (Default eth0)")
parser.add_argument('-l', dest="live", action="store_true", default=False, help="Enables live capture")
parser.add_argument('-t', dest="timeout", help="Specify live sniff timeout in seconds (Default 0 means unlimited)",
                    type=int, default=0)
parser.add_argument('-mp', dest="max_packet", help="Maximum packet i want to read (Default 0 means unlimited)",
                    type=int, default=0)
parser.add_argument('-fi', dest="input_file", help="File that i want to read")
parser.add_argument('-fo', dest="output_file", help="Log file where to store the results")
fo = None
fi = None


# TODO chain
class TLSCert:
    def __init__(self, x):
        self.not_before = None
        self.not_after = None
        self.issuer = []
        self.subject = []
        self.num = x

    def add_issuer_sequence(self, seq):
        self.issuer.append(seq)

    def add_subject_sequence(self, seq):
        self.subject.append(seq)

    def add_not_before(self, time):
        self.not_before = datetime.strptime(time, '%y-%m-%d %H:%M:%S (%Z)')

    def add_not_after(self, time):
        self.not_after = datetime.strptime(time, '%y-%m-%d %H:%M:%S (%Z)')

    def isValid(self):
        now = datetime.now()
        if self.not_before > now or self.not_after < now:
            return False
        return True

    def isSelfSigned(self):
        if self.issuer == self.subject:
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
    field_container: LayerFieldsContainer
    for field_container in list(tls_layer._all_fields.values()):  # prendo il field container per ogni campo
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
    certs = []
    for x in range(cert_count):
        cert = TLSCert(x)
        for y in range(int(if_rdnSequence_count[x])):
            cert.add_issuer_sequence(rdn.pop(0))
        for y in range(int(af_rdnSequence_count[x])):
            cert.add_subject_sequence(rdn.pop(0))
        cert.add_not_before(times.pop(0))
        cert.add_not_after(times.pop(0))
        certs.append(cert)

    return certs


def analyzePacket(packet):
    packet: Packet
    layer: Layer
    layer = packet.tls
    field: LayerFieldsContainer
    cert_list = extract_certs(layer)
    for cert in cert_list:
        out = "{}:{} {} Certificate (Chain position {}/{}):\n {}\n"
        found = False
        if not cert.isValid() and cert.isSelfSigned():
            out = out.format(packet.ip.src, packet.tcp.get_field_by_showname("Source Port"),
                             'Not Valid and Self-Signed', cert.num, len(cert_list), cert)
            found = True
            print(out)
        elif not cert.isValid():
            out = out.format(packet.ip.src, packet.tcp.get_field_by_showname("Source Port"), 'Not Valid', cert.num,
                             len(cert_list), cert)
            found = True
            print(out)
        elif cert.isSelfSigned():
            out = out.format(packet.ip.src, packet.tcp.get_field_by_showname("Source Port"), 'Self-Signed', cert.num,
                             len(cert_list), cert)
            found = True
            print(out)
        if results.output_file is not None and found:
            fo = open(results.output_file, "a")
            fo.write(out)
            fo.close()


results = parser.parse_args()

if __name__ == "__main__":
    if results.live:
        capture = pyshark.LiveCapture(interface=results.interface, display_filter='tls.handshake.certificate')
        capture.sniff(timeout=results.timeout)
        packet: Packet
        print('Listening on:', results.interface)
        capture.apply_on_packets(analyzePacket, packet_count=results.max_packet)
        # for packet in capture.sniff_continuously():
        #   analyzePacket(packet)

    else:
        capture = pyshark.FileCapture(input_file=results.input_file, display_filter='tls.handshake.certificate')
        capture.apply_on_packets(analyzePacket, packet_count=results.max_packet)
        # for packet in capture:
        #   analyzePacket(packet)

    if fo is not None:
        fo.close()
