import socket

separator = 'load=b\''

# funzione che estrae da un pacchetto inviato il metodo http richiesto
def get_http_request(pkt):
    if pkt.getlayer('HTTP Request') != None:
        return pkt.getlayer('HTTP Request').Method
    return None

# funzione che estrae da un pacchetto la risposta, e relativo codice, ricevuta
def get_http_response_code(pkt):
    if pkt.getlayer('HTTP Response') != None:
        try:
            resp = pkt.getlayer('HTTP Response').fields['Status-Line']
            if resp != None:
                resp = str(resp, encoding='utf-8')
                if resp.find('HTTP/1.1') != -1:
                    sep = 'HTTP/1.1'
                elif resp.find('HTTP/1.0'):
                    sep = 'HTTP/1.0'
                else:
                    return None
                return bytes(resp[resp.find(sep) + len(sep) + 1:], encoding='utf-8')
        except:
            pass
    '''
    else:
        if pkt.haslayer('Raw'):
            http_layer = str(pkt.getlayer('Raw').command())
            if http_layer.find('HTTP/1.1') != -1:
                sep = 'HTTP/1.1'
            elif http_layer.find('HTTP/1.0') != -1:
                sep = 'HTTP/1.0'
            else:
                return None
            tmp = http_layer[http_layer.find(sep) + len(sep):].split(' ')
            return tmp[1] + ' ' + tmp[2]
    '''
    return None

class Stats:
    '''
        La classe Stats raccoglie statistiche soltanto sul numero di bytes e di pacchetti rilevati
    '''
    def __init__(self):
        self.packets = 0
        self.bytes = 0

    def add_packet(self, pkt):
        self.packets += 1
        try:
            bs = pkt
            self.bytes += len(bs)
        except:
            pass

class SentPacketStats(Stats):
    '''
        La classe SentPacketStats raccoglie statistiche sui pacchetti inviati, numero di bytes,
        numero di pacchetti e tipo di metodi http richiesti
    '''
    def __init__(self):
        super().__init__()
        self.reqs = dict()

    def add_packet(self, pkt):
        super().add_packet(pkt)
        b_req = get_http_request(pkt)
        if b_req != None:
            if type(b_req) == bytes:
                req = str(b_req, encoding='utf-8')
            else:
                req = b_req
            if req in self.reqs:
                self.reqs[req] += 1
            else:
                self.reqs[req] = 1


class RcvdPacketStats(Stats):
    '''
            La classe RcvdPacketStats raccoglie statistiche sui pacchetti ricevuti, numero di bytes,
            numero di pacchetti e tipi e codici di risposta ricevuti
        '''
    def __init__(self):
        super().__init__()
        self.err = dict()

    def add_packet(self, pkt):
        super().add_packet(pkt)
        b_resp = get_http_response_code(pkt)
        if b_resp != None:
            if type(b_resp) == bytes:
                resp = str(b_resp, encoding='utf-8')
            else:
                resp = b_resp
            if resp in self.err:
                self.err[resp] += 1
            else:
                self.err[resp] = 1



class HTTPStats(Stats):
    '''
        La classe HTTPStats raccoglie statistiche sul traffico http avvenuto tra l'host locale
        e un determinato host remoto, ditinguendole tra traffico in unscita e traffico in entrata
    '''
    def __init__(self, ip_addr):
        super().__init__()
        self.ip = ip_addr
        self.rcvd = RcvdPacketStats()
        self.sent = SentPacketStats()

    def add_packet(self, pkt):
        super().add_packet(pkt)
        if pkt.haslayer('IP'):
            if pkt.getlayer('IP').dst == self.ip:
                self.sent.add_packet(pkt)
            elif pkt.getlayer('IP').src == self.ip:
                self.rcvd.add_packet(pkt)



class ClientStats(dict):
    '''
        La classe ClientStats implementa un dizionario che associa ad ogni indiizzo ip, con cui c'è stata
        una comunicazione, un oggetto di tipo HTTPStats
    '''
    def __init__(self, ip_addr):
        super().__init__()
        self.ip = ip_addr

    def add_packet(self, pkt, verbose=False, resolve=False):
        if pkt.haslayer('IP'):
            remote = pkt.getlayer('IP').src if pkt.getlayer('IP').dst in self.ip else pkt.getlayer('IP').dst
            if remote in self:
                self[remote].add_packet(pkt)
            else:
                if verbose:
                    if resolve:
                        host = self.__try_reolve(remote)
                    else:
                        host = remote
                    print('New HTTP-comunication with ' + host)
                self[remote] = HTTPStats(remote)
                self[remote].add_packet(pkt)

    def print(self, resolve=False):
        for k, v in self.items():
            if resolve:
                host = self.__try_reolve(k)
            else:
                host = k
            print('|', host)
            print(format('\t Tot', '15s') + format('Packets:', '25s') + str(v.packets))
            print(format('\t', '15s') + format('Bytes:', '25s') + str(v.bytes))
            print(format('\t Received', '15s') + format('Packets:', '25s') + str(v.rcvd.packets))
            print(format('\t', '15s') + format('Bytes:', '25s') + str(v.rcvd.bytes))
            for resp, val in v.rcvd.err.items():
                print(format('\t', '15s') + format(resp, '25s') + str(val))
            print(format('\t Sent', '15s') + format('Packets:', '25s') + str(v.sent.packets))
            print(format('\t', '15s') + format('Bytes:', '25s') + str(v.sent.bytes))
            for req, val in v.sent.reqs.items():
                print(format('\t', '15s') + format(req, '25s') + str(val))
            print('='*40 + '\n')

    def __try_reolve(self, ip):
        try:
            host = socket.gethostbyaddr(ip)[0]
        except socket.herror:
            host = ip
        return host

