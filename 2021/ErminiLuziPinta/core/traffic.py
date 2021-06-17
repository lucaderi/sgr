from scapy.sendrecv import sniff
from scapy.layers.inet import TCP, IP
from .detectors import SYNNPCusumDetector, SYNCusumDetector
import time
import netifaces as ni
import core.utils as utils
import curses


class TrafficCatcher:

    def __init__(self, source: str, parametric=False, time_interval=5, threshold=0.65, verbose=False):

        self._time_interval = time_interval
        self._source = source
        self._threshold = threshold
        self._anomalous_intervals_count = 0
        self._max_volume = 0
        self._min_volume = 0
        self._volumes = []
        self._time_start = 0
        self._time_end = 0
       
        utils.colors(0,0,"Status: monitoring...",5)

        if parametric:
            self._syn_cusum = SYNCusumDetector(threshold=threshold, verbose=verbose)
        else:
            self._syn_cusum = SYNNPCusumDetector(verbose=verbose)

        self._syn_counter = 0
        self._synack_counter = 0

    def _counter_reader(self):
        """
        - Computes the volume with cusum algorithm __g and checks if threshold has been exceeded.
        - Resets the syn counter for the next interval
        - If threshold is exceeded resets last computed volume to 0.
        - If threshold is not exceeded but in last interval an attack was detected resets last computed ewma to 0.
        """

        volume, threshold = self._syn_cusum.analyze(self._syn_counter, self._synack_counter)

        self._max_volume = max(volume, self._max_volume)
        self._volumes.append(volume)

        if self._syn_cusum.under_attack():
            self._anomalous_intervals_count += 1
            if self._time_start == 0:
                self._time_start = self._syn_cusum.get_time_start()
        elif self._anomalous_intervals_count > 1: self._time_end = self._syn_cusum.get_time_end()
        
        self._syn_counter = 0
        self._synack_counter = 0

        return volume, threshold

    def get_mean_volume(self) -> float:
        return sum(self._volumes)/self._syn_cusum.intervals

    def get_max_volume(self) -> float:
        return self._max_volume

    def get_total_intervals(self) -> int:
        return self._syn_cusum.intervals

    def get_anomalous_intervals_count(self) -> int:
        return self._anomalous_intervals_count

    def get_time_start(self):
        return self._time_start

    def get_time_end(self):
        return self._time_end


class LiveCatcher(TrafficCatcher):
    """
    A thread used for capturing traffic and saving data of interest into DB
    """

    def __init__(self, source, plot=None, parametric=False, time_interval=5, threshold=0.65, verbose=False):
        super().__init__(source, parametric, time_interval, threshold, verbose)

        self.__timestamp = time.time()
        self.__ipv4_address = ni.ifaddresses(self._source)[ni.AF_INET][0]['addr']


        self.__graph = False
        if plot is not None:
            self.__plot = plot
            self.__graph = True

    def __callback(self, pkt):
        """
        Called by sniff every time it reads a packet.
        If given packet is a TCP packet and has SYN flag set to 1
        increases syn packets counter

        :param pkt: packet read
        """

        syn = 0x2
        ack = 0x10

        # current time minus last computation time
        diff_time = time.time() - self.__timestamp

        syn_count = self._syn_counter
        synack_count = self._synack_counter

        # checks if it's been at least self.__time_interval seconds and not more than self.__time_interval*2
        if self._time_interval <= diff_time < self._time_interval * 2:

            volume, threshold = self._counter_reader()
            

            # graphing
            if self.__graph:
                self.__plot.update_data(
                    (
                        ("volume", float(volume)),
                        ("threshold", float(threshold)),
                        ("syn_counter", int(syn_count)),
                        ("synack_counter", int(synack_count))
                    ), time.time()
                )

            self.__timestamp += self._time_interval

        # if it's been more than self.__time_interval*2 seconds:
        elif diff_time > self._time_interval * 2:

            # number of lost intervals
            lost_intervals_number = int(diff_time / self._time_interval)

            # for each lost interval will be called self.__counter_reader()
            for c in range(lost_intervals_number):
                volume, threshold = self._counter_reader()

                # graphing
                if self.__graph:
                    self.__plot.update_data(
                        (
                            ("volume", float(volume)),
                            ("threshold", float(threshold)),
                            ("syn_counter", int(syn_count)),
                            ("synack_counter", int(synack_count))
                        ), time.time()
                    )

                self.__timestamp += self._time_interval

        if pkt.haslayer(TCP):
            if (pkt[TCP].flags & syn) and not (pkt[TCP].flags & ack) and (pkt[IP].dst == self.__ipv4_address):
                self._syn_counter += 1
            elif (pkt[TCP].flags & syn) and (pkt[TCP].flags & ack) and (pkt[IP].src == self.__ipv4_address):
                self._synack_counter += 1

    def start(self):
        """
        Starts packet capturing and analyzing
        """

        sniff(iface=self._source, prn=self.__callback, store=0)


class OfflineCatcher(TrafficCatcher):
    """
    A thread used for capturing traffic and saving data of interest into DB
    """

    def __init__(self, source, ipv4_address, parametric=False, time_interval=5, threshold=0.65, verbose=False):

        super().__init__(source, parametric, time_interval, threshold, verbose)

        self.__ipv4_address = ipv4_address

        # timestamp of first packet in a new time interval
        self.__first_pkt_timestamp = 0

    def __callback(self, pkt):
        """
        Called by sniff every time it reads a packet.
        If given packet is a TCP packet and has SYN flag set to 1
        increases syn packets counter

        :param pkt: packet read
        """

        syn = 0x2
        ack = 0x10

        if self.__first_pkt_timestamp == 0:
            self.__first_pkt_timestamp = pkt.time

        # current packet time minus first packet time in interval
        diff_time = pkt.time - self.__first_pkt_timestamp

        # checks if it's been at least self.__time_interval seconds and not more than self.__time_interval*2
        if self._time_interval <= diff_time:
            self._counter_reader()
            self.__first_pkt_timestamp = 0

        if pkt.haslayer(TCP):
            if (pkt[TCP].flags & syn) and not (pkt[TCP].flags & ack) and (pkt[IP].dst == self.__ipv4_address):
                self._syn_counter += 1
            elif (pkt[TCP].flags & syn) and (pkt[TCP].flags & ack) and (pkt[IP].src == self.__ipv4_address):
                self._synack_counter += 1

    def start(self):
        """
        Starts packet capturing and analyzing
        """

        sniff(offline=self._source, prn=self.__callback, store=0)

