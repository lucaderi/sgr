import time
import copy
from scapy.all import*
from multiprocessing import Queue
import pyprctl
import utils

#Device types
UNIDENTIFIED = utils.UNIDENTIFIED
AP = utils.AP
STA = utils.STA
MESH = utils.MESH
#Frame types
MANAGEMENT = "MANAGEMENT"
CONTROL = "CONTROL"
DATA = "DATA"

#Parameters
DEVICE = "DEVICE"
DISTANCE = "DISTANCE"
RANDOMIZED = "RANDOMIZED"
CHANNELS = "CHANNELS"
PACKETS = "PACKETS"
VOLUME = "VOLUME"#Bytes
PKT_TYPES = "PKT_TYPES"

ROUND = utils.ROUND
SESSION = utils.SESSION

channel_table = {
            #2.4GHz
            2412: 1,
            2417: 2,
            2422: 3,
            2427: 4,
            2432: 5,
            2437: 6,
            2442: 7,
            2447: 8,
            2452: 9,
            2457: 10,
            2462: 11,
            2467: 12,
            2472: 13, 
            #5GHz
            5180: 36,
            5200: 40,
            5220: 44,
            5240: 48,
            5260: 52,
            5280: 56,
            5300: 60,
            5320: 64,
            5500: 100,
            5520: 104,
            5540: 108,
            5560: 112,
            5580: 116,
            5600: 120,
            5620: 124,
            5640: 128,
            5660: 132,
            5680: 136,
            5700: 140,
            5720: 144,
            5745: 149,
            5765: 153,
            5785: 157,
            5805: 161,
            5825: 165
    }

def log_distance_path_loss(RSSI, path_loss_exponent): 
    RSSI_ref = -34 #RSSI medio a 1m dalla sorgente
    distance = 10**((RSSI - RSSI_ref)/(-10*path_loss_exponent))
    if distance <= 5:
        return utils.NEAR_CLUSTER
    if distance > 5 and distance <= 15:
        return utils.MEDIUM_CLUSTER
    if distance > 15 and distance <= 30:
        return utils.FAR_CLUSTER
    if distance > 30:
        return utils.OUT_OF_RANGE_CLUSTER 

def is_randomized(mac:str): 
    msb_hex = mac.split(':')[0]
    msb = bytes.fromhex(msb_hex)[0]
    return bool(msb & 0x02)

class Range_cluster:
    def __init__(self):
        self.total_devices = 0
        self.devices = {UNIDENTIFIED: 0,
                        AP: 0,
                        STA: 0,
                        MESH: 0}
        self.randomized_count = 0
        self.round_pkts = 0
        self.round_volume = 0
        self.session_pkts = 0
        self.session_volume = 0
        self.round_pkts_per_sec = 0
        self.round_volume_per_sec = 0
        self.session_pkts_per_sec = 0
        self.session_volume_per_sec = 0
        self.traffic_composition = {MANAGEMENT: {PACKETS: 0, 
                                                 VOLUME: 0},  
                                    CONTROL: {PACKETS: 0,
                                              VOLUME: 0},
                                    DATA: {PACKETS: 0,
                                           VOLUME: 0}}
        self.management_pkts_perc = 0
        self.management_volume_perc = 0
        self.control_pkts_perc = 0
        self.control_volume_perc = 0
        self.data_pkts_perc = 0
        self.data_volume_perc = 0
        self.channels = {}
        self.busiest_channel = (0, 0, 0)

    def reset_cluster(self):
        self.total_devices = 0
        self.devices = {UNIDENTIFIED: 0,
                        AP: 0,
                        STA: 0,
                        MESH: 0}
        self.randomized_count = 0
        self.round_pkts = 0
        self.round_volume = 0
        self.round_pkts_per_sec = 0
        self.round_volume_per_sec = 0
        self.traffic_composition = {MANAGEMENT: {PACKETS: 0, 
                                                 VOLUME: 0},  
                                    CONTROL: {PACKETS: 0,
                                              VOLUME: 0},
                                    DATA: {PACKETS: 0,
                                           VOLUME: 0}}
        self.management_pkts_perc = 0
        self.management_volume_perc = 0
        self.control_pkts_perc = 0
        self.control_volume_perc = 0
        self.data_pkts_perc = 0
        self.data_volume_perc = 0
        self.channels = {}
        self.busiest_channel = (0, 0, 0)
        
    def update_cluster(self, data, round_time_interval, session_time_interval):
        self.total_devices += 1

        dev_type = data[DEVICE]
        self.devices[dev_type] += 1

        self.randomized_count += 1 if data[RANDOMIZED] else 0

        self.round_pkts += data[ROUND][PACKETS]
        self.round_volume += data[ROUND][VOLUME]

        self.session_pkts += data[ROUND][PACKETS] #Round non Session, perché un dispositivo potrebbe cambiare cluster
        self.session_volume += data[ROUND][VOLUME]

        self.round_pkts_per_sec = int(self.round_pkts // round_time_interval)
        self.round_volume_per_sec = int(self.round_volume // round_time_interval)

        self.session_pkts_per_sec = int(self.session_pkts // session_time_interval)
        self.session_volume_per_sec = int(self.session_volume // session_time_interval)

        for pkt_type, traffic in data[ROUND][PKT_TYPES].items():
            self.traffic_composition[pkt_type][PACKETS] += traffic[PACKETS]
            self.traffic_composition[pkt_type][VOLUME] += traffic[VOLUME]
        
        if self.round_pkts > 0 and self.round_volume > 0:
            self.management_pkts_perc = int((self.traffic_composition[MANAGEMENT][PACKETS] / self.round_pkts)*100)
            self.management_volume_perc = int((self.traffic_composition[MANAGEMENT][VOLUME] / self.round_volume)*100)
            self.control_pkts_perc = int((self.traffic_composition[CONTROL][PACKETS] / self.round_pkts)*100)
            self.control_volume_perc = int((self.traffic_composition[CONTROL][VOLUME] / self.round_volume)*100)
            self.data_pkts_perc = int((self.traffic_composition[DATA][PACKETS] / self.round_pkts)*100)
            self.data_volume_perc = int((self.traffic_composition[DATA][VOLUME] / self.round_volume)*100)
        else:
            self.management_pkts_perc = 0
            self.management_volume_perc = 0
            self.control_pkts_perc = 0
            self.control_volume_perc = 0
            self.data_pkts_perc = 0
            self.data_volume_perc = 0

        for channel, traffic in data[ROUND][CHANNELS].items():
            if channel not in self.channels:
                self.channels[channel] = traffic.copy()
            else:
                self.channels[channel][PACKETS] += traffic[PACKETS]
                self.channels[channel][VOLUME] += traffic[VOLUME]
        if self.channels:
            busiest_channel = max(self.channels, key= lambda ch: (self.channels[ch][PACKETS] + self.channels[ch][VOLUME]))
            self.busiest_channel = (busiest_channel, self.channels[busiest_channel][PACKETS], self.channels[busiest_channel][VOLUME])
        else: self.busiest_channel = (0, 0, 0)
        

def analyze(pkt_queue:Queue, stats_queue:Queue, path_loss_exponent):
    #Rinuncia alle capabilities ereditate
    state = pyprctl.CapState.get_current() #ottiene un oggetto che descrive lo stato corrente delle capabilities
    state.effective.discard(pyprctl.Cap.NET_ADMIN) 
    state.effective.discard(pyprctl.Cap.NET_RAW)
    state.permitted.discard(pyprctl.Cap.NET_ADMIN)
    state.permitted.discard(pyprctl.Cap.NET_RAW)
    state.set_current()
    #Macro utili
    LAST_SEEN = "LAST_SEEN"
    MAX_ADDRESSES = 300 #Previene espansione incontrollata delle strutture in caso di molti indirizzi randomizzati
    BEACON = 8
    PRB_REQUEST = 4
    REFRESH_TIME = 2
    #Strutture dati
    pkt_types = {0: MANAGEMENT, 
                 1: CONTROL, 
                 2: DATA}
    timeout_list = utils.heap_dict() #Per gestione dei timeout ottimizzata
    mac_table = dict()
    near_cl = Range_cluster()
    medium_cl = Range_cluster()
    far_cl = Range_cluster()
    out_of_range_cl = Range_cluster()

    #Per metriche di performance
    #Session 
    session_start_time = time.time()
    session_total_rounds = 0
    session_qsize = 0
    session_processed_volume = 0
    session_processed_pkts = 0
    #Round 
    rounds_to_reset = 20
    rounds = 0
    round_start_time = 0
    sum_queue_size = 0
    round_processed_volume = 0
    round_processed_packets = 0
    
    #Per metriche di traffico
    epsilon = 10**(-6) #per evitare divisione per zero nel calcolo di pkts/sec (solo per sicurezza, non viene quasi mai usato)
    #Session
    session_first_timestamp = 0
    session_unassigned_pkts = 0
    session_unassigned_volume = 0
    #Round
    round_first_timestamp = 0
    round_last_timestamp = 0
    round_unassigned_pkts = 0
    round_unassigned_volume = 0

    while True:
        #Analisi dei pacchetti
        pkt_list = pkt_queue.get(block=True)
        for header, pkt in pkt_list:

            if round_start_time == 0:
                round_start_time = time.time()
            if rounds == rounds_to_reset:
                rounds = 0
                sum_queue_size = 0
                print("STATISTICHE RESETTATE")

            sc_pkt = RadioTap(pkt)
            if not sc_pkt.dBm_AntSignal:
                continue
            if not sc_pkt.haslayer(Dot11):
                continue
            if not sc_pkt[Dot11].addr2: 
                if not round_first_timestamp:
                    round_first_timestamp = header[0]
                if not session_first_timestamp:
                    session_first_timestamp = header[0]
                round_last_timestamp = header[0]

                round_unassigned_pkts += 1
                round_unassigned_volume += header[1]
                round_processed_packets += 1
                round_processed_volume += header[1]
                session_unassigned_pkts += 1
                session_unassigned_volume += header[1]
                session_processed_pkts += 1
                session_processed_volume += header[1]
                continue
            
            pkt_timestamp = header[0] 
            if not round_first_timestamp:
                round_first_timestamp = pkt_timestamp
            round_last_timestamp = pkt_timestamp
            if not session_first_timestamp:
                session_first_timestamp = pkt_timestamp

            pkt_size = header[1] 
            rssi = sc_pkt.dBm_AntSignal
            channel = channel_table.get(sc_pkt.ChannelFrequency)
            pkt_type = pkt_types.get(sc_pkt[Dot11].type)
            device_type = UNIDENTIFIED
            if pkt_type == MANAGEMENT:
                pkt_subtype = sc_pkt[Dot11].subtype  
                if pkt_subtype == BEACON: device_type = AP
                elif pkt_subtype == PRB_REQUEST: device_type = STA
            source_address = sc_pkt[Dot11].addr2
            if source_address not in mac_table:
                randomized = is_randomized(source_address)
            distance = log_distance_path_loss(rssi, path_loss_exponent)
            
            #aggiornamento dati (locale)
            timeout_list.update((source_address, pkt_timestamp))
            if source_address not in mac_table:
                if len(mac_table) >= MAX_ADDRESSES:
                    mac_to_elim = timeout_list.remove_min()[0]
                    mac_table.pop(mac_to_elim)

                mac_table[source_address] = {
                    DEVICE: device_type,
                    DISTANCE:{
                        distance: 1
                    },
                    RANDOMIZED: randomized,
                    LAST_SEEN: pkt_timestamp,
                    ROUND: {
                        PACKETS: 1,
                        VOLUME: pkt_size,
                        CHANNELS: {
                            channel: {PACKETS: 1,
                                    VOLUME: pkt_size}
                        },
                        PKT_TYPES:{
                            pkt_type: {PACKETS: 1,
                                    VOLUME: pkt_size}
                        }
                    },
                    SESSION: {
                        PACKETS: 1,
                        VOLUME: pkt_size,
                        CHANNELS: {
                            channel: {PACKETS: 1,
                                    VOLUME: pkt_size}
                        },
                        PKT_TYPES:{
                            pkt_type: {PACKETS: 1,
                                    VOLUME: pkt_size}
                        }
                    }
                }

            else:
                #Device Type
                if mac_table[source_address][DEVICE] != device_type:
                    if mac_table[source_address][DEVICE] == UNIDENTIFIED and device_type != UNIDENTIFIED:
                        mac_table[source_address][DEVICE] = device_type
                    elif mac_table[source_address][DEVICE] != MESH and device_type != UNIDENTIFIED:
                        mac_table[source_address][DEVICE] = MESH
                #Distance
                if distance not in mac_table[source_address][DISTANCE]:
                    mac_table[source_address][DISTANCE][distance] = 1
                else:
                    mac_table[source_address][DISTANCE][distance] += 1
                #Last Seen
                mac_table[source_address][LAST_SEEN] = pkt_timestamp
                #Packets and Volume
                mac_table[source_address][ROUND][PACKETS] += 1
                mac_table[source_address][ROUND][VOLUME] += pkt_size
                mac_table[source_address][SESSION][PACKETS] += 1
                mac_table[source_address][SESSION][VOLUME] += pkt_size
                #Channels
                if channel not in mac_table[source_address][SESSION][CHANNELS]:
                    mac_table[source_address][ROUND][CHANNELS][channel] = {PACKETS: 1,
                                                                           VOLUME: pkt_size}
                    mac_table[source_address][SESSION][CHANNELS][channel] = {PACKETS: 1,
                                                                             VOLUME: pkt_size}
                elif channel not in mac_table[source_address][ROUND][CHANNELS]:
                    mac_table[source_address][ROUND][CHANNELS][channel] = {PACKETS: 1,
                                                                           VOLUME: pkt_size}
                    mac_table[source_address][SESSION][CHANNELS][channel][PACKETS] += 1
                    mac_table[source_address][SESSION][CHANNELS][channel][VOLUME] += pkt_size
                else:
                    mac_table[source_address][ROUND][CHANNELS][channel][PACKETS] += 1
                    mac_table[source_address][ROUND][CHANNELS][channel][VOLUME] += pkt_size
                    mac_table[source_address][SESSION][CHANNELS][channel][PACKETS] += 1
                    mac_table[source_address][SESSION][CHANNELS][channel][VOLUME] += pkt_size
                #Packet Types
                if pkt_type not in mac_table[source_address][SESSION][PKT_TYPES]:
                    mac_table[source_address][ROUND][PKT_TYPES][pkt_type] = {PACKETS: 1,
                                                                             VOLUME: pkt_size}
                    mac_table[source_address][SESSION][PKT_TYPES][pkt_type] = {PACKETS: 1,
                                                                               VOLUME: pkt_size}
                elif pkt_type not in mac_table[source_address][ROUND][PKT_TYPES]:
                    mac_table[source_address][ROUND][PKT_TYPES][pkt_type] = {PACKETS: 1,
                                                                             VOLUME: pkt_size}
                    mac_table[source_address][SESSION][PKT_TYPES][pkt_type][PACKETS] += 1
                    mac_table[source_address][SESSION][PKT_TYPES][pkt_type][VOLUME] += pkt_size
                else:
                    mac_table[source_address][ROUND][PKT_TYPES][pkt_type][PACKETS] += 1
                    mac_table[source_address][ROUND][PKT_TYPES][pkt_type][VOLUME] += pkt_size
                    mac_table[source_address][SESSION][PKT_TYPES][pkt_type][PACKETS] += 1
                    mac_table[source_address][SESSION][PKT_TYPES][pkt_type][VOLUME] += pkt_size
                
            round_processed_packets += 1
            round_processed_volume += pkt_size
            session_processed_pkts += 1
            session_processed_volume += pkt_size
            round_end_time = time.time()
            round_duration = round_end_time - round_start_time#

            if round_duration >= REFRESH_TIME:
                
                #update round performance metrics
                rounds += 1
                qsize = pkt_queue.qsize()
                sum_queue_size += qsize
                avg_queue_size = sum_queue_size / rounds
                print(f"AVG QUEUE SIZE: {avg_queue_size}")
                round_processed_packets_per_sec = int(round_processed_packets // round_duration)
                round_processed_volume_per_sec = int(round_processed_volume // round_duration)
                print(f"ROUND PROCESSED PACKETS PER SECOND: {round_processed_packets_per_sec}")
                print(f"ROUND PROCESSED VOLUME PER SECOND: {round_processed_volume_per_sec}")
                
                #update session performance metrics
                session_total_rounds += 1
                session_duration = (round_end_time - session_start_time)
                session_qsize += qsize
                session_avg_queue_size = session_qsize / session_total_rounds
                print(f"SESSION AVG QUEUE SIZE: {session_avg_queue_size}")
                session_processed_pkts_per_sec = int(session_processed_pkts // session_duration)
                session_processed_volume_per_sec = int(session_processed_volume // session_duration)
                print(f"SESSION PROCESSED PACKETS PER SECOND: {session_processed_pkts_per_sec}")
                print(f"SESSION PROCESSED VOLUME PER SECOND: {session_processed_volume_per_sec}")

                #update round traffic metrics
                round_time_interval = max((round_last_timestamp - round_first_timestamp), epsilon)
                round_pkts_per_sec = int(round_processed_packets / round_time_interval)
                round_volume_per_sec = int(round_processed_volume / round_time_interval)
                perc_round_unassigned_pkts = int((round_unassigned_pkts  / round_processed_packets)*100)
                perc_round_unassigned_volume = int((round_unassigned_volume / round_processed_volume)*100)
                print(f"ROUND PKTS PER SECOND: {round_pkts_per_sec}")
                print(f"ROUND VOLUME PER SECOND: {round_volume_per_sec}")
                print(f"ROUND UNASSIGNED TRAFFIC (PKTS/SEC): {perc_round_unassigned_pkts}%")
                print(f"ROUND UNASSIGNED TRAFFIC (VOLUME/SEC): {perc_round_unassigned_volume}%")
                round_start_time = 0
                round_first_timestamp = 0
                round_processed_packets = 0
                round_processed_volume = 0
                round_unassigned_volume = 0
                round_unassigned_pkts = 0
                #update session traffic metrics
                session_time_interval = max((round_last_timestamp - session_first_timestamp), epsilon)
                session_pkts_per_sec = int(session_processed_pkts / session_time_interval)
                session_volume_per_sec = int(session_processed_volume / session_time_interval)
                perc_session_unassigned_pkts = int((session_unassigned_pkts / session_processed_pkts)*100)
                perc_session_unassigned_volume = int((session_unassigned_volume / session_processed_volume)*100)
                print(f"SESSION PKTS PER SECOND: {session_pkts_per_sec}")
                print(f"SESSION VOLUME PER SECOND: {session_volume_per_sec}")
                print(f"SESSION UNASSIGNED TRAFFIC (PKTS/SEC): {perc_session_unassigned_pkts}%")
                print(f"SESSION UNASSIGNED TRAFFIC (VOLUME/SEC): {perc_session_unassigned_volume}%")

                #Get global device stats and update clusters
                dev_stats = {
                    utils.TOTAL_DEV: 0,
                    utils.AP: 0,
                    utils.STA: 0,
                    utils.MESH: 0,
                    utils.UNIDENTIFIED: 0,
                    utils.TOTAL_RANDOMIZED: 0
                }

                for address, data in mac_table.items():
                    cluster = max(data[DISTANCE], key = lambda x: data[DISTANCE][x])
                    if cluster == utils.NEAR_CLUSTER:
                        near_cl.update_cluster(data, round_time_interval, session_time_interval)
                    elif cluster == utils.MEDIUM_CLUSTER:
                        medium_cl.update_cluster(data, round_time_interval, session_time_interval)
                    elif cluster == utils.FAR_CLUSTER:
                        far_cl.update_cluster(data, round_time_interval, session_time_interval)
                    elif cluster == utils.OUT_OF_RANGE_CLUSTER:
                        out_of_range_cl.update_cluster(data, round_time_interval, session_time_interval)

                    dev_stats[utils.TOTAL_DEV] += 1
                    dev_type = data[DEVICE]
                    dev_stats[dev_type] += 1
                    dev_stats[utils.TOTAL_RANDOMIZED] += 1 if data[RANDOMIZED] else 0
                    #reset round values
                    mac_table[address][ROUND] = {
                        PACKETS: 0,
                        VOLUME: 0,
                        CHANNELS: {},
                        PKT_TYPES: {}
                    }

                #aggregate and send to GUI
                aggregate_data = {
                    utils.GLOBAL: {
                        utils.PERFORMANCE: {
                            utils.ROUND: {
                                utils.AVG_ROUND_QUEUE_SIZE: avg_queue_size,
                                utils.ROUND_PROCESSED_PKTS_PER_SEC: round_processed_packets_per_sec,
                                utils.ROUND_PROCESSED_VOLUME_PER_SEC: round_processed_volume_per_sec
                            },
                            utils.SESSION: {
                                utils.SESSION_AVG_QUEUE_SIZE: session_avg_queue_size,
                                utils.SESSION_PROCESSED_PKTS_PER_SEC: session_processed_pkts_per_sec,
                                utils.SESSION_PROCESSED_VOLUME_PER_SEC: session_processed_volume_per_sec
                            },
                        },
                        utils.TRAFFIC: {
                            utils.ROUND: {
                                utils.ROUND_PKTS_PER_SEC: round_pkts_per_sec,
                                utils.ROUND_VOLUME_PER_SEC: round_volume_per_sec,
                                utils.PERC_ROUND_UNASSIGNED_PKTS: perc_round_unassigned_pkts,
                                utils.PERC_ROUND_UNASSIGNED_VOLUME: perc_round_unassigned_volume
                            },
                            utils.SESSION: {
                                utils.SESSION_PKTS_PER_SEC: session_pkts_per_sec,
                                utils.SESSION_VOLUME_PER_SEC: session_volume_per_sec,
                                utils.PERC_SESSION_UNASSIGNED_PKTS: perc_session_unassigned_pkts,
                                utils.PERC_SESSION_UNASSIGNED_VOLUME: perc_session_unassigned_volume
                            }
                        },
                        utils.DEVICES: dev_stats.copy()
                    },
                    utils.CLUSTERS: {
                        utils.NEAR_CLUSTER: copy.deepcopy(near_cl),
                        utils.MEDIUM_CLUSTER: copy.deepcopy(medium_cl),
                        utils.FAR_CLUSTER: copy.deepcopy(far_cl),
                        utils.OUT_OF_RANGE_CLUSTER: copy.deepcopy(out_of_range_cl),
                    }
                }
                
                stats_queue.put(aggregate_data)
                #Reset cluster metrics
                near_cl.reset_cluster()
                medium_cl.reset_cluster()
                far_cl.reset_cluster()
                out_of_range_cl.reset_cluster()
                
                    

if __name__ == '__main__':
    import sensor
    from multiprocessing import Process
    from pyroute2 import IW

    stats_queue = Queue()
    pkt_queue = Queue()
    iw = IW()
    sniffer_process = Process(target=sensor.sniffer, args=(3, 'wlo1mon', pkt_queue))
    sniffer_process.daemon = True
    sniffer_process.start()
    try:
        analyze(pkt_queue, stats_queue, 4.5)
    except KeyboardInterrupt as e:
        print("Interruzione da tastiera rilevata")
    finally:
        sniffer_process.join(timeout= 2)

        if sniffer_process.is_alive():
            print("Terminazione forzata")
            sniffer_process.terminate()
            sniffer_process.join()



            



