from influxdb_client.client.write_api import SYNCHRONOUS
import influxdb_client
import heapq
import core.utils as utils
import threading


class Graph():

    def __init__(self, config_file, bucket_name="dostect", time_interval=1):
        """
        Called by traffic catching classes.
        Connect to influxdb2 throughout a given config.ini file.
        Provides a shared priority queue for TCP volume computed by detection algorithms
        and retrieve every time_interval sec these data to create plotting point to write in bucket_name

        :param config_file: path to config file (.ini)
        :param bucket_name: influxdb bucket's name
        :param time_interval: time interval provided by input
        """

        self.interval = time_interval
        self.bucket_name = bucket_name
        self.org = ""
        self.write_api = None
        self.tcp_queue = []
        self._timer = None
        self.__stopped = False
        self.__writing_thread = None

        client = None
        result = 0
        try:
            # Load influx configuration from .ini file: retrieve HOST:PORT, ORG ID, ACCESS TOKEN
            client = influxdb_client.InfluxDBClient.from_config_file(config_file=config_file)

            self.org = client.org

                # Creating buckets API for buckets access
            bucket = client.buckets_api()

            # Checks if bucket bucket_name already exists, else create it
            try: #API call to InfluxCloud return an exception
                result = bucket.find_bucket_by_name(self.bucket_name)
            except:
                bucket.create_bucket(bucket_name=self.bucket_name)
                utils.colors(8,0,"[Graph mode] - Bucket " + self.bucket_name + " created!", 3)
            
            #API call to local influxd service return None
            if result is None:
                bucket.create_bucket(bucket_name=self.bucket_name)
                utils.colors(8,0,"[Graph mode] - Bucket " + self.bucket_name + " created!", 3)

        except Exception:
            raise Exception("Error while connecting to influxdb instance: check your service or .ini file!")

        # Creating write API for points creation
        self.write_api = client.write_api(write_options=SYNCHRONOUS)

        # Start periodical writing thread
        self.__write_data_thread()

    def __write_data(self):
        """
        Writes into influxdb data found into internal shared priority queue
        """

        # Check if there is volume values to write
        while len(self.tcp_queue) > 0:

            # Retrieve timestamp,values from <timestamp:[data]>
            timestamp, values = heapq.heappop(self.tcp_queue)

            # Create point with [data] and write it to bucket bucket_name
            p_syn = influxdb_client.Point("data_interval")

            for label, value in values:
                p_syn.field(label, value)

            try:
                # Writing point to influxdb
                self.write_api.write(bucket=self.bucket_name, org=self.org, record=p_syn)
            except Exception:
                
                self.stop_writing_thread()
                raise Exception("[Graph mode] - Error while writing to influxdb instance: check your service or .ini file!")

    def update_data(self, data: tuple, timestamp: int):
        """
        Insert data (TCP volume,threshold, SYN volume, ACK volume) into shared priority queue

        :param data: a tuple of data to add, each element in data is a tuple of two elements (label:str, value:Any)
        :param timestamp: the time of record
        """

        heapq.heappush(self.tcp_queue, (timestamp, data))

    def stop_writing_thread(self):
        """
        Closes the thread if a signal is reached

        :param signal_number:
        :param frame:
        """

        self.__stopped = True
        self.__writing_thread.join()

    def __write_data_thread(self):
        """
        Calls self.__write_data() periodically in a thread to write data
        saved into internal shared priority queue asynchronously
        """

        if not self.__stopped:
            self.__writing_thread = threading.Timer(self.interval, self.__write_data_thread)
            self.__writing_thread.start()

        try:
            self.__write_data()
        except:
            utils.colors(8,0,"[Graph mode] - Error while writing to influxdb instance: --graph mode deactivate!", 12)
            exit(1)
