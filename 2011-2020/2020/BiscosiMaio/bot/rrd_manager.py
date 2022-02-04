import os
import rrdtool
import datetime
from threading import Thread
from threading import Event
from time import sleep


class RRDManager(Thread):
    """Class used to store and analyze data from an agent snmp, with the support of RRDtool"""

    def __init__(
            self, session, storage_time, season_time,
            hostname="localhost", community="public", version=1):
        """ Inits RRDManager with info about an snmp agent and storage time

        :param session: an easysnmp session of an snmp agent
        :param storage_time: the total amount of time, in seconds, the program has to storage data into the file,
                            before wrap-around
        :param season_time: is the number of primary data points in the seasonal period. This value will be the RRA row
                            counts for the SEASONAL and DEVSEASONAL RRAs
        :param hostname: is the ip address of the snmp agent
        :param community: is the community used by the snmp agent
        :param version: is the version used by the snmp agent
        """
        super().__init__()
        self.hostname = hostname
        self.community = community
        self.version = version
        self.session = session
        self.storage_time = int(storage_time / 10)
        self.season_time = int(season_time / 10)
        self._stopper = Event()
        self.dir = None
        self.cpu = None
        self.ram = None
        self.disk = None
        self.in_net = None
        self.out_net = None

    def run(self):
        """ start the execution of the creation and data storing """
        self.print_stats(self.cpu,
                         self.ram,
                         self.disk,
                         self.in_net,
                         self.out_net)

    def stopit(self):
        """ terminate the execution of thread which is storing data """
        self._stopper.set()

    def __stopped(self):
        return self._stopper.is_set()

    def print_stats(self, cpu, ram, disk, in_net, out_net):
        """ store CPU, RAM, Disk, InOctets, OutOctets
        (if available) data from the snmp agent every 10 seconds"""

        # Getting time using datetime.now(), more accurate then the time() function
        # because it gets until microseconds
        current_time = datetime.datetime.now().timestamp()

        cpu_available = False
        ram_available = False
        disk_available = False
        in_octet_available = False
        out_octet_available = False

        # Updates .rrd files
        if cpu:
            cpu_available = self.print_cpu(session=self.session,
                                           hostname=self.hostname)

        if ram:
            ram_available = self.print_ram(session=self.session,
                                           hostname=self.hostname)

        if disk:
            disk_available = self.print_disk(session=self.session,
                                             hostname=self.hostname)

        if in_net:
            in_octet_available = self.print_in_octet(session=self.session,
                                                     hostname=self.hostname)

        if out_net:
            out_octet_available = self.print_out_octet(session=self.session,
                                                       hostname=self.hostname)

        # Error check
        if (cpu_available is False and
                ram_available is False and
                disk_available is False and
                in_octet_available is False and
                out_octet_available is False):
            print("ERROR: hostname = " + self.hostname +
                  "\nNone of the system info is accessible, the program will now terminate.")
            exit(1)

        # Loop until self.__stopped() is not set
        while not self.__stopped():
            sleep_time = datetime.datetime.now().timestamp() - current_time

            if sleep_time < 10:
                sleep_time = 10 - sleep_time

                try:
                    sleep(sleep_time)
                except KeyboardInterrupt:
                    print("ERROR: hostname = " + self.hostname +
                          "\nProgram interrupted from the user.")
                    exit(1)

            current_time = datetime.datetime.now().timestamp()

            # Update
            if cpu_available is True:
                cpu_available = self.print_cpu(session=self.session,
                                               hostname=self.hostname)

            if ram_available is True:
                ram_available = self.print_ram(session=self.session,
                                               hostname=self.hostname)

            if disk_available is True:
                disk_available = self.print_disk(session=self.session,
                                                 hostname=self.hostname)

            if in_octet_available:
                in_octet_available = self.print_in_octet(session=self.session,
                                                         hostname=self.hostname)

            if out_octet_available:
                out_octet_available = self.print_out_octet(session=self.session,
                                                           hostname=self.hostname)

    def print_cpu(
            self, session, hostname):
        """ insert into the corresponding file the percentage of CPU usage

        :param session: an easysnmp session of an snmp agent
        :param hostname: ip address of the snmp agent
        :return: `True` if update was successful, `False` otherwise
        :rtype: bool
        """
        try:
            rsp = session.get(".1.3.6.1.4.1.2021.11.9.0")
            rrdtool.update(
                "./RRDlog/" + hostname + "/cpu.rrd",
                "N:" + rsp.value)
        except Exception:
            return False

        return True

    def print_ram(
            self, session, hostname):
        """ insert into the corresponding file the percentage of RAM usage

        :param session: an easysnmp session of an snmp agent
        :param hostname: ip address of the snmp agent
        :return: `True` if update was successful, `False` otherwise
        :rtype: bool
        """
        try:
            # Calculates the percentage
            mem_avail_real = session.get(".1.3.6.1.4.1.2021.4.6.0")
            mem_total_real = session.get(".1.3.6.1.4.1.2021.4.5.0")
            mem_used = float(mem_total_real.value) - float(mem_avail_real.value)
            percentage = (100 * mem_used) / float(mem_total_real.value)
            rrdtool.update(
                "./RRDlog/" + hostname + "/ram.rrd",
                "N:" + str(round(percentage, 2)))
        except Exception:
            return False

        return True

    def print_disk(
            self, session, hostname):
        """ insert into the corresponding file the percentage of Disk usage

        :param session: an easysnmp session of an snmp agent
        :param hostname: ip address of the snmp agent
        :return: `True` if update was successful, `False` otherwise
        :rtype: bool
        """
        try:
            rsp = session.get(".1.3.6.1.4.1.2021.9.1.9.1")
            rrdtool.update(
                "./RRDlog/" + hostname + "/disk.rrd",
                "N:" + rsp.value)
        except Exception:
            return False

        return True

    def print_in_octet(
            self, session, hostname):
        """ insert into the corresponding file the number of InOctet

        :param session: an easysnmp session of an snmp agent
        :param hostname: ip address of the snmp agent
        :return: `True` if update was successful, `False` otherwise
        :rtype: bool
        """
        try:
            rsp = session.get(".1.3.6.1.2.1.2.2.1.16.1")
            rrdtool.update(
                "./RRDlog/" + hostname + "/inOctet.rrd",
                "N:" + rsp.value)
        except Exception:
            return False

        return True

    def print_out_octet(
            self, session, hostname):
        """ insert into the corresponding file the number of OutOctet

        :param session: an easysnmp session of an snmp agent
        :param hostname: ip address of the snmp agent
        :return: `True` if update was successful, `False` otherwise
        :rtype: bool
        """
        try:
            rsp = session.get(".1.3.6.1.2.1.2.2.1.16.2")
            rrdtool.update(
                "./RRDlog/" + hostname + "/outOctet.rrd",
                "N:" + rsp.value)
        except Exception:
            return False

        return True

    def check_rrd(
            self, hostname, storage_time,
            season_time):
        """ Checks if the log's directory and the various files, used to store data, exist
            otherwise it creates them. The hostname will be used as the name of the repository
            of the corresponding host

        :param hostname: ip address of the snmp agent
        :param storage_time: the total amount of time, in seconds, the program has to storage data into the file,
                            before wrap-around
        :param season_time: is the number of primary data points in the seasonal period. This value will be the RRA row
                            counts for the SEASONAL and DEVSEASONAL RRAs
        :return (bool) dir: is the outcome of the creation of the directories
        :return (bool) cpu: is the outcome of the creation of CPU storage file
        :return (bool) ram: is the outcome of the creation of RAM storage file
        :return (bool) disk: is the outcome of the creation of Disk storage file
        :return (bool) in_net: is the outcome of the creation of inOctet storage file
        :return (bool) out_net: is the outcome of the creation of outOctet storage file
        """
        storage_time = int(storage_time / 10)
        season_time = int(season_time / 10)

        dir, dir1, cpu, ram, disk, in_net, out_net = True, True, True, True, True, True, True

        # Checking if the log directory exists
        if os.path.isdir("./RRDlog"):

            # Checking if the hostname directory already exists into the log directory
            if not os.path.isdir("./RRDlog/" + hostname):
                dir1 = self.create_dir("./RRDlog/" + hostname)

                # Checking if the various .rrd files exists into the hostname log directory
                if dir1:
                    if not os.path.exists("./RRDlog/" + hostname + "/cpu.rrd"):
                        cpu = self.create_cpu(hostname=hostname,
                                              storage_time=storage_time,
                                              season_time=season_time)

                    if not os.path.exists("./RRDlog/" + hostname + "/ram.rrd"):
                        ram = self.create_ram(hostname=hostname,
                                              storage_time=storage_time,
                                              season_time=season_time)

                    if not os.path.exists("./RRDlog/" + hostname + "/disk.rrd"):
                        disk = self.create_disk(hostname=hostname,
                                                storage_time=storage_time,
                                                season_time=season_time)

                    if not os.path.exists("./RRDlog/" + hostname + "/inOctet.rrd"):
                        in_net = self.create_in_octet(hostname=hostname,
                                                      storage_time=storage_time,
                                                      season_time=season_time)

                    if not os.path.exists("./RRDlog/" + hostname + "/outOctet.rrd"):
                        out_net = self.create_out_octet(hostname=hostname,
                                                        storage_time=storage_time,
                                                        season_time=season_time)

            else:
                if not os.path.exists("./RRDlog/" + hostname + "/cpu.rrd"):
                    cpu = self.create_cpu(hostname=hostname,
                                          storage_time=storage_time,
                                          season_time=season_time)

                if not os.path.exists("./RRDlog/" + hostname + "/ram.rrd"):
                    ram = self.create_ram(hostname=hostname,
                                          storage_time=storage_time,
                                          season_time=season_time)

                if not os.path.exists("./RRDlog/" + hostname + "/disk.rrd"):
                    disk = self.create_disk(hostname=hostname,
                                            storage_time=storage_time,
                                            season_time=season_time)

                if not os.path.exists("./RRDlog/" + hostname + "/inOctet.rrd"):
                    in_net = self.create_in_octet(hostname=hostname,
                                                  storage_time=storage_time,
                                                  season_time=season_time)

                if not os.path.exists("./RRDlog/" + hostname + "/outOctet.rrd"):
                    out_net = self.create_out_octet(hostname=hostname,
                                                    storage_time=storage_time,
                                                    season_time=season_time)

        else:
            dir = self.create_dir("./RRDlog")

            dir1 = self.create_dir("./RRDlog/" + hostname)

            cpu = self.create_cpu(hostname=hostname,
                                  storage_time=storage_time,
                                  season_time=season_time)

            ram = self.create_ram(hostname=hostname,
                                  storage_time=storage_time,
                                  season_time=season_time)

            disk = self.create_disk(hostname=hostname,
                                    storage_time=storage_time,
                                    season_time=season_time)

            in_net = self.create_in_octet(hostname=hostname,
                                          storage_time=storage_time,
                                          season_time=season_time)

            out_net = self.create_out_octet(hostname=hostname,
                                            storage_time=storage_time,
                                            season_time=season_time)

        if dir1:
            return dir, cpu, ram, disk, in_net, out_net
        return False, False, False, False, False, False

    def create_dir(
            self, path):
        """ Used to create a directory into path

        :param path: path + name of the directory to create
        :return: `True` if creation was successful, `False` otherwise
        :rtype: bool
        """
        try:
            os.mkdir(path)
        except Exception:
            return False

        return True

    def create_cpu(
            self, hostname, storage_time,
            season_time):
        """ Used to create CPU storage file

        :param hostname: is the ip address of the snmp agent
        :param storage_time: the total amount of time the program has to storage data into the file, before wrap-around
        :param season_time: is the number of primary data points in the seasonal period. This value will be the RRA row
                            counts for the SEASONAL and DEVSEASONAL RRAs
        :return: `True` if creation was successful, `False` otherwise
        :rtype: bool
        """
        try:
            rrdtool.create(
                "./RRDlog/" + hostname + "/cpu.rrd",
                "--start", "now",
                "--step", "10",
                "DS:cpu:GAUGE:20:0:100",
                "RRA:AVERAGE:0.5:1:" + str(storage_time),
                "RRA:HWPREDICT:" + str(storage_time) + ":0.1:0.0035:" + str(season_time) + ":3",
                "RRA:SEASONAL:" + str(season_time) + ":0.1:2",
                "RRA:DEVSEASONAL:" + str(season_time) + ":0.1:2",
                "RRA:DEVPREDICT:" + str(storage_time) + ":4",
                "RRA:FAILURES:" + str(storage_time) + ":3:3:4"
            )

        except Exception:
            return False

        return True

    def create_ram(
            self, hostname, storage_time,
            season_time):
        """ Used to create RAM storage file

        :param hostname: is the ip address of the snmp agent
        :param storage_time: the total amount of time the program has to storage data into the file, before wrap-around
        :param season_time: is the number of primary data points in the seasonal period. This value will be the RRA row
                            counts for the SEASONAL and DEVSEASONAL RRAs
        :return: `True` if creation was successful, `False` otherwise
        :rtype: bool
        """
        try:
            rrdtool.create(
                "./RRDlog/" + hostname + "/ram.rrd",
                "--start", "now",
                "--step", "10",
                "DS:ram:GAUGE:20:0:100",
                "RRA:AVERAGE:0.5:1:" + str(storage_time),
                "RRA:HWPREDICT:" + str(storage_time) + ":0.1:0.0035:" + str(season_time) + ":3",
                "RRA:SEASONAL:" + str(season_time) + ":0.1:2",
                "RRA:DEVSEASONAL:" + str(season_time) + ":0.1:2",
                "RRA:DEVPREDICT:" + str(storage_time) + ":4",
                "RRA:FAILURES:" + str(storage_time) + ":3:3:4"
            )
        except Exception:
            return False

        return True

    def create_disk(
            self, hostname, storage_time,
            season_time):
        """ Used to create Disk storage file

        :param hostname: is the ip address of the snmp agent
        :param storage_time: the total amount of time the program has to storage data into the file, before wrap-around
        :param season_time: is the number of primary data points in the seasonal period. This value will be the RRA row
                            counts for the SEASONAL and DEVSEASONAL RRAs
        :return: `True` if creation was successful, `False` otherwise
        :rtype: bool
        """
        try:
            rrdtool.create(
                "./RRDlog/" + hostname + "/disk.rrd",
                "--start", "now",
                "--step", "10",
                "DS:disk:GAUGE:20:0:100",
                "RRA:AVERAGE:0.5:1:" + str(storage_time),
                "RRA:HWPREDICT:" + str(storage_time) + ":0.1:0.0035:" + str(season_time) + ":3",
                "RRA:SEASONAL:" + str(season_time) + ":0.1:2",
                "RRA:DEVSEASONAL:" + str(season_time) + ":0.1:2",
                "RRA:DEVPREDICT:" + str(storage_time) + ":4",
                "RRA:FAILURES:" + str(storage_time) + ":3:3:4"
            )
        except Exception:
            return False

        return True

    def create_in_octet(
            self, hostname, storage_time,
            season_time):
        """ Used to create InOctets storage file

        :param hostname: is the ip address of the snmp agent
        :param storage_time: the total amount of time the program has to storage data into the file, before wrap-around
        :param season_time: is the number of primary data points in the seasonal period. This value will be the RRA row
                            counts for the SEASONAL and DEVSEASONAL RRAs
        :return: `True` if creation was successful, `False` otherwise
        :rtype: bool
        """
        try:
            rrdtool.create(
                "./RRDlog/" + hostname + "/inOctet.rrd",
                "--start", "now",
                "--step", "10",
                "DS:inOctet:COUNTER:20:0:U",
                "RRA:AVERAGE:0.5:1:" + str(storage_time),
                "RRA:HWPREDICT:" + str(storage_time) + ":0.1:0.0035:" + str(season_time) + ":3",
                "RRA:SEASONAL:" + str(season_time) + ":0.1:2",
                "RRA:DEVSEASONAL:" + str(season_time) + ":0.1:2",
                "RRA:DEVPREDICT:" + str(storage_time) + ":4",
                "RRA:FAILURES:" + str(storage_time) + ":3:3:4"
            )
        except Exception:
            return False

        return True

    def create_out_octet(
            self, hostname, storage_time,
            season_time):
        """ Used to create OutOctets storage file

        :param hostname: is the ip address of the snmp agent
        :param storage_time: the total amount of time the program has to storage data into the file, before wrap-around
        :param season_time: is the number of primary data points in the seasonal period. This value will be the RRA row
                            counts for the SEASONAL and DEVSEASONAL RRAs
        :return: `True` if creation was successful, `False` otherwise
        :rtype: bool
        """
        try:
            rrdtool.create(
                "./RRDlog/" + hostname + "/outOctet.rrd",
                "--start", "now",
                "--step", "10",
                "DS:outOctet:COUNTER:20:0:U",
                "RRA:AVERAGE:0.5:1:" + str(storage_time),
                "RRA:HWPREDICT:" + str(storage_time) + ":0.1:0.0035:" + str(season_time) + ":3",
                "RRA:SEASONAL:" + str(season_time) + ":0.1:2",
                "RRA:DEVSEASONAL:" + str(season_time) + ":0.1:2",
                "RRA:DEVPREDICT:" + str(storage_time) + ":4",
                "RRA:FAILURES:" + str(storage_time) + ":3:3:4"
            )
        except Exception:
            return False

        return True

    # Various setter methods
    def set_dir(self, dir):
        """ Set self.dir to dir

        :param dir: boolean that indicates if the directories were created
        """
        self.dir = dir

    def set_cpu(self, cpu):
        """ Set self.cpu to cpu

        :param cpu: boolean that indicates if the cpu.rrd were created
        """
        self.cpu = cpu

    def set_ram(self, ram):
        """ Set self.ram to ram

        :param ram: boolean that indicates if the ram.rrd were created
        """
        self.ram = ram

    def set_disk(self, disk):
        """ Set self.disk to disk

        :param disk: boolean that indicates if the disk.rrd were created
        """
        self.disk = disk

    def set_in_net(self, in_net):
        """ Set self.dir to dir

        :param in_net: boolean that indicates if the inOctet.rrd were created
        """
        self.in_net = in_net

    def set_out_net(self, out_net):
        """ Set self.dir to dir

        :param out_net: boolean that indicates if the outOctet.rrd were created
        """
        self.out_net = out_net