
import glob
import psutil
import os
from easysnmp import Session
from easysnmp import exceptions as exce
from rrd_manager import RRDManager
from graph_maker import create_dir_graph
from bot_command import host_details
import bot_command


def get_cpu_usage(chat_id, bot):
    """ Send response of 'snmpget' request for CPU usage.

    :param chat_id: chat id to send SNMP get response.
    :param bot: bot instance.
    """
    try:
        session = Session(hostname=host_details.get_host(), community=host_details.get_community(),
                          version=host_details.get_version())

        cpuUsage = session.get(".1.3.6.1.4.1.2021.11.9.0")
        cpu = int(cpuUsage.value)

        bot.sendMessage(chat_id, 'Actual CPU percentage: ' + host_details.get_host() + ' = ' + str(cpu) + "%")
        bot.sendMessage(chat_id, 'Back to command list', reply_markup=bot_command.keyboard)

    except exce.EasySNMPError as error:
        bot.sendMessage(chat_id, 'Error during processing the request, agent: <' + host_details.get_host() + ' '
                        + host_details.get_community() + '> on cpu request')
        bot_command.back_home(chat_id, bot)
        print(error)


def get_tot_mem(chat_id, bot):
    """ Send response of 'snmpget' request for memTotalReal (Total RAM)

    :param chat_id: chat id to send SNMP get response.
    :param bot: bot instance.
    """
    try:
        session = Session(hostname=host_details.get_host(), community=host_details.get_community(),
                          version=host_details.get_version())

        memTotalReal = session.get(".1.3.6.1.4.1.2021.4.5.0")
        mem = int(memTotalReal.value)

        bot.sendMessage(chat_id, 'Total RAM memory of the host: ' + host_details.get_host() + ' = ' + str(mem) + "kB")
        bot.sendMessage(chat_id, 'Back to command list', reply_markup=bot_command.keyboard)

    except exce.EasySNMPError as error:
        bot.sendMessage(chat_id, 'Error during processing the request, agent: <' + host_details.get_host() + ' '
                        + host_details.get_community() + '> on tot mem request')
        bot_command.back_home(chat_id, bot)
        print(error)


def get_usage_mem(chat_id, bot):
    """ Send response of 'snmpget' request for usage RAM.

    :param chat_id: chat id to send SNMP get response.
    :param bot: bot instance.
    """
    try:
        session = Session(hostname=host_details.get_host(), community=host_details.get_community(),
                          version=host_details.get_version())

        mem_avail_real = session.get(".1.3.6.1.4.1.2021.4.6.0")
        mem_total_real = session.get(".1.3.6.1.4.1.2021.4.5.0")
        mem_usage = float(mem_total_real.value) - float(mem_avail_real.value)
        percentage = (100 * mem_usage) / float(mem_total_real.value)
        gb_usage = mem_usage / (1024 * 1024)

        bot.sendMessage(chat_id, 'RAM usage on: ' + host_details.get_host() + ' = ' + str(round(percentage, 2)) + "%" +
                        " (" + str(round(gb_usage, 2)) + "GB)")
        bot.sendMessage(chat_id, 'Back to command list', reply_markup=bot_command.keyboard)

    except exce.EasySNMPError as error:
        bot.sendMessage(chat_id, 'Error during processing the request, agent: <' + host_details.get_host() + ' '
                        + host_details.get_community() + '> on used mem request')
        bot_command.back_home(chat_id, bot)
        print(error)


def get_tasks(chat_id, bot):
    """ Send number of tasks in execution on host

    :param chat_id: chat id to send response.
    :param bot: bot instance.
    """
    try:
        session = Session(hostname=host_details.get_host(), community=host_details.get_community(),
                          version=host_details.get_version())

        numTasks = session.get(".1.3.6.1.2.1.25.1.6.0")
        num = int(numTasks.value)

        bot.sendMessage(chat_id, 'Actual tasks in execution on: ' + host_details.get_host() + ' = ' + str(num))
        bot.sendMessage(chat_id, 'Back to command list', reply_markup=bot_command.keyboard)

    except exce.EasySNMPError as error:
        bot.sendMessage(chat_id,
                        'Error during processing the request, agent: <' + host_details.get_host() + ' '
                        + host_details.get_community() + '> on num tasks request')
        bot_command.back_home(chat_id, bot)
        print(error)


def get_disk(chat_id, bot):
    """ Send response of 'snmpget' request for dskPercent (Disk usage percent)

    :param chat_id: chat id to send SNMP get response.
    :param bot: bot instance.
    """

    try:
        session = Session(hostname=host_details.get_host(), community=host_details.get_community(),
                          version=host_details.get_version())

        disk = session.get(".1.3.6.1.4.1.2021.9.1.9.1")

        bot.sendMessage(chat_id, 'Actual Disk usage on: ' + host_details.get_host() + ' = ' + str(disk.value) + "%")
        bot.sendMessage(chat_id, 'Back to command list', reply_markup=bot_command.keyboard)

    except exce.EasySNMPError as error:
        bot.sendMessage(chat_id, 'Error during processing the request, agent: <' + host_details.get_host() + ' '
                        + host_details.get_community() + '> on disk request')
        bot_command.back_home(chat_id, bot)
        print(error)


def convert(seconds):
    """ Converts host's SysUpTime seconds to '(seconds, minutes, hours)'

    :param seconds: seconds of SysUpTime.
    :return: hour, minutes, seconds
    """
    min, sec = divmod(seconds, 60)
    hour, min = divmod(min, 60)
    return "%d:%02d:%02d" % (hour, min, sec)


def get_info_sys(chat_id, bot):
    """ Send some info about the host

    :param chat_id: chat id to send system info.
    :param bot: bot instance.
    """
    session = ''

    #
    # create easysnmp session
    try:
        session = Session(hostname=host_details.get_host(), community=host_details.get_community(),
                          version=host_details.get_version())
    except exce.EasySNMPError as error:
        bot.sendMessage(chat_id,
                        'Error during processing the request, agent: <' + host_details.get_host() + ' '
                        + host_details.get_community() + '> on system info request')
        bot_command.back_home(chat_id, bot)
        print(error)

    #
    # take user name, owner of the host.
    try:
        info_name = session.get('.1.3.6.1.2.1.1.5.0')
    except exce as error:
        info_name = None
        print(error)

    #
    # take location of the host.
    try:
        info_location = session.get('.1.3.6.1.2.1.1.6.0')
    except exce as error:
        info_location = None
        print(error)

    #
    # take description of the host.
    try:
        info_description = session.get('.1.3.6.1.2.1.1.1.0')
    except exce as error:
        info_description = None
        print(error)
    #
    # take oid of the host.
    try:
        info_oid = session.get('.1.3.6.1.2.1.1.2.0')
    except exce as error:
        info_oid = None
        print(error)

    #
    # take contact of the user, owner of the host.
    try:
        info_contact = session.get('.1.3.6.1.2.1.1.4.0')
    except exce as error:
        info_contact = None
        print(error)
    #
    # take sysUpTime of the snmp agent.
    try:
        info_sys_up_time = session.get('.1.3.6.1.2.1.1.3.0')
        seconds = float(info_sys_up_time.value) / 100
    except exce as error:
        seconds = None
        print(error)

    #
    # send messages to bot.
    bot.sendMessage(chat_id, "Name: " + str(info_name.value))
    bot.sendMessage(chat_id, "Location: " + str(info_location.value))
    bot.sendMessage(chat_id, "Contact: " + str(info_contact.value))
    bot.sendMessage(chat_id, "OID: " + str(info_oid.value))
    bot.sendMessage(chat_id, "Description: " + str(info_description.value))
    bot.sendMessage(chat_id, "Sys Up Time: " + str(convert(seconds)))
    bot_command.back_home(chat_id, bot)


def app_classific(chat_id, bot):
    """ Send ranking of apps based on host's memory usage

    :param chat_id: chat id to send the classification.
    :param bot: bot instance.
    """
    if host_details.get_host() != 'localhost' and host_details.get_host() != '127.0.0.1':
        bot.sendMessage(chat_id, 'Operation not available, it is available just for localhost')
    else:
        list_of_proc_objects = []
        # Iterate over the list
        for proc in psutil.process_iter():
            try:
                # Fetch process details as dict
                pinfo = proc.as_dict(attrs=['pid', 'name', 'username'])
                pinfo['vms'] = proc.memory_info().vms / (1024 * 1024 * 1024)
                # Append dict to list
                list_of_proc_objects.append(pinfo)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass

        # Sort list of dict by key vms i.e. memory usage
        list_of_proc_objects = sorted(list_of_proc_objects, key=lambda procObj: procObj['vms'], reverse=True)

        # Send to bot the classification.
        bot.sendMessage(chat_id, "{0:<10} {1:<10} {2:<10}".format('Name', 'PID', 'MemoryUsage'))
        for i in range(3):
            bot.sendMessage(chat_id, "{0:<10} {1:<10} {2:<10}".format(str(list_of_proc_objects[i]['name']),
                                                                      str(list_of_proc_objects[i]['pid'])
                                                                      , str(round(list_of_proc_objects[i]['vms'], 2))))
        bot.sendMessage(chat_id, 'Back to command list', reply_markup=bot_command.keyboard)


def start_monitoring(
        chat_id, bot, season_time,
        storage_time):
    """ Start the monitoring of the actual host

    :param chat_id: id of the telegram chat
    :param bot: id of the bot
    :param length_seas: is the number of predictions to store before wrap-around
    :param season_time: is the number of primary data points in the seasonal period. This value will be the RRA row
                        counts for the SEASONAL and DEVSEASONAL RRAs
    :param storage_time: the total amount of time the program has to storage data into the file, before wrap-around
    """
    try:
        session = Session(hostname=host_details.get_host(),
                          community=host_details.get_community(),
                          version=host_details.get_version())

        # Checking if the host is already monitored or not
        if host_details.get_monitor() is False:

            thread_monitor = RRDManager(session=session,
                                        storage_time=storage_time,
                                        season_time=season_time,
                                        hostname=host_details.get_host(),
                                        community=host_details.get_community(),
                                        version=host_details.get_version())

            # Checking/creating the necessary directories and files
            dir, cpu, ram, disk, in_net, out_net = thread_monitor.check_rrd(hostname=host_details.get_host(),
                                                                            storage_time=storage_time,
                                                                            season_time=season_time)

            # If there were problems creating the directories or all files, return an error
            if not dir:
                bot.sendMessage(chat_id,
                                "Error during processing the request, agent: <" + host_details.get_host() + " "
                                + host_details.get_community() + "> on start monitoring request")
                bot_command.back_home(chat_id, bot)
                return

            else:
                if (not cpu and
                        not disk and
                        not ram and
                        not in_net and
                        not out_net):
                    bot.sendMessage(chat_id,
                                    "Error during processing the request, agent: <" + host_details.get_host() + " "
                                    + host_details.get_community() + "> on start monitoring request")
                    bot_command.back_home(chat_id, bot)
                    return

            # Otherwise setting up the necessary variables and starting
            # the monitoring thread as a daemon
            thread_monitor.set_dir(dir=dir)
            thread_monitor.set_cpu(cpu=cpu)
            thread_monitor.set_ram(ram=ram)
            thread_monitor.set_disk(disk=disk)
            thread_monitor.set_in_net(in_net=in_net)
            thread_monitor.set_out_net(out_net=out_net)

            thread_monitor.daemon = True
            thread_monitor.start()
            host_details.set_thread_monitor(thread_monitor)
            host_details.set_monitor(True)

            bot.sendMessage(chat_id, "Monitoring started")
            bot_command.back_home(chat_id, bot)

        else:

            bot.sendMessage(chat_id, "Monitoring already started!")
            bot_command.back_home(chat_id, bot)

    except Exception as error:
        bot.sendMessage(chat_id,
                        "Error during processing the request, agent: <" + host_details.get_host() + " "
                        + host_details.get_community() + "> on start monitoring request")
        bot_command.back_home(chat_id, bot)
        print(error)


def stop_monitoring(
        chat_id, bot):
    """ Stop the monitoring of the snmp agent

    :param chat_id: id of the chat
    :param bot: id of the bot
    """
    try:
        # Checking that the monitoring is really active, if it is,
        # it stop it setting the _stopper to True
        if host_details.get_monitor() is True:

            thread_monitor = host_details.get_thread_monitor()
            thread_monitor.stopit()
            host_details.set_monitor(False)
            host_details.set_thread_monitor(None)

            bot.sendMessage(chat_id, "Monitoring stopped")
            bot_command.back_home(chat_id, bot)

        else:

            bot.sendMessage(chat_id, "Monitoring already stopped!")
            bot_command.back_home(chat_id, bot)

    except Exception as error:
        bot.sendMessage(chat_id,
                        "Error during processing the request, agent: <" + host_details.get_host() + " "
                        + host_details.get_community() + "> on stop monitoring request")
        bot_command.back_home(chat_id, bot)
        print(error)


def print_graph(
        chat_id, bot, graph_type):
    """ Create a graph of the resource requested and send it back

    :param chat_id: id of the chat
    :param bot: id of the box
    :param graph_type: resource requested, 0 for CPU, 1 for RAM, 2 for Disk, 3 for InOctets, 4 for OutOctets
    """
    try:
        # Creating the necessary directories and png photo
        result = create_dir_graph(host_details.get_host(), graph_type)

        if result is True:

            # Sending the photo based on the request
            send_image(chat_id, bot, graph_type)
            bot_command.back_home(chat_id, bot)

        # If there was a problem during the creation, it will send an error msg
        else:

            bot.sendMessage(chat_id, "Error while creating the image!")
            bot_command.back_home(chat_id, bot)

    except Exception as error:
        bot.sendMessage(chat_id, "Error during processing the request, agent: <" + host_details.get_host() + " "
                        + host_details.get_community() + "> on graph request")
        bot_command.back_home(chat_id, bot)
        print(error)


def send_image(
        chat_id, bot, graph_type):
    """ Send the graph to chat_id

    :param chat_id: id of the chat
    :param bot: id of the bot
    :param graph_type: resource requested, 0 for CPU, 1 for RAM, 2 for Disk, 3 for InOctets, 4 for OutOctets
    """
    if graph_type == 0:
        bot.sendPhoto(chat_id, open("./graph/" + host_details.get_host() + "/cpuGraph.png", "rb"))

    if graph_type == 1:
        bot.sendPhoto(chat_id, open("./graph/" + host_details.get_host() + "/ramGraph.png", "rb"))

    if graph_type == 2:
        bot.sendPhoto(chat_id, open("./graph/" + host_details.get_host() + "/diskGraph.png", "rb"))

    if graph_type == 3:
        bot.sendPhoto(chat_id, open("./graph/" + host_details.get_host() + "/inOctetGraph.png", "rb"))

    if graph_type == 4:
        bot.sendPhoto(chat_id, open("./graph/" + host_details.get_host() + "/outOctetGraph.png", "rb"))


def remove_data():
    """ Removes the data collected until now of the host, operation available only
    if the host is not currently monitored
    """
    try:
        files = glob.glob("./RRDlog/" + host_details.get_host() + "/*.rrd")

        if not files:
            return False

        for f in files:
            os.remove(f)

        return True
    except:
        return False
