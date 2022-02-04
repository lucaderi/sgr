
#
# Import
import os
import emoji
from telepot.namedtuple import InlineKeyboardMarkup
from telepot.namedtuple import InlineKeyboardButton


class HostInfo:
    """ Class used to manage SNMP Session info.

    """
    host = "localhost"
    community = "public"
    version = 1
    monitor = False
    thread_monitor = None

    def get_host(self):
        """ Method used to obtain host name.

        """
        return self.host

    def get_community(self):
        """ Method used to obtain SNMP community info.

        """
        return self.community

    def get_version(self):
        """ Method used to obtain SNMP version info.

        """
        return self.version

    def get_monitor(self):
        """ Method used to obtain value of monitor,
                a boolean variable used to check if the bot is
                monitoring the chosen host.

        """
        return self.monitor

    def get_thread_monitor(self):
        """ Method used to obtain the instance of the thread
                that is monitoring the chosen host.

        """
        return self.thread_monitor

    def set_host(self, new_host):
        """ Method used to change host name.

        :param new_host: the new host name.
        """
        print(self.monitor)
        if not self.monitor:
            self.host = new_host
            return True
        else:
            return False

    def set_version(self, new_version):
        """ Method used to change version of SNMP Session.

        :param new_version: the new SNMP version.
        """
        if not self.monitor:
            self.version = int(new_version)
            return True
        else:
            return False

    def set_community(self, new_community):
        """ Method used to change community of SNMP Session.

        :param new_community: the new SNMP community
        """
        if not self.monitor:

            self.community = new_community
            return True
        else:
            return False

    def set_monitor(self, new_monitor):
        """ Method used to change value of monitor variable.

        :param new_monitor: new value of monitor v.
        """
        self.monitor = new_monitor

    def set_thread_monitor(self, new_thread_monitor):
        """ Method used to set the new thread instance.

        :param new_thread_monitor: the new thread instance.
        """
        self.thread_monitor = new_thread_monitor


host_details = HostInfo()

#
# Keyboard for the Back button.
keyboard = InlineKeyboardMarkup(inline_keyboard=[
    [InlineKeyboardButton(text='Back', callback_data='comm')]
])

#
# Keyboard with command list.
keyboard2 = InlineKeyboardMarkup(inline_keyboard=[
    [InlineKeyboardButton(text='CPU Usage', callback_data='cpuU'),
     InlineKeyboardButton(text='Total RAM', callback_data='totMem')],
    [InlineKeyboardButton(text='RAM Usage', callback_data='usedMem'),
     InlineKeyboardButton(text='# Tasks', callback_data='tasks')],
    [InlineKeyboardButton(text='Disk Usage', callback_data='disk'),
     InlineKeyboardButton(text='App Classification', callback_data='classApp')]
])

#
# Keyboard with the possible storage time to monitor the host.
keyboard_length = InlineKeyboardMarkup(inline_keyboard=[
    [
        InlineKeyboardButton(text='1 day', callback_data='1day_length'),
        InlineKeyboardButton(text='1 week', callback_data='1week_length')
    ],
    [
        InlineKeyboardButton(text='1 month', callback_data='1month_length'),
        InlineKeyboardButton(text='1 year', callback_data='1year_length')
    ]
])


def send_length(chat_id, bot):
    """ Send the possible commands to choose the storage time to monitor
        host with rrdtool

    :param chat_id: chat id to send the keyboard with the possible storage time to.
    :param bot: bot instance.
    """
    if os.path.isdir("./rrdLogs") and os.path.isdir("./rrdLogs/" + host_details.get_host()) \
            and os.path.exists(
                "./rrdLogs/" + host_details.get_host() + "/cpu.rrd") and os.path.exists(
                "./rrdLogs/" + host_details.get_host() + "/ram.rrd") or os.path.exists(
                "./rrdLogs/" + host_details.get_host() + "/disk.rrd") or os.path.exists(
                "./rrdLogs/" + host_details.get_host() + "/inOctet.rrd") or os.path.exists(
                "./rrdLogs/" + host_details.get_host() + "/outOctet.rrd"):
        start_monitoring(chat_id=chat_id, bot=bot, alfa=0, periodo=0, lenghtSeas=0)
    else:
        bot.sendMessage(chat_id, 'Choose length', reply_markup=keyboard_length)


def back_home(chat_id, bot):
    """ Send the back button

    :param chat_id: chat id to send the keyboard with back button to.
    :param bot: bot instance.
    """
    keyboard3 = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text='Back', callback_data='home')]
    ])
    bot.sendMessage(chat_id, 'Home', reply_markup=keyboard3)


def send_home(chat_id, bot):
    """ Send the keyboard with the command list of the home.

    :param chat_id: chat id to send the keyboard with home commands list to.
    :param bot: bot instance.
    """
    em = emoji.emojize('Graphs :chart_with_upwards_trend:', use_aliases=True)
    sysinfo = emoji.emojize('SystemInfo :speech_balloon:', use_aliases=True)
    helpem = emoji.emojize('HELP :question:', use_aliases=True)
    comandem = emoji.emojize('Commands :rocket:', use_aliases=True)
    startmonem = emoji.emojize('START MONITORING :mag_right:', use_aliases=True)
    stopmonem = emoji.emojize('STOP MONITORING :mag_right:', use_aliases=True)
    settingem = emoji.emojize('Settings :wrench:', use_aliases=True)
    # If the user has yet to start to monitor SNMP agent
    if not host_details.monitor:

        keyboard = InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text='%s' % helpem, callback_data='help')],
            [InlineKeyboardButton(text='%s' % comandem, callback_data='comm'),
             InlineKeyboardButton(text='%s' % em, callback_data='graph')],
            [InlineKeyboardButton(text='%s' % settingem, callback_data='settings'),
             InlineKeyboardButton(text='%s' % sysinfo, callback_data='system')],
            [InlineKeyboardButton(text='%s' % startmonem, callback_data='start_monitoring')]
        ])

    # If the user has already started to monitor SNMP agent
    else:
        keyboard = InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text='%s' % helpem, callback_data='help')],
            [InlineKeyboardButton(text='%s' % comandem, callback_data='comm'),
             InlineKeyboardButton(text='%s' % em, callback_data='graph')],
            [InlineKeyboardButton(text='%s' % settingem, callback_data='settings'),
             InlineKeyboardButton(text='%s' % sysinfo, callback_data='system')],
            [InlineKeyboardButton(text='%s' % stopmonem, callback_data='stop_monitoring')]
        ])
    try:
        bot.sendMessage(chat_id, 'Welcome!', reply_markup=keyboard)
    except exception.BotWasKickedError as exce:
        print('Bot kicked from group, error: ' + str(exce))


def send_graph(chat_id, bot):
    """ Send keyboard to choose the graph that user can see.

    :param chat_id: chat id to send the keyboard with graph list to.
    :param bot: bot instance.
    """
    keyboard_graph = InlineKeyboardMarkup(inline_keyboard=[
        [
            InlineKeyboardButton(text='CPU', callback_data='graph_cpu'),
            InlineKeyboardButton(text='RAM', callback_data='graph_ram')
        ],
        [InlineKeyboardButton(text='Disk', callback_data='graph_disk')],
        [
            InlineKeyboardButton(text='Download', callback_data='graph_in'),
            InlineKeyboardButton(text='Upload', callback_data='graph_out')
        ]
    ])
    bot.sendMessage(chat_id, 'Choose graph', reply_markup=keyboard_graph)


def send_comm_list(chat_id, bot):
    """ Send the SNMP command list

    :param chat_id: chat id to send the keyboard SNMP commands list to.
    :param bot: bot instance.
    """
    bot.sendMessage(chat_id, 'Command List', reply_markup=keyboard2)
    back_home(chat_id, bot)


def send_settings(chat_id, bot):
    """ Send information to change te SNMP session info.

    :param chat_id: chat id to send settings command
    :param bot: bot instance.
    """
    bot.sendMessage(chat_id, '/sethost <new host> to change host address')
    bot.sendMessage(chat_id, '/setversion <new version> to change version for the SNMP request')
    bot.sendMessage(chat_id, '/setcommunity <new community> to change community for the SNMP request')
    bot.sendMessage(chat_id, '/remove to remove data collected until now')


def send_helper(chat_id, bot):
    """ Send help info to chat id.

    :param chat_id: chat id to send help information.
    :param bot: bot instance.
    """
    bot.sendMessage(chat_id,
                    "*SNMPNotifierBot*"+" helps you to monitor an host using Telegram.\n\n\n" +
                    "*Login*: to sign in and start using bot you need to send \n /login <password>\n\n\n" +
                    "*Commands*"+": this button allows you to view the possible SNMP"
                    + " requests that can be requested to a host.\n"
                    + "\t\t *CPU Usage*: return the CPU usage percent on setted up host.\n"
                    + "\t\t *Total RAM*: return the total RAM value on setted up host.\n"
                    + "\t\t *RAM Usage*: return the usage RAM value in percent on setted up host.\n"
                    + "\t\t *# Tasks*: return the number of tasks actual in execution on setted up host.\n"
                    + "\t\t *Disk Usage*: return the usage of Disk in percent on setted up host.\n"
                    + "\t\t *App Classification*: return a classification of the app with" +
                      "most memory usage on setted up host.\n\n\n"
                    + "*Graphs*: this button allows you to view graphs about info collected from the host"
                    + " using SNMP.\n"
                    + "\t\t *CPU*: graph of the CPU usage percent on setted up host\n"
                    + "\t\t *RAM*: graph of the RAM usage percent on setted up host\n"
                    + "\t\t *Disk*: graph of the Disk usage percent on setted up host\n"
                    + "\t\t *Download*: graph of the downloaded bits on setted up host\n"
                    + "\t\t *Upload*: graph of the uploaded bits on setted up host\n\n\n"
                    + "*Settings*: this button allows you to view how to change easysnmp session settings\n\n\n"
                    + "*SystemInfo*: this button allows you to view some system info of setted up host\n\n\n"
                    + "*START MONITORING*: this button allows you to start collecting info of setted up host"
                    + " (available only if the host is not currently monitored)\n\n\n"
                    + "\t\t*1 day*: collect info from the host at max for 1 day, before overwriting them\n"
                    + "\t\t*1 week*: collect info from the host at max for 1 week, before overwriting them\n"
                    + "\t\t*1 month*: collect info from the host at max for 1 month, before overwriting them\n"
                    + "\t\t*1 year*: collect info from the host at max for 1 year, before overwriting them\n\n\n"
                    + "*STOP MONITORING*: this button allows you to stop collecting info of setted up host"
                    + "(available only if the host is currently monitored)",
                    parse_mode='Markdown')
    send_home(chat_id,bot)