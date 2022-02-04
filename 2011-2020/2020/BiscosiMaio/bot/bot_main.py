#!/usr/bin/python3

######################################################
#                    Documentation                   #
#    code on:                                        #
#    https://github.com/lucaderisgr/2020/BiscosiMaio #
#    python doc on:                                  #
#    bot/docs/_build/html/index.html                 #
#                    Installation                    #
#                pip3 install easysnmp               #
#                pip3 install telepot                #
#                pip3 install psutil                 #
#                pip3 install rrdtool                #
#                pip3 install emoji                  #
######################################################

#
# Import
import time
import os
from telepot import Bot
from telepot import glance
from telepot.loop import MessageLoop
import bot_command
from package_login.login import logClass
import snmp_op

#
# TOKEN
token = '11111111'

bot = Bot(token)


def run():
    """ Runs the function used to start the bot.
    """

    MessageLoop(bot,
                {'chat': on_chat_message, 'callback_query': on_callback_query}
                ).run_as_thread()

    print('Listening ...')

    while 1:
        time.sleep(10)


def on_chat_message(msg):
    """ Manages the predefined commands of the telegram bot.

    :param msg: message received from telegram.
    """

    content_type, chat_type, chat_id = glance(msg)

    #
    # Check if the content_type of the message is a text
    if content_type == 'text':
        text = msg['text']
        txt = text.lower()

        print(txt)
        #
        # Switch construct to manage the various commands
        if '/start' == txt:
            #
            # start command,
            # example on telegram: /start

            #
            # Check if the login is respected
            x = logClass.method_isloggedid(chat_id)
            if x == 0:
                bot_command.send_home(chat_id,bot)
            elif x == 1:
                bot.sendMessage(chat_id, 'The password is changed, please send /login <password>')
            elif x == 2:
                bot.sendMessage(chat_id, 'You need to be logged in to start using bot, please send /login password')

        elif '/login' in txt:
            #
            # login command,
            # example on telegram /login <password>

            elenco = txt.split(' ')
            x = logClass.method_loginid(chat_id, elenco[1])

            if x == True:
                bot.sendMessage(chat_id, 'Login completed')
                bot_command.send_home(chat_id,bot)
            else:
                bot.sendMessage(chat_id, 'Uncorrect password, try again /login <password>')

        elif '/sethost' in txt:
            #
            # set host command, to change host,
            # example on telegram /sethost <new_host>

            elenco = txt.split(' ')
            val = bot_command.host_details.set_host(elenco[1])

            if val:
                bot.sendMessage(chat_id,
                                'Host correctly modified into: '+elenco[1])
            else:
                bot.sendMessage(chat_id,
                                'Cannot change host address while monitoring: '
                                + str(bot_command.host_details.get_host()))
            bot_command.send_home(chat_id, bot)

        elif '/setversion' in txt:
            #
            # set version command, to change snmp version of the snmp queries,
            # example on telegram: /setversion <new_version>

            elenco = txt.split(' ')
            if elenco[1] != '1' and elenco[1] != '2':
                bot.sendMessage(chat_id,
                                'Please insert a supported version... supported version 1 and 2 ')
            else:
                val = bot_command.host_details.set_version(elenco[1])
                if val:
                    bot.sendMessage(chat_id,
                                    'Version correctly modified into: ' + elenco[1])
                else:
                    bot.sendMessage(chat_id,
                                    'Cannot change version while monitoring with version: '
                                    + str(bot_command.host_details.get_version()))
            bot_command.send_home(chat_id, bot)

        elif '/setcommunity' in txt:
            #
            # set community command, to change snmp community of the snmp queries,
            # example on telegram: /setcommunity <new_community>

            elenco = txt.split(' ')
            val = bot_command.host_details.set_community(elenco[1])
            if val:
                bot.sendMessage(chat_id,
                                'Community correctly modified into: ' + elenco[1])
            else:
                bot.sendMessage(chat_id,
                                'Cannot change community while monitoring with community: '
                                + str(bot_command.host_details.get_community()))
            bot_command.send_home(chat_id, bot)

        elif '/remove' in txt:
            #
            # remove command, to remove the data collected for the graphs,
            # example on telegram: /remove
            if bot_command.host_details.get_monitor():
                bot.sendMessage(chat_id, 'Cannot remove data while monitoring')
            else:
                val = snmp_op.remove_data()
                if val:
                    bot.sendMessage(chat_id, 'Data correctly removed')
                else:
                    bot.sendMessage(chat_id, 'No data collected from ' + bot_command.host_details.get_host())
            bot_command.send_home(chat_id, bot)


def on_callback_query(msg):
    """ Manages the command buttons of the telegram bot.

    :param msg: message received from telegram.
    """

    #
    # Select the content of the message (query_data), and the chat id (chat_id)
    query_id, chat_id, query_data = glance(msg, flavor='callback_query')
    chat_id = msg['message']['chat']['id']
    print('Callback Query: ',  query_data)
    #
    # Check if the chat_id is logged correctly
    x = logClass.method_isloggedid(chat_id)

    if x == 0:
        #
        # Switch construct to manage the various command selected
        #   pushing button on telegram bot.

        ##################################
        #                                #
        #          Home commands         #
        #                                #
        ##################################

        if query_data == 'help':
            bot_command.send_helper(chat_id, bot)

        elif query_data == 'graph':
            bot_command.send_graph(chat_id, bot)

        elif query_data == 'comm':
            bot_command.send_comm_list(chat_id, bot)

        elif query_data == 'settings':
            bot_command.send_settings(chat_id, bot)

        elif query_data == 'system':
            snmp_op.get_info_sys(chat_id, bot)

        elif query_data == 'home':
            bot_command.send_home(chat_id, bot)

        elif query_data == 'start_monitoring':
            if os.path.isdir("./RRDlog/" + bot_command.host_details.get_host()):
                if len(os.listdir("./RRDlog/" + bot_command.host_details.get_host())) == 5:
                    snmp_op.start_monitoring(chat_id, bot, 0, 0)
                else:
                    bot_command.send_length(chat_id, bot)
            else:
                bot_command.send_length(chat_id, bot)

        elif query_data == 'stop_monitoring':
            snmp_op.stop_monitoring(chat_id, bot)

        ##################################
        #                                #
        #          Commands for          #
        #          SNMP requests         #
        #                                #
        ##################################

        elif query_data == 'cpuU':
            snmp_op.get_cpu_usage(chat_id, bot)

        elif query_data == 'totMem':
            snmp_op.get_tot_mem(chat_id, bot)

        elif query_data == 'usedMem':
            snmp_op.get_usage_mem(chat_id, bot)

        elif query_data == 'tasks':
            snmp_op.get_tasks(chat_id, bot)

        elif query_data == 'disk':
            snmp_op.get_disk(chat_id, bot)

        elif query_data == 'classApp':
            snmp_op.app_classific(chat_id, bot)

        ##################################
        #                                #
        #         Graph commands         #
        #                                #
        ##################################

        elif query_data == 'graph_cpu':
            snmp_op.print_graph(chat_id, bot, 0)

        elif query_data == 'graph_ram':
            snmp_op.print_graph(chat_id, bot, 1)

        elif query_data == 'graph_disk':
            snmp_op.print_graph(chat_id, bot, 2)

        elif query_data == 'graph_in':
            snmp_op.print_graph(chat_id, bot, 3)

        elif query_data == 'graph_out':
            snmp_op.print_graph(chat_id, bot, 4)

        ##################################
        #                                #
        #          Dimensions graphs     #
        #          commands              #
        #                                #
        ##################################

        elif query_data == '1day_length':
            length = 86400
            season = 3600
            snmp_op.start_monitoring(chat_id, bot, season, length)

        elif query_data == '1week_length':
            length = 604800
            season = 86400
            snmp_op.start_monitoring(chat_id, bot, season, length)

        elif query_data == '1month_length':
            length = 2419200
            season = 604800
            snmp_op.start_monitoring(chat_id, bot, season, length)

        elif query_data == '1year_length':
            length = 29030400
            season = 2419200
            snmp_op.start_monitoring(chat_id, bot, season, length)

    elif x == 1:
        #
        # The password is change, so the user need to sign in again.
        bot.sendMessage(chat_id, 'The password is changed, please send /login <password>')
    elif x == 2:
        #
        # In this case the user is not logged in.
        bot.sendMessage(chat_id, 'You need to be logged in to start using bot, please send /login password')

    # clearing msg parameter.
    msg = ''


run()
