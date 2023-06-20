#!/usr/bin/python3

# Version: 1.2
# Source: https://github.com/eval2A/dionaeaToJSON
# Scripted for Dionaea 0.6.0, but should also work for Dionaea 0.8.0

# Description:
# Converts the SQLite database produced by Dionaea to a JSON format suitable for the ELK stack.
# The JSON log files includes details about connections, downloads, logins, SQL commands, etc.

# Requirements for running the script:
# Python 3
# SQLite logging enabled in Dionaea

# This script is meant to run every minute as a cronjob. However, it may be a little heavy
# to run this script the first time, so it is advised that this is done manually.
# This is what you should put in your crontab, it will make the script run every minute:
# */1 * * * * /usr/bin/python3 /path/to/dionaeaSqliteToJson.py

import sqlite3
import json
from datetime import datetime
import time
import re
import os
import subprocess

# Path of the Dionaea SQLite database file (make sure this is the correct path)
dionaeaSQLite = '/ctlr1/dionaea/log/dionaea.sqlite'

# Path to where to store the json log files (optional path)
dionaeaLogPath = '/ctrl1/dionaea/json1'

# Path to binaries captured by Dionaea
dionaeaBinariesPath = '/ctrl1/dionaea/binaries'

# Configure the SQL database tables to extract information from.
# The configuration is set up for a defaul installation of Dionaea 0.6.0, with Virus Total enabled.
sqlTables = {
    0:{
        'table':'dcerpcbinds',
        'index':'dcerpcbind',
        'joins':{
            'dcerpcservices':{
                'joinTable':'dcerpcservices',
                'parentIndex':'dcerpcbind_uuid',
                'joinIndex':'dcerpcservice_uuid',
                'joins':{
                    'dcerpcserviceops':{
                        'joinTable':'dcerpcserviceops',
                        'parentIndex':'dcerpcservice',
                        'joinIndex':'dcerpcservice'
                    }
                }
            }
        }
    },
    1:{
        'table':'dcerpcrequests',
        'index':'dcerpcrequest',
        'joins':{
            'dcerpcservices':{
                'joinTable':'dcerpcservices',
                'parentIndex':'dcerpcrequest_uuid',
                'joinIndex':'dcerpcservice_uuid',
                'joins':{
                    'dcerpcserviceops':{
                        'joinTable':'dcerpcserviceops',
                        'parentIndex':'dcerpcservice',
                        'joinIndex':'dcerpcservice'
                    }
                }
            }
        }
    },
    2:{
        'table':'downloads',
        'index':'download',
        'removeHTMLFiles':True,
        'virusTotal':True
    },
    3:{
        'table':'emu_profiles',
        'index':'emu_profile'
    },
    4:{
        'table':'emu_services',
#       'index':'emu_service' There is a typo in the Dionaea SQLite DB. Bug report: https://github.com/DinoTools/dionaea/issues/139
        'index':'emu_serivce'
    },
    5:{
        'table':'logins',
        'index':'login'
    },
    6:{
        'table':'mqtt_fingerprints',
        'index':'mqtt_fingerprint'
    },
    7:{
        'table':'mqtt_publish_commands',
        'index':'mqtt_publish_command'
    },
    8:{
        'table':'mqtt_subscribe_commands',
        'index':'mqtt_subscribe_command'
    },
    9:{
        'table':'mssql_commands',
        'index':'mssql_command'
    },
    10:{
        'table':'mssql_fingerprints',
        'index':'mssql_fingerprint'
    },
    11:{
        'table':'mysql_commands',
        'index':'mysql_command',
        'joins':{
            'mysql_command_args':{
                'joinTable':'mysql_command_args',
                'parentIndex':'mysql_command',
                'joinIndex':'mysql_command'
            },
            'mysql_command_ops':{
                'joinTable':'mysql_command_ops',
                'parentIndex':'mysql_command_cmd',
                'joinIndex':'mysql_command_cmd'
            }
        }
    },
    12:{
        'table':'offers',
        'index':'offer'
    },
    13:{
        'table':'p0fs',
        'index':'p0f'
    },
    14:{
        'table':'resolves',
        'index':'resolve'
    },
    15:{
        'table':'sip_commands',
        'index':'sip_command',
        'joins':{
            'sip_addrs':{
                'joinTable':'sip_addrs',
                'parentIndex':'sip_command',
                'joinIndex':'sip_command'
            },
            'sip_sdp_connectiondatas':{
                'joinTable':'sip_sdp_connectiondatas',
                'parentIndex':'sip_command',
                'joinIndex':'sip_command'
            },
            'sip_sdp_medias':{
                'joinTable':'sip_sdp_medias',
                'parentIndex':'sip_command',
                'joinIndex':'sip_command'
            },
            'sip_sdp_origins':{
                'joinTable':'sip_sdp_origins',
                'parentIndex':'sip_command',
                'joinIndex':'sip_command'
            },
            'sip_vias':{
                'joinTable':'sip_vias',
                'parentIndex':'sip_command',
                'joinIndex':'sip_command'
            }
        }
    },

    # Custom config for other services/ihandlers.
    # x:{
    #     'table':'',
    #     'index':''
    # },
    #
    # Custom config for other services/ihandlers that require data from other tables as well.
    # x:{
    #     'table':'',
    #     'index':'',
    #     'joins':{
    #         '':{
    #             'joinTable':'',
    #             'parentIndex':'',
    #             'joinIndex':'',
    #             'joins':{
    #                 '':{
    #                     'joinTable':'',
    #                     'parentIndex':'',
    #                     'joinIndex':'',
    #                     'joins':{
    #                         '':{
    #                             'joinTable':'',
    #                             'parentIndex':'',
    #                             'joinIndex':''
    #                         },
    #                         '':{
    #                             'joinTable':'',
    #                             'parentIndex':'',
    #                             'joinIndex':''
    #                         },
    #                         '':{
    #                             'joinTable':'',
    #                             'parentIndex':'',
    #                             'joinIndex':''
    #                         }
    #                     }
    #                 },
    #                 '':{
    #                     'joinTable':'',
    #                     'parentIndex':'',
    #                     'joinIndex':''
    #                 }
    #             }
    #         },
    #         '':{
    #             'joinTable':'',
    #             'parentIndex':'',
    #             'joinIndex':''
    #         }
    #     }
    # },

    # Connections must be the last table in order to avoid duplicate entries.
    100:{
        'table':'connections',
        'index':'connection'
    }
}

# Check if the SQLite database file is located
if os.path.isfile(dionaeaSQLite):

    # Assure that the log directory exists
    if not os.path.isdir(dionaeaLogPath):
        os.makedirs(dionaeaLogPath)

    # To avoid having to process data from the sqlite db file already processed,
    # this script keeps a registry database over where it last extracted data from the configured SQL tables.
    # To initiate this index process, we need to prepare an array for this sessions index checkup.
    currentIndex = {}

    # Check for if the database of the previous indexes exists
    registryExists = os.path.isfile(dionaeaLogPath + '/dionaea.registry.json')

    # Import the index database created by the script, or prepare to create one.
    if registryExists:
        previousIndex = json.load(open(dionaeaLogPath + '/dionaea.registry.json'))
    else:
        previousIndex = {}

    # Create a temporary list over connections used, so that we can avoid including those twice.
    usedConnections = []

    # Function to turn the results into a dictionary
    def dictFactory(cursor, row):
        d = {}
        for idx, col in enumerate(cursor.description):
            d[col[0]] = row[idx]
        return d

    # Iniate a connection to the database
    connection = sqlite3.connect(dionaeaSQLite)
    connection.row_factory = dictFactory
    cursor = connection.cursor()

    # Function to loop through joins from config and generate the required sql join commands
    def joinsLoop(parentTableIdentifier, joinsConfig):
        sql = ''
        for joinIdentifier, joinConfig in joinsConfig.items():
            sql += 'LEFT JOIN '+joinConfig['joinTable']+' '+joinIdentifier+' ON'+' '+parentTableIdentifier+'.'+joinConfig['parentIndex']+'='+joinIdentifier+'.'+joinConfig['joinIndex']+' '
            if 'joins' in joinConfig:
                sql += (joinsLoop(joinIdentifier, joinConfig['joins']))
        return (sql)

    # A counter to count total entries
    totalEntries = 0
    totalNewEntries = 0

    # Build the sql commands and execute them, then log the results
    for sqlTableIdentifier, sqlTableConfig in sqlTables.items():

        # Convert the sqlTableIdentifier to a string as it is automatically converted from int when storing it to the registy file
        sqlTableIdentifier = str(sqlTableIdentifier)

        print ('=========================================')
        print ('# Processing ' + sqlTableConfig['index'] + ':')
        print ('# ---------------------------------------')
        # Get the current index of the table
        cursor.execute('SELECT COALESCE(MAX(' + sqlTableConfig['index'] + ')+0, 0) FROM ' + sqlTableConfig['table'])
        results = cursor.fetchone()
        # Convert the result into a string (probably not the best way to this, but hey..)
        coalMaxString = str(results)
        # Extract all integers from that string
        coalMaxIntegers = (re.findall('\d+', coalMaxString ))
        # Store the correct integer in the currentIndex
        currentIndex[sqlTableIdentifier] = coalMaxIntegers[2]
        # Update the total entries counter
        totalEntries += int(currentIndex[sqlTableIdentifier])
        # Print the total numbers of entries
        print ('# Total entries: ' + currentIndex[sqlTableIdentifier])

        # Build the SQL query
        # Check if there are any new inputs in the database and limit the results
        if sqlTableIdentifier in previousIndex:
            newResults = int(currentIndex[sqlTableIdentifier]) - int(previousIndex[sqlTableIdentifier])
            sqlLimit = 'LIMIT ' + previousIndex[sqlTableIdentifier] + ',' + str(newResults)
        else:
            newResults = currentIndex[sqlTableIdentifier]
            sqlLimit = False

        # Update the total new entries counter
        totalNewEntries += int(newResults)

        # Print status about new results
        print ('# New entries to process: ' + str(newResults))

        # Building the SQL queries
        if sqlTableConfig['index'] == 'connection':
            usedConnectionsString = ', '.join(str(e) for e in usedConnections)
            sql = 'SELECT * FROM connections WHERE NOT connection in (' + usedConnectionsString + ') '
        else:
            sql = 'SELECT * FROM ' + sqlTableConfig['table'] + ' '
            if 'joins' in sqlTableConfig:
                sql += joinsLoop(sqlTableConfig['table'], sqlTableConfig['joins'])
            # Include data from connections
            sql += 'LEFT JOIN connections USING (connection) '

        # Set a limit to the query
        if sqlLimit:
            sql += sqlLimit

        # Execute and fetch results
        cursor.execute(sql)
        results = cursor.fetchall()

        # Iterate the results and correct a few things
        for result in results:

            # Add result event id
            result['eventid'] = sqlTableConfig['index']

            # Create a time stamp in ISO 8601 format with accordance to ELK
            result['timestamp'] = (datetime.fromtimestamp(result['connection_timestamp']).isoformat() + 'Z')

            # Create a date-format to used for the log names
            timestampYMD = time.strftime('%Y-%m-%d', time.localtime(result['connection_timestamp']))
            result.pop('connection_timestamp', None)

            ignoreDownload = False
            if sqlTableConfig['index'] == 'download':
                # Check download for filetype
                if os.path.isfile(dionaeaBinariesPath + '/' + result['download_md5_hash']):
                    result['download_filetype'] = subprocess.check_output('file -b ' + dionaeaBinariesPath + '/'  + result['download_md5_hash'], shell=True)
                    if isinstance(result['download_filetype'], bytes):
                        result['download_filetype'] = result['download_filetype'].decode('utf-8', 'replace')
                    # Remove HTML files
                    if 'removeHTMLFiles' in sqlTableConfig and sqlTableConfig['removeHTMLFiles']:
                        if result['download_filetype'].startswith('HTML'):
                            os.system('rm ' + dionaeaBinariesPath + '/'  + result['download_md5_hash'])
                            ignoreDownload = True
                # Check if VT is enabled
                if 'virusTotal' in sqlTableConfig and sqlTableConfig['virusTotal']:
                    result['virustotal'] = {}
                    cursor.execute('SELECT * FROM virustotals WHERE virustotal_md5_hash="' + result['download_md5_hash'] + '" ORDER BY virustotal_timestamp DESC')
                    virusTotalsResult = cursor.fetchone()
                    if virusTotalsResult:
                        result['virustotal_total_scanners'] = 0
                        result['virustotal_total_positive_results'] = 0
                        virusTotalsResult['virustotal_timestamp'] = (datetime.fromtimestamp(virusTotalsResult['virustotal_timestamp']).isoformat() + 'Z')
                        result.update(virusTotalsResult)
                        cursor.execute('SELECT virustotalscan_scanner, virustotalscan_result FROM virustotalscans WHERE virustotal=' + str(virusTotalsResult['virustotal']))
                        virusTotalsScanResults = cursor.fetchall()
                        for virusTotalsScanResult in virusTotalsScanResults:
                            result['virustotal_total_scanners'] += 1
                            if virusTotalsScanResult['virustotalscan_result']:
                                result['virustotal_total_positive_results'] += 1
                            result.update({virusTotalsScanResult['virustotalscan_scanner']:virusTotalsScanResult['virustotalscan_result']})

            # Clean the results for byte string issues
            for i in result:
                if isinstance(result[i], bytes):
                    result[i] = result[i].decode('utf-8', 'replace')

            # Generate empty log files if they don't exist
            if not os.path.isfile(dionaeaLogPath + '/dionaea.json.' + timestampYMD):
                open(dionaeaLogPath + '/dionaea.json.' + timestampYMD,'a').close()
                print ('# Created log file:')
                print ('# ' + dionaeaLogPath + '/dionaea.json.' + timestampYMD)

            # Append the result to the log file
            if not ignoreDownload:
                with open(dionaeaLogPath + '/dionaea.json.' + timestampYMD, 'a') as file:
                    file.write(json.dumps(result) + '\n')

            # Append connection ID used to the connection ID dictionary
            if not sqlTableIdentifier == '100':
                usedConnections.append(result['connection'])

    # Close the sqlite3 connection
    connection.close()

    # Register the current indexes
    with open(dionaeaLogPath + "/dionaea.registry.json", "w") as file:
        file.write(json.dumps(currentIndex))

    # End of code
    print ('=========================================')
    print ('#                Finished!               ')
    print ('# ---------------------------------------')
    print ('# Total entries: ' + str(totalEntries))
    print ('# Total processed entries: ' + str(totalNewEntries))
    print ('# ---------------------------------------')
    print ('# The logs are located in:')
    print ('# ' + dionaeaLogPath)
    print ('=========================================')

# SQLite database file not located
else:
    print ('=========================================')
    print ('# Unable to locate the sqlite db file:')
    print ('# ' + dionaeaSQLite)
    print ('# ---------------------------------------')
    print ('# Make sure that:')
    print ('# - Dionaea is installed')
    print ('# - SQLite is logging enabled')
    print ('# - The script uses the correct path')
    print ('=========================================')
