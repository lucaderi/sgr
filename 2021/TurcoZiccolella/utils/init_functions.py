import shutil
import os
import configparser
from configparser import NoOptionError, NoSectionError
import glob

def Setup():
    
    print("Removing Old Files")

    if os.path.exists("rrd"): shutil.rmtree("rrd")
    if os.path.exists("xml"): shutil.rmtree("xml")
    if os.path.exists("pcap"): shutil.rmtree("pcap")

    for f in glob.glob("*.pcap"):
        os.remove(f)

    config()

    os.makedirs("rrd")
    os.makedirs("xml")
    os.makedirs("pcap")

    print("\n Setup completed \n")


def config():
    #Controlla se il file config esiste e chiedi all'utente se lo vuole modificare o no 
    if os.path.isfile("config.ini"):
        try:

            conf = configparser.ConfigParser()
            conf.read("config.ini")
            if_ = conf.get("Settings", "interface")
            grafana_api = conf.get("Settings","grafana_api")
            filter_mode = conf.get("Settings","filter_mode")
            rrd_step = conf.get("Settings","refresh")
            ttl = conf.get("Settings","ttl_flow")
            max_talkers = conf.get("Settings", "max_talkers")
            rk_tim = conf.get("Settings", "refr_ranking")
            max_top = conf.get("Settings", "max_top")



            print("Config file found -> \n")

            print("Interface : " + if_)
            print("Grafana_API_Key : " + grafana_api)
            print("Aggregation Mode : " + filter_mode + " (aggregate traffic by ip or prot7)")
            print("RDD_step : " + rrd_step + " (compute flows every x sec)")
            print("Flow TTL : " + ttl + " (remove talker's after x sec of inactivity)")
            print("Max Talkers : " + max_talkers + " (max number of talkers to keep in memory)")
            print("Ranking Refresh Time : " + rk_tim + " (refresh ranking every x steps)")
            print("Max Ranking Talker : " + max_top + " (display max x talkers)\n")
            
            
        except (NoOptionError,NoSectionError) as e:
            os.remove("config.ini")
            create_ini()
            return

        while True:
            choice = input("do want to keep this configuration? [y/n]")
            if choice == "y":
                return
            elif choice == "n":
                os.remove("config.ini")
                create_ini()
                break
            

    else: create_ini()

def create_ini():
    
        file = open("config.ini", 'w')
        conf = configparser.ConfigParser()
        conf.add_section("Settings")

        # Choosing Interface
        interfaces = os.listdir('/sys/class/net/')
        print("Interfaces Available")
        for _if in interfaces:
            print("- " + _if)

        while True:
            chosen_if = input("Choose an interface from the list :\n")

            if chosen_if in interfaces:
                conf.set("Settings", "interface", chosen_if)
                break
            else:
                print("You typed a wrong interface")
        
        # Choosing API Key
        api_key = input("Type grafana api key [Bearer --------] :\n")
        conf.set("Settings","grafana_api", api_key)

        # Choosing  Aggregation Mode
        while True:
            mode = input("Choose Aggregation Mode [ip,prot7] (aggregate traffic by ip or prot7) :\n")
            if mode== "ip" or mode== "prot7":
                conf.set("Settings", "filter_mode", mode)
                break
            else:
                print("Modes available :  ip' or 'prot7'")
        
        # Choosing RRD Step
        while True:
            refresh_rate = input("Choose RDD_step [int -> seconds] (compute flows every x sec) :\n")
            if int(refresh_rate) > 0:
                conf.set("Settings", "refresh", refresh_rate)
                break
            else:
                print("RRD_Step must be > 0")

            
        # Choosing timetolive
        while True:
            ttl_flow = input("Choose the ttl of flows [int -> seconds] (remove talker's after x sec of inactivity):\n")
            v = int(ttl_flow)
            if v > int(refresh_rate):
                conf.set("Settings", "ttl_flow", ttl_flow)
                break
            else:
                print("The flow ttl must be > rrd_step")

        # Choosing max_talkers
        while True:
            max_talkers = input("Choose the max number of talkers to keep in memory: [int] (if too low you will lose talkers) \n")
            v = int(max_talkers)
            if v>0 and v<=999999:
                conf.set("Settings", "max_talkers",max_talkers)
                break
            else:
                print("Max talkers must be > 0 and < 999999")
            
        # Choosing ranking timer
        while True:
            rk_tim = input("Choose every how many rrd_steps the ranking will be updated [int] :\n")
            if int(rk_tim)>0:
                conf.set("Settings", "refr_ranking", rk_tim)
                break
            else:
                print("The ranking refresh time must be > 1")
        
        # Choosing max top
        while True:
            max_top = input("Choose how many talkers do you want to display in grafana ranking [int] :\n")
            v = int(max_top)
            if v>0 and v<=20:
                conf.set("Settings", "max_top", max_top )
                break
            else:
                print("The ranking refresh time must be > 1")

        
        conf.write(file)
        file.close()