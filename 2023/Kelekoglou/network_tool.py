from scapy import *
import tkinter as tk
import psutil
from geolite2 import geolite2
import socket



geoip_reader = geolite2.reader()

last_recv = psutil.net_io_counters().bytes_recv
last_sent = psutil.net_io_counters().bytes_sent
last_total = last_recv + last_sent

def update_info():
    global last_recv, last_sent, last_total

    bytes_r = psutil.net_io_counters().bytes_recv
    bytes_s = psutil.net_io_counters().bytes_sent
    bytes_t = bytes_r + bytes_s

    new_recv = bytes_r - last_recv
    new_sent = bytes_s - last_sent
    new_total = bytes_t - last_total

    mb_n_recv = new_recv/1024/1024
    mb_n_s = new_sent/1024/1024
    mb_n_t = new_total/1024/1024

    label_text = "Mb received: " + str(mb_n_recv) + "\n  Mb sent:  " + str(mb_n_s) + "\n Mb total: " + str(mb_n_t) + ""
    label.config(text=label_text)

    last_recv = bytes_r
    last_sent = bytes_s
    last_total = bytes_t

    # update every 1 sec
    root.after(1000, update_info)


def geolocation(packet):
    packet_info = packet.summary()

    #src and dest IP 
    src_ip = packet[0][1].src
    dst_ip = packet[0][1].dst

    #geo location for src and dest IP
    src_location = geoip_reader.get(src_ip)
    dst_location = geoip_reader.get(dst_ip)
    

    if src_location != None : 
        src_info =  "Source " + src_ip + " ( " +  src_location['country']['names']['en'] + ")"
    else:
        src_info = "Source Unkwown location "
    
    if dst_location  !=  None:
        dst_info = "Destination " + dst_ip + " ( " + dst_location['country']['names']['en'] + ")"
    else:
        dst_info = "Destination Unkwown location "
    
    packet_textbox.insert(tk.END, packet_info + "\n")
    packet_textbox.insert(tk.END, src_info + "\n")
    packet_textbox.insert(tk.END, dst_info + "\n")
    packet_textbox.insert(tk.END, "...........................\n")


#how many packets
def capturePackets():
    sniff(prn=geolocation, count=10)
    
    


def clear():
    packet_textbox.delete(1.0, tk.END)

#window
root = tk.Tk()
root.title("Network Information and Packet Capturing")

def showDevices():
    def update_device_list():
        
        device_listbox.delete(0, tk.END)
        connected_devices = set()
        for interface, addresses in psutil.net_if_addrs().items():
            for address in addresses:
                if address.family == socket.AF_INET:
                    connected_devices.add(address.address)

        for device in connected_devices:
            device_listbox.insert(tk.END, device)

        root.after(5000, update_device_list)
        
    root = tk.Tk()
    root.title("Connected Devices")
    device_listbox = tk.Listbox(root, font=("Arial", 12))
    device_listbox.pack(padx=20, pady=10)
    update_device_list()    
    root.mainloop()
    

label = tk.Label(root, font=("Arial", 14))
label.pack(padx=20, pady=20)
packet_textbox = tk.Text(root, font=("Arial", 12))
packet_textbox.pack(padx=20, pady=10)
capture_button = tk.Button(root, text="CAPTURE", command=capturePackets)
capture_button.pack(pady=10)
devices_button  = tk.Button(root,text="CONNECTED DEVICES",command =showDevices)
devices_button.pack(pady=10)
clear_button = tk.Button(root, text="CLEAR", command=clear)
clear_button.pack(pady=10)

update_info()
root.mainloop()
