#!/usr/bin/python3

# Installation
# sudo apt-get install libsnmp-dev snmp-mibs-downloader gcc python3-dev
# pip3 install easysnmp
# sudo apt-get install python3-tk

# Import
import sys
from easysnmp import Session
from easysnmp import snmp_get, snmp_set, snmp_walk
from tkinter import *
from time import sleep

# Parameters
hostname = "localhost"
community = "public"
version = 2
if len(sys.argv) == 3:
    hostname = sys.argv[2]
    community = sys.argv[1]
elif len(sys.argv) == 2:
    print("Usage: ./snmpCPUMemory.py or ./snmpCPUMemory.py <community> <hostname>")
    exit(1)
elif len(sys.argv) > 3:
    print("Usage: ./snmpCPUMemory.py or ./snmpCPUMemory.py <community> <hostname>")
    exit(1)

# Create a SNMP session to be used for all our requests
try:
    session = Session(hostname=hostname, community=community, version=version)
except:
    print("ERROR: Bad session!")
    print("Maybe you were wrong to write community and hostname")
    exit(1)
descr = session.get('sysDescr.0')
location = session.get('sysLocation.0')
contact = session.get('sysContact.0')
cpuIdle = session.get('ssCpuIdle.0')
cpuTempPack = session.get('lmTempSensorsValue.1')
memTotalReal = session.get('memTotalReal.0')
memAvailReal = session.get('memAvailReal.0')

# GUI
root = Tk()
root.title("SNMP CPU&Memory Monitor")
root.resizable(False,False)

# Function to update the Label in GUI
def updateCpuUsage(infoLabel):
    cpuIdle = session.get('ssCpuIdle.0')
    infoLabel.configure(text=str(100-int(cpuIdle.value))+'%')
    infoLabel.update()
    infoLabel.after(1000, updateCpuUsage, infoLabel)

def updateCpuTemp(infoLabel, MIB):
    cpuTemp = session.get(MIB)
    infoLabel.configure(text=(str(int(cpuTemp.value)/1000)+" C"))
    infoLabel.update()
    infoLabel.after(1000, updateCpuTemp, infoLabel, MIB)

def updateMemoryFree(infoLabel):
    memAvailReal = session.get('memAvailReal.0')
    infoLabel.configure(text=memAvailReal.value+" kB")
    infoLabel.update()
    infoLabel.after(100, updateMemoryFree, infoLabel)

#GUI General Info
frameTitle1 = Frame(root)
frameTitle1.pack()
generalInfoLabel = Label(frameTitle1, text="General Info", font=("Helvetica",18), fg="blue")
generalInfoLabel.grid()
frameObj1 = Frame(root)
frameObj1.pack(pady=(5,40))
agentLabel = Label(frameObj1, text="Agent:", font=("Helvetica",10, "bold"))
agentLabel.grid(row=0, column=0, sticky=W, padx=20)
agentInfoLaber = Label(frameObj1, text=community+" "+hostname)
agentInfoLaber.grid(row=0, column=1, sticky=W, padx=20)
localLabel = Label(frameObj1, text="Site:", font=("Helvetica",10, "bold"))
localLabel.grid(row=1, column=0, sticky=W, padx=20)
localInfoLabel = Label(frameObj1, text=location.value)
localInfoLabel.grid(row=1, column=1, sticky=W, padx=20)
contactLabel = Label(frameObj1, text="Contact:", font=("Helvetica",10, "bold"))
contactLabel.grid(row=2, column=0, sticky=W, padx=20)
contactInfoLabel = Label(frameObj1, text=contact.value)
contactInfoLabel.grid(row=2, column=1, sticky=W, padx=20)
descrMessage = Message(frameObj1, text=descr.value)
descrMessage.grid(row=3, columnspan=2)

#GUI CPU Info
frameTitle2 = Frame(root)
frameTitle2.pack()
cpuInfoLabel = Label(frameTitle2, text="CPU Info", font=("Helvetica",18), fg="blue")
cpuInfoLabel.grid()
frameObj2 = Frame(root)
frameObj2.pack(pady=(5,40))
cpuUsageLabel = Label(frameObj2, text="Cpu Usage:", font=("Helvetica",10, "bold"))
cpuUsageLabel.grid(row=0, column=0, sticky=W, padx=20)
cpuUsageInfoLabel = Label(frameObj2, text=str(100-int(cpuIdle.value))+'%')
cpuUsageInfoLabel.grid(row=0, column=1, sticky=W, padx=20)
updateCpuUsage(cpuUsageInfoLabel)
if cpuTempPack.value != "NOSUCHINSTANCE":
    cpuTempPackLabel = Label(frameObj2, text="Cpu package Temperature:", font=("Helvetica",10, "bold"))
    cpuTempPackLabel.grid(row=1, column=0, sticky=W, padx=20)
    cpuTemppackInfoLabel = Label(frameObj2, text=str(int(cpuTempPack.value)/1000)+" C")
    cpuTemppackInfoLabel.grid(row=1, column=1, sticky=W, padx=20)
    updateCpuTemp(cpuTemppackInfoLabel, 'lmTempSensorsValue.1')

#GUI Memory Info
frameTitle3 = Frame(root)
frameTitle3.pack()
memoryInfoLabel = Label(frameTitle3, text="Memory Info", font=("Helvetica",18), fg="blue")
memoryInfoLabel.grid()
frameObj3 = Frame(root)
frameObj3.pack(pady=(5,40))
memTotalLabel = Label(frameObj3, text="RAM in machine:", font=("Helvetica",10, "bold"))
memTotalLabel.grid(row=0, column=0, sticky=E, padx=20)
memTotalInfoLabel = Label(frameObj3, text=memTotalReal.value+" kB")
memTotalInfoLabel.grid(row=0, column=1, sticky=E, padx=20)
memAvailLabel = Label(frameObj3, text="RAM free:", font=("Helvetica",10, "bold"))
memAvailLabel.grid(row=1, column=0, sticky=E, padx=20)
memAvaiInfolLabel = Label(frameObj3, text=memAvailReal.value+" kB")
memAvaiInfolLabel.grid(row=1, column=1, sticky=E, padx=20)
updateMemoryFree(memAvaiInfolLabel)

if __name__ == "__main__":
    root.mainloop()

