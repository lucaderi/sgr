from genericpath import isfile
import os

def inputFilePath():

    filePath = input("Enter the path to the PCAP file to analyze: \n")

    if(os.path.isfile(filePath)):
        return filePath;
    else:
        print("No file found at specified path")
        inputFilePath()
