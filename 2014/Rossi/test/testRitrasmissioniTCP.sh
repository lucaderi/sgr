#!/bin/bash

TEST_FILE1="NoRitrasmissioni"
TEST_FILE2="2Ritrasmissioni"
TEST_FILE3="TCP_SACK.pcap"
TEST_FILE4="demo.pcap"

echo "Attenzione questo script può richiedere l'inserimento della propria password" 
echo "Premere un Tasto per continuare"
read n

echo " 1 Test file: $TEST_FILE1 :file generato con il tool Packeth"
java -jar RitrasmissioniTCP.jar readfile $TEST_FILE1 
echo "Premere Invio per continuare "
read n

echo " 2 Test file: $TEST_FILE2 :file generato con il tool Packeth"
java -jar RitrasmissioniTCP.jar readfile $TEST_FILE2 
echo "Premere Invio per continuare "
read n


echo " 3 Test file: $TEST_FILE3 : file generato da wireshark"
java -jar RitrasmissioniTCP.jar readfile $TEST_FILE3 
echo "Premere Invio per continuare "
read n

echo " 4 Test file: $TEST_FILE4 : file generato da wireshark"
java -jar RitrasmissioniTCP.jar readfile $TEST_FILE4 
echo "Premere Invio per continuare "
read n

echo " 5 Test realTime"
echo -e "\e[0;31mInserire nome interfaccia\e[0m"
read line
echo "Premi ctrl + c per uscire"
sudo java -jar RitrasmissioniTCP.jar realtime $line  
echo "Premere Invio per continuare "
read n



