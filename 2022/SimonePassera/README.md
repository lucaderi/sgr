# Raspberry Pi Temp :fire:
Il progetto consiste nel monitoraggio del sensore di temperatura (DS18B20) collegato tramite GPIO ad un Raspberry Pi.

![DS18B20](img/sensor.jpg?raw=true "DS18B20")

## SNMP
Sul raspberry pi è installato un agent snmp opportunamente  [configurato](snmp/snmpd.conf) per restituire, quando interrogato, il valore della temperatura corrente presente nella stanza.

  ### Installazione
  ```
  sudo apt install snmp snmp-mibs-downloader snmpd
  ```

  ### Utilizzo
  ```
  snmpget -v1 -c public raspberrypi-simone.ddns.net nsExtendOutputFull.\"temp\"
  ```
## Previsione

## Avviso Telegram

## Temp Manager bot

## Sito web
