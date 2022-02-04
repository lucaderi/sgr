"""Traffic flow config module

@autor: Alessandro Ambrogini

"""
from netaddr import IPNetwork, IPAddress

myPublicIP = IPAddress("xxx.xxx.xxx.xxx")
localNet = IPNetwork("xxx.xxx.xxx.0/24")

#definizione del dizionario per collezionare i dati, 
# ogni minuto verrà resettato dopo la chiamata della API da InfluxDB
data = {}
